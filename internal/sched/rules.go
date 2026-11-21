package sched

import (
	"fmt"
	"net"
	"strings"

	"proxygw/internal/model"
)

// Domain pattern kinds accepted by the sticky blacklist.
type domainKind int

const (
	domainExact domainKind = iota
	domainSuffix
	domainWildcard
)

// domainPattern is one compiled TargetSpec.Domains entry.
type domainPattern struct {
	kind  domainKind
	value string // lower case, no leading dot / "*."
}

// domainMatches reports whether host matches the pattern.
//
//	"bank.com"    exact match only ("bank.com")
//	".bank.com"   apex plus subdomains ("bank.com", "www.bank.com")
//	"*.bank.com"  subdomains only, never the bare apex ("www.bank.com")
//
// Comparison is case insensitive; a single trailing dot (fully qualified form)
// is ignored on both sides.
func (p domainPattern) domainMatches(host string) bool {
	if host == "" {
		return false
	}
	switch p.kind {
	case domainExact:
		return host == p.value
	case domainSuffix:
		return host == p.value || strings.HasSuffix(host, "."+p.value)
	case domainWildcard:
		return strings.HasSuffix(host, "."+p.value)
	default:
		return false
	}
}

// compiledRule is the immutable, validated form of a model.StickyRule.
type compiledRule struct {
	id        string
	enabled   bool
	cidrs     []*net.IPNet
	domains   []domainPattern
	nodeIDs   map[string]struct{}
	nodeGroup []string
}

// ruleSet is an immutable list of compiled sticky rules, swapped atomically by
// SetStickyRules so Select never blocks on rule updates.
type ruleSet struct {
	rules []compiledRule
}

// targetView is the normalized destination of one request, pre-parsed once per
// decision so CIDR matching does not re-parse the host for every rule.
type targetView struct {
	host string
	ip   net.IP
}

func makeTargetView(t model.RequestTarget) targetView {
	host := normalizeHost(t.Host)
	var ip net.IP
	if host != "" {
		ip = net.ParseIP(host)
	}
	return targetView{host: host, ip: ip}
}

// hits reports whether the rule's target dimension matches the destination.
func (v targetView) hits(r *compiledRule) bool {
	if v.ip != nil {
		for _, cidr := range r.cidrs {
			if cidr.Contains(v.ip) {
				return true
			}
		}
	}
	if v.host == "" {
		return false
	}
	for _, d := range r.domains {
		if d.domainMatches(v.host) {
			return true
		}
	}
	return false
}

// ruleNodeHits reports whether the rule's node dimension matches the node or one
// of the additionally supplied group IDs.
func ruleNodeHits(r *compiledRule, node *model.Node, extraGroups []string) bool {
	if node != nil {
		if _, ok := r.nodeIDs[node.ID]; ok {
			return true
		}
	}
	if len(r.nodeGroup) == 0 {
		return false
	}
	for _, want := range r.nodeGroup {
		if node != nil && containsExactToken(node.Groups, want) {
			return true
		}
		if containsExactToken(extraGroups, want) {
			return true
		}
	}
	return false
}

// explain walks the rules in order and returns the first enabled rule whose
// target or node dimension hits. node may be nil, in which case only the target
// dimension and the extra nodeGroups are evaluated.
func (rs *ruleSet) explain(target model.RequestTarget, node *model.Node, nodeGroups []string) (string, bool) {
	if rs == nil {
		return "", false
	}
	view := makeTargetView(target)
	for i := range rs.rules {
		r := &rs.rules[i]
		if !r.enabled {
			continue
		}
		if view.hits(r) || ruleNodeHits(r, node, nodeGroups) {
			return r.id, true
		}
	}
	return "", false
}

// matchTarget evaluates only the target dimension of the enabled rules.
func (rs *ruleSet) matchTarget(target model.RequestTarget) (string, bool) {
	return rs.explain(target, nil, nil)
}

// matchNode evaluates the target dimension (empty target never hits) plus the
// node dimension against node.Groups.
func (rs *ruleSet) matchNode(node *model.Node, extraGroups []string) (string, bool) {
	if node == nil {
		return "", false
	}
	return rs.explain(model.RequestTarget{}, node, extraGroups)
}

// compileStickyRules validates and compiles a rule list. The returned set is
// never nil; on error the caller keeps its previous rule set.
func compileStickyRules(rules []model.StickyRule) (*ruleSet, error) {
	set := &ruleSet{rules: make([]compiledRule, 0, len(rules))}
	for i := range rules {
		src := rules[i]
		cr := compiledRule{
			id:      src.ID,
			enabled: src.Enabled,
		}
		where := ruleLabel(i, src.ID)
		for _, raw := range src.Target.CIDRs {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			ipnet, err := parseTargetCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("sched: sticky rule %s: target cidr: %w", where, err)
			}
			cr.cidrs = append(cr.cidrs, ipnet)
		}
		for _, raw := range src.Target.Domains {
			dp, err := compileDomainPattern(raw)
			if err != nil {
				return nil, fmt.Errorf("sched: sticky rule %s: target domain: %w", where, err)
			}
			cr.domains = append(cr.domains, dp)
		}
		for _, id := range src.NodeIDs {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if cr.nodeIDs == nil {
				cr.nodeIDs = make(map[string]struct{}, len(src.NodeIDs))
			}
			cr.nodeIDs[id] = struct{}{}
		}
		for _, group := range src.NodeGroups {
			group = strings.TrimSpace(group)
			if group == "" {
				continue
			}
			cr.nodeGroup = append(cr.nodeGroup, group)
		}
		set.rules = append(set.rules, cr)
	}
	return set, nil
}

// ruleLabel renders a rule for error messages.
func ruleLabel(index int, id string) string {
	if id != "" {
		return fmt.Sprintf("%q", id)
	}
	return fmt.Sprintf("#%d", index+1)
}

// parseTargetCIDR accepts a CIDR or a bare IP address (treated as /32 or /128).
func parseTargetCIDR(raw string) (*net.IPNet, error) {
	if strings.Contains(raw, "/") {
		ip, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		if ip == nil || ipnet == nil {
			return nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		return ipnet, nil
	}
	ip := net.ParseIP(normalizeHost(raw))
	if ip == nil {
		return nil, fmt.Errorf("invalid IP or CIDR %q", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// compileDomainPattern validates and compiles a TargetSpec.Domains entry.
func compileDomainPattern(raw string) (domainPattern, error) {
	s := normalizeHost(raw)
	if s == "" {
		return domainPattern{}, fmt.Errorf("empty value")
	}
	if strings.Contains(s, "://") {
		return domainPattern{}, fmt.Errorf("%q is a URL, want a domain name", raw)
	}
	if strings.ContainsAny(s, "/: \t") {
		return domainPattern{}, fmt.Errorf("invalid domain pattern %q", raw)
	}
	switch {
	case strings.HasPrefix(s, "*."):
		base := strings.TrimPrefix(s, "*.")
		if base == "" || strings.Contains(base, "*") {
			return domainPattern{}, fmt.Errorf("unsupported wildcard %q (only a leading \"*.\" is allowed)", raw)
		}
		return domainPattern{kind: domainWildcard, value: base}, nil
	case strings.HasPrefix(s, "."):
		base := strings.TrimPrefix(s, ".")
		if base == "" || strings.Contains(base, "*") {
			return domainPattern{}, fmt.Errorf("unsupported suffix %q", raw)
		}
		return domainPattern{kind: domainSuffix, value: base}, nil
	default:
		if strings.Contains(s, "*") {
			return domainPattern{}, fmt.Errorf("unsupported wildcard %q (only a leading \"*.\" is allowed)", raw)
		}
		return domainPattern{kind: domainExact, value: s}, nil
	}
}

// normalizeHost lower-cases and normalizes a host name or IP literal.
func normalizeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimSuffix(h, ".")
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return h
}

// containsExactToken reports whether tokens contains want (trimmed, case
// sensitive: node/group IDs are opaque identifiers).
func containsExactToken(tokens []string, want string) bool {
	for _, token := range tokens {
		if strings.TrimSpace(token) == want {
			return true
		}
	}
	return false
}
