package acl

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"proxygw/internal/model"
)

// compiledRule is the immutable, pre-compiled form of one operator rule. Rules
// are compiled once by SetRules so request path matching never parses text.
type compiledRule struct {
	raw       model.ACLRule
	action    string
	src       []*net.IPNet
	domains   []domainMatcher
	ports     []portRange
	protocols map[string]struct{} // nil means any protocol
}

// domainKind selects how a domain rule entry is matched against a target host.
type domainKind uint8

const (
	// domainExact matches the bare host name only: "example.com".
	domainExact domainKind = iota
	// domainSubdomains matches the host and every subdomain: ".example.com".
	domainSubdomains
	// domainWildcard matches subdomains only, never the bare host: "*.example.com".
	domainWildcard
	// domainIPNet matches IP literal targets: "10.0.0.0/8" or "8.8.8.8".
	domainIPNet
)

// domainMatcher is one compiled entry of an ACLRule.Domains list. The Domains
// field accepts host names and IP/CIDR literals; the two never match each
// other because a target is classified once as either an IP or a name.
type domainMatcher struct {
	kind domainKind
	host string
	ipn  *net.IPNet
}

// portRange is one compiled entry of an ACLRule.Ports list.
type portRange struct {
	lo, hi int
}

// compileRules clones, validates and compiles the operator rules. The returned
// raw rules are in evaluation order; the compilation order is stable, so equal
// Order values keep configuration order.
func compileRules(in []model.ACLRule) ([]compiledRule, []model.ACLRule, error) {
	rules := cloneRules(in)
	compiled := make([]compiledRule, len(rules))
	for i := range rules {
		cr, err := compileRule(rules[i])
		if err != nil {
			return nil, nil, fmt.Errorf("acl: rule[%d] (id=%q): %w", i, rules[i].ID, err)
		}
		compiled[i] = *cr
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].raw.Order < compiled[j].raw.Order
	})
	sorted := make([]model.ACLRule, len(compiled))
	for i := range compiled {
		sorted[i] = compiled[i].raw
	}
	return compiled, sorted, nil
}

func compileRule(r model.ACLRule) (*compiledRule, error) {
	cr := &compiledRule{raw: r}
	action := strings.ToLower(strings.TrimSpace(r.Action))
	switch action {
	case model.ActionAllow, model.ActionDeny:
		cr.action = action
	default:
		return nil, fmt.Errorf("action %q: must be %q or %q", r.Action, model.ActionAllow, model.ActionDeny)
	}
	for i, raw := range r.SrcCIDRs {
		n, err := parseCIDROrIP(raw)
		if err != nil {
			return nil, fmt.Errorf("src_cidrs[%d] %q: %w", i, raw, err)
		}
		cr.src = append(cr.src, n)
	}
	for i, raw := range r.Domains {
		m, err := compileDomain(raw)
		if err != nil {
			return nil, fmt.Errorf("domains[%d] %q: %w", i, raw, err)
		}
		cr.domains = append(cr.domains, m)
	}
	for i, raw := range r.Ports {
		pr, err := parsePortRange(raw)
		if err != nil {
			return nil, fmt.Errorf("ports[%d] %q: %w", i, raw, err)
		}
		cr.ports = append(cr.ports, pr)
	}
	if len(r.Protocols) > 0 {
		cr.protocols = make(map[string]struct{}, len(r.Protocols))
		for i, raw := range r.Protocols {
			proto := strings.ToLower(strings.TrimSpace(raw))
			switch proto {
			case model.ProtoHTTP, model.ProtoConnect, model.ProtoSOCKS5, model.ProtoTCP:
				cr.protocols[proto] = struct{}{}
			default:
				return nil, fmt.Errorf("protocols[%d] %q: must be one of %s, %s, %s, %s",
					i, raw, model.ProtoHTTP, model.ProtoConnect, model.ProtoSOCKS5, model.ProtoTCP)
			}
		}
	}
	return cr, nil
}

// cloneRules deep copies a rule slice. It always returns a non-nil slice so
// Rules() and the panel API render [] instead of null.
func cloneRules(in []model.ACLRule) []model.ACLRule {
	out := make([]model.ACLRule, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].SrcCIDRs = cloneStrings(in[i].SrcCIDRs)
		out[i].Domains = cloneStrings(in[i].Domains)
		out[i].Ports = cloneStrings(in[i].Ports)
		out[i].Protocols = cloneStrings(in[i].Protocols)
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// compileDomain classifies and validates one ACLRule.Domains entry.
//
// Accepted forms:
//
//	example.com      exact host name only
//	.example.com     the host and every subdomain
//	*.example.com    subdomains only, never the bare host
//	10.0.0.0/8       IP literal targets inside the CIDR
//	8.8.8.8          one IP literal target
//
// Matching is case insensitive and ignores one trailing root dot.
func compileDomain(raw string) (domainMatcher, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return domainMatcher{}, fmt.Errorf("empty domain")
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if ip := net.ParseIP(s[1 : len(s)-1]); ip != nil {
			return domainMatcher{kind: domainIPNet, ipn: ipNet(ip)}, nil
		}
	}
	s = strings.TrimSuffix(s, ".")
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return domainMatcher{}, fmt.Errorf("invalid IP/CIDR: %w", err)
		}
		return domainMatcher{kind: domainIPNet, ipn: n}, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return domainMatcher{kind: domainIPNet, ipn: ipNet(ip)}, nil
	}
	kind := domainExact
	switch {
	case s == "*":
		return domainMatcher{}, fmt.Errorf("wildcard must be written as *.example.com")
	case strings.HasPrefix(s, "*."):
		kind = domainWildcard
		s = s[2:]
	case strings.HasPrefix(s, "."):
		kind = domainSubdomains
		s = s[1:]
	}
	host, err := validateHostname(s)
	if err != nil {
		return domainMatcher{}, err
	}
	return domainMatcher{kind: kind, host: host}, nil
}

// normalizeHostname lowercases a host name and drops one trailing root dot
// before validating every label. It is used for request targets, whose host
// may arrive as an FQDN with the root dot.
func normalizeHostname(s string) (string, error) {
	return validateHostname(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// validateHostname validates an already trimmed host name. It never performs
// IDNA conversion: operators must enter ASCII (punycode) names.
func validateHostname(s string) (string, error) {
	s = strings.ToLower(s)
	if s == "" {
		return "", fmt.Errorf("empty host name")
	}
	if len(s) > 253 {
		return "", fmt.Errorf("host name longer than 253 bytes")
	}
	for _, label := range strings.Split(s, ".") {
		if err := validateLabel(label); err != nil {
			return "", fmt.Errorf("invalid host name %q: %w", s, err)
		}
	}
	return s, nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q longer than 63 bytes", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return fmt.Errorf("label %q contains invalid character %q", label, string(c))
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q must not start or end with '-'", label)
	}
	return nil
}

// parseCIDROrIP accepts either a CIDR ("10.0.0.0/8") or a bare IP address
// ("10.1.2.3" / "::1"), which is treated as a /32 or /128.
func parseCIDROrIP(raw string) (*net.IPNet, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("empty address")
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		return n, nil
	}
	ip := parseIPLiteral(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	return ipNet(ip), nil
}

// ipNet returns the /32 or /128 network of one IP address.
func ipNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// parseIPLiteral parses a bare IP address, accepting the bracketed and zoned
// IPv6 forms that proxy authority strings may carry ("[::1]", "fe80::1%eth0").
func parseIPLiteral(s string) net.IP {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if i := strings.IndexByte(s, '%'); i > 0 {
		s = s[:i]
	}
	return net.ParseIP(s)
}

// parsePortRange parses one ACLRule.Ports entry: either a single port ("443")
// or an inclusive range ("8000-9000"). Commas are not supported inside one
// entry; use multiple entries instead.
func parsePortRange(raw string) (portRange, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return portRange{}, fmt.Errorf("empty port")
	}
	lo, hi, isRange := strings.Cut(s, "-")
	start, err := parsePort(lo)
	if err != nil {
		return portRange{}, err
	}
	if !isRange {
		return portRange{lo: start, hi: start}, nil
	}
	end, err := parsePort(hi)
	if err != nil {
		return portRange{}, err
	}
	if start > end {
		return portRange{lo: start, hi: end}, fmt.Errorf("range start %d is greater than end %d", start, end)
	}
	return portRange{lo: start, hi: end}, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", p)
	}
	return p, nil
}
