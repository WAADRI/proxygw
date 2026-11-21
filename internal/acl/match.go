package acl

import (
	"fmt"
	"net"
	"strings"

	"proxygw/internal/model"
)

// targetInfo is the normalized form of one request target. It is computed once
// per evaluation and reused by the forced list and by every operator rule.
type targetInfo struct {
	ip    net.IP // set when Host is an IP literal
	host  string // normalized host name when Host is not an IP literal
	port  int
	proto string
	srcIP net.IP // nil when SourceIP is empty or invalid
}

// analyzeTarget classifies the target host as an IP literal or a host name and
// normalizes the remaining fields. It never performs DNS resolution.
func analyzeTarget(t model.RequestTarget) targetInfo {
	info := targetInfo{
		port:  t.Port,
		proto: strings.ToLower(strings.TrimSpace(t.Protocol)),
		srcIP: parseIPLiteral(t.SourceIP),
	}
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return info
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip := parseIPLiteral(host); ip != nil {
		info.ip = ip
		return info
	}
	// Normalization strips one trailing root dot and lowercases the name; the
	// second IP attempt makes forms such as "127.0.0.1." resolve to the forced
	// IP list instead of being treated as a host name.
	name, err := normalizeHostname(host)
	if err != nil {
		return info
	}
	if ip := parseIPLiteral(name); ip != nil {
		info.ip = ip
		return info
	}
	info.host = name
	return info
}

// matches reports whether the rule applies to the target. Every non-empty
// dimension must match; dimensions are independent (AND), entries inside one
// dimension are alternatives (OR).
func (r *compiledRule) matches(t targetInfo) bool {
	if len(r.src) > 0 {
		if t.srcIP == nil || !containsIP(r.src, t.srcIP) {
			return false
		}
	}
	if len(r.domains) > 0 {
		hit := false
		for i := range r.domains {
			if r.domains[i].matches(t) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(r.ports) > 0 {
		hit := false
		for _, pr := range r.ports {
			if t.port >= pr.lo && t.port <= pr.hi {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(r.protocols) > 0 {
		if _, ok := r.protocols[t.proto]; !ok {
			return false
		}
	}
	return true
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// matches reports whether one compiled domain entry matches the target host.
func (m *domainMatcher) matches(t targetInfo) bool {
	switch m.kind {
	case domainIPNet:
		return t.ip != nil && m.ipn.Contains(t.ip)
	case domainExact:
		return t.ip == nil && t.host != "" && t.host == m.host
	case domainSubdomains:
		return t.ip == nil && t.host != "" && (t.host == m.host || strings.HasSuffix(t.host, "."+m.host))
	case domainWildcard:
		return t.ip == nil && t.host != "" && strings.HasSuffix(t.host, "."+m.host)
	default:
		return false
	}
}

// verdict is the internal result of one evaluation.
type verdict struct {
	allowed        bool
	ruleID         string
	forced         bool
	reason         string // set for forced deny decisions
	matched        *compiledRule
	defaultAction  string // raw value returned by the default action provider
	defaultUsed    bool
	defaultInvalid bool
	defaultPanic   bool
}

const defaultDenyReason = "no ACL rule matched; default_acl_action=deny"

// evaluate runs the fixed three stage pipeline: forced deny list, ordered
// operator rules, dynamic default action.
func (e *Engine) evaluate(t model.RequestTarget) verdict {
	info := analyzeTarget(t)
	if name, reason, denied := forcedDeny(info, e.allowTestTargets); denied {
		return verdict{ruleID: name, forced: true, reason: reason}
	}
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	for i := range rules {
		if rules[i].matches(info) {
			return verdict{
				allowed: rules[i].action == model.ActionAllow,
				ruleID:  rules[i].raw.ID,
				matched: &rules[i],
			}
		}
	}
	allowed, raw, invalid, panicked := e.defaultDecision()
	if !allowed {
		return verdict{
			reason:         defaultDenyReason,
			defaultAction:  raw,
			defaultUsed:    true,
			defaultInvalid: invalid,
			defaultPanic:   panicked,
		}
	}
	return verdict{
		allowed:        true,
		defaultAction:  raw,
		defaultUsed:    true,
		defaultInvalid: invalid,
		defaultPanic:   panicked,
	}
}

// defaultDecision applies the dynamic default action outside the engine lock.
// Invalid values and provider panics are treated as allow so an operator
// configuration mistake never panics or blocks the request path; Explain
// reports both cases.
func (e *Engine) defaultDecision() (allowed bool, raw string, invalid, panicked bool) {
	if e.defaultAction == nil {
		return true, model.ActionAllow, false, false
	}
	raw, panicked = callDefaultAction(e.defaultAction)
	if panicked {
		return true, raw, true, true
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case model.ActionAllow:
		return true, raw, false, false
	case model.ActionDeny:
		return false, raw, false, false
	default:
		return true, raw, true, false
	}
}

func callDefaultAction(fn func() string) (raw string, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			raw = fmt.Sprintf("panic: %v", r)
		}
	}()
	return fn(), false
}

// explainReason renders the operator facing reason behind a verdict.
func explainReason(v verdict) string {
	if v.matched != nil {
		action := model.ActionAllow
		if !v.allowed {
			action = model.ActionDeny
		}
		if v.matched.raw.ID != "" {
			return fmt.Sprintf("matched %s rule id=%q order=%d", action, v.matched.raw.ID, v.matched.raw.Order)
		}
		return fmt.Sprintf("matched %s rule order=%d", action, v.matched.raw.Order)
	}
	if !v.defaultUsed {
		return v.reason
	}
	if v.defaultPanic {
		return fmt.Sprintf("no ACL rule matched; default_acl_action provider panicked (%s), treated as allow", v.defaultAction)
	}
	if v.defaultInvalid {
		return fmt.Sprintf("no ACL rule matched; invalid default_acl_action %q treated as allow", v.defaultAction)
	}
	action := strings.ToLower(strings.TrimSpace(v.defaultAction))
	if action == "" {
		action = model.ActionAllow
	}
	return fmt.Sprintf("no ACL rule matched; default_acl_action=%s", action)
}
