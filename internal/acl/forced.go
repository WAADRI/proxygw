package acl

import (
	"fmt"
	"net"
	"strings"
)

// ForcedRule describes one entry of the built-in forced deny list, as shown in
// the panel. The list is part of the security baseline: it cannot be disabled
// from the panel or by configuration, and operator ACL rules cannot override
// it. It is not persisted because it is compiled into the binary.
type ForcedRule struct {
	Name   string   `json:"name"`
	CIDRs  []string `json:"cidrs,omitempty"`
	Ports  []string `json:"ports,omitempty"`
	Reason string   `json:"reason"`
}

// forcedRuleDef pairs a forced rule with its test-only escape hatch behaviour.
// exempt rules are skipped when Options.AllowLoopbackTargets (or
// NP_ACL_ALLOW_LOOPBACK_TARGETS=1) is active, which exists so in-process
// integration tests can reach local echo servers.
type forcedRuleDef struct {
	rule   ForcedRule
	exempt bool
}

// forcedNetRule is one compiled forced deny entry for IP literal targets.
type forcedNetRule struct {
	def  forcedRuleDef
	nets []*net.IPNet
}

// forcedIPRules is the compiled form of the forced IP list. Order matters for
// the reported reason and for the panel: the cloud metadata endpoints are
// checked before the link local range that also contains them.
var forcedIPRules = buildForcedIPRules([]forcedRuleDef{
	{
		rule: ForcedRule{
			Name:   "cloud_metadata",
			CIDRs:  []string{"169.254.169.254/32", "fe80::a9fe:a9fe/128"},
			Reason: "cloud metadata endpoints are blocked to prevent credential theft",
		},
		// Always denied, even with the test-only escape hatch: metadata access
		// is the exact attack this list exists to prevent.
		exempt: false,
	},
	{
		rule: ForcedRule{
			Name:   "loopback",
			CIDRs:  []string{"127.0.0.0/8", "::1/128"},
			Reason: "loopback targets are blocked to prevent SSRF",
		},
		exempt: true,
	},
	{
		rule: ForcedRule{
			Name:   "private_network",
			CIDRs:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			Reason: "private network targets are blocked to prevent SSRF",
		},
		exempt: true,
	},
	{
		rule: ForcedRule{
			Name:   "unique_local_ipv6",
			CIDRs:  []string{"fc00::/7"},
			Reason: "IPv6 unique local targets are blocked to prevent SSRF",
		},
		exempt: true,
	},
	{
		rule: ForcedRule{
			Name:   "link_local",
			CIDRs:  []string{"169.254.0.0/16", "fe80::/10"},
			Reason: "link local targets are blocked to prevent SSRF",
		},
		exempt: true,
	},
	{
		rule: ForcedRule{
			Name:   "unspecified",
			CIDRs:  []string{"0.0.0.0/8", "::/128"},
			Reason: "unspecified addresses are not valid proxy targets",
		},
		exempt: false,
	},
	{
		rule: ForcedRule{
			Name:   "cgnat",
			CIDRs:  []string{"100.64.0.0/10"},
			Reason: "carrier grade NAT ranges are blocked to prevent SSRF",
		},
		exempt: false,
	},
})

// forcedHostRule denies loopback host names. The engine never resolves DNS, so
// this only catches the well known literal names that are loopback by
// definition; other names are covered by the node side address checks after
// resolution.
var forcedHostRule = forcedRuleDef{
	rule: ForcedRule{
		Name:   "loopback_hostname",
		Reason: "loopback host names are blocked to prevent SSRF",
	},
	exempt: true,
}

// forcedPortRule denies high risk service ports for every target and every
// protocol: proxying these ports is only useful for scanning or abuse.
var forcedPortRule = forcedRuleDef{
	rule: ForcedRule{
		Name:   "high_risk_ports",
		Ports:  []string{"25", "135", "139", "445", "6379"},
		Reason: "high risk ports (SMTP/RPC/SMB/Redis) are blocked for every target",
	},
	exempt: true,
}

// forcedHostnames are the literal host names treated as loopback. "localhost"
// covers the bare name, its ".localhost" subdomains (below) and the common
// /etc/hosts aliases of the loopback interface.
var forcedHostnames = map[string]struct{}{
	"localhost":             {},
	"localhost.localdomain": {},
	"ip6-localhost":         {},
	"ip6-loopback":          {},
}

var forcedPortSet = func() map[int]struct{} {
	m := make(map[int]struct{}, len(forcedPortRule.rule.Ports))
	for _, raw := range forcedPortRule.rule.Ports {
		r, err := parsePortRange(raw)
		if err != nil {
			panic("acl: invalid built-in forced port " + raw)
		}
		for p := r.lo; p <= r.hi; p++ {
			m[p] = struct{}{}
		}
	}
	return m
}()

// buildForcedIPRules compiles the built-in CIDR table. A bad built-in entry is
// a programming error and panics at init time.
func buildForcedIPRules(defs []forcedRuleDef) []forcedNetRule {
	out := make([]forcedNetRule, len(defs))
	for i, def := range defs {
		nets := make([]*net.IPNet, len(def.rule.CIDRs))
		for j, cidr := range def.rule.CIDRs {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				panic("acl: invalid built-in forced CIDR " + cidr)
			}
			nets[j] = n
		}
		out[i] = forcedNetRule{def: def, nets: nets}
	}
	return out
}

// ForcedDenies returns the built-in forced deny list for panel display. The
// returned rules are copies; the list itself cannot be changed. It is returned
// even when the test-only escape hatch is active, because that switch only
// affects evaluation.
func (e *Engine) ForcedDenies() []ForcedRule {
	out := make([]ForcedRule, 0, len(forcedIPRules)+2)
	for i := range forcedIPRules {
		out = append(out, cloneForcedRule(forcedIPRules[i].def.rule))
	}
	out = append(out, cloneForcedRule(forcedHostRule.rule), cloneForcedRule(forcedPortRule.rule))
	return out
}

func cloneForcedRule(in ForcedRule) ForcedRule {
	return ForcedRule{
		Name:   in.Name,
		CIDRs:  cloneStrings(in.CIDRs),
		Ports:  cloneStrings(in.Ports),
		Reason: in.Reason,
	}
}

// forcedDeny reports whether the normalized target is rejected by the built-in
// forced deny list. It is always called before operator rules. When testMode is
// active the loopback/link-local/private/unique-local ranges, loopback host
// names and the high risk port list are skipped; cloud metadata endpoints,
// unspecified addresses and CGNAT ranges stay blocked because the escape hatch
// is meant for local test servers only.
func forcedDeny(info targetInfo, testMode bool) (name, reason string, denied bool) {
	if info.ip != nil {
		for i := range forcedIPRules {
			fr := &forcedIPRules[i]
			if testMode && fr.def.exempt {
				continue
			}
			for _, n := range fr.nets {
				if n.Contains(info.ip) {
					return fr.def.rule.Name, fmt.Sprintf("forced deny %q: target IP %s is in %s; %s",
						fr.def.rule.Name, info.ip, strings.Join(fr.def.rule.CIDRs, ", "), fr.def.rule.Reason), true
				}
			}
		}
	}
	if !(testMode && forcedHostRule.exempt) && info.host != "" && isLoopbackHostname(info.host) {
		return forcedHostRule.rule.Name, fmt.Sprintf("forced deny %q: target host %q is a loopback host name; %s",
			forcedHostRule.rule.Name, info.host, forcedHostRule.rule.Reason), true
	}
	if !(testMode && forcedPortRule.exempt) {
		if _, ok := forcedPortSet[info.port]; ok {
			return forcedPortRule.rule.Name, fmt.Sprintf("forced deny %q: target port %d is one of %s; %s",
				forcedPortRule.rule.Name, info.port, strings.Join(forcedPortRule.rule.Ports, ", "), forcedPortRule.rule.Reason), true
		}
	}
	return "", "", false
}

func isLoopbackHostname(host string) bool {
	if _, ok := forcedHostnames[host]; ok {
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}
