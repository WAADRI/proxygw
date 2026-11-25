package acl

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"proxygw/internal/model"
)

const envLoopback = loopbackTargetsEnv

// newEngine builds an Engine with the test-only forced-list escape hatch off.
func newEngine(t *testing.T, opts Options) *Engine {
	t.Helper()
	t.Setenv(envLoopback, "")
	return New(opts)
}

// newEngineWithDefault builds an Engine whose dynamic default action is fixed.
func newEngineWithDefault(t *testing.T, action string) *Engine {
	t.Helper()
	return newEngine(t, Options{DefaultAction: func() string { return action }})
}

func mustSetRules(t *testing.T, e *Engine, rules ...model.ACLRule) {
	t.Helper()
	if err := e.SetRules(rules); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
}

func mkTarget(proto, host string, port int, src string) model.RequestTarget {
	return model.RequestTarget{Protocol: proto, Host: host, Port: port, SourceIP: src}
}

func requireAllowed(t *testing.T, e *Engine, target model.RequestTarget) {
	t.Helper()
	if err := e.Check(target); err != nil {
		t.Fatalf("Check(%s %s) = %v, want allow", target.Protocol, target, err)
	}
}

func requireDenied(t *testing.T, e *Engine, target model.RequestTarget, wantForced bool, wantRuleID string) *DeniedError {
	t.Helper()
	err := e.Check(target)
	if err == nil {
		t.Fatalf("Check(%s %s) = nil, want denial", target.Protocol, target)
	}
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("Check(%s %s) error type %T, want *DeniedError", target.Protocol, target, err)
	}
	if de.Forced != wantForced {
		t.Fatalf("Check(%s %s) Forced = %v, want %v (reason: %s)", target.Protocol, target, de.Forced, wantForced, de.Reason)
	}
	if wantRuleID != "" && de.RuleID != wantRuleID {
		t.Fatalf("Check(%s %s) RuleID = %q, want %q", target.Protocol, target, de.RuleID, wantRuleID)
	}
	if de.Reason == "" {
		t.Fatalf("Check(%s %s) Reason is empty", target.Protocol, target)
	}
	if !strings.Contains(err.Error(), "acl:") {
		t.Fatalf("Error() = %q, want acl: prefix", err.Error())
	}
	return de
}

func TestRuleOrderAllowBeforeDeny(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e,
		model.ACLRule{ID: "allow-first", Order: 10, Domains: []string{"example.com"}, Action: model.ActionAllow},
		model.ACLRule{ID: "deny-second", Order: 20, Domains: []string{"example.com"}, Action: model.ActionDeny},
	)
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	requireAllowed(t, e, target)
	d := e.Explain(target)
	if !d.Allowed || d.RuleID != "allow-first" || d.Forced {
		t.Fatalf("Explain = %+v, want allowed by allow-first", d)
	}
	if !strings.Contains(d.Reason, "allow rule") {
		t.Fatalf("Explain reason = %q, want allow rule description", d.Reason)
	}
}

func TestRouteActionReturnsForcedGroups(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionAllow)
	mustSetRules(t, e, model.ACLRule{
		ID:         "route-cn",
		Order:      1,
		Domains:    []string{"*.example.cn"},
		Action:     model.ActionRoute,
		NodeGroups: []string{"cn-edge", "cn-home"},
	})
	target := mkTarget(model.ProtoHTTP, "www.example.cn", 443, "")
	requireAllowed(t, e, target)
	groups, err := e.ForcedGroups(target)
	if err != nil {
		t.Fatalf("ForcedGroups: %v", err)
	}
	if len(groups) != 2 || groups[0] != "cn-edge" || groups[1] != "cn-home" {
		t.Fatalf("forced groups = %v", groups)
	}
	if d := e.Explain(target); !d.Allowed || d.RuleID != "route-cn" || len(d.NodeGroups) != 2 {
		t.Fatalf("Explain = %+v", d)
	}
	// The route rule must not match unrelated targets; default allow yields no
	// forced groups.
	groups, err = e.ForcedGroups(mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	if err != nil || len(groups) != 0 {
		t.Fatalf("non-matching groups = %v err=%v", groups, err)
	}
}

func TestRouteActionRejectsEmptyGroups(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionAllow)
	if err := e.SetRules([]model.ACLRule{{
		Action:  model.ActionRoute,
		Domains: []string{"example.com"},
	}}); err == nil {
		t.Fatal("route with no node_groups must be rejected")
	}
}

func TestRuleOrderDenyBeforeAllow(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionAllow)
	mustSetRules(t, e,
		model.ACLRule{ID: "deny-first", Order: 10, Domains: []string{"example.com"}, Action: model.ActionDeny},
		model.ACLRule{ID: "allow-second", Order: 20, Domains: []string{"example.com"}, Action: model.ActionAllow},
	)
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	de := requireDenied(t, e, target, false, "deny-first")
	if de.RuleID != "deny-first" {
		t.Fatalf("RuleID = %q, want deny-first", de.RuleID)
	}
	d := e.Explain(target)
	if d.Allowed || d.RuleID != "deny-first" || d.Forced || !strings.Contains(d.Reason, "deny rule") {
		t.Fatalf("Explain = %+v, want deny rule deny-first", d)
	}
}

func TestRuleOrderTieKeepsConfigurationOrder(t *testing.T) {
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	denyFirst := newEngineWithDefault(t, model.ActionAllow)
	mustSetRules(t, denyFirst,
		model.ACLRule{ID: "deny-tie", Order: 5, Domains: []string{"example.com"}, Action: model.ActionDeny},
		model.ACLRule{ID: "allow-tie", Order: 5, Domains: []string{"example.com"}, Action: model.ActionAllow},
	)
	requireDenied(t, denyFirst, target, false, "deny-tie")

	allowFirst := newEngineWithDefault(t, model.ActionAllow)
	mustSetRules(t, allowFirst,
		model.ACLRule{ID: "allow-tie", Order: 5, Domains: []string{"example.com"}, Action: model.ActionAllow},
		model.ACLRule{ID: "deny-tie", Order: 5, Domains: []string{"example.com"}, Action: model.ActionDeny},
	)
	requireAllowed(t, allowFirst, target)
}

func TestRulesReturnedInEvaluationOrder(t *testing.T) {
	e := newEngine(t, Options{})
	mustSetRules(t, e,
		model.ACLRule{ID: "c", Order: 30, Action: model.ActionAllow},
		model.ACLRule{ID: "a", Order: 10, Action: model.ActionAllow},
		model.ACLRule{ID: "b", Order: 20, Action: model.ActionDeny},
	)
	got := e.Rules()
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("Rules() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("Rules()[%d].ID = %q, want %q", i, got[i].ID, want[i])
		}
	}
}

func TestPortRangeBoundaries(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "web-range", Order: 1, Domains: []string{"example.com"},
		Ports: []string{"8000-9000"}, Action: model.ActionAllow,
	})
	cases := []struct {
		port int
		want bool
	}{
		{7999, false}, {8000, true}, {8001, true}, {8999, true}, {9000, true}, {9001, false},
	}
	for _, tc := range cases {
		target := mkTarget(model.ProtoHTTP, "example.com", tc.port, "")
		if tc.want {
			requireAllowed(t, e, target)
			continue
		}
		de := requireDenied(t, e, target, false, "")
		if de.RuleID != "" {
			t.Fatalf("port %d: RuleID = %q, want default deny", tc.port, de.RuleID)
		}
	}
}

func TestPortSingleEntry(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "https", Order: 1, Domains: []string{"example.com"},
		Ports: []string{"443"}, Action: model.ActionAllow,
	})
	requireAllowed(t, e, mkTarget(model.ProtoConnect, "example.com", 443, ""))
	requireDenied(t, e, mkTarget(model.ProtoConnect, "example.com", 442, ""), false, "")
	requireDenied(t, e, mkTarget(model.ProtoConnect, "example.com", 444, ""), false, "")
}

func TestPortMultipleEntries(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "multi", Order: 1, Ports: []string{"80", "443", "8080-8081"}, Action: model.ActionAllow,
	})
	for _, port := range []int{80, 443, 8080, 8081} {
		requireAllowed(t, e, mkTarget(model.ProtoHTTP, "any.example.com", port, ""))
	}
	for _, port := range []int{79, 81, 442, 8079, 8082} {
		requireDenied(t, e, mkTarget(model.ProtoHTTP, "any.example.com", port, ""), false, "")
	}
}

func TestPortExtremeBoundaries(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{ID: "low", Order: 1, Ports: []string{"1"}, Action: model.ActionAllow})
	requireAllowed(t, e, mkTarget(model.ProtoTCP, "example.com", 1, ""))

	e2 := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e2, model.ACLRule{ID: "high", Order: 1, Ports: []string{"65535"}, Action: model.ActionAllow})
	requireAllowed(t, e2, mkTarget(model.ProtoTCP, "example.com", 65535, ""))
	// Port 0 is not a valid target port and never matches a port rule.
	requireDenied(t, e2, mkTarget(model.ProtoTCP, "example.com", 0, ""), false, "")
}

func TestSourceCIDRMatching(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "office", Order: 1, SrcCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"},
		Domains: []string{"example.com"}, Action: model.ActionAllow,
	})
	allowed := []string{"10.0.0.0", "10.0.0.1", "10.255.255.255", "2001:db8::", "2001:db8::1"}
	for _, src := range allowed {
		requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, src))
	}
	denied := []string{"9.255.255.255", "11.0.0.1", "172.16.0.1", "2001:db9::1", "", "not-an-ip"}
	for _, src := range denied {
		de := requireDenied(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, src), false, "")
		if de.RuleID != "" {
			t.Fatalf("source %q: RuleID = %q, want default deny", src, de.RuleID)
		}
	}
}

func TestSourceCIDRNotRequired(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "any-src", Order: 1, Domains: []string{"example.com"}, Action: model.ActionAllow,
	})
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, "not-an-ip"))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
}

func TestDomainMatching(t *testing.T) {
	cases := []struct {
		name string
		rule string
		host string
		want bool
	}{
		{"exact hit", "example.com", "example.com", true},
		{"exact case insensitive", "example.com", "EXAMPLE.com", true},
		{"exact trailing dot target", "example.com", "example.com.", true},
		{"exact no subdomain", "example.com", "a.example.com", false},
		{"exact no suffix confusion", "example.com", "badexample.com", false},
		{"suffix apex", ".bank.com", "bank.com", true},
		{"suffix subdomain", ".bank.com", "a.bank.com", true},
		{"suffix deep subdomain", ".bank.com", "a.b.bank.com", true},
		{"suffix no confusion", ".bank.com", "notbank.com", false},
		{"suffix hyphen boundary", ".bank.com", "evil-bank.com", false},
		{"wildcard subdomain", "*.bank.com", "a.bank.com", true},
		{"wildcard deep subdomain", "*.bank.com", "a.b.bank.com", true},
		{"wildcard no apex", "*.bank.com", "bank.com", false},
		{"wildcard no confusion", "*.bank.com", "notbank.com", false},
		{"ipv4 cidr", "10.0.0.0/8", "10.1.2.3", true},
		{"ipv4 cidr outside", "10.0.0.0/8", "11.1.2.3", false},
		{"ipv4 bare", "8.8.8.8", "8.8.8.8", true},
		{"ipv4 bare other", "8.8.8.8", "8.8.4.4", false},
		{"ipv4 mapped ipv6 target", "127.0.0.0/8", "::ffff:127.0.0.1", true},
		{"ipv6 cidr", "2001:db8::/32", "2001:db8::1", true},
		{"ipv6 bracket target", "2001:db8::/32", "[2001:db8::1]", true},
		{"ipv6 bare", "::1", "::1", true},
		{"ip rule does not match host name", "10.0.0.0/8", "ten.example.com", false},
		{"domain rule does not match ip", "example.com", "1.2.3.4", false},
		{"uppercase rule entry", "EXAMPLE.COM", "example.com", true},
		{"wildcard trailing dot rule", "*.bank.com.", "a.bank.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, Options{
				AllowLoopbackTargets: true,
				DefaultAction:        func() string { return model.ActionDeny },
			})
			mustSetRules(t, e, model.ACLRule{
				ID: "domain-rule", Order: 1, Domains: []string{tc.rule}, Action: model.ActionAllow,
			})
			target := mkTarget(model.ProtoConnect, tc.host, 443, "")
			if tc.want {
				requireAllowed(t, e, target)
				d := e.Explain(target)
				if !d.Allowed || d.RuleID != "domain-rule" {
					t.Fatalf("Explain = %+v, want allowed by domain-rule", d)
				}
				return
			}
			de := requireDenied(t, e, target, false, "")
			if de.RuleID != "" {
				t.Fatalf("RuleID = %q, want default deny", de.RuleID)
			}
		})
	}
}

func TestProtocolMatching(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "http-only", Order: 1, Domains: []string{"example.com"},
		Protocols: []string{"http"}, Action: model.ActionAllow,
	})
	cases := []struct {
		proto string
		want  bool
	}{
		{model.ProtoHTTP, true},
		{model.ProtoConnect, false},
		{model.ProtoSOCKS5, false},
		{model.ProtoTCP, false},
		{"", false},
		{"HTTP", true},
	}
	for _, tc := range cases {
		target := mkTarget(tc.proto, "example.com", 443, "")
		if tc.want {
			requireAllowed(t, e, target)
			continue
		}
		requireDenied(t, e, target, false, "")
	}
}

func TestProtocolMatchingCaseInsensitiveRule(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "connect-only", Order: 1, Protocols: []string{"CoNnEcT"}, Action: model.ActionAllow,
	})
	requireAllowed(t, e, mkTarget(model.ProtoConnect, "example.com", 443, ""))
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""), false, "")
}

func TestProtocolMatchingAllValues(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "all-protos", Order: 1, Protocols: []string{"http", "connect", "socks5", "tcp"},
		Action: model.ActionAllow,
	})
	for _, proto := range []string{model.ProtoHTTP, model.ProtoConnect, model.ProtoSOCKS5, model.ProtoTCP} {
		requireAllowed(t, e, mkTarget(proto, "example.com", 443, ""))
	}
}

func TestCombinedDimensions(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID:        "strict",
		Order:     1,
		SrcCIDRs:  []string{"10.1.0.0/16"},
		Domains:   []string{".corp.example.com"},
		Ports:     []string{"443"},
		Protocols: []string{"connect"},
		Action:    model.ActionAllow,
	})
	requireAllowed(t, e, mkTarget(model.ProtoConnect, "api.corp.example.com", 443, "10.1.2.3"))
	// Each single dimension mismatch must fall through to the default deny.
	requireDenied(t, e, mkTarget(model.ProtoConnect, "api.corp.example.com", 443, "10.2.2.3"), false, "")
	requireDenied(t, e, mkTarget(model.ProtoConnect, "api.corp.example.com", 8443, "10.1.2.3"), false, "")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "api.corp.example.com", 443, "10.1.2.3"), false, "")
	requireDenied(t, e, mkTarget(model.ProtoConnect, "corp.example.com.evil.com", 443, "10.1.2.3"), false, "")
}

func TestDefaultActionNilAllows(t *testing.T) {
	e := newEngine(t, Options{})
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "8.8.8.8", 443, ""))
	d := e.Explain(mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	if !d.Allowed || d.RuleID != "" || d.Forced || !strings.Contains(d.Reason, "default_acl_action=allow") {
		t.Fatalf("Explain = %+v, want default allow", d)
	}
}

func TestDefaultActionDynamic(t *testing.T) {
	action := model.ActionAllow
	e := newEngine(t, Options{DefaultAction: func() string { return action }})
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	requireAllowed(t, e, target)
	action = model.ActionDeny
	requireDenied(t, e, target, false, "")
	action = model.ActionAllow
	requireAllowed(t, e, target)
}

func TestDefaultActionDeny(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	de := requireDenied(t, e, target, false, "")
	if de.RuleID != "" {
		t.Fatalf("RuleID = %q, want empty for default deny", de.RuleID)
	}
	if !strings.Contains(de.Reason, "default_acl_action=deny") {
		t.Fatalf("Reason = %q, want default deny description", de.Reason)
	}
	d := e.Explain(target)
	if d.Allowed || d.Forced || d.RuleID != "" {
		t.Fatalf("Explain = %+v, want default deny", d)
	}
}

func TestDefaultActionInvalidTreatedAsAllow(t *testing.T) {
	e := newEngineWithDefault(t, "banana")
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	requireAllowed(t, e, target)
	d := e.Explain(target)
	if !d.Allowed {
		t.Fatalf("Explain = %+v, want allow", d)
	}
	if !strings.Contains(d.Reason, "invalid default_acl_action") || !strings.Contains(d.Reason, "banana") {
		t.Fatalf("Reason = %q, want invalid default action record", d.Reason)
	}
}

func TestDefaultActionEmptyTreatedAsInvalid(t *testing.T) {
	e := newEngineWithDefault(t, "")
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	if d := e.Explain(mkTarget(model.ProtoHTTP, "example.com", 443, "")); !strings.Contains(d.Reason, "invalid default_acl_action") {
		t.Fatalf("Reason = %q, want invalid default action record", d.Reason)
	}
}

func TestDefaultActionPanicRecovered(t *testing.T) {
	e := newEngine(t, Options{DefaultAction: func() string { panic("settings store broken") }})
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	requireAllowed(t, e, target)
	d := e.Explain(target)
	if !d.Allowed || !strings.Contains(d.Reason, "panicked") {
		t.Fatalf("Explain = %+v, want recovered panic recorded", d)
	}
}

func TestExplainForcedAndRuleDecisions(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e,
		model.ACLRule{ID: "allow-doc", Order: 1, Domains: []string{"docs.example.com"}, Action: model.ActionAllow},
		model.ACLRule{ID: "deny-blocked", Order: 2, Domains: []string{"blocked.example.com"}, Action: model.ActionDeny},
	)
	if d := e.Explain(mkTarget(model.ProtoHTTP, "docs.example.com", 443, "")); !d.Allowed || d.RuleID != "allow-doc" || d.Forced {
		t.Fatalf("Explain allowed = %+v", d)
	}
	if d := e.Explain(mkTarget(model.ProtoHTTP, "blocked.example.com", 443, "")); d.Allowed || d.RuleID != "deny-blocked" || d.Forced {
		t.Fatalf("Explain deny rule = %+v", d)
	}
	if d := e.Explain(mkTarget(model.ProtoHTTP, "other.example.com", 443, "")); d.Allowed || d.RuleID != "" || d.Forced {
		t.Fatalf("Explain default deny = %+v", d)
	}
	d := e.Explain(mkTarget(model.ProtoConnect, "127.0.0.1", 8080, ""))
	if d.Allowed || !d.Forced || d.RuleID != "loopback" || !strings.Contains(d.Reason, "forced deny") {
		t.Fatalf("Explain forced = %+v", d)
	}
}

func TestExplainAgreesWithCheck(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e,
		model.ACLRule{ID: "allow-a", Order: 1, Domains: []string{".allowed.example.com"}, Action: model.ActionAllow},
		model.ACLRule{ID: "deny-b", Order: 2, Domains: []string{"blocked.example.com"}, Action: model.ActionDeny},
	)
	targets := []model.RequestTarget{
		mkTarget(model.ProtoHTTP, "api.allowed.example.com", 443, ""),
		mkTarget(model.ProtoHTTP, "blocked.example.com", 443, ""),
		mkTarget(model.ProtoHTTP, "other.example.com", 443, ""),
		mkTarget(model.ProtoConnect, "127.0.0.1", 80, ""),
		mkTarget(model.ProtoConnect, "169.254.169.254", 80, ""),
	}
	for _, target := range targets {
		err := e.Check(target)
		d := e.Explain(target)
		if (err == nil) != d.Allowed {
			t.Fatalf("target %s: Check err = %v, Explain allowed = %v", target, err, d.Allowed)
		}
		if d.Reason == "" {
			t.Fatalf("target %s: empty Explain reason", target)
		}
	}
}

func TestSetRulesAtomicReplacement(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionAllow)
	mustSetRules(t, e, model.ACLRule{ID: "deny-example", Order: 1, Domains: []string{"example.com"}, Action: model.ActionDeny})
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""), false, "deny-example")

	invalid := []model.ACLRule{{ID: "broken", Order: 1, SrcCIDRs: []string{"10.0.0.0/33"}, Action: model.ActionAllow}}
	if err := e.SetRules(invalid); err == nil {
		t.Fatal("SetRules with invalid CIDR = nil, want error")
	}
	// The failed replacement must keep the previous rule set.
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""), false, "deny-example")
	if got := e.Rules(); len(got) != 1 || got[0].ID != "deny-example" {
		t.Fatalf("Rules() after failed SetRules = %+v, want old rule", got)
	}

	mustSetRules(t, e, model.ACLRule{ID: "allow-example", Order: 1, Domains: []string{"example.com"}, Action: model.ActionAllow})
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))

	if err := e.SetRules(nil); err != nil {
		t.Fatalf("SetRules(nil): %v", err)
	}
	got := e.Rules()
	if got == nil || len(got) != 0 {
		t.Fatalf("Rules() after clear = %#v, want empty non-nil slice", got)
	}
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
}

func TestSetRulesDeepCopies(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	rule := model.ACLRule{
		ID: "copy-check", Order: 1, Domains: []string{"example.com"},
		Ports: []string{"443"}, Protocols: []string{"http"}, SrcCIDRs: []string{"10.0.0.0/8"},
		Action: model.ActionAllow,
	}
	mustSetRules(t, e, rule)
	rule.Domains[0] = "mutated.example.com"
	rule.Ports[0] = "1"
	rule.Protocols[0] = "connect"
	rule.SrcCIDRs[0] = "0.0.0.0/0"
	rule.Action = model.ActionDeny
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, "10.1.2.3"))
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "mutated.example.com", 443, "10.1.2.3"), false, "")

	got := e.Rules()
	got[0].Domains[0] = "changed-again.example.com"
	got[0].Action = model.ActionDeny
	again := e.Rules()
	if again[0].Domains[0] != "example.com" || again[0].Action != model.ActionAllow {
		t.Fatalf("Rules() mutation leaked into engine: %+v", again[0])
	}
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, "10.1.2.3"))
}

func TestAllowRuleWithoutDimensionsMatchesEverything(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{ID: "allow-all", Order: 1, Action: model.ActionAllow})
	for _, target := range []model.RequestTarget{
		mkTarget(model.ProtoHTTP, "example.com", 443, ""),
		mkTarget(model.ProtoConnect, "8.8.8.8", 22, "203.0.113.9"),
		mkTarget(model.ProtoSOCKS5, "", 1, ""),
	} {
		requireAllowed(t, e, target)
	}
}

func TestZeroValueEngine(t *testing.T) {
	var e Engine
	requireAllowed(t, &e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	requireDenied(t, &e, mkTarget(model.ProtoConnect, "127.0.0.1", 80, ""), true, "loopback")
	if got := e.Rules(); got == nil || len(got) != 0 {
		t.Fatalf("zero value Rules() = %#v, want empty non-nil", got)
	}
	if got := e.ForcedDenies(); len(got) == 0 {
		t.Fatal("zero value ForcedDenies() is empty")
	}
	if err := e.SetRules([]model.ACLRule{{ID: "deny-any", Action: model.ActionDeny}}); err != nil {
		t.Fatalf("zero value SetRules: %v", err)
	}
	requireDenied(t, &e, mkTarget(model.ProtoHTTP, "example.com", 443, ""), false, "deny-any")
}

func TestMalformedTargetHostNeverMatchesDomainRules(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e, model.ACLRule{
		ID: "allow-domain", Order: 1, Domains: []string{"example.com"}, Action: model.ActionAllow,
	})
	for _, host := range []string{"", "bad host", "exa_mple.com", "example.com.."} {
		de := requireDenied(t, e, mkTarget(model.ProtoHTTP, host, 443, ""), false, "")
		if de.RuleID != "" {
			t.Fatalf("host %q: RuleID = %q, want default deny", host, de.RuleID)
		}
	}
}

func TestCheckPerformanceSmoke(t *testing.T) {
	e := newEngine(t, Options{DefaultAction: func() string { return model.ActionAllow }})
	var rules []model.ACLRule
	for i := 0; i < 20; i++ {
		rules = append(rules, model.ACLRule{
			ID:      fmt.Sprintf("deny-%d", i),
			Order:   i,
			Domains: []string{fmt.Sprintf("blocked%d.example.com", i)},
			Ports:   []string{"8080-8090"},
			Action:  model.ActionDeny,
		})
	}
	mustSetRules(t, e, rules...)
	target := mkTarget(model.ProtoHTTP, "allowed.example.com", 443, "203.0.113.10")
	for i := 0; i < 100; i++ {
		requireAllowed(t, e, target)
	}
	start := time.Now()
	for i := 0; i < 10000; i++ {
		if err := e.Check(target); err != nil {
			t.Fatalf("Check = %v, want allow", err)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("10000 Check calls took %v, want < 200ms", elapsed)
	}
	t.Logf("10000 Check calls in %v", elapsed)
}

func BenchmarkCheckAllow(b *testing.B) {
	e := New(Options{DefaultAction: func() string { return model.ActionAllow }})
	_ = e.SetRules([]model.ACLRule{
		{ID: "allow-doc", Order: 1, Domains: []string{".example.com"}, Action: model.ActionAllow},
	})
	target := mkTarget(model.ProtoHTTP, "api.example.com", 443, "203.0.113.10")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.Check(target); err != nil {
			b.Fatalf("Check = %v", err)
		}
	}
}
