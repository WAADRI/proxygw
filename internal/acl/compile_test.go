package acl

import (
	"strings"
	"testing"

	"proxygw/internal/model"
)

func TestSetRulesValidationErrors(t *testing.T) {
	cases := []struct {
		name     string
		rule     model.ACLRule
		wantText []string
	}{
		{
			name:     "bad action",
			rule:     model.ACLRule{Action: "block"},
			wantText: []string{"action", "block"},
		},
		{
			name:     "empty action",
			rule:     model.ACLRule{},
			wantText: []string{`action ""`},
		},
		{
			name:     "bad source cidr",
			rule:     model.ACLRule{Action: "allow", SrcCIDRs: []string{"10.0.0.0/33"}},
			wantText: []string{"src_cidrs[0]", "10.0.0.0/33"},
		},
		{
			name:     "bad source ip",
			rule:     model.ACLRule{Action: "allow", SrcCIDRs: []string{"999.1.1.1"}},
			wantText: []string{"src_cidrs[0]", "999.1.1.1"},
		},
		{
			name:     "empty source entry",
			rule:     model.ACLRule{Action: "allow", SrcCIDRs: []string{"   "}},
			wantText: []string{"src_cidrs[0]"},
		},
		{
			name:     "bad domain",
			rule:     model.ACLRule{Action: "allow", Domains: []string{"bad host"}},
			wantText: []string{"domains[0]", "bad host"},
		},
		{
			name:     "bad wildcard",
			rule:     model.ACLRule{Action: "allow", Domains: []string{"*"}},
			wantText: []string{"domains[0]", "wildcard"},
		},
		{
			name:     "bad domain cidr",
			rule:     model.ACLRule{Action: "allow", Domains: []string{"10.0.0.0/33"}},
			wantText: []string{"domains[0]", "10.0.0.0/33"},
		},
		{
			name:     "bad port text",
			rule:     model.ACLRule{Action: "allow", Ports: []string{"abc"}},
			wantText: []string{"ports[0]", "abc"},
		},
		{
			name:     "port zero",
			rule:     model.ACLRule{Action: "allow", Ports: []string{"0"}},
			wantText: []string{"ports[0]", "out of range"},
		},
		{
			name:     "port too high",
			rule:     model.ACLRule{Action: "allow", Ports: []string{"65536"}},
			wantText: []string{"ports[0]", "out of range"},
		},
		{
			name:     "reversed port range",
			rule:     model.ACLRule{Action: "allow", Ports: []string{"9000-8000"}},
			wantText: []string{"ports[0]", "9000", "8000"},
		},
		{
			name:     "comma separated port",
			rule:     model.ACLRule{Action: "allow", Ports: []string{"80,443"}},
			wantText: []string{"ports[0]", "80,443"},
		},
		{
			name:     "bad protocol",
			rule:     model.ACLRule{Action: "allow", Protocols: []string{"ftp"}},
			wantText: []string{"protocols[0]", "ftp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngineWithDefault(t, model.ActionAllow)
			err := e.SetRules([]model.ACLRule{tc.rule})
			if err == nil {
				t.Fatalf("SetRules(%+v) = nil, want error", tc.rule)
			}
			msg := err.Error()
			if !strings.Contains(msg, "rule[0]") {
				t.Fatalf("error %q does not identify the rule index", msg)
			}
			for _, text := range tc.wantText {
				if !strings.Contains(msg, text) {
					t.Fatalf("error %q does not contain %q", msg, text)
				}
			}
			// A failed SetRules must leave the engine untouched.
			if got := e.Rules(); got == nil || len(got) != 0 {
				t.Fatalf("Rules() after failed SetRules = %#v, want empty", got)
			}
		})
	}
}

func TestSetRulesNormalizesActionAndProtocol(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e,
		model.ACLRule{ID: "allow-upper", Order: 1, Action: " ALLOW ", Domains: []string{"upper.example.com"}},
		model.ACLRule{ID: "deny-mixed", Order: 2, Action: "Deny", Domains: []string{"mixed.example.com"}},
	)
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "upper.example.com", 443, ""))
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "mixed.example.com", 443, ""), false, "deny-mixed")

	e2 := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e2, model.ACLRule{
		ID: "proto-normalize", Order: 1, Domains: []string{"example.com"},
		Protocols: []string{" HTTP ", "Connect"}, Action: model.ActionAllow,
	})
	requireAllowed(t, e2, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	requireAllowed(t, e2, mkTarget(model.ProtoConnect, "example.com", 443, ""))
	requireDenied(t, e2, mkTarget(model.ProtoSOCKS5, "example.com", 443, ""), false, "")
}

func TestSetRulesAllowsEmptyRuleID(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionAllow)
	mustSetRules(t, e, model.ACLRule{Order: 1, Domains: []string{"example.com"}, Action: model.ActionDeny})
	target := mkTarget(model.ProtoHTTP, "example.com", 443, "")
	de := requireDenied(t, e, target, false, "")
	if de.RuleID != "" {
		t.Fatalf("RuleID = %q, want empty", de.RuleID)
	}
	d := e.Explain(target)
	if d.Allowed || !strings.Contains(d.Reason, "deny rule") {
		t.Fatalf("Explain = %+v, want deny rule reason", d)
	}
}

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Example.COM", "example.com", true},
		{"example.com.", "example.com", true},
		{"example.com..", "", false},
		{"", "", false},
		{"bad host", "", false},
		{"_dmarc.example.com", "", false},
		{"-bad.example.com", "", false},
		{"bad-.example.com", "", false},
		{strings.Repeat("a", 63) + ".example.com", strings.Repeat("a", 63) + ".example.com", true},
		{strings.Repeat("a", 64) + ".example.com", "", false},
	}
	for _, tc := range cases {
		got, err := normalizeHostname(tc.in)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Fatalf("normalizeHostname(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("normalizeHostname(%q) = %q, want error", tc.in, got)
		}
	}
}

func TestParsePortRange(t *testing.T) {
	cases := []struct {
		in string
		lo int
		hi int
		ok bool
	}{
		{"443", 443, 443, true},
		{" 443 ", 443, 443, true},
		{"8000-9000", 8000, 9000, true},
		{"1-1", 1, 1, true},
		{"1", 1, 1, true},
		{"65535", 65535, 65535, true},
		{"0", 0, 0, false},
		{"65536", 0, 0, false},
		{"9000-8000", 0, 0, false},
		{"abc", 0, 0, false},
		{"", 0, 0, false},
		{"-1", 0, 0, false},
		{"1-", 0, 0, false},
		{"1-2-3", 0, 0, false},
	}
	for _, tc := range cases {
		got, err := parsePortRange(tc.in)
		if tc.ok {
			if err != nil || got.lo != tc.lo || got.hi != tc.hi {
				t.Fatalf("parsePortRange(%q) = %+v, %v; want {%d %d}", tc.in, got, err, tc.lo, tc.hi)
			}
			continue
		}
		if err == nil {
			t.Fatalf("parsePortRange(%q) = %+v, want error", tc.in, got)
		}
	}
}

func TestCompileDomainForms(t *testing.T) {
	cases := []struct {
		in   string
		kind domainKind
		host string
		net  string
	}{
		{"example.com", domainExact, "example.com", ""},
		{"Example.COM.", domainExact, "example.com", ""},
		{".example.com", domainSubdomains, "example.com", ""},
		{"*.example.com", domainWildcard, "example.com", ""},
		{"10.0.0.0/8", domainIPNet, "", "10.0.0.0/8"},
		{"10.1.2.3", domainIPNet, "", "10.1.2.3/32"},
		{"::1", domainIPNet, "", "::1/128"},
		{"[::1]", domainIPNet, "", "::1/128"},
	}
	for _, tc := range cases {
		m, err := compileDomain(tc.in)
		if err != nil {
			t.Fatalf("compileDomain(%q): %v", tc.in, err)
		}
		if m.kind != tc.kind {
			t.Fatalf("compileDomain(%q) kind = %v, want %v", tc.in, m.kind, tc.kind)
		}
		if tc.kind == domainIPNet {
			if m.ipn == nil || m.ipn.String() != tc.net {
				t.Fatalf("compileDomain(%q) net = %v, want %s", tc.in, m.ipn, tc.net)
			}
			continue
		}
		if m.host != tc.host {
			t.Fatalf("compileDomain(%q) host = %q, want %q", tc.in, m.host, tc.host)
		}
	}
}
