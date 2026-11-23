package sched

import (
	"testing"
	"time"

	"proxygw/internal/model"
)

func mustSetRules(t *testing.T, sel *Selector, rules ...model.StickyRule) {
	t.Helper()
	if err := sel.SetStickyRules(rules); err != nil {
		t.Fatalf("SetStickyRules: %v", err)
	}
}

func TestStickyBlacklistTargetCIDR(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	rec := &auditRecorder{}
	sel := newTestSelector(t, ts, clk, 13, rec)
	mustSetRules(t, sel, model.StickyRule{
		ID:      "cidr-rule",
		Enabled: true,
		Target:  model.TargetSpec{CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}},
	})
	candidates := makeNodes("a")
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	req.Target = model.RequestTarget{Host: "10.9.9.9", Port: 443}

	node, d, err := sel.Select(req, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if node.ID != "a" {
		t.Fatalf("blacklisted request scheduled on %s, want a", node.ID)
	}
	if !d.Blacklisted || d.BlacklistRule != "cidr-rule" {
		t.Fatalf("decision blacklisted=%v rule=%q", d.Blacklisted, d.BlacklistRule)
	}
	if d.StickyHit {
		t.Fatal("blacklisted target must not use stickiness")
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("blacklisted request created %d binding(s)", stats.Keys)
	}
	if rec.count(EventStickyBlacklisted) != 1 {
		t.Fatalf("blacklisted audit events = %d, want 1", rec.count(EventStickyBlacklisted))
	}
	detail, _ := rec.last(EventStickyBlacklisted)
	if detail["rule_id"] != "cidr-rule" || detail["dimension"] != "target" {
		t.Fatalf("blacklist audit detail = %v", detail)
	}

	// IPv6 literal in the CIDR.
	req.Target = model.RequestTarget{Host: "2001:db8::5", Port: 443}
	if _, d, err := sel.Select(req, candidates); err != nil || !d.Blacklisted {
		t.Fatalf("ipv6 CIDR blacklist: blacklisted=%v err=%v", d.Blacklisted, err)
	}

	// A domain is never resolved: the CIDR rule must not match it.
	req.Target = model.RequestTarget{Host: "10.0.0.1.example.com", Port: 443}
	_, d, err = sel.Select(req, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Blacklisted {
		t.Fatal("CIDR rule matched a domain name without DNS resolution")
	}
	if _, d, err := sel.Select(req, candidates); err != nil || !d.StickyHit {
		t.Fatalf("non-blacklisted target was not bound: hit=%v err=%v", d.StickyHit, err)
	}
}

func TestStickyBlacklistDomainPatterns(t *testing.T) {
	ts := newTestSettings()
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 14, nil)
	mustSetRules(t, sel, model.StickyRule{
		ID:      "domains",
		Enabled: true,
		Target: model.TargetSpec{Domains: []string{
			"bank.com",        // exact
			"*.wild.com",      // subdomains only
			".suffix.com",     // apex + subdomains
			"*.Mixed.Example", // case insensitive
		}},
	})

	hit := func(host string) (string, bool) {
		return sel.StickyExplain(model.RequestTarget{Host: host, Port: 443}, nil, nil)
	}
	cases := []struct {
		host string
		want bool
		why  string
	}{
		{"bank.com", true, "exact match"},
		{"BANK.COM", true, "case insensitive exact match"},
		{"www.bank.com", false, "exact pattern must not match subdomains"},
		{"a.wild.com", true, "wildcard subdomain"},
		{"a.b.wild.com", true, "wildcard covers deeper subdomains"},
		{"wild.com", false, "*. must not match the bare apex"},
		{"suffix.com", true, ".suffix matches the apex"},
		{"www.suffix.com", true, ".suffix matches subdomains"},
		{"x.mixed.example", true, "wildcard case insensitive"},
		{"mixed.example", false, "wildcard does not match its apex"},
		{"example.com", false, "unrelated domain"},
	}
	for _, tc := range cases {
		ruleID, got := hit(tc.host)
		if got != tc.want {
			t.Errorf("Explain(%q) hit=%v, want %v (%s)", tc.host, got, tc.want, tc.why)
		}
		if got && ruleID != "domains" {
			t.Errorf("Explain(%q) rule = %q, want domains", tc.host, ruleID)
		}
	}
}

func TestStickyBlacklistNodeDimension(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 15, nil)
	mustSetRules(t, sel, model.StickyRule{
		ID:         "node-rule",
		Enabled:    true,
		NodeIDs:    []string{"node-a"},
		NodeGroups: []string{"residential"},
	})

	plain := makeNode("plain")
	full := makeNode("node-a")
	full.Groups = []string{"residential", "us"}
	plain.Groups = []string{"datacenter"}

	if _, hit := sel.StickyExplain(model.RequestTarget{Host: "example.com", Port: 443}, full, nil); !hit {
		t.Fatal("node ID rule did not hit")
	}
	if _, hit := sel.StickyExplain(model.RequestTarget{Host: "example.com", Port: 443}, plain, nil); hit {
		t.Fatal("node rule hit an unrelated node")
	}
	// Group matching also works for a plain node with the matching group.
	if _, hit := sel.StickyExplain(model.RequestTarget{Host: "example.com", Port: 443}, plain, []string{"residential"}); !hit {
		t.Fatal("extra nodeGroups did not hit the group rule")
	}

	// Selecting a blacklisted node must not create a binding.
	node, d, err := sel.Select(Request{CredentialID: "cred", SourceIP: "192.0.2.10"}, []*model.Node{full})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if node.ID != "node-a" {
		t.Fatalf("selected %s, want node-a", node.ID)
	}
	if !d.Blacklisted || d.BlacklistRule != "node-rule" {
		t.Fatalf("node blacklist not applied: %+v", d)
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("node-blacklisted request created %d binding(s)", stats.Keys)
	}
}

func TestStickyBlacklistBeatsBinding(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 16, nil)
	a, b := makeNode("a"), makeNode("b")
	a.Inflight, b.Inflight = 0, 100

	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	req.Target = model.RequestTarget{Host: "example.com", Port: 443}
	if node, _, err := sel.Select(req, []*model.Node{a, b}); err != nil || node.ID != "a" {
		t.Fatalf("initial select: node=%v err=%v", node, err)
	}
	if stats := sel.StickyStats(); stats.Keys != 1 {
		t.Fatalf("expected an existing binding, got %+v", stats)
	}

	mustSetRules(t, sel, model.StickyRule{
		ID:      "no-sticky",
		Enabled: true,
		Target:  model.TargetSpec{CIDRs: []string{"10.0.0.0/8"}},
	})
	req.Target = model.RequestTarget{Host: "10.1.1.1", Port: 443}
	a.Inflight, b.Inflight = 100, 0
	node, d, err := sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if node.ID != "b" {
		t.Fatalf("blacklisted request used the bound node %s, want b", node.ID)
	}
	if !d.Blacklisted || d.BlacklistRule != "no-sticky" {
		t.Fatalf("blacklist not reported: %+v", d)
	}
	if d.StickyHit {
		t.Fatal("blacklisted request reported a sticky hit")
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("binding was not cleared: %+v", stats)
	}

	// Once the target is no longer blacklisted the (new) scheduling decision is
	// bound again.
	req.Target = model.RequestTarget{Host: "example.com", Port: 443}
	if _, d, err := sel.Select(req, []*model.Node{a, b}); err != nil || d.StickyHit || d.Blacklisted {
		t.Fatalf("fresh binding: hit=%v blacklisted=%v err=%v", d.StickyHit, d.Blacklisted, err)
	}
	if stats := sel.StickyStats(); stats.Keys != 1 {
		t.Fatalf("expected a fresh binding, got %+v", stats)
	}
}

func TestStickyBlacklistDisabledRule(t *testing.T) {
	ts := newTestSettings()
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 17, nil)
	mustSetRules(t, sel, model.StickyRule{
		ID:      "disabled",
		Enabled: false,
		Target:  model.TargetSpec{CIDRs: []string{"10.0.0.0/8"}},
	})
	if ruleID, hit := sel.StickyExplain(model.RequestTarget{Host: "10.1.1.1"}, nil, nil); hit {
		t.Fatalf("disabled rule hit: %q", ruleID)
	}
}

func TestStickyBlacklistSourceCIDR(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	rec := &auditRecorder{}
	sel := newTestSelector(t, ts, clk, 24, rec)
	mustSetRules(t, sel, model.StickyRule{
		ID:          "source-rule",
		Enabled:     true,
		SourceCIDRs: []string{"203.0.113.0/24", "2001:db8::/32"},
	})
	candidates := makeNodes("a")
	req := Request{CredentialID: "cred", SourceIP: "203.0.113.9"}
	req.Target = model.RequestTarget{Host: "example.com", Port: 443}

	if _, d, err := sel.Select(req, candidates); err != nil {
		t.Fatalf("Select: %v", err)
	} else if !d.Blacklisted || d.BlacklistRule != "source-rule" || d.Reason != ReasonStickyBlacklist {
		t.Fatalf("source IP blacklist not applied: %+v", d)
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("source-blacklisted request created %d binding(s)", stats.Keys)
	}
	detail, _ := rec.last(EventStickyBlacklisted)
	if detail["dimension"] != "source" || detail["source_ip"] != "203.0.113.9" {
		t.Fatalf("source blacklist audit detail = %v", detail)
	}

	// IPv6 source is matched too.
	req.SourceIP = "2001:db8::5"
	if _, d, err := sel.Select(req, candidates); err != nil || !d.Blacklisted {
		t.Fatalf("IPv6 source blacklist: blacklisted=%v err=%v", d.Blacklisted, err)
	}

	// A different source IP is allowed to use normal stickiness.
	req.SourceIP = "198.51.100.9"
	if _, d, err := sel.Select(req, candidates); err != nil {
		t.Fatalf("Select: %v", err)
	} else if d.Blacklisted {
		t.Fatalf("unrelated source got blacklisted: %+v", d)
	}
	if _, d, err := sel.Select(req, candidates); err != nil || !d.StickyHit {
		t.Fatalf("non-blacklisted source was not bound: hit=%v err=%v", d.StickyHit, err)
	}
}

func TestStickyBlacklistSourceRulePreview(t *testing.T) {
	sel := newTestSelector(t, newTestSettings(), newFakeClock(), 25, nil)
	if err := sel.SetStickyRules([]model.StickyRule{{
		ID:          "source-preview",
		Enabled:     true,
		SourceCIDRs: []string{"192.0.2.7"},
	}}); err != nil {
		t.Fatalf("SetStickyRules: %v", err)
	}
	if ruleID, hit := sel.StickyExplainSource("192.0.2.7", model.RequestTarget{Host: "example.com", Port: 443}, nil, nil); !hit || ruleID != "source-preview" {
		t.Fatalf("source preview = %q/%v", ruleID, hit)
	}
	if _, hit := sel.StickyExplainSource("192.0.2.8", model.RequestTarget{Host: "example.com", Port: 443}, nil, nil); hit {
		t.Fatal("unrelated source IP hit the source rule")
	}
}

func TestStickyBlacklistValidation(t *testing.T) {
	ts := newTestSettings()
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 18, nil)

	good := model.StickyRule{
		ID:      "keep",
		Enabled: true,
		Target:  model.TargetSpec{Domains: []string{"bank.com"}, CIDRs: []string{"10.0.0.0/8"}},
	}
	mustSetRules(t, sel, good)

	bad := []model.StickyRule{
		{ID: "bad-cidr", Enabled: true, Target: model.TargetSpec{CIDRs: []string{"not-a-cidr"}}},
		{ID: "bad-wildcard", Enabled: true, Target: model.TargetSpec{Domains: []string{"a.*.com"}}},
		{ID: "bad-url", Enabled: true, Target: model.TargetSpec{Domains: []string{"https://bank.com"}}},
		{ID: "bad-empty", Enabled: true, Target: model.TargetSpec{Domains: []string{"  "}}},
	}
	for _, rule := range bad {
		if err := sel.SetStickyRules([]model.StickyRule{rule}); err == nil {
			t.Errorf("SetStickyRules accepted invalid rule %q", rule.ID)
		}
	}
	// The valid rule set must survive a rejected update.
	if ruleID, hit := sel.StickyExplain(model.RequestTarget{Host: "10.1.1.1"}, nil, nil); !hit || ruleID != "keep" {
		t.Fatalf("previous rules lost after rejected update: rule=%q hit=%v", ruleID, hit)
	}
}

func TestStickyBlacklistClearsBoundNode(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 22, nil)
	node := makeNode("residential-1")
	node.Groups = []string{"residential"}
	candidates := []*model.Node{node}
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	req.Target = model.RequestTarget{Host: "example.com", Port: 443}

	if _, d, err := sel.Select(req, candidates); err != nil || d.Blacklisted {
		t.Fatalf("initial select: blacklisted=%v err=%v", d.Blacklisted, err)
	}
	if stats := sel.StickyStats(); stats.Keys != 1 {
		t.Fatalf("expected an initial binding, got %+v", stats)
	}

	// The bound node's group is blacklisted afterwards: the binding must be
	// dropped and the request must keep scheduling normally.
	mustSetRules(t, sel, model.StickyRule{
		ID:         "no-residential",
		Enabled:    true,
		NodeGroups: []string{"residential"},
	})
	_, d, err := sel.Select(req, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !d.Blacklisted || d.BlacklistRule != "no-residential" {
		t.Fatalf("node group blacklist not applied: %+v", d)
	}
	if d.StickyHit {
		t.Fatal("blacklisted bound node was reported as a sticky hit")
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("binding not cleared after node blacklist: %+v", stats)
	}
	// A following request must not rebuild the binding either.
	mustSelectForTest(t, sel, req, candidates)
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("blacklisted node got bound again: %+v", stats)
	}
}

// mustSelectForTest is a small helper for tests that only need to assert the
// selection succeeded.
func mustSelectForTest(t *testing.T, sel *Selector, req Request, candidates []*model.Node) *model.Node {
	t.Helper()
	node, _, err := sel.Select(req, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	return node
}

func TestStickyMigrationRespectsBlacklist(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 23, nil)
	a, b := makeNode("a"), makeNode("b")
	a.Inflight, b.Inflight = 0, 100
	candidates := []*model.Node{a, b}
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	req.Target = model.RequestTarget{Host: "example.com", Port: 443}
	if node, _, err := sel.Select(req, candidates); err != nil || node.ID != "a" {
		t.Fatalf("initial select: node=%v err=%v", node, err)
	}

	mustSetRules(t, sel, model.StickyRule{ID: "no-b", Enabled: true, NodeIDs: []string{"b"}})
	a.Online = false
	node, d, err := sel.Select(req, candidates)
	if err != nil {
		t.Fatalf("Select during migration: %v", err)
	}
	if node.ID != "b" {
		t.Fatalf("migration selected %s, want b", node.ID)
	}
	if !d.StickyMigrated {
		t.Fatal("migration was not reported")
	}
	if !d.Blacklisted || d.BlacklistRule != "no-b" {
		t.Fatalf("migrated-to node blacklist not applied: %+v", d)
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("blacklisted migration target got bound: %+v", stats)
	}
}

func TestStickyExplainPrefersFirstMatchingRule(t *testing.T) {
	ts := newTestSettings()
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 19, nil)
	mustSetRules(t, sel,
		model.StickyRule{ID: "first", Enabled: true, Target: model.TargetSpec{CIDRs: []string{"10.0.0.0/8"}}},
		model.StickyRule{ID: "second", Enabled: true, Target: model.TargetSpec{CIDRs: []string{"10.1.0.0/16"}}},
	)
	if ruleID, hit := sel.StickyExplain(model.RequestTarget{Host: "10.1.2.3"}, nil, nil); !hit || ruleID != "first" {
		t.Fatalf("Explain = %q/%v, want first", ruleID, hit)
	}
	// Bare IP entries are accepted and treated as host routes.
	if err := sel.SetStickyRules([]model.StickyRule{{ID: "host-route", Enabled: true, Target: model.TargetSpec{CIDRs: []string{"192.0.2.7"}}}}); err != nil {
		t.Fatalf("bare IP rule rejected: %v", err)
	}
	if ruleID, hit := sel.StickyExplain(model.RequestTarget{Host: "192.0.2.7"}, nil, nil); !hit || ruleID != "host-route" {
		t.Fatalf("host route Explain = %q/%v", ruleID, hit)
	}
}
