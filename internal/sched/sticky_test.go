package sched

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"proxygw/internal/model"
)

func TestStickySameKey(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyRandom
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 3, nil)
	candidates := makeNodes("a", "b")
	req := Request{CredentialID: "cred-1", SourceIP: "192.0.2.10"}

	first, d, err := sel.Select(req, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.StickyHit {
		t.Fatal("first request must not be a sticky hit")
	}
	if stats := sel.StickyStats(); stats.Keys != 1 {
		t.Fatalf("StickyStats.Keys = %d, want 1", stats.Keys)
	}

	for i := 0; i < 19; i++ {
		node, d, err := sel.Select(req, candidates)
		if err != nil {
			t.Fatalf("Select #%d: %v", i, err)
		}
		if !d.StickyHit {
			t.Fatalf("Select #%d was not a sticky hit", i)
		}
		if node.ID != first.ID {
			t.Fatalf("Select #%d chose %s, want bound node %s", i, node.ID, first.ID)
		}
	}

	// Different credentials or source IPs must not share the binding.
	if _, d, _ := sel.Select(Request{CredentialID: "cred-2", SourceIP: "192.0.2.10"}, candidates); d.StickyHit {
		t.Fatal("different credential reused the binding")
	}
	if _, d, _ := sel.Select(Request{CredentialID: "cred-1", SourceIP: "192.0.2.11"}, candidates); d.StickyHit {
		t.Fatal("different source IP reused the binding")
	}
}

func TestStickyCustomKeyOverride(t *testing.T) {
	ts := newTestSettings()
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 4, nil)
	candidates := makeNodes("a", "b")

	alphaReq := Request{CredentialID: "cred", SourceIP: "192.0.2.10", StickyKey: "alpha"}
	alpha, _, err := sel.Select(alphaReq, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	node, d, err := sel.Select(alphaReq, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !d.StickyHit || node.ID != alpha.ID {
		t.Fatalf("custom sticky key did not stick: hit=%v node=%s want %s", d.StickyHit, node.ID, alpha.ID)
	}

	betaReq := Request{CredentialID: "cred", SourceIP: "192.0.2.10", StickyKey: "beta"}
	if _, d, _ := sel.Select(betaReq, candidates); d.StickyHit {
		t.Fatal("a different StickyKey reused the binding")
	}
	if stats := sel.StickyStats(); stats.Keys != 2 {
		t.Fatalf("StickyStats.Keys = %d, want 2", stats.Keys)
	}
}

func TestStickyTTLExpiry(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(100 * time.Millisecond)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 5, nil)
	a, b := makeNode("a"), makeNode("b")
	a.Inflight, b.Inflight = 0, 100
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}

	first, d, err := sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if first.ID != "a" || d.StickyHit {
		t.Fatalf("first select = %s hit=%v, want a with no hit", first.ID, d.StickyHit)
	}

	clk.Advance(200 * time.Millisecond)
	a.Inflight, b.Inflight = 100, 0
	node, d, err := sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select after TTL: %v", err)
	}
	if d.StickyHit {
		t.Fatal("expired binding was still a sticky hit")
	}
	if d.StickyMigrated {
		t.Fatal("an expired TTL is a plain miss, not a migration")
	}
	if node.ID != "b" {
		t.Fatalf("after TTL selected %s, want b", node.ID)
	}
	// The new selection is bound again.
	node, d, err = sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !d.StickyHit || node.ID != "b" {
		t.Fatalf("rebound node not sticky: hit=%v node=%s", d.StickyHit, node.ID)
	}
}

func TestStickySlidingRenewal(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Second)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 6, nil)
	a, b := makeNode("a"), makeNode("b")
	a.Inflight, b.Inflight = 0, 100
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	if node, _, err := sel.Select(req, []*model.Node{a, b}); err != nil || node.ID != "a" {
		t.Fatalf("initial select: node=%v err=%v", node, err)
	}

	clk.Advance(800 * time.Millisecond) // t=0.8s, TTL would expire at 1.0s
	if _, d, err := sel.Select(req, []*model.Node{a, b}); err != nil || !d.StickyHit {
		t.Fatalf("renewal at 0.8s: hit=%v err=%v", d.StickyHit, err)
	}
	clk.Advance(800 * time.Millisecond) // t=1.6s, old expiry was 1.0s
	if _, d, err := sel.Select(req, []*model.Node{a, b}); err != nil || !d.StickyHit {
		t.Fatalf("sliding TTL did not renew: hit=%v err=%v", d.StickyHit, err)
	}
	clk.Advance(1500 * time.Millisecond) // t=3.1s, expiry was 2.6s
	a.Inflight, b.Inflight = 100, 0
	node, d, err := sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select after expiry: %v", err)
	}
	if d.StickyHit {
		t.Fatal("binding survived past the sliding TTL")
	}
	if node.ID != "b" {
		t.Fatalf("selected %s after expiry, want b", node.ID)
	}
}

func TestStickyMigrationOnOffline(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	rec := &auditRecorder{}
	sel := newTestSelector(t, ts, clk, 7, rec)
	a, b := makeNode("a"), makeNode("b")
	a.Inflight, b.Inflight = 0, 100
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}

	if node, _, err := sel.Select(req, []*model.Node{a, b}); err != nil || node.ID != "a" {
		t.Fatalf("initial select: node=%v err=%v", node, err)
	}

	a.Online = false
	node, d, err := sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select after offline: %v", err)
	}
	if node.ID != "b" {
		t.Fatalf("migrated to %s, want b", node.ID)
	}
	if !d.StickyMigrated {
		t.Fatal("Decision.StickyMigrated = false, want true")
	}
	if d.StickyHit {
		t.Fatal("migration must not be reported as a hit")
	}
	if d.Filtered != 1 {
		t.Fatalf("Filtered = %d, want 1", d.Filtered)
	}
	if rec.count(EventStickyMigrated) != 1 {
		t.Fatalf("audit migration events = %d, want 1", rec.count(EventStickyMigrated))
	}
	detail, ok := rec.last(EventStickyMigrated)
	if !ok || detail["from"] != "a" || detail["to"] != "b" {
		t.Fatalf("migration audit detail = %v", detail)
	}

	// The migrated session sticks to the new node.
	node, d, err = sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !d.StickyHit || node.ID != "b" {
		t.Fatalf("after migration hit=%v node=%s, want b", d.StickyHit, node.ID)
	}
	stats := sel.StickyStats()
	if stats.Keys != 1 || stats.ByNode["b"] != 1 {
		t.Fatalf("sticky stats after migration = %+v", stats)
	}
}

func TestStickyMigrationOnBreakerOpen(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyLeastInflight
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	rec := &auditRecorder{}
	sel := newTestSelector(t, ts, clk, 8, rec)
	a, b := makeNode("a"), makeNode("b")
	a.Inflight, b.Inflight = 0, 100
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	if node, _, err := sel.Select(req, []*model.Node{a, b}); err != nil || node.ID != "a" {
		t.Fatalf("initial select: node=%v err=%v", node, err)
	}

	// Node-side failures only; five consecutive failures open the breaker.
	for i := 0; i < 5; i++ {
		sel.OnStreamResult("a", errors.New("dial timeout"))
	}
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("breaker state = %q, want open", state)
	}

	node, d, err := sel.Select(req, []*model.Node{a, b})
	if err != nil {
		t.Fatalf("Select after breaker open: %v", err)
	}
	if node.ID != "b" || !d.StickyMigrated {
		t.Fatalf("breaker migration: node=%s migrated=%v", node.ID, d.StickyMigrated)
	}
	if rec.count(EventStickyMigrated) != 1 {
		t.Fatalf("audit migration events = %d, want 1", rec.count(EventStickyMigrated))
	}
}

func TestStickyKeyCap(t *testing.T) {
	const cap = 1000
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Sticky.MaxKeysPerNode = cap
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 9, nil)
	candidates := makeNodes("a")

	for i := 0; i < cap; i++ {
		req := Request{StickyKey: fmt.Sprintf("key-%d", i)}
		if _, _, err := sel.Select(req, candidates); err != nil {
			t.Fatalf("Select #%d: %v", i, err)
		}
	}
	stats := sel.StickyStats()
	if stats.Keys != cap || stats.ByNode["a"] != cap {
		t.Fatalf("stats after %d bindings = %+v", cap, stats)
	}

	overReq := Request{StickyKey: "key-overflow"}
	node, d, err := sel.Select(overReq, candidates)
	if err != nil {
		t.Fatalf("Select over cap: %v", err)
	}
	if node.ID != "a" {
		t.Fatalf("over-cap request selected %s, want a (normal scheduling)", node.ID)
	}
	if d.Reason != ReasonStickyKeyCap {
		t.Fatalf("Reason = %q, want %q", d.Reason, ReasonStickyKeyCap)
	}
	if d.StickyHit {
		t.Fatal("over-cap request must not be a sticky hit")
	}
	// Still not bound on the next attempt.
	if _, d, _ := sel.Select(overReq, candidates); d.StickyHit || d.Reason != ReasonStickyKeyCap {
		t.Fatalf("over-cap key got bound later: hit=%v reason=%s", d.StickyHit, d.Reason)
	}
	if stats := sel.StickyStats(); stats.Keys != cap {
		t.Fatalf("over-cap request changed binding count to %d", stats.Keys)
	}
}

func TestStickyDisabled(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Sticky.Enabled = false
		s.Scheduler.Strategy = model.StrategyRandom
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 10, nil)
	candidates := makeNodes("a", "b")
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		node, d, err := sel.Select(req, candidates)
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if d.StickyHit || d.StickyMigrated || d.Blacklisted {
			t.Fatalf("sticky disabled but decision = %+v", d)
		}
		if d.Reason != ReasonStrategy && d.Reason != "" {
			t.Fatalf("Reason = %q, want strategy", d.Reason)
		}
		seen[node.ID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("sticky disabled: visited %d nodes, want 2", len(seen))
	}
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("sticky disabled but %d bindings exist", stats.Keys)
	}
}

func TestStickyPurgeAndInvalidate(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Sticky.TTL = model.D(time.Hour)
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 12, nil)
	candidates := makeNodes("a")
	req := Request{CredentialID: "cred", SourceIP: "192.0.2.10"}

	if _, _, err := sel.Select(req, candidates); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if stats := sel.StickyStats(); stats.Keys != 1 {
		t.Fatalf("Keys = %d, want 1", stats.Keys)
	}
	sel.PurgeSticky()
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("Keys after purge = %d, want 0", stats.Keys)
	}

	if _, _, err := sel.Select(req, candidates); err != nil {
		t.Fatalf("Select: %v", err)
	}
	sel.InvalidateNode("a")
	if stats := sel.StickyStats(); stats.Keys != 0 {
		t.Fatalf("Keys after InvalidateNode = %d, want 0", stats.Keys)
	}
	if _, d, _ := sel.Select(req, candidates); d.StickyHit {
		t.Fatal("invalidated node still hit on next request")
	}
}
