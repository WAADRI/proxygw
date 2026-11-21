package sched

import (
	"errors"
	"testing"
	"time"

	"proxygw/internal/model"
)

// disableSticky switches the default sticky behaviour off so strategy tests are
// not affected by bindings.
func disableSticky(ts *testSettings) {
	ts.mutate(func(s *model.Settings) { s.Scheduler.Sticky.Enabled = false })
}

func newStrategySelector(t *testing.T, strategy string) (*Selector, *testSettings, *fakeClock) {
	t.Helper()
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = strategy
		s.Scheduler.Sticky.Enabled = false
	})
	clk := newFakeClock()
	return newTestSelector(t, ts, clk, 42, nil), ts, clk
}

func TestRandomDistribution(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyRandom)
	candidates := makeNodes("a", "b", "c")
	counts := countSelects(t, sel, Request{}, candidates, 1000)
	if len(counts) != 3 {
		t.Fatalf("random strategy covered %d nodes, want 3: %v", len(counts), counts)
	}
	for id, n := range counts {
		if n < 150 {
			t.Errorf("random strategy starved node %s: %d/1000", id, n)
		}
	}
}

func TestLeastInflight(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyLeastInflight)
	a, b, c := makeNode("a"), makeNode("b"), makeNode("c")
	a.Inflight = 7
	b.Inflight = 2
	c.Inflight = 2

	counts := countSelects(t, sel, Request{}, []*model.Node{a, b, c}, 1000)
	if counts["a"] != 0 {
		t.Fatalf("least_inflight selected the busiest node %d times", counts["a"])
	}
	if counts["b"] == 0 || counts["c"] == 0 {
		t.Fatalf("least_inflight did not randomize the tie: %v", counts)
	}

	// The strict minimum always wins.
	a.Inflight = 0
	b.Inflight = 5
	c.Inflight = 9
	for i := 0; i < 100; i++ {
		node, _, err := sel.Select(Request{}, []*model.Node{a, b, c})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if node.ID != "a" {
			t.Fatalf("least_inflight picked %s, want a", node.ID)
		}
	}
}

func TestFastest(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyFastest)
	a, b, c := makeNode("a"), makeNode("b"), makeNode("c")
	a.LatencyEWMA = 50
	b.LatencyEWMA = 10
	c.LatencyEWMA = 30
	for i := 0; i < 100; i++ {
		node, _, err := sel.Select(Request{}, []*model.Node{a, b, c})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if node.ID != "b" {
			t.Fatalf("fastest picked %s, want b", node.ID)
		}
	}

	// An unsampled node is neutral and gets a probe before sampled nodes: it is
	// preferred exactly once it has a sample, then normal comparison applies.
	unsampled := makeNode("new")
	node, _, err := sel.Select(Request{}, []*model.Node{a, b, c, unsampled})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if node.ID != "new" {
		t.Fatalf("fastest did not probe the unsampled node, picked %s", node.ID)
	}
	sel.OnLatency("new", 100*time.Millisecond)
	// Now "new" has a 100ms EWMA locally, so b (10ms in the snapshot) wins.
	node, _, err = sel.Select(Request{}, []*model.Node{a, b, c, unsampled})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if node.ID != "b" {
		t.Fatalf("fastest after sampling picked %s, want b", node.ID)
	}
}

func TestFastestLocalEWMA(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyFastest
		s.Scheduler.Sticky.Enabled = false
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 7, nil)
	sel.OnLatency("ext", 100*time.Millisecond)
	sel.OnLatency("ext", 200*time.Millisecond)
	// EWMA: 0.3*200 + 0.7*100 = 130ms.
	lat := sel.effectiveLatency(makeNode("ext"))
	if lat < 129.9 || lat > 130.1 {
		t.Fatalf("local EWMA = %f ms, want 130", lat)
	}
}

func TestWeightedDistribution(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyWeighted)
	a, b, c := makeNode("a"), makeNode("b"), makeNode("c")
	a.Weight = 3
	b.Weight = 1
	c.Weight = 1
	counts := countSelects(t, sel, Request{}, []*model.Node{a, b, c}, 1000)
	if counts["a"] < 560 || counts["a"] > 640 {
		t.Errorf("weighted node a = %d/1000, want about 600", counts["a"])
	}
	if counts["b"] < 170 || counts["b"] > 230 {
		t.Errorf("weighted node b = %d/1000, want about 200", counts["b"])
	}
	if counts["c"] < 170 || counts["c"] > 230 {
		t.Errorf("weighted node c = %d/1000, want about 200", counts["c"])
	}
}

func TestWeightedDynamicNodes(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyWeighted)
	a, b := makeNode("a"), makeNode("b")
	a.Weight, b.Weight = 3, 1
	countSelects(t, sel, Request{}, []*model.Node{a, b}, 100)

	c := makeNode("c")
	for i := 0; i < 300; i++ {
		node, _, err := sel.Select(Request{}, []*model.Node{a, b, c})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if node == nil {
			t.Fatal("nil node")
		}
	}
	// Remove a and b: the SWRR state of stale nodes must be pruned and the only
	// remaining node must always be picked.
	for i := 0; i < 10; i++ {
		node, _, err := sel.Select(Request{}, []*model.Node{c})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if node.ID != "c" {
			t.Fatalf("weighted picked %s, want c", node.ID)
		}
	}
	sel.weightedMu.Lock()
	stateLen := len(sel.weighted)
	sel.weightedMu.Unlock()
	if stateLen != 1 {
		t.Fatalf("weighted state retained %d stale entries, want 1", stateLen)
	}
}

func TestWeightedZeroWeightTreatedAsOne(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyWeighted)
	a, b := makeNode("a"), makeNode("b")
	a.Weight = 0
	b.Weight = 0
	counts := countSelects(t, sel, Request{}, []*model.Node{a, b}, 100)
	if counts["a"] == 0 || counts["b"] == 0 {
		t.Fatalf("zero weights must still be scheduled: %v", counts)
	}
}

func TestUnknownStrategyFallsBackToRandom(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = "not-a-strategy"
		s.Scheduler.Sticky.Enabled = false
	})
	clk := newFakeClock()
	sel := newTestSelector(t, ts, clk, 11, nil)
	candidates := makeNodes("a", "b")
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		node, d, err := sel.Select(Request{}, candidates)
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if d.Strategy != model.StrategyRandom {
			t.Fatalf("Decision.Strategy = %q, want random fallback", d.Strategy)
		}
		if d.Reason != ReasonStrategyFallback {
			t.Fatalf("Decision.Reason = %q, want %q", d.Reason, ReasonStrategyFallback)
		}
		seen[node.ID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("fallback strategy visited %d nodes, want 2", len(seen))
	}
}

func TestFilteredCandidates(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyRandom)
	disabled := makeNode("disabled")
	disabled.Enabled = false
	offline := makeNode("offline")
	offline.Online = false
	good := makeNode("good")

	node, d, err := sel.Select(Request{}, []*model.Node{disabled, offline, good, nil})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if node.ID != "good" {
		t.Fatalf("selected %s, want good", node.ID)
	}
	if d.Filtered != 3 {
		t.Fatalf("Filtered = %d, want 3 (disabled+offline+nil)", d.Filtered)
	}
}

func TestNoCandidates(t *testing.T) {
	sel, _, _ := newStrategySelector(t, model.StrategyRandom)
	disabled := makeNode("disabled")
	disabled.Enabled = false
	_, d, err := sel.Select(Request{}, []*model.Node{disabled})
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("Select error = %v, want ErrNoCandidates", err)
	}
	if d.Filtered != 1 {
		t.Fatalf("Filtered = %d, want 1", d.Filtered)
	}
	if _, _, err := sel.Select(Request{}, nil); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("empty candidate list: error = %v, want ErrNoCandidates", err)
	}
}
