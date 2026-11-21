package sched

import (
	"errors"
	"sync"
	"testing"
	"time"

	"proxygw/internal/model"
)

func newBreakerSelector(t *testing.T) (*Selector, *testSettings, *fakeClock) {
	t.Helper()
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Sticky.Enabled = false
		s.Scheduler.Strategy = model.StrategyRandom
	})
	clk := newFakeClock()
	return newTestSelector(t, ts, clk, 20, nil), ts, clk
}

func mustSelect(t *testing.T, sel *Selector, candidates []*model.Node) *model.Node {
	t.Helper()
	node, _, err := sel.Select(Request{}, candidates)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	return node
}

func TestBreakerConsecutiveFailuresAndHalfOpen(t *testing.T) {
	sel, _, clk := newBreakerSelector(t)
	node := makeNode("a")
	candidates := []*model.Node{node}
	mustSelect(t, sel, candidates)

	failure := errors.New("dial timeout")
	for i := 0; i < 4; i++ {
		sel.OnStreamResult("a", failure)
		if state := sel.BreakerState("a"); state != model.BreakerClosed {
			t.Fatalf("after %d failures state = %q, want closed", i+1, state)
		}
	}
	sel.OnStreamResult("a", failure)
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("after 5 consecutive failures state = %q, want open", state)
	}
	_, d, err := sel.Select(Request{}, candidates)
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("Select while open: error = %v, want ErrNoCandidates", err)
	}
	if d.Filtered != 1 {
		t.Fatalf("Filtered = %d, want 1", d.Filtered)
	}

	// One OpenTimeout later the breaker allows exactly one probe.
	clk.Advance(30 * time.Second)
	if state := sel.BreakerState("a"); state != model.BreakerHalfOpen {
		t.Fatalf("state after cooldown = %q, want half_open", state)
	}
	if got := mustSelect(t, sel, candidates); got.ID != "a" {
		t.Fatalf("probe selected %s, want a", got.ID)
	}
	_, d, err = sel.Select(Request{}, candidates)
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("second concurrent probe: error = %v, want ErrNoCandidates", err)
	}
	if d.Filtered != 1 {
		t.Fatalf("Filtered while probe in flight = %d, want 1", d.Filtered)
	}

	// Probe success closes and resets the breaker.
	sel.OnStreamResult("a", nil)
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("state after probe success = %q, want closed", state)
	}
	mustSelect(t, sel, candidates)
}

func TestBreakerProbeFailureReopensWithoutBackoff(t *testing.T) {
	sel, _, clk := newBreakerSelector(t)
	node := makeNode("a")
	candidates := []*model.Node{node}
	failure := errors.New("stream reset")
	for i := 0; i < 5; i++ {
		sel.OnStreamResult("a", failure)
	}
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("state = %q, want open", state)
	}

	clk.Advance(30 * time.Second)
	mustSelect(t, sel, candidates) // admit the probe
	sel.OnStreamResult("a", failure)
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("state after failed probe = %q, want open", state)
	}

	// Fixed OpenTimeout, never exponential.
	clk.Advance(29 * time.Second)
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("state before cooldown = %q, want open", state)
	}
	clk.Advance(2 * time.Second)
	if state := sel.BreakerState("a"); state != model.BreakerHalfOpen {
		t.Fatalf("state after second cooldown = %q, want half_open", state)
	}
	mustSelect(t, sel, candidates)
	sel.OnStreamResult("a", nil)
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("state after successful probe = %q, want closed", state)
	}
}

func TestBreakerFailureRateRule(t *testing.T) {
	sel, _, _ := newBreakerSelector(t)
	failure := errors.New("dial refused")

	// 19 samples with 10 failures: below MinSamples and never 5 consecutive
	// failures, so the breaker must stay closed.
	for i := 0; i < 9; i++ {
		sel.OnStreamResult("a", failure)
		sel.OnStreamResult("a", nil)
	}
	sel.OnStreamResult("a", failure)
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("state with 19 samples = %q, want closed", state)
	}
	// The 20th sample is the 11th failure: 11/20 = 55% > 50% opens the breaker.
	sel.OnStreamResult("a", failure)
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("state after 11/20 failures = %q, want open", state)
	}
}

func TestBreakerSuccessResetsConsecutive(t *testing.T) {
	sel, _, _ := newBreakerSelector(t)
	failure := errors.New("dial refused")

	for i := 0; i < 4; i++ {
		sel.OnStreamResult("a", failure)
	}
	sel.OnStreamResult("a", nil) // resets the consecutive counter
	for i := 0; i < 4; i++ {
		sel.OnStreamResult("a", failure)
	}
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("state = %q, want closed (success must reset consecutive failures)", state)
	}
	sel.OnStreamResult("a", failure) // 5th consecutive failure
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("state = %q, want open", state)
	}
}

func TestBreakerThresholdHotReload(t *testing.T) {
	sel, ts, _ := newBreakerSelector(t)
	failure := errors.New("dial refused")
	sel.OnStreamResult("a", failure)
	sel.OnStreamResult("a", failure)
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("state = %q, want closed", state)
	}
	ts.mutate(func(s *model.Settings) { s.Scheduler.Breaker.FailureThreshold = 2 })
	sel.OnStreamResult("a", failure)
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("state after hot reloaded threshold = %q, want open", state)
	}
}

func TestBreakerStaleResultsIgnored(t *testing.T) {
	sel, _, clk := newBreakerSelector(t)
	failure := errors.New("dial refused")
	candidates := []*model.Node{makeNode("a")}
	for i := 0; i < 5; i++ {
		sel.OnStreamResult("a", failure)
	}
	clk.Advance(20 * time.Second)
	// A late result from a stream admitted before the breaker opened must not
	// restart the cool-down.
	sel.OnStreamResult("a", failure)
	clk.Advance(11 * time.Second) // t = 31s
	if state := sel.BreakerState("a"); state != model.BreakerHalfOpen {
		t.Fatalf("state = %q, want half_open (stale result extended cooldown)", state)
	}
	mustSelect(t, sel, candidates)
	sel.OnStreamResult("a", nil)

	// A stale success while open must not close the breaker either.
	for i := 0; i < 5; i++ {
		sel.OnStreamResult("a", failure)
	}
	clk.Advance(10 * time.Second)
	sel.OnStreamResult("a", nil)
	if state := sel.BreakerState("a"); state != model.BreakerOpen {
		t.Fatalf("stale success closed the breaker: state = %q", state)
	}
	clk.Advance(21 * time.Second)
	if state := sel.BreakerState("a"); state != model.BreakerHalfOpen {
		t.Fatalf("state = %q, want half_open", state)
	}
}

func TestBreakerHalfOpenSingleProbeConcurrent(t *testing.T) {
	sel, _, clk := newBreakerSelector(t)
	node := makeNode("a")
	candidates := []*model.Node{node}
	failure := errors.New("dial refused")
	for i := 0; i < 5; i++ {
		sel.OnStreamResult("a", failure)
	}
	clk.Advance(30 * time.Second)

	const goroutines = 10
	results := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := sel.Select(Request{}, candidates)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	admitted := 0
	for err := range results {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrNoCandidates):
			// The single probe slot was already taken.
		default:
			t.Fatalf("unexpected Select error: %v", err)
		}
	}
	if admitted != 1 {
		t.Fatalf("half_open admitted %d probes, want exactly 1", admitted)
	}
	sel.OnStreamResult("a", nil)
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("state = %q, want closed", state)
	}
}

func TestBreakerSuccessOnlyStaysClosed(t *testing.T) {
	sel, _, _ := newBreakerSelector(t)
	for i := 0; i < 200; i++ {
		sel.OnStreamResult("a", nil)
	}
	if state := sel.BreakerState("a"); state != model.BreakerClosed {
		t.Fatalf("200 successes opened the breaker: %q", state)
	}
	if state := sel.BreakerState("unknown-node"); state != model.BreakerClosed {
		t.Fatalf("unknown node state = %q, want closed", state)
	}
}
