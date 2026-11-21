package sched

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"proxygw/internal/model"
)

// TestConcurrentSelectAndFeedback exercises every public scheduler entry point
// from many goroutines at once; it is designed to be run with -race.
func TestConcurrentSelectAndFeedback(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Scheduler.Strategy = model.StrategyRandom
		s.Scheduler.Sticky.TTL = model.D(10 * time.Minute)
		s.Scheduler.Breaker.FailureThreshold = 8
	})
	clk := newFakeClock()
	rec := &auditRecorder{}
	sel := newTestSelector(t, ts, clk, 21, rec)
	candidates := makeNodes("n0", "n1", "n2", "n3", "n4")
	for i, n := range candidates {
		n.Weight = i + 1
		n.Inflight = int64(i)
		n.LatencyEWMA = float64(i * 10)
	}
	rules := []model.StickyRule{{
		ID:      "rule-a",
		Enabled: true,
		Target:  model.TargetSpec{CIDRs: []string{"203.0.113.0/24"}},
	}}
	if err := sel.SetStickyRules(rules); err != nil {
		t.Fatalf("SetStickyRules: %v", err)
	}

	stop := make(chan struct{})
	var background sync.WaitGroup

	// Hot settings churn: the selector must always see a consistent snapshot.
	background.Add(1)
	go func() {
		defer background.Done()
		strategies := []string{
			model.StrategyRandom,
			model.StrategyLeastInflight,
			model.StrategyFastest,
			model.StrategyWeighted,
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			strategy := strategies[i%len(strategies)]
			ts.mutate(func(s *model.Settings) { s.Scheduler.Strategy = strategy })
			time.Sleep(time.Millisecond)
		}
	}()

	// Concurrent rule swaps.
	background.Add(1)
	go func() {
		defer background.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sel.SetStickyRules(rules)
			_ = sel.SetStickyRules(nil)
			time.Sleep(time.Millisecond)
		}
	}()

	// Concurrent maintenance operations.
	background.Add(1)
	go func() {
		defer background.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sel.PurgeSticky()
			sel.InvalidateNode("n3")
			_ = sel.StickyStats()
			time.Sleep(time.Millisecond)
		}
	}()

	var workers sync.WaitGroup
	for i := 0; i < 50; i++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			rng := rand.New(rand.NewSource(int64(worker) + 1))
			for j := 0; j < 50; j++ {
				req := Request{
					CredentialID: fmt.Sprintf("cred-%d", worker%7),
					SourceIP:     fmt.Sprintf("198.51.100.%d", worker+1),
					Protocol:     model.ProtoConnect,
				}
				if rng.Intn(2) == 0 {
					req.StickyKey = fmt.Sprintf("key-%d", rng.Intn(20))
				}
				if rng.Intn(4) == 0 {
					req.Target = model.RequestTarget{Host: fmt.Sprintf("203.0.113.%d", rng.Intn(20)), Port: 443}
				} else {
					req.Target = model.RequestTarget{Host: "example.com", Port: 443}
				}
				node, d, err := sel.Select(req, candidates)
				if err != nil {
					if !errors.Is(err, ErrNoCandidates) {
						t.Errorf("Select: %v", err)
					}
					continue
				}
				if node == nil {
					t.Errorf("Select returned nil node without error")
					continue
				}
				if d.NodeID != node.ID {
					t.Errorf("Decision.NodeID = %q, node = %q", d.NodeID, node.ID)
				}
				var streamErr error
				if rng.Intn(20) == 0 {
					streamErr = errors.New("stream reset")
				}
				sel.OnStreamResult(node.ID, streamErr)
				if rng.Intn(3) == 0 {
					sel.OnLatency(node.ID, time.Duration(rng.Intn(100)+1)*time.Millisecond)
				}
				_ = sel.BreakerState(node.ID)
				if stats := sel.StickyStats(); stats.Keys < 0 {
					t.Errorf("negative sticky key count: %d", stats.Keys)
				}
			}
		}(i)
	}
	workers.Wait()
	close(stop)
	background.Wait()

	// The scheduler must remain usable after the churn.
	ts.mutate(func(s *model.Settings) { s.Scheduler.Strategy = model.StrategyRandom })
	if _, _, err := sel.Select(Request{}, candidates); err != nil && !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("final Select: %v", err)
	}
}
