package sched

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"proxygw/internal/model"
)

// testEpoch is the fixed wall clock used by the fake clock.
const testEpoch int64 = 1_700_000_000

// fakeClock is a deterministic clock for breaker/sticky/limiter tests. After
// registers waiters that fire when Advance passes their deadline.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*fakeWaiter
}

type fakeWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(testEpoch, 0).UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, &fakeWaiter{deadline: c.now.Add(d), ch: ch})
	return ch
}

// Advance moves the fake clock forward and fires every due waiter.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	now := c.now
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.deadline.After(now) {
			w.ch <- now
			continue
		}
		kept = append(kept, w)
	}
	for i := len(kept); i < len(c.waiters); i++ {
		c.waiters[i] = nil
	}
	c.waiters = kept
}

// waiterCount reports how many blocked waiters are registered.
func (c *fakeClock) waiterCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// waitForWaiters blocks the test until n fake-clock waiters are registered.
func (c *fakeClock) waitForWaiters(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c.waiterCount() >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake clock: timed out waiting for %d waiter(s), have %d", n, c.waiterCount())
		}
		time.Sleep(time.Millisecond)
	}
}

// testSettings is a race-safe mutable settings source for hot-reload tests.
type testSettings struct {
	mu sync.Mutex
	s  model.Settings
}

func newTestSettings() *testSettings {
	return &testSettings{s: model.DefaultSettings()}
}

func newTestSettingsWith(fn func(*model.Settings)) *testSettings {
	ts := newTestSettings()
	ts.mutate(fn)
	return ts
}

func (ts *testSettings) get() model.Settings {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.s
}

func (ts *testSettings) mutate(fn func(*model.Settings)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	fn(&ts.s)
}

// auditRecord is one captured OnAudit callback.
type auditRecord struct {
	event  string
	detail map[string]string
}

// auditRecorder captures audit events from the selector.
type auditRecorder struct {
	mu      sync.Mutex
	records []auditRecord
}

func (a *auditRecorder) hook(event string, detail map[string]string) {
	cp := make(map[string]string, len(detail))
	for k, v := range detail {
		cp[k] = v
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, auditRecord{event: event, detail: cp})
}

func (a *auditRecorder) count(event string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.records {
		if r.event == event {
			n++
		}
	}
	return n
}

func (a *auditRecorder) last(event string) (map[string]string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.records) - 1; i >= 0; i-- {
		if a.records[i].event == event {
			return a.records[i].detail, true
		}
	}
	return nil, false
}

// newTestSelector builds a Selector wired to a fake clock and deterministic RNG.
func newTestSelector(t *testing.T, ts *testSettings, clk *fakeClock, seed int64, rec *auditRecorder) *Selector {
	t.Helper()
	opts := Options{
		Settings: ts.get,
		Now:      clk.Now,
		Random:   rand.New(rand.NewSource(seed)),
	}
	if rec != nil {
		opts.OnAudit = rec.hook
	}
	return NewSelector(opts)
}

// makeNode builds an enabled, online candidate node.
func makeNode(id string) *model.Node {
	return &model.Node{
		ID:      id,
		Alias:   id,
		Weight:  1,
		Enabled: true,
		Online:  true,
	}
}

// makeNodes builds enabled, online candidate nodes.
func makeNodes(ids ...string) []*model.Node {
	nodes := make([]*model.Node, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, makeNode(id))
	}
	return nodes
}

// countSelects runs n selections and returns the observed node distribution.
func countSelects(t *testing.T, sel *Selector, req Request, candidates []*model.Node, n int) map[string]int {
	t.Helper()
	counts := make(map[string]int, len(candidates))
	for i := 0; i < n; i++ {
		node, _, err := sel.Select(req, candidates)
		if err != nil {
			t.Fatalf("Select returned error: %v", err)
		}
		if node == nil {
			t.Fatalf("Select returned nil node without error")
		}
		counts[node.ID]++
	}
	return counts
}

// waitNBudgeted runs b.WaitN(ctx, n) on a goroutine and drives the fake clock in
// small steps until it finishes. It returns the simulated time spent and the
// WaitN result.
func waitNBudgeted(t *testing.T, b *Bucket, ctx context.Context, n int, clk *fakeClock) (time.Duration, error) {
	t.Helper()
	start := clk.Now()
	done := make(chan error, 1)
	go func() { done <- b.WaitN(ctx, n) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-done:
			return clk.Now().Sub(start), err
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("WaitN(%d) did not finish", n)
		}
		if clk.waiterCount() > 0 {
			clk.Advance(5 * time.Millisecond)
			continue
		}
		time.Sleep(100 * time.Microsecond)
	}
}
