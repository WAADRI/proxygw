package sched

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"proxygw/internal/model"
)

// TestBucketBurstAndRate documents the standard token bucket: the bucket starts
// full with one second of traffic, so two 500 byte reads fit in the burst; the
// next 500 bytes must wait about half a second.
func TestBucketBurstAndRate(t *testing.T) {
	clk := newFakeClock()
	b := newBucketWithClock(1000, clk)
	if got := b.Limit(); got != 1000 {
		t.Fatalf("Limit() = %d, want 1000", got)
	}
	ctx := context.Background()
	start := clk.Now()
	if err := b.WaitN(ctx, 500); err != nil {
		t.Fatalf("first WaitN: %v", err)
	}
	if err := b.WaitN(ctx, 500); err != nil {
		t.Fatalf("second WaitN: %v", err)
	}
	if elapsed := clk.Now().Sub(start); elapsed != 0 {
		t.Fatalf("burst reads advanced the clock by %v", elapsed)
	}

	sim, err := waitNBudgeted(t, b, ctx, 500, clk)
	if err != nil {
		t.Fatalf("third WaitN: %v", err)
	}
	if sim < 400*time.Millisecond || sim > 650*time.Millisecond {
		t.Fatalf("third WaitN simulated wait = %v, want about 500ms", sim)
	}

	// A read larger than the bucket capacity is split into capacity-sized
	// chunks; the simulated wait still matches the configured rate (plus the
	// initial one second burst).
	large := newBucketWithClock(1000, clk)
	sim, err = waitNBudgeted(t, large, ctx, 2500, clk)
	if err != nil {
		t.Fatalf("large WaitN: %v", err)
	}
	if sim < 1400*time.Millisecond || sim > 1700*time.Millisecond {
		t.Fatalf("2500 byte WaitN simulated wait = %v, want about 1.5s", sim)
	}
}

func TestBucketContextCancel(t *testing.T) {
	clk := newFakeClock()
	b := newBucketWithClock(1000, clk)
	if err := b.WaitN(context.Background(), 1000); err != nil {
		t.Fatalf("drain: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := b.WaitN(ctx, 500)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitN error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("cancellation took %v, want < 200ms", elapsed)
	}
	// The cancelled reservation must be refunded, so a later read does not pay
	// it twice.
	layer := b.layers[0]
	layer.mu.Lock()
	tokens := layer.tokens
	layer.mu.Unlock()
	if tokens < -0.01 || tokens > 0.01 {
		t.Fatalf("tokens after cancelled reservation = %f, want 0", tokens)
	}
}

func TestBucketUnlimited(t *testing.T) {
	clk := newFakeClock()
	unlimited := newBucketWithClock(0, clk)
	if got := unlimited.Limit(); got != 0 {
		t.Fatalf("Limit() = %d, want 0", got)
	}
	if err := unlimited.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("unlimited WaitN: %v", err)
	}
	if err := (&Bucket{}).WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("empty bucket WaitN: %v", err)
	}
	var nilBucket *Bucket
	if err := nilBucket.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("nil bucket WaitN: %v", err)
	}
	if got := nilBucket.Limit(); got != 0 {
		t.Fatalf("nil Limit() = %d, want 0", got)
	}
}

func TestBucketNonPositiveN(t *testing.T) {
	clk := newFakeClock()
	b := newBucketWithClock(10, clk)
	if err := b.WaitN(context.Background(), 0); err != nil {
		t.Fatalf("WaitN(0): %v", err)
	}
	if err := b.WaitN(context.Background(), -100); err != nil {
		t.Fatalf("WaitN(-100): %v", err)
	}
	// A nil context must be tolerated (treated as Background).
	if err := b.WaitN(nil, -1); err != nil {
		t.Fatalf("WaitN(nil ctx): %v", err)
	}
}

func TestLimitersCompositeSlowestLayer(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Limits.GlobalDownKbps = 0
		s.Limits.PerNodeDownKbps = 8        // 1024 B/s
		s.Limits.PerCredentialDownKbps = 16 // 2048 B/s
	})
	clk := newFakeClock()
	l := newLimiters(ts.get, clk)
	b := l.Down("cred", "node")
	if got := b.Limit(); got != 1024 {
		t.Fatalf("composite Limit() = %d, want slowest layer 1024", got)
	}
	ctx := context.Background()
	if err := b.WaitN(ctx, 1024); err != nil {
		t.Fatalf("first WaitN: %v", err)
	}
	sim, err := waitNBudgeted(t, b, ctx, 1024, clk)
	if err != nil {
		t.Fatalf("second WaitN: %v", err)
	}
	if sim < 800*time.Millisecond || sim > 1300*time.Millisecond {
		t.Fatalf("composite wait = %v, want about 1s (node layer is slowest)", sim)
	}

	// Remove the node limit: the composed rate becomes the credential rate.
	// The credential bucket refilled to its full capacity while the node layer
	// was blocking, so drain it first and then measure the refill rate.
	ts.mutate(func(s *model.Settings) {
		s.Limits.PerNodeDownKbps = 0
		s.Limits.PerCredentialDownKbps = 16
	})
	b = l.Down("cred", "node")
	if got := b.Limit(); got != 2048 {
		t.Fatalf("composite Limit() = %d, want 2048", got)
	}
	if err := b.WaitN(ctx, 2048); err != nil {
		t.Fatalf("credential burst: %v", err)
	}
	sim, err = waitNBudgeted(t, b, ctx, 1024, clk)
	if err != nil {
		t.Fatalf("credential WaitN: %v", err)
	}
	if sim < 300*time.Millisecond || sim > 800*time.Millisecond {
		t.Fatalf("credential-only wait = %v, want about 500ms", sim)
	}

	// Global layer alone: 64 kbps = 8192 B/s.
	ts.mutate(func(s *model.Settings) {
		s.Limits.GlobalDownKbps = 64
		s.Limits.PerNodeDownKbps = 0
		s.Limits.PerCredentialDownKbps = 0
	})
	b = l.Down("cred", "node")
	if got := b.Limit(); got != 8192 {
		t.Fatalf("composite Limit() = %d, want 8192", got)
	}
	if err := b.WaitN(ctx, 8192); err != nil {
		t.Fatalf("global burst: %v", err)
	}
	sim, err = waitNBudgeted(t, b, ctx, 8192, clk)
	if err != nil {
		t.Fatalf("global WaitN: %v", err)
	}
	if sim < 800*time.Millisecond || sim > 1300*time.Millisecond {
		t.Fatalf("global wait = %v, want about 1s", sim)
	}
}

func TestLimitersUnlimitedByDefault(t *testing.T) {
	ts := newTestSettings() // all limits are 0 in DefaultSettings
	clk := newFakeClock()
	l := newLimiters(ts.get, clk)
	down := l.Down("cred", "node")
	if got := down.Limit(); got != 0 {
		t.Fatalf("Down Limit() = %d, want 0", got)
	}
	if err := down.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("Down WaitN: %v", err)
	}
	up := l.Up("cred", "node")
	if got := up.Limit(); got != 0 {
		t.Fatalf("Up Limit() = %d, want 0 (no upstream cap configured)", got)
	}
	if err := up.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("Up WaitN: %v", err)
	}
}

func TestLimitersCredentialIsolation(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Limits.PerCredentialDownKbps = 8 // 1024 B/s
	})
	clk := newFakeClock()
	l := newLimiters(ts.get, clk)
	ctx := context.Background()
	bA := l.Down("cred-a", "node")
	bB := l.Down("cred-b", "node")

	if err := bA.WaitN(ctx, 1024); err != nil {
		t.Fatalf("credential A burst: %v", err)
	}
	// A different credential has its own bucket and is not throttled by A.
	if err := bB.WaitN(ctx, 1024); err != nil {
		t.Fatalf("credential B burst: %v", err)
	}
	sim, err := waitNBudgeted(t, bA, ctx, 1024, clk)
	if err != nil {
		t.Fatalf("credential A refill: %v", err)
	}
	if sim < 800*time.Millisecond || sim > 1300*time.Millisecond {
		t.Fatalf("credential A wait = %v, want about 1s", sim)
	}
}

func TestLimitersHotReloadRate(t *testing.T) {
	ts := newTestSettingsWith(func(s *model.Settings) {
		s.Limits.PerNodeDownKbps = 8 // 1024 B/s
	})
	clk := newFakeClock()
	l := newLimiters(ts.get, clk)
	ctx := context.Background()
	if err := l.Down("cred", "node").WaitN(ctx, 1024); err != nil {
		t.Fatalf("burst: %v", err)
	}

	// Raising the limit recreates the node bucket full, so a read sized for the
	// new rate is available immediately.
	ts.mutate(func(s *model.Settings) { s.Limits.PerNodeDownKbps = 64 }) // 8192 B/s
	b := l.Down("cred", "node")
	if got := b.Limit(); got != 8192 {
		t.Fatalf("Limit() after hot reload = %d, want 8192", got)
	}
	if err := b.WaitN(ctx, 1024); err != nil {
		t.Fatalf("post-reload burst: %v", err)
	}
	sim, err := waitNBudgeted(t, b, ctx, 8192, clk)
	if err != nil {
		t.Fatalf("post-reload WaitN: %v", err)
	}
	if sim < 80*time.Millisecond || sim > 300*time.Millisecond {
		t.Fatalf("post-reload wait = %v, want about 125ms", sim)
	}
}

func TestLimitersConcurrentWaiters(t *testing.T) {
	l := NewLimiters(func() model.Settings {
		s := model.DefaultSettings()
		s.Limits.PerNodeDownKbps = 1 << 20 // effectively unlimited for this test
		return s
	})
	// Warm up the shared maps once so the concurrent phase is mostly bucket IO.
	_ = l.Down("cred", "node")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := l.Down("cred", "node")
			for j := 0; j < 20; j++ {
				if err := b.WaitN(context.Background(), 1000); err != nil {
					t.Errorf("WaitN: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
