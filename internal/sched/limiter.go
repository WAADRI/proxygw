package sched

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"proxygw/internal/model"
)

// tokenBucket is a byte-rate token bucket with a one-second capacity
// (initialised full) and a refill clock that can be injected for tests.
//
// WaitN may reserve more than the current balance: the balance is allowed to go
// negative and the caller waits for the debt to be repaid. This lets several
// buckets be composed into one logical limit without over-throttling (the
// composed rate is exactly the slowest layer) and without holding any lock while
// sleeping.
type tokenBucket struct {
	clk      clock
	rate     float64 // bytes per second, > 0 (immutable after construction)
	capacity float64 // one second of traffic, at least 1 byte

	mu     sync.Mutex
	tokens float64 // may be negative while reservations are pending
	last   time.Time
}

func newTokenBucket(rate int, clk clock) *tokenBucket {
	r := float64(rate)
	if r < 1 {
		r = 1
	}
	return &tokenBucket{
		clk:      clk,
		rate:     r,
		capacity: r,
		tokens:   r,
		last:     clk.Now(),
	}
}

// refillLocked credits the tokens that accrued since the last refill.
func (tb *tokenBucket) refillLocked(now time.Time) {
	if now.After(tb.last) {
		tb.tokens += now.Sub(tb.last).Seconds() * tb.rate
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.last = now
	}
}

// reserve immediately takes take tokens (possibly driving the balance negative)
// and returns how long the caller must wait before those bytes are "paid for".
// Locks are released before the caller waits.
func (tb *tokenBucket) reserve(take float64) time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refillLocked(tb.clk.Now())
	tb.tokens -= take
	if tb.tokens >= 0 {
		return 0
	}
	wait := time.Duration(math.Ceil((-tb.tokens) / tb.rate * float64(time.Second)))
	if wait <= 0 {
		wait = time.Nanosecond
	}
	return wait
}

// refund gives back a reservation that was cancelled while waiting.
func (tb *tokenBucket) refund(take float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refillLocked(tb.clk.Now())
	tb.tokens += take
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
}

// Bucket is a byte-rate limiter. A nil bucket, or a bucket without layers, is
// unlimited so callers can always wrap a connection without nil checks.
//
// A Bucket returned by Limiters.Down/Up combines several token buckets: WaitN
// reserves the same amount from every layer and waits for the slowest one, so
// the composed throughput equals the slowest configured layer.
type Bucket struct {
	clk    clock
	layers []*tokenBucket
}

// NewBucket builds a single byte-rate limiter. bytesPerSecond <= 0 means
// unlimited.
func NewBucket(bytesPerSecond int) *Bucket {
	return &Bucket{clk: realClock{}, layers: newTokenLayers(bytesPerSecond, realClock{})}
}

// newBucketWithClock is the test constructor allowing an injected clock.
func newBucketWithClock(bytesPerSecond int, clk clock) *Bucket {
	return &Bucket{clk: clk, layers: newTokenLayers(bytesPerSecond, clk)}
}

// newTokenLayers builds the layer list for one rate.
func newTokenLayers(bytesPerSecond int, clk clock) []*tokenBucket {
	if bytesPerSecond <= 0 {
		return nil
	}
	return []*tokenBucket{newTokenBucket(bytesPerSecond, clk)}
}

// Limit reports the effective byte rate of the bucket (0 = unlimited).
func (b *Bucket) Limit() int {
	if b == nil || len(b.layers) == 0 {
		return 0
	}
	slowest := math.Inf(1)
	for _, layer := range b.layers {
		if layer.rate < slowest {
			slowest = layer.rate
		}
	}
	return int(slowest)
}

// WaitN blocks until n bytes of budget are available or ctx is cancelled.
// n <= 0 returns immediately; an unlimited bucket never blocks.
func (b *Bucket) WaitN(ctx context.Context, n int) error {
	if n <= 0 || b == nil || len(b.layers) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	remaining := float64(n)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Reserve one chunk no larger than the smallest capacity so that no
		// layer is charged more than one second of its own traffic at once.
		chunk := remaining
		minCapacity := math.Inf(1)
		for _, layer := range b.layers {
			if layer.capacity < minCapacity {
				minCapacity = layer.capacity
			}
		}
		if chunk > minCapacity {
			chunk = minCapacity
		}
		var wait time.Duration
		clk := b.clk
		if clk == nil {
			clk = realClock{}
		}
		for _, layer := range b.layers {
			if layer.clk != nil {
				clk = layer.clk
			}
			if w := layer.reserve(chunk); w > wait {
				wait = w
			}
		}
		if wait > 0 {
			select {
			case <-clk.After(wait):
			case <-ctx.Done():
				for _, layer := range b.layers {
					layer.refund(chunk)
				}
				return ctx.Err()
			}
		}
		remaining -= chunk
	}
	return nil
}

// Limiters builds the global / per-node / per-credential bandwidth buckets from
// the hot-reloadable settings. Buckets keep their token state between calls and
// are recreated when the configured rate changes, so panel edits take effect on
// the next wrapped read.
type Limiters struct {
	settings func() model.Settings
	clk      clock

	mu     sync.Mutex
	global *tokenBucket
	byNode map[string]*tokenBucket
	byCred map[string]*tokenBucket
}

// NewLimiters builds a Limiters reading rates from settings.
func NewLimiters(settings func() model.Settings) *Limiters {
	return newLimiters(settings, realClock{})
}

// newLimiters is the test constructor allowing an injected clock.
func newLimiters(settings func() model.Settings, clk clock) *Limiters {
	if settings == nil {
		settings = model.DefaultSettings
	}
	return &Limiters{
		settings: settings,
		clk:      clk,
		byNode:   make(map[string]*tokenBucket),
		byCred:   make(map[string]*tokenBucket),
	}
}

// kbpsToBytesPerSecond converts a kbps setting to bytes per second, counting one
// kbps as 1024 bits (128 bytes) per second.
func kbpsToBytesPerSecond(kbps int) int {
	if kbps <= 0 {
		return 0
	}
	b := kbps * 1024 / 8
	if b < 1 {
		b = 1
	}
	return b
}

// Down returns the downstream limiter for one credential/node pair, combining
// the global, node and credential layers. Layers whose configured rate is 0 are
// unlimited and are omitted; the composed rate is the slowest remaining layer.
func (l *Limiters) Down(credentialID, nodeID string) *Bucket {
	cfg := l.settings()
	limits := cfg.Limits
	var layers []*tokenBucket
	if b := l.globalBucket(limits.GlobalDownKbps); b != nil {
		layers = append(layers, b)
	}
	if b := l.nodeBucket(nodeID, limits.PerNodeDownKbps); b != nil {
		layers = append(layers, b)
	}
	if b := l.credentialBucket(credentialID, limits.PerCredentialDownKbps); b != nil {
		layers = append(layers, b)
	}
	// Wait on the slowest layer first; without over-throttling this is only a
	// hint, but it keeps the common case (one clearly dominant limit) cheap.
	sort.SliceStable(layers, func(i, j int) bool { return layers[i].rate < layers[j].rate })
	return &Bucket{clk: l.clk, layers: layers}
}

// Up returns the upstream limiter for one credential/node pair.
//
// The runtime settings currently expose only downstream caps (global/node/
// credential down_kbps); upstream traffic is unlimited unless the caller layers
// its own sched.NewBucket over the upload path.
func (l *Limiters) Up(credentialID, nodeID string) *Bucket {
	return &Bucket{clk: l.clk}
}

// globalBucket returns the shared global bucket, recreating it when the
// configured rate changes.
func (l *Limiters) globalBucket(kbps int) *tokenBucket {
	rate := kbpsToBytesPerSecond(kbps)
	if rate <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global == nil || int(l.global.rate) != rate {
		l.global = newTokenBucket(rate, l.clk)
	}
	return l.global
}

// nodeBucket returns the per-node bucket.
func (l *Limiters) nodeBucket(nodeID string, kbps int) *tokenBucket {
	rate := kbpsToBytesPerSecond(kbps)
	if rate <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.byNode[nodeID]
	if b == nil || int(b.rate) != rate {
		b = newTokenBucket(rate, l.clk)
		l.byNode[nodeID] = b
	}
	return b
}

// credentialBucket returns the per-credential bucket.
func (l *Limiters) credentialBucket(credentialID string, kbps int) *tokenBucket {
	rate := kbpsToBytesPerSecond(kbps)
	if rate <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.byCred[credentialID]
	if b == nil || int(b.rate) != rate {
		b = newTokenBucket(rate, l.clk)
		l.byCred[credentialID] = b
	}
	return b
}
