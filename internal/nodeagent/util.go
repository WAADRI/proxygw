package nodeagent

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"
)

// relayBufPool recycles the fixed 32 KiB relay buffers. The relay hot path must
// not allocate per read/write pair nor use time.After.
var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufSize)
		return &b
	},
}

func getRelayBuf() *[]byte { return relayBufPool.Get().(*[]byte) }

func putRelayBuf(b *[]byte) { relayBufPool.Put(b) }

// backoffDuration returns base * 2^(n-1), capped at max. n starts at 1.
func backoffDuration(n int, base, max time.Duration) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if max <= 0 {
		max = 10 * time.Minute
	}
	if base > max {
		return max
	}
	d := base
	for i := 1; i < n; i++ {
		if d >= max/2 {
			return max
		}
		d *= 2
	}
	if d > max {
		return max
	}
	return d
}

// jitter returns a pseudo random duration in [0, max].
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max) + 1))
}

// sleepCtx waits for d unless ctx is cancelled first. It reports whether the
// full delay elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// isTimeoutErr classifies deadline/timeout errors across context, net and os
// layers (transport implementations wrap their own error types).
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// truncateMsg bounds an error message that is going to the wire.
func truncateMsg(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// retryGate is the agent-wide reconnect backoff. While no plane is ready the
// gate enforces the 1m/2m/4m/8m/10m sequence; a single success resets it.
type retryGate struct {
	mu       sync.Mutex
	failures int
	nextAt   time.Time
	wake     chan struct{}
}

// wait blocks until the current backoff window elapses. It returns ctx.Err()
// when the agent is shutting down.
func (g *retryGate) wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		at := g.nextAt
		wake := g.wake
		g.mu.Unlock()
		if at.IsZero() || !time.Now().Before(at) {
			return nil
		}
		timer := time.NewTimer(time.Until(at))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		case <-wake:
			timer.Stop()
		}
	}
}

// fail escalates the reconnect backoff. Concurrent plane failures inside the
// same window do not double-escalate.
func (g *retryGate) fail(base, max time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if !g.nextAt.IsZero() && now.Before(g.nextAt) {
		return
	}
	g.failures++
	g.nextAt = now.Add(backoffDuration(g.failures, base, max))
}

// success resets the backoff and wakes every waiting plane.
func (g *retryGate) success() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failures == 0 && g.nextAt.IsZero() {
		return
	}
	g.failures = 0
	g.nextAt = time.Time{}
	close(g.wake)
	g.wake = make(chan struct{})
}

// failuresCount exposes the current backoff step for tests.
func (g *retryGate) failuresCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failures
}

// closeWrite performs a TCP half close on conn when supported. Generic
// connections (tests, wrappers) fall back to a full close by the caller.
func closeWrite(conn io.Closer) error {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

var errNilConn = errors.New("nodeagent: 拨号返回空连接")

// waitGroupTimeout waits for wg with a bound.
func waitGroupTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// waitUntil polls cond until it is true or the timeout expires.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}
