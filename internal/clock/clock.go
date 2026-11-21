// Package clock detects clock skew between the local host and a remote peer
// from one way timestamp samples.
//
// The proxy server and its nodes exchange timestamps over the tunnel control
// stream (HELLO.TS, STATS.TS and HELLO_ACK.server_time). Each pair yields
// offset = local - remote; a ring buffer keeps the most recent samples and the
// median is reported, so a few samples delayed by scheduling or network jitter
// do not move the estimate. The Detector never adjusts the system clock; it
// only observes and exposes the offset so the caller can log, show it on the
// panel or raise an alert.
//
// A Detector is safe for concurrent use and is intended to be kept per remote
// node (or per tunnel session).
package clock

import (
	"sort"
	"sync"
	"time"
)

// Defaults used when NewDetector gets a non-positive argument. 32 samples at
// the 10 s STATS cadence covers more than five minutes of history; 30 s is the
// threshold above which a certificate/JWT time window would become unreliable.
const (
	DefaultWindow    = 32
	DefaultThreshold = 30 * time.Second
)

// Stats is a snapshot of the detector state.
type Stats struct {
	// Samples is the number of samples currently held in the window
	// (0 <= Samples <= window size).
	Samples int
	// Offset is the median offset (local - remote) of the window; zero when
	// there are no samples.
	Offset time.Duration
	// Min and Max are the smallest and largest offsets in the window; both zero
	// when there are no samples.
	Min, Max time.Duration
}

// Detector tracks the clock offset between the local system clock and one
// remote peer. The zero value is not usable; build it with NewDetector.
type Detector struct {
	mu        sync.Mutex
	window    []time.Duration // ring buffer of offsets
	next      int             // index of the next slot to overwrite
	count     int             // number of valid samples, <= len(window)
	threshold time.Duration
}

// NewDetector returns a detector with the given ring buffer size and skew
// threshold. Non-positive values select DefaultWindow / DefaultThreshold.
func NewDetector(window int, threshold time.Duration) *Detector {
	if window <= 0 {
		window = DefaultWindow
	}
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Detector{
		window:    make([]time.Duration, window),
		threshold: threshold,
	}
}

// Sample records one observation: the remote peer reported remoteUnixMS while
// the local clock read local at (approximately) the same moment. Offsets with a
// non-positive remote timestamp are ignored because peers that omit their
// timestamp (omitempty) would otherwise look catastrophically skewed.
//
// One way samples include network latency and asymmetric routing, so callers
// should feed the kind of samples that are statistically fair: periodic STATS
// timestamps and HELLO timestamps are fine, latency measurements are not.
func (d *Detector) Sample(remoteUnixMS int64, local time.Time) {
	if remoteUnixMS <= 0 {
		return
	}
	offset := local.Sub(time.UnixMilli(remoteUnixMS))
	d.mu.Lock()
	d.window[d.next] = offset
	d.next = (d.next + 1) % len(d.window)
	if d.count < len(d.window) {
		d.count++
	}
	d.mu.Unlock()
}

// Offset returns the median offset (local - remote) over the current window, or
// zero when no sample was recorded yet.
func (d *Detector) Offset() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return medianSorted(d.snapshotLocked())
}

// Skewed reports whether the absolute median offset exceeds the threshold. The
// comparison is strict: exactly threshold is not considered skewed. A detector
// without samples is never skewed.
func (d *Detector) Skewed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	vals := d.snapshotLocked()
	if len(vals) == 0 {
		return false
	}
	off := medianSorted(vals)
	return off > d.threshold || off < -d.threshold
}

// Stats returns a consistent snapshot of the window.
func (d *Detector) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	vals := d.snapshotLocked()
	if len(vals) == 0 {
		return Stats{}
	}
	// snapshotLocked returns the values sorted ascending.
	return Stats{
		Samples: len(vals),
		Offset:  medianSorted(vals),
		Min:     vals[0],
		Max:     vals[len(vals)-1],
	}
}

// Reset discards every sample and keeps the configured window and threshold.
func (d *Detector) Reset() {
	d.mu.Lock()
	for i := range d.window {
		d.window[i] = 0
	}
	d.next = 0
	d.count = 0
	d.mu.Unlock()
}

// snapshotLocked copies the valid ring entries into a fresh slice sorted
// ascending. The caller must hold d.mu.
func (d *Detector) snapshotLocked() []time.Duration {
	if d.count == 0 {
		return nil
	}
	vals := make([]time.Duration, d.count)
	if d.count < len(d.window) {
		// While filling, samples live at window[0:count] in arrival order.
		copy(vals, d.window[:d.count])
	} else {
		// Full ring: the oldest sample is at next.
		n := copy(vals, d.window[d.next:])
		copy(vals[n:], d.window[:d.next])
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return vals
}

// medianSorted returns the median of an ascending slice: the middle element for
// an odd count, or the mean of the two middle elements for an even count. It
// returns zero for an empty slice.
func medianSorted(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	mid := len(vals) / 2
	if len(vals)%2 == 1 {
		return vals[mid]
	}
	return durationMean(vals[mid-1], vals[mid])
}

// durationMean returns (a+b)/2 without overflowing int64: subtracting
// durations close to the int64 limits could overflow, so same-sign values are
// averaged in halves. The result is truncated toward zero for odd sums, which
// is at most one nanosecond away from the exact mean.
func durationMean(a, b time.Duration) time.Duration {
	if (a < 0) != (b < 0) {
		// With opposite signs a+b cannot overflow.
		return (a + b) / 2
	}
	return a/2 + b/2 + (a%2+b%2)/2
}
