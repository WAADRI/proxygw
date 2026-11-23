// Package stats provides the in-memory observability helpers required by the
// panel: a 15 minute trend ring buffer (no TSDB), sliding-window TopN target
// statistics and a rolling overview counter set. Everything is bounded so the
// server memory footprint stays predictable.
package stats

import (
	"sort"
	"sync"
	"time"
)

// Point is one trend sample.
type Point struct {
	TS       int64 `json:"ts"`
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
	Active   int64 `json:"active"`
}

// Trend is a fixed-size ring buffer of per-interval samples.
type Trend struct {
	mu       sync.Mutex
	window   time.Duration
	interval time.Duration
	points   []Point
	last     time.Time
	// pending accumulates events since the last emitted point.
	reqs   int64
	errors int64
	active int64
}

// NewTrend creates a trend buffer covering window with the given sample
// interval (typically 15m / 15s).
func NewTrend(window, interval time.Duration) *Trend {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	n := int(window / interval)
	if n < 1 {
		n = 1
	}
	return &Trend{window: window, interval: interval, points: make([]Point, 0, n), last: time.Now()}
}

// Record adds request/error events and sets the current active connection gauge.
func (t *Trend) Record(requests, errors, active int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reqs += requests
	t.errors += errors
	t.active = active
	t.maybeEmitLocked(time.Now())
}

// Snapshot returns the retained samples inside the configured window (oldest
// first, always a copy). The timestamp filter is a second guard on top of the
// ring capacity so a caller can never receive points older than the advertised
// 15-minute window.
func (t *Trend) Snapshot() []Point {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.maybeEmitLocked(now)
	cutoff := now.Add(-t.window).Unix()
	out := make([]Point, 0, len(t.points))
	for _, p := range t.points {
		if p.TS >= cutoff {
			out = append(out, p)
		}
	}
	return out
}

func (t *Trend) maybeEmitLocked(now time.Time) {
	elapsed := now.Sub(t.last)
	if elapsed < t.interval {
		return
	}
	buckets := int(elapsed / t.interval)
	if buckets < 1 {
		return
	}
	if buckets > cap(t.points) {
		buckets = cap(t.points)
	}
	// Emit the accumulated counters in the first bucket, zeros for skipped
	// buckets so the x axis keeps a constant spacing.
	t.points = append(t.points, Point{TS: t.last.Add(t.interval).Unix(), Requests: t.reqs, Errors: t.errors, Active: t.active})
	for i := 1; i < buckets; i++ {
		t.points = append(t.points, Point{TS: t.last.Add(time.Duration(i+1) * t.interval).Unix(), Active: t.active})
	}
	t.reqs, t.errors = 0, 0
	// Trim to the retained window.
	if len(t.points) > cap(t.points) {
		t.points = t.points[len(t.points)-cap(t.points):]
	}
	t.last = t.last.Add(time.Duration(buckets) * t.interval)
}

// TargetStat is one TopN entry.
type TargetStat struct {
	Target string `json:"target"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
	Errors int64  `json:"errors"`
}

// Counter is a sliding window counter set for one key.
type Counter struct {
	Count  int64
	Bytes  int64
	Errors int64
}

// TopN keeps per-target/node/credential counters in one-minute buckets over a
// 15 minute window. Cardinality is capped to avoid unbounded memory growth.
type TopN struct {
	mu       sync.Mutex
	maxKeys  int
	buckets  int
	curr     map[string]*Counter
	previous []map[string]*Counter
	lastRoll time.Time
}

// NewTopN creates a TopN tracker. window/interval typically 15m/1m and maxKeys
// bounds cardinality (e.g. 2048 targets).
func NewTopN(window, interval time.Duration, maxKeys int) *TopN {
	if interval <= 0 {
		interval = time.Minute
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	n := int(window / interval)
	if n < 1 {
		n = 1
	}
	if maxKeys <= 0 {
		maxKeys = 2048
	}
	return &TopN{maxKeys: maxKeys, buckets: n, curr: map[string]*Counter{}, lastRoll: time.Now()}
}

// Record adds one request observation. bytes is the total transferred and
// errors counts node-side failures.
func (t *TopN) Record(key string, bytes int64, failed bool) {
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollLocked(time.Now())
	c, ok := t.curr[key]
	if !ok {
		if len(t.curr) >= t.maxKeys {
			// Cardinality cap: fold everything else into an overflow bucket.
			key = "__overflow__"
			c = t.curr[key]
			if c == nil {
				c = &Counter{}
				t.curr[key] = c
			}
		} else {
			c = &Counter{}
			t.curr[key] = c
		}
	}
	c.Count++
	c.Bytes += bytes
	if failed {
		c.Errors++
	}
}

// Top returns the top n keys by count over the retained window.
func (t *TopN) Top(n int) []TargetStat {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollLocked(time.Now())
	if n <= 0 || n > t.maxKeys {
		n = 10
	}
	merged := map[string]*Counter{}
	for _, bucket := range t.previous {
		for k, c := range bucket {
			m := merged[k]
			if m == nil {
				m = &Counter{}
				merged[k] = m
			}
			m.Count += c.Count
			m.Bytes += c.Bytes
			m.Errors += c.Errors
		}
	}
	for k, c := range t.curr {
		m := merged[k]
		if m == nil {
			m = &Counter{}
			merged[k] = m
		}
		m.Count += c.Count
		m.Bytes += c.Bytes
		m.Errors += c.Errors
	}
	out := make([]TargetStat, 0, len(merged))
	for k, c := range merged {
		out = append(out, TargetStat{Target: k, Count: c.Count, Bytes: c.Bytes, Errors: c.Errors})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Target < out[j].Target
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (t *TopN) rollLocked(now time.Time) {
	elapsed := now.Sub(t.lastRoll)
	if elapsed < time.Minute {
		return
	}
	rolls := int(elapsed / time.Minute)
	if rolls < 1 {
		return
	}
	if rolls > t.buckets {
		t.previous = nil
		t.curr = map[string]*Counter{}
		t.lastRoll = now
		return
	}
	for i := 0; i < rolls; i++ {
		t.previous = append(t.previous, t.curr)
		if len(t.previous) > t.buckets {
			t.previous = t.previous[len(t.previous)-t.buckets:]
		}
		t.curr = map[string]*Counter{}
	}
	t.lastRoll = t.lastRoll.Add(time.Duration(rolls) * time.Minute)
}

// Counters is a small thread-safe counters bundle used for overview numbers.
type Counters struct {
	mu       sync.Mutex
	requests int64
	errors   int64
	retries  int64
	limited  int64
	trips    int64
}

// AddRequests records a request result.
func (c *Counters) AddRequests(ok bool) {
	c.mu.Lock()
	c.requests++
	if !ok {
		c.errors++
	}
	c.mu.Unlock()
}

// AddRetry records a transparent retry.
func (c *Counters) AddRetry() {
	c.mu.Lock()
	c.retries++
	c.mu.Unlock()
}

// AddRateLimited records a rate limiter backpressure event.
func (c *Counters) AddRateLimited() {
	c.mu.Lock()
	c.limited++
	c.mu.Unlock()
}

// AddBreakerTrip records a breaker open transition.
func (c *Counters) AddBreakerTrip() {
	c.mu.Lock()
	c.trips++
	c.mu.Unlock()
}

// Snapshot returns the current counters.
func (c *Counters) Snapshot() (requests, errors, retries, limited, trips int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.errors, c.retries, c.limited, c.trips
}
