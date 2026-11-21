package geo

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"proxygw/internal/model"
)

// Cache and limiter defaults (chapter E.7).
const (
	defaultCacheEntries  = 10000
	defaultCacheTTL      = 24 * time.Hour
	defaultMaxConcurrent = 4
	maxRateBurst         = 60 // token bucket capacity cap, keeps bursts bounded
)

// geoCache is a size bounded LRU cache of resolved Geo values keyed by the
// canonical IP string. Entries expire after ttl. The mutex is only held for map
// and list manipulation; no I/O ever happens under it.
type geoCache struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	order    *list.List // front = most recently used
	capacity int
	ttl      time.Duration
	now      func() time.Time
}

type cacheEntry struct {
	key     string
	geo     model.Geo
	expires time.Time
}

func newGeoCache(capacity int, ttl time.Duration, now func() time.Time) *geoCache {
	if capacity <= 0 {
		capacity = defaultCacheEntries
	}
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	if now == nil {
		now = time.Now
	}
	return &geoCache{
		entries:  make(map[string]*list.Element, capacity),
		order:    list.New(),
		capacity: capacity,
		ttl:      ttl,
		now:      now,
	}
}

// get returns a deep copy of the cached geo so callers cannot mutate shared
// state through the Sources map.
func (c *geoCache) get(key string) (model.Geo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return model.Geo{}, false
	}
	entry := element.Value.(*cacheEntry)
	if !entry.expires.IsZero() && !c.now().Before(entry.expires) {
		c.order.Remove(element)
		delete(c.entries, key)
		return model.Geo{}, false
	}
	c.order.MoveToFront(element)
	return copyGeo(entry.geo), true
}

// set stores (or refreshes) one entry and evicts the least recently used entry
// when the size limit is exceeded.
func (c *geoCache) set(key string, geo model.Geo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires := c.now().Add(c.ttl)
	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*cacheEntry)
		entry.geo = copyGeo(geo)
		entry.expires = expires
		c.order.MoveToFront(element)
		return
	}
	element := c.order.PushFront(&cacheEntry{key: key, geo: copyGeo(geo), expires: expires})
	c.entries[key] = element
	for len(c.entries) > c.capacity {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheEntry).key)
	}
}

// len returns the current number of cached entries (tests/diagnostics).
func (c *geoCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// copyGeo returns a copy whose Sources map can be mutated independently.
func copyGeo(geo model.Geo) model.Geo {
	if geo.Sources != nil {
		sources := make(map[string]model.FieldSource, len(geo.Sources))
		for field, source := range geo.Sources {
			sources[field] = source
		}
		geo.Sources = sources
	}
	return geo
}

// flightGroup coalesces concurrent lookups of the same IP (singleflight). It is
// a small local implementation instead of an extra dependency.
type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	done chan struct{}
	geo  model.Geo
	err  error
}

func newFlightGroup() *flightGroup {
	return &flightGroup{calls: make(map[string]*flightCall)}
}

// do runs fn once per key; concurrent callers wait for the first result. A
// waiting caller may give up when its context is cancelled, while the in-flight
// lookup still completes and populates the cache.
func (g *flightGroup) do(ctx context.Context, key string, fn func() (model.Geo, error)) (model.Geo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		g.mu.Lock()
		if call, ok := g.calls[key]; ok {
			g.mu.Unlock()
			select {
			case <-call.done:
				return copyGeo(call.geo), call.err
			case <-ctx.Done():
				return model.Geo{}, ctx.Err()
			}
		}
		call := &flightCall{done: make(chan struct{})}
		g.calls[key] = call
		g.mu.Unlock()

		geo, err := safeResolve(fn)

		g.mu.Lock()
		call.geo = geo
		call.err = err
		delete(g.calls, key)
		g.mu.Unlock()
		close(call.done)
		return copyGeo(geo), err
	}
}

// safeResolve runs fn and converts a panic into an error: lookups are triggered
// from background node registration paths that must never crash the process.
func safeResolve(fn func() (model.Geo, error)) (geo model.Geo, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			geo = model.Geo{}
			err = fmt.Errorf("geo: internal panic during lookup: %v", recovered)
		}
	}()
	return fn()
}

// tokenBucket is a small context aware token bucket used to rate limit online
// provider calls (Config.RatePerMin). A nil bucket means "unlimited".
type tokenBucket struct {
	mu         sync.Mutex
	ratePerSec float64
	capacity   float64
	tokens     float64
	last       time.Time
}

func newTokenBucket(ratePerMin int) *tokenBucket {
	if ratePerMin <= 0 {
		return nil
	}
	rate := float64(ratePerMin) / 60.0
	capacity := math.Min(float64(ratePerMin), maxRateBurst)
	if capacity < 1 {
		capacity = 1
	}
	return &tokenBucket{
		ratePerSec: rate,
		capacity:   capacity,
		tokens:     capacity,
		last:       time.Now(),
	}
}

// wait blocks until one token is available or ctx is cancelled.
func (b *tokenBucket) wait(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.ratePerSec)
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		missing := 1 - b.tokens
		wait := time.Duration(missing / b.ratePerSec * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		b.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// acquireProviderSlot blocks until a provider concurrency slot is free
// (Config.MaxConcurrent) or ctx is cancelled.
func (r *Resolver) acquireProviderSlot(ctx context.Context) error {
	if r == nil || r.slots == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case r.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseProviderSlot returns a concurrency slot previously acquired.
func (r *Resolver) releaseProviderSlot() {
	if r == nil || r.slots == nil {
		return
	}
	select {
	case <-r.slots:
	default:
	}
}

// errResolverClosed is returned when a lookup races with Close.
var errResolverClosed = errors.New("geo: resolver is closed")
