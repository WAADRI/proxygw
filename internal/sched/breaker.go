package sched

import (
	"sync"
	"time"

	"proxygw/internal/model"
)

// defaultBreakerOpenTimeout mirrors the specification default when a torn
// settings snapshot carries a non-positive open timeout.
const defaultBreakerOpenTimeout = 30 * time.Second

// breakerNode is the per-node circuit breaker state
// (see tunnel-state-machine.md chapter 5).
type breakerNode struct {
	state         string // closed | open | half_open
	consecutive   int    // consecutive node-side failures while closed
	samples       int    // observations in the current closed window
	failures      int    // failures in the current closed window
	openedAt      time.Time
	probeInFlight bool // half_open: one probe admitted, result pending
}

func newBreakerNode() *breakerNode {
	return &breakerNode{state: model.BreakerClosed}
}

func (b *breakerNode) resetLocked() {
	b.consecutive = 0
	b.samples = 0
	b.failures = 0
}

// breakerRegistry owns all per-node breaker states. It has its own mutex; no
// scheduler lock is ever held while taking it.
type breakerRegistry struct {
	mu    sync.Mutex
	nodes map[string]*breakerNode
}

func newBreakerRegistry() *breakerRegistry {
	return &breakerRegistry{nodes: make(map[string]*breakerNode)}
}

func (br *breakerRegistry) getLocked(nodeID string) *breakerNode {
	b, ok := br.nodes[nodeID]
	if !ok {
		b = newBreakerNode()
		br.nodes[nodeID] = b
	}
	return b
}

// breakerOpenTimeout returns the effective cool-down duration.
func breakerOpenTimeout(cfg model.BreakerSettings) time.Duration {
	if cfg.OpenTimeout <= 0 {
		return defaultBreakerOpenTimeout
	}
	return cfg.OpenTimeout.Std()
}

// advanceLocked moves an open breaker to half_open once the cool-down elapsed.
// The half-open state starts with no probe in flight, so exactly one request can
// win the probe slot.
func (br *breakerRegistry) advanceLocked(b *breakerNode, now time.Time, cfg model.BreakerSettings) {
	if b.state == model.BreakerOpen && !now.Before(b.openedAt.Add(breakerOpenTimeout(cfg))) {
		b.state = model.BreakerHalfOpen
		b.probeInFlight = false
	}
}

// peek reports whether the node is currently admissible without consuming a
// half-open probe slot. It is used by the candidate filter.
func (br *breakerRegistry) peek(nodeID string, cfg model.BreakerSettings, now time.Time) bool {
	if nodeID == "" {
		return true
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	b := br.getLocked(nodeID)
	br.advanceLocked(b, now, cfg)
	return b.state != model.BreakerOpen
}

// acquire admits one request through the breaker. Closed nodes always pass; a
// half-open node passes exactly once until its probe result is recorded; open
// nodes are rejected. The half-open "one probe in flight" invariant is enforced
// with a compare-and-set under the registry mutex.
func (br *breakerRegistry) acquire(nodeID string, cfg model.BreakerSettings, now time.Time) bool {
	if nodeID == "" {
		return true
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	b := br.getLocked(nodeID)
	br.advanceLocked(b, now, cfg)
	switch b.state {
	case model.BreakerOpen:
		return false
	case model.BreakerHalfOpen:
		if b.probeInFlight {
			return false
		}
		b.probeInFlight = true
		return true
	default: // closed
		return true
	}
}

// state returns the current breaker state (after applying the cool-down
// transition) for the panel.
func (br *breakerRegistry) state(nodeID string, cfg model.BreakerSettings, now time.Time) string {
	if nodeID == "" {
		return model.BreakerClosed
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	b := br.getLocked(nodeID)
	br.advanceLocked(b, now, cfg)
	return b.state
}

// record feeds one stream outcome into the breaker.
//
// Only node-side failures are reported here (dial failure, stream error, write
// timeout); target responses and ACL denials are filtered by the caller.
// Results received while the breaker is open come from streams admitted before
// it opened: they carry no probe information and are ignored so they cannot
// extend the cool-down.
func (br *breakerRegistry) record(nodeID string, success bool, cfg model.BreakerSettings, now time.Time) {
	if nodeID == "" {
		return
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	b := br.getLocked(nodeID)
	switch b.state {
	case model.BreakerClosed:
		b.samples++
		if success {
			b.consecutive = 0
		} else {
			b.consecutive++
			b.failures++
		}
		if breakerShouldOpen(b, cfg) {
			b.state = model.BreakerOpen
			b.openedAt = now
			b.probeInFlight = false
			b.resetLocked()
		}
	case model.BreakerHalfOpen:
		// The admitted probe reported back.
		b.probeInFlight = false
		if success {
			b.state = model.BreakerClosed
		} else {
			// Re-open and wait one full OpenTimeout again: no exponential
			// backoff, which keeps recovery time bounded during a regional
			// outage.
			b.state = model.BreakerOpen
			b.openedAt = now
		}
		b.resetLocked()
	case model.BreakerOpen:
		// Stale result from before the breaker opened; ignore.
	}
}

// breakerShouldOpen applies the consecutive-failure and failure-rate rules
// using the settings of the moment, so panel changes take effect immediately.
func breakerShouldOpen(b *breakerNode, cfg model.BreakerSettings) bool {
	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = 5
	}
	if b.consecutive >= threshold {
		return true
	}
	minSamples := cfg.MinSamples
	if minSamples <= 0 {
		minSamples = 20
	}
	if b.samples < minSamples {
		return false
	}
	rate := cfg.FailureRate
	if rate <= 0 || rate > 1 {
		rate = 0.5
	}
	return float64(b.failures)/float64(b.samples) > rate
}
