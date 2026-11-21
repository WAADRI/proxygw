package sched

import (
	"sync"
	"time"
)

// StickyStats is the panel view of the affinity table.
type StickyStats struct {
	Keys   int            // number of live bindings
	ByNode map[string]int // live bindings per node ID
}

// stickyBinding is one key -> node mapping with a sliding expiry.
type stickyBinding struct {
	nodeID  string
	expires time.Time
}

// stickyStore is the key -> node affinity table. It has its own mutex so that
// Select never needs to serialize unrelated components.
type stickyStore struct {
	mu        sync.Mutex
	bindings  map[string]stickyBinding
	perNode   map[string]int
	lastSweep time.Time
}

func newStickyStore() *stickyStore {
	return &stickyStore{
		bindings: make(map[string]stickyBinding),
		perNode:  make(map[string]int),
	}
}

// lookup returns the live binding for key, dropping it when expired.
func (st *stickyStore) lookup(key string, now time.Time) (stickyBinding, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	b, ok := st.bindings[key]
	if !ok {
		return stickyBinding{}, false
	}
	if !b.expires.After(now) {
		st.removeLocked(key)
		return stickyBinding{}, false
	}
	return b, true
}

// renew extends the sliding TTL of an existing binding.
func (st *stickyStore) renew(key string, now time.Time, ttl time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if b, ok := st.bindings[key]; ok {
		st.bindings[key] = stickyBinding{nodeID: b.nodeID, expires: now.Add(ttl)}
	}
}

// bind creates or replaces the binding for key. It returns false when the node
// already holds maxKeysPerNode live bindings (0 = unlimited); the request keeps
// its normal scheduling decision either way.
func (st *stickyStore) bind(key, nodeID string, now time.Time, ttl time.Duration, maxKeysPerNode int) bool {
	if key == "" || nodeID == "" {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.lastSweep.IsZero() || now.Sub(st.lastSweep) >= sweepInterval(ttl) {
		st.sweepLocked(now)
	}
	if old, ok := st.bindings[key]; ok && old.nodeID == nodeID {
		// Refreshing an existing binding does not consume a new slot.
		st.bindings[key] = stickyBinding{nodeID: nodeID, expires: now.Add(ttl)}
		return true
	}
	if maxKeysPerNode > 0 && st.perNode[nodeID] >= maxKeysPerNode {
		return false
	}
	if old, ok := st.bindings[key]; ok {
		st.decLocked(old.nodeID)
	}
	st.bindings[key] = stickyBinding{nodeID: nodeID, expires: now.Add(ttl)}
	st.perNode[nodeID]++
	return true
}

// remove deletes the binding for key and reports whether one existed.
func (st *stickyStore) remove(key string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.removeLocked(key)
}

func (st *stickyStore) removeLocked(key string) bool {
	b, ok := st.bindings[key]
	if !ok {
		return false
	}
	delete(st.bindings, key)
	st.decLocked(b.nodeID)
	return true
}

func (st *stickyStore) decLocked(nodeID string) {
	if n := st.perNode[nodeID]; n > 1 {
		st.perNode[nodeID] = n - 1
	} else {
		delete(st.perNode, nodeID)
	}
}

// sweepLocked drops every expired binding. It is called periodically from bind
// so that idle keys do not keep per-node counters elevated.
func (st *stickyStore) sweepLocked(now time.Time) {
	st.lastSweep = now
	for key, b := range st.bindings {
		if !b.expires.After(now) {
			delete(st.bindings, key)
			st.decLocked(b.nodeID)
		}
	}
}

// sweepInterval derives how often expired entries are reaped, bounded so that a
// very long TTL does not iterate a huge table on every bind.
func sweepInterval(ttl time.Duration) time.Duration {
	iv := ttl / 2
	if iv < 100*time.Millisecond {
		iv = 100 * time.Millisecond
	}
	if iv > time.Minute {
		iv = time.Minute
	}
	return iv
}

// purge drops every binding (panel maintenance / tests).
func (st *stickyStore) purge() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.bindings = make(map[string]stickyBinding)
	st.perNode = make(map[string]int)
	st.lastSweep = time.Time{}
}

// invalidateNode drops every binding that points at nodeID.
func (st *stickyStore) invalidateNode(nodeID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for key, b := range st.bindings {
		if b.nodeID == nodeID {
			delete(st.bindings, key)
			st.decLocked(nodeID)
		}
	}
}

// stats reports live bindings after reaping expired ones.
func (st *stickyStore) stats(now time.Time) StickyStats {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.lastSweep.IsZero() || now.Sub(st.lastSweep) >= time.Second {
		st.sweepLocked(now)
	}
	byNode := make(map[string]int, len(st.perNode))
	for id, n := range st.perNode {
		if n > 0 {
			byNode[id] = n
		}
	}
	return StickyStats{Keys: len(st.bindings), ByNode: byNode}
}
