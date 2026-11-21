package sched

import (
	"math"
	"math/rand"

	"proxygw/internal/model"
)

// chooseIndex applies the routing strategy to the working set and returns the
// index of the node to try next. All strategies guarantee a valid index for a
// non-empty slice.
func (s *Selector) chooseIndex(nodes []*model.Node, strategy string) int {
	if len(nodes) == 0 {
		return -1
	}
	switch strategy {
	case model.StrategyLeastInflight:
		return s.leastInflightIndex(nodes)
	case model.StrategyFastest:
		return s.fastestIndex(nodes)
	case model.StrategyWeighted:
		return s.weightedIndex(nodes)
	default:
		return s.randIntn(len(nodes))
	}
}

// leastInflightIndex picks the node with the smallest live inflight count.
// Ties are broken uniformly at random so equal nodes share load.
func (s *Selector) leastInflightIndex(nodes []*model.Node) int {
	best := nodes[0].Inflight
	ties := []int{0}
	for i := 1; i < len(nodes); i++ {
		switch v := nodes[i].Inflight; {
		case v < best:
			best = v
			ties = ties[:0]
			ties = append(ties, i)
		case v == best:
			ties = append(ties, i)
		}
	}
	if len(ties) == 1 {
		return ties[0]
	}
	return ties[s.randIntn(len(ties))]
}

// fastestIndex picks the node with the smallest latency EWMA.
//
// Nodes that have never been sampled (latency <= 0 in the registry snapshot and
// no local EWMA) are treated as neutral and preferred over sampled nodes: this
// is a bounded exploration step that gives every node one sample instead of
// starving new nodes forever or treating them as infinitely fast. Nodes sampled
// by OnLatency or by the registry join the regular comparison afterwards.
// Ties are broken uniformly at random.
func (s *Selector) fastestIndex(nodes []*model.Node) int {
	lats := make([]float64, len(nodes))
	unknown := make([]int, 0, len(nodes))
	known := make([]int, 0, len(nodes))
	for i, n := range nodes {
		lat := s.effectiveLatency(n)
		lats[i] = lat
		if lat <= 0 || math.IsNaN(lat) || math.IsInf(lat, 0) {
			unknown = append(unknown, i)
		} else {
			known = append(known, i)
		}
	}
	pool := known
	if len(unknown) > 0 {
		pool = unknown
	}
	best := lats[pool[0]]
	ties := []int{pool[0]}
	for _, i := range pool[1:] {
		switch v := lats[i]; {
		case v < best:
			best = v
			ties = ties[:0]
			ties = append(ties, i)
		case v == best:
			ties = append(ties, i)
		}
	}
	if len(ties) == 1 {
		return ties[0]
	}
	return ties[s.randIntn(len(ties))]
}

// weightedIndex implements nginx style smooth weighted round-robin (SWRR).
//
// Per node state is the current weight map. Every call adds the node weight to
// its current weight, picks the largest current weight (first wins ties, like
// nginx, which keeps the sequence deterministic), then subtracts the total
// weight from the winner. Weight <= 0 is treated as 1 so that a zero weight can
// never remove a node from the pool. Entries for nodes that are no longer
// candidates are pruned on every call, which makes dynamic node add/remove safe.
func (s *Selector) weightedIndex(nodes []*model.Node) int {
	s.weightedMu.Lock()
	defer s.weightedMu.Unlock()
	present := make(map[string]struct{}, len(nodes))
	total := 0
	bestIdx := 0
	bestCW := math.MinInt
	var bestID string
	for i, n := range nodes {
		present[n.ID] = struct{}{}
		w := n.Weight
		if w <= 0 {
			w = 1
		}
		cw := s.weighted[n.ID] + w
		s.weighted[n.ID] = cw
		total += w
		if cw > bestCW {
			bestCW = cw
			bestIdx = i
			bestID = n.ID
		}
	}
	// Prune state of nodes that disappeared from the candidate set.
	if len(s.weighted) > len(nodes) {
		for id := range s.weighted {
			if _, ok := present[id]; !ok {
				delete(s.weighted, id)
			}
		}
	}
	s.weighted[bestID] = bestCW - total
	return bestIdx
}

// randIntn returns a uniform value in [0,n) from the (optionally injected)
// random source. It is safe for concurrent use.
func (s *Selector) randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	if s.rng == nil {
		return rand.Intn(n)
	}
	s.rngMu.Lock()
	defer s.rngMu.Unlock()
	return s.rng.Intn(n)
}
