// Package sched implements node selection for the proxy gateway: the four
// routing strategies, session stickiness with a highest-priority target/node
// blacklist, per-node circuit breakers and byte-rate token buckets.
//
// The package is deliberately free of network and storage dependencies. The
// registry hands in candidate nodes, the caller reports stream results and
// latency samples, and every configurable value is read from the hot-reloadable
// model.Settings through a callback so panel changes take effect immediately.
//
// Locking rules: each component owns its own mutex. Select acquires and
// releases component locks one at a time and never invokes the OnAudit callback
// while holding a lock (audit events are collected and emitted after all state
// updates are done).
package sched

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/model"
)

// ErrNoCandidates is returned when every candidate node was filtered out
// (disabled, offline or circuit-open). The proxy layer maps it to HTTP 503 /
// SOCKS5 host-unreachable; it must never silently fall back to a wider node set.
var ErrNoCandidates = errors.New("sched: no candidates")

// Decision.Reason values. Upper layers may show them in logs and the panel.
const (
	ReasonStrategy         = "strategy"          // routed by the configured strategy
	ReasonStrategyFallback = "strategy_fallback" // configured strategy invalid, fell back to random
	ReasonStickyHit        = "sticky_hit"        // reused the bound node
	ReasonStickyBound      = "sticky_bound"      // first request, binding created
	ReasonStickyMigrated   = "sticky_migrated"   // bound node unusable, session migrated
	ReasonStickyKeyCap     = "sticky_key_cap"    // binding skipped: per-node key cap reached
	ReasonStickyBlacklist  = "sticky_blacklist"  // request excluded from stickiness by a rule
)

// Audit event names passed to Options.OnAudit. The scheduler never writes logs
// by itself; every event is delivered through that callback.
const (
	EventStickyMigrated    = "sticky.migrated"
	EventStickyBlacklisted = "sticky.blacklisted"
)

// defaultStickyTTL is used when the hot-reloaded settings carry a non-positive
// TTL (validation rejects that, but a mid-write snapshot must not disable
// stickiness accidentally).
const defaultStickyTTL = 10 * time.Minute

// latencyAlpha is the EWMA smoothing factor for OnLatency samples.
const latencyAlpha = 0.3

// Request is one scheduling request after the entry point parsed and
// authenticated it.
type Request struct {
	CredentialID string
	Username     string
	SourceIP     string
	Protocol     string
	Target       model.RequestTarget
	StickyKey    string // optional override; empty = credential ID + source IP
}

// Decision describes why a node was selected. The scheduler does not mutate the
// node or the registry; the caller updates inflight counters and the audit log.
type Decision struct {
	NodeID         string
	Strategy       string // effective strategy after fallback
	StickyHit      bool   // the sticky binding was reused
	StickyMigrated bool   // the old binding was unusable and replaced (audit this)
	Blacklisted    bool   // a sticky blacklist rule matched; still scheduled normally
	BlacklistRule  string // ID of the first matching sticky rule
	Filtered       int    // candidates dropped by breaker/disabled/offline filtering
	Reason         string // one of the Reason* constants
}

// Options configures a Selector. All fields are optional.
type Options struct {
	// Settings returns the current hot-reloadable settings. nil means
	// model.DefaultSettings().
	Settings func() model.Settings
	// Now is the time source; nil means time.Now. Tests inject a fake clock.
	Now func() time.Time
	// Random is the random source used by random/weighted tie breaking; nil
	// means the process wide math/rand source. The Selector serializes access,
	// so callers must not share the injected *rand.Rand with other goroutines.
	Random *rand.Rand
	// OnAudit receives sticky migration and blacklist hit events. It is called
	// without any scheduler lock held and must be safe for concurrent use.
	OnAudit func(event string, detail map[string]string)
}

// Selector picks a node for each proxy request. It is safe for concurrent use.
type Selector struct {
	settings func() model.Settings
	now      func() time.Time
	onAudit  func(string, map[string]string)

	rngMu sync.Mutex
	rng   *rand.Rand

	sticky   *stickyStore
	breakers *breakerRegistry
	rules    atomic.Pointer[ruleSet]

	weightedMu sync.Mutex
	weighted   map[string]int // smooth weighted round-robin current weights

	latencyMu sync.Mutex
	latency   map[string]float64 // node ID -> latency EWMA in milliseconds
}

// NewSelector builds a Selector with the supplied options.
func NewSelector(opts Options) *Selector {
	settings := opts.Settings
	if settings == nil {
		settings = model.DefaultSettings
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := &Selector{
		settings: settings,
		now:      now,
		onAudit:  opts.OnAudit,
		rng:      opts.Random,
		sticky:   newStickyStore(),
		breakers: newBreakerRegistry(),
		weighted: make(map[string]int),
		latency:  make(map[string]float64),
	}
	s.rules.Store(&ruleSet{})
	return s
}

// Select picks the best candidate for req.
//
// Candidates are expected to be pre-filtered by credential/group authorization
// (fail-closed happens in the caller). Select additionally drops nodes that are
// disabled, offline or circuit-open, then applies the sticky blacklist, session
// stickiness and the configured routing strategy in that order.
func (s *Selector) Select(req Request, candidates []*model.Node) (*model.Node, Decision, error) {
	cfg := s.settings()
	now := s.now()
	d := Decision{}

	usable, filtered := s.filterCandidates(candidates, cfg.Scheduler.Breaker, now)
	d.Filtered = filtered
	if len(usable) == 0 {
		return nil, d, noCandidatesError(len(candidates), filtered)
	}

	d.Strategy = requestedStrategy(cfg.Scheduler.Strategy)
	switch d.Strategy {
	case model.StrategyRandom, model.StrategyLeastInflight, model.StrategyFastest, model.StrategyWeighted:
	default:
		// Settings are validated on write; this is a defensive fallback for a
		// torn/partial snapshot. Degrade to random instead of failing requests.
		d.Strategy = model.StrategyRandom
		d.Reason = ReasonStrategyFallback
	}

	audits := make([]auditEntry, 0, 2)
	stickyCfg := cfg.Scheduler.Sticky
	if !stickyCfg.Enabled {
		node, ok := s.pickNode(usable, d.Strategy, cfg.Scheduler.Breaker, now, &d)
		if !ok {
			return nil, d, noCandidatesError(len(candidates), d.Filtered)
		}
		d.NodeID = node.ID
		if d.Reason == "" {
			d.Reason = ReasonStrategy
		}
		return node, d, nil
	}

	key := stickyKey(req)
	rules := s.currentRules()

	// 1. Sticky blacklist beats every binding: a matching request is never
	// pinned, but it still takes part in normal scheduling. Source IP, target
	// and node are independent dimensions; the first matching dimension wins.
	if ruleID, dimension, hit := rules.matchRequest(req.SourceIP, req.Target); hit {
		d.Blacklisted = true
		d.BlacklistRule = ruleID
		d.Reason = ReasonStickyBlacklist
		s.sticky.remove(key)
		audits = append(audits, blacklistAudit(ruleID, dimension, key, "", req))
	}

	if !d.Blacklisted {
		if binding, ok := s.sticky.lookup(key, now); ok {
			node := findNodeByID(usable, binding.nodeID)
			if node != nil {
				// 2a. The bound node may itself be excluded from stickiness.
				if ruleID, hit := rules.matchNode(node, nil); hit {
					d.Blacklisted = true
					d.BlacklistRule = ruleID
					d.Reason = ReasonStickyBlacklist
					s.sticky.remove(key)
					audits = append(audits, blacklistAudit(ruleID, "node", key, node.ID, req))
					selected, ok := s.pickNode(usable, d.Strategy, cfg.Scheduler.Breaker, now, &d)
					if !ok {
						return nil, d, noCandidatesError(len(candidates), d.Filtered)
					}
					d.NodeID = selected.ID
					s.emitAudits(audits)
					return selected, d, nil
				}
				// 2b. Binding still valid: extend the sliding TTL and use it.
				if s.breakers.acquire(binding.nodeID, cfg.Scheduler.Breaker, now) {
					s.sticky.renew(key, now, stickyTTL(stickyCfg))
					d.NodeID = binding.nodeID
					d.StickyHit = true
					d.Reason = ReasonStickyHit
					s.emitAudits(audits)
					return node, d, nil
				}
				// 2c. We lost the half-open probe race for this node: it must not
				// receive a second probe, so treat it as unusable and migrate.
				usable = removeNodeByID(usable, binding.nodeID)
				d.Filtered++
				if len(usable) == 0 {
					return nil, d, noCandidatesError(len(candidates), d.Filtered)
				}
			}
			// 2d. Binding node is offline/disabled/circuit-open or not a
			// candidate: clear the stale binding and migrate the session.
			from := binding.nodeID
			s.sticky.remove(key)
			selected, ok := s.pickNode(usable, d.Strategy, cfg.Scheduler.Breaker, now, &d)
			if !ok {
				return nil, d, noCandidatesError(len(candidates), d.Filtered)
			}
			d.NodeID = selected.ID
			d.StickyMigrated = true
			d.Reason = ReasonStickyMigrated
			// The freshly selected node may itself be excluded from stickiness
			// by its node dimension: migrate for this request but never pin it.
			if ruleID, hit := rules.matchNode(selected, nil); hit {
				d.Blacklisted = true
				d.BlacklistRule = ruleID
				d.Reason = ReasonStickyBlacklist
				audits = append(audits, blacklistAudit(ruleID, "node", key, selected.ID, req))
			} else if !s.sticky.bind(key, selected.ID, now, stickyTTL(stickyCfg), stickyCfg.MaxKeysPerNode) {
				d.Reason = ReasonStickyKeyCap
			}
			var target string
			if req.Target.Host != "" {
				target = req.Target.String()
			}
			audits = append(audits, auditEntry{event: EventStickyMigrated, detail: map[string]string{
				"key":    key,
				"from":   from,
				"to":     selected.ID,
				"target": target,
			}})
			s.emitAudits(audits)
			return selected, d, nil
		}
	}

	// 3. No binding (first request, expired TTL, or a blacklisted request):
	// route normally and pin the result when stickiness allows it.
	selected, ok := s.pickNode(usable, d.Strategy, cfg.Scheduler.Breaker, now, &d)
	if !ok {
		return nil, d, noCandidatesError(len(candidates), d.Filtered)
	}
	d.NodeID = selected.ID
	if d.Blacklisted {
		s.emitAudits(audits)
		return selected, d, nil
	}
	if ruleID, hit := rules.matchNode(selected, nil); hit {
		d.Blacklisted = true
		d.BlacklistRule = ruleID
		d.Reason = ReasonStickyBlacklist
		audits = append(audits, blacklistAudit(ruleID, "node", key, selected.ID, req))
		s.emitAudits(audits)
		return selected, d, nil
	}
	if s.sticky.bind(key, selected.ID, now, stickyTTL(stickyCfg), stickyCfg.MaxKeysPerNode) {
		if d.Reason == "" {
			d.Reason = ReasonStickyBound
		}
	} else {
		d.Reason = ReasonStickyKeyCap
	}
	s.emitAudits(audits)
	return selected, d, nil
}

// filterCandidates drops candidate nodes that cannot take traffic right now and
// reports how many were dropped. Ordering of the input is preserved.
func (s *Selector) filterCandidates(candidates []*model.Node, breakerCfg model.BreakerSettings, now time.Time) ([]*model.Node, int) {
	usable := make([]*model.Node, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	filtered := 0
	for _, node := range candidates {
		if node == nil {
			filtered++
			continue
		}
		if _, dup := seen[node.ID]; dup {
			// Duplicate pointers/IDs are not a scheduling decision; ignore them
			// without charging them to the Filtered counter.
			continue
		}
		seen[node.ID] = struct{}{}
		if !node.Enabled || !node.Online {
			filtered++
			continue
		}
		if !s.breakers.peek(node.ID, breakerCfg, now) {
			filtered++
			continue
		}
		usable = append(usable, node)
	}
	return usable, filtered
}

// pickNode applies the strategy and then acquires the breaker admission token
// for the chosen node. Losing a half-open probe race removes the node from the
// working set and retries with the remaining candidates.
func (s *Selector) pickNode(usable []*model.Node, strategy string, breakerCfg model.BreakerSettings, now time.Time, d *Decision) (*model.Node, bool) {
	remaining := make([]*model.Node, len(usable))
	copy(remaining, usable)
	for len(remaining) > 0 {
		idx := s.chooseIndex(remaining, strategy)
		node := remaining[idx]
		if s.breakers.acquire(node.ID, breakerCfg, now) {
			return node, true
		}
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		d.Filtered++
	}
	return nil, false
}

// noCandidatesError wraps ErrNoCandidates with enough detail for the decision
// log required by the specification.
func noCandidatesError(total, filtered int) error {
	return fmt.Errorf("%w: %d candidates, all filtered (disabled/offline/circuit-open=%d)", ErrNoCandidates, total, filtered)
}

// requestedStrategy normalizes the configured strategy name.
func requestedStrategy(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// stickyKey derives the affinity key for a request. The credential ID separates
// users behind the same NAT; unauthenticated traffic falls back to its source
// IP, and requests without either share the "anon:" bucket.
func stickyKey(req Request) string {
	if k := strings.TrimSpace(req.StickyKey); k != "" {
		return "key:" + k
	}
	if req.CredentialID != "" {
		return "cred:" + req.CredentialID + "|ip:" + req.SourceIP
	}
	return "anon:" + req.SourceIP
}

// stickyTTL returns the effective sticky TTL from settings.
func stickyTTL(cfg model.StickySettings) time.Duration {
	if cfg.TTL <= 0 {
		return defaultStickyTTL
	}
	return cfg.TTL.Std()
}

// findNodeByID returns the node with the given ID from the usable set or nil.
func findNodeByID(nodes []*model.Node, id string) *model.Node {
	for _, n := range nodes {
		if n != nil && n.ID == id {
			return n
		}
	}
	return nil
}

// removeNodeByID returns nodes without the given ID. The input slice is not
// modified.
func removeNodeByID(nodes []*model.Node, id string) []*model.Node {
	out := make([]*model.Node, 0, len(nodes))
	for _, n := range nodes {
		if n != nil && n.ID == id {
			continue
		}
		out = append(out, n)
	}
	return out
}

// OnStreamResult feeds the circuit breaker with the outcome of a stream that was
// attributed to nodeID. err must be nil on success and non-nil only for
// node-side failures (dial failure, stream error, write timeout). Target-side
// 4xx/5xx responses and ACL denials must not be reported here.
//
// Every stream attempt admitted by Select must eventually report exactly once,
// including the single half-open probe: the probe slot is released by this call,
// so a missing report keeps the node's breaker in half_open.
func (s *Selector) OnStreamResult(nodeID string, err error) {
	if nodeID == "" {
		return
	}
	cfg := s.settings()
	s.breakers.record(nodeID, err == nil, cfg.Scheduler.Breaker, s.now())
}

// OnLatency records a latency sample for nodeID. The scheduler keeps its own
// EWMA which is used by the fastest strategy when the registry snapshot has no
// latency value yet.
func (s *Selector) OnLatency(nodeID string, latency time.Duration) {
	if nodeID == "" || latency < 0 {
		return
	}
	ms := float64(latency) / float64(time.Millisecond)
	s.latencyMu.Lock()
	if old, ok := s.latency[nodeID]; ok && old > 0 {
		s.latency[nodeID] = latencyAlpha*ms + (1-latencyAlpha)*old
	} else {
		s.latency[nodeID] = ms
	}
	s.latencyMu.Unlock()
}

// effectiveLatency returns the latency used by the fastest strategy: the
// registry snapshot wins, the locally recorded EWMA is the fallback. Values <= 0
// mean "never sampled".
func (s *Selector) effectiveLatency(node *model.Node) float64 {
	if node.LatencyEWMA > 0 {
		return node.LatencyEWMA
	}
	s.latencyMu.Lock()
	defer s.latencyMu.Unlock()
	return s.latency[node.ID]
}

// SetStickyRules compiles and installs the sticky blacklist. On validation
// failure the previously installed rules are kept and an error is returned.
func (s *Selector) SetStickyRules(rules []model.StickyRule) error {
	set, err := compileStickyRules(rules)
	if err != nil {
		return err
	}
	s.rules.Store(set)
	return nil
}

// currentRules returns the currently installed sticky rule set (never nil).
func (s *Selector) currentRules() *ruleSet {
	if set := s.rules.Load(); set != nil {
		return set
	}
	return &ruleSet{}
}

// StickyExplain evaluates the installed blacklist for a panel "trial run"
// without touching bindings. node may be nil; nodeGroups may carry additional
// group IDs (for example the groups a credential is authorized for).
func (s *Selector) StickyExplain(target model.RequestTarget, node *model.Node, nodeGroups []string) (ruleID string, hit bool) {
	return s.StickyExplainSource("", target, node, nodeGroups)
}

// StickyExplainSource evaluates the blacklist with a request source IP. It is
// used by the panel preview for source-IP rules.
func (s *Selector) StickyExplainSource(sourceIP string, target model.RequestTarget, node *model.Node, nodeGroups []string) (ruleID string, hit bool) {
	ruleID, _, hit = s.currentRules().explain(sourceIP, target, node, nodeGroups)
	return ruleID, hit
}

// BreakerState returns the current circuit breaker state of a node
// (closed/open/half_open) for the panel. Unknown nodes are closed.
func (s *Selector) BreakerState(nodeID string) string {
	cfg := s.settings()
	return s.breakers.state(nodeID, cfg.Scheduler.Breaker, s.now())
}

// StickyStats reports the number of live bindings and their distribution over
// nodes.
func (s *Selector) StickyStats() StickyStats {
	return s.sticky.stats(s.now())
}

// PurgeSticky drops every sticky binding (panel maintenance / tests).
func (s *Selector) PurgeSticky() {
	s.sticky.purge()
}

// InvalidateNode drops every binding that points at nodeID, for example when
// the node goes offline. The next request on those keys migrates on demand.
func (s *Selector) InvalidateNode(nodeID string) {
	if nodeID == "" {
		return
	}
	s.sticky.invalidateNode(nodeID)
}

// --- audit plumbing -------------------------------------------------------

type auditEntry struct {
	event  string
	detail map[string]string
}

// blacklistAudit builds the sticky.blacklisted event.
func blacklistAudit(ruleID, dimension, key, nodeID string, req Request) auditEntry {
	detail := map[string]string{
		"rule_id":   ruleID,
		"dimension": dimension,
		"key":       key,
	}
	if nodeID != "" {
		detail["node_id"] = nodeID
	}
	if req.Target.Host != "" {
		detail["target"] = req.Target.String()
	}
	if req.SourceIP != "" {
		detail["source_ip"] = req.SourceIP
	}
	return auditEntry{event: EventStickyBlacklisted, detail: detail}
}

// emitAudits delivers collected events after all scheduler locks are released.
// A panicking callback must never take the proxy request path down.
func (s *Selector) emitAudits(entries []auditEntry) {
	if s.onAudit == nil || len(entries) == 0 {
		return
	}
	for _, e := range entries {
		s.callAudit(e)
	}
}

func (s *Selector) callAudit(e auditEntry) {
	defer func() { _ = recover() }()
	detail := make(map[string]string, len(e.detail))
	for k, v := range e.detail {
		detail[k] = v
	}
	s.onAudit(e.event, detail)
}
