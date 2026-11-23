// Package registry aggregates transport plane sessions into node records. It is
// the single source of truth for the panel, the scheduler and the tunnel layer:
// online state, per-node statistics, operator overrides, group membership and
// duplicate egress detection all live here.
//
// The registry is safe for concurrent use. Only in-memory bookkeeping happens
// while the lock is held; persistence is delegated to internal/store, which
// performs atomic writes.
package registry

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/store"
)

// Errors returned by the registry.
var (
	// ErrClosed is returned once Close was called.
	ErrClosed = errors.New("registry: closed")
	// ErrEmptyNodeID is returned for operations without a node id.
	ErrEmptyNodeID = errors.New("registry: empty node id")
)

// latencyAlpha is the EWMA smoothing factor for node latency samples.
const latencyAlpha = 0.2

// PlaneMeta is the metadata reported by one transport plane during HELLO.
type PlaneMeta struct {
	NodeID     string
	PlaneIndex int
	Alias      string
	Tags       []string
	Region     string
	ISPLabel   string
	Weight     int
	Version    string
	Transport  string
	EgressV4   string
	EgressV6   string
	// Capabilities and Compression are negotiated during HELLO.
	Capabilities  []string
	Compression   bool
	Runtime       string
	UpdateCapable bool
}

type planeState struct {
	meta       PlaneMeta
	attachedAt time.Time
}

type nodeState struct {
	node   model.Node
	planes map[int]planeState
	epoch  uint32
}

// Registry aggregates node runtime state.
type Registry struct {
	logger  *slog.Logger
	metrics *metrics.Metrics

	storePath string
	store     *store.JSON[[]model.NodeOverride]

	mu             sync.RWMutex
	nodes          map[string]*nodeState
	overrides      map[string]model.NodeOverride
	groupsResolver func(*model.Node) []string
	online         int
	uniqueEgress   int
	closed         bool
}

// New builds an empty registry. overridesPath may be empty to disable operator
// override persistence. metrics may be nil.
func New(logger *slog.Logger, m *metrics.Metrics, overridesPath string) (*Registry, error) {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Registry{
		logger:    logger,
		metrics:   m,
		storePath: overridesPath,
		nodes:     make(map[string]*nodeState),
		overrides: make(map[string]model.NodeOverride),
	}
	if overridesPath != "" {
		r.store = store.New[[]model.NodeOverride](overridesPath)
		list, warnings, err := r.store.Load(nil)
		for _, w := range warnings {
			logger.Warn("node override state recovered", "warning", w)
		}
		if err != nil {
			return nil, fmt.Errorf("registry: load overrides %s: %w", overridesPath, err)
		}
		for _, ov := range list {
			id := strings.TrimSpace(ov.ID)
			if id == "" {
				logger.Warn("node override state: skipping record without id")
				continue
			}
			ov.ID = id
			r.overrides[id] = ov
		}
		logger.Info("node overrides loaded", "count", len(r.overrides), "path", overridesPath)
	}
	if r.metrics != nil {
		r.metrics.NodesOnline.Set(0)
		r.metrics.UniqueEgressIPs.Set(0)
		r.metrics.SetNodeCount(0)
	}
	return r, nil
}

// AttachPlane records that plane planeIndex of node meta.NodeID is connected.
// Every call returns a new monotonic registration epoch for that node starting
// at 1; the tunnel hands it to the transport so late frames from a previous
// session can be dropped.
// maxNodes bounds the node registry. Node ids are self reported, so an
// authenticated node could otherwise create unlimited records (memory and panel
// list growth). 4096 nodes is far above any realistic single instance fleet.
const maxNodes = 4096

func (r *Registry) AttachPlane(meta PlaneMeta) (model.Node, uint32, error) {
	nodeID := strings.TrimSpace(meta.NodeID)
	if nodeID == "" {
		return model.Node{}, 0, ErrEmptyNodeID
	}
	if meta.PlaneIndex < 0 {
		return model.Node{}, 0, fmt.Errorf("registry: node %q plane index must be >= 0, got %d", nodeID, meta.PlaneIndex)
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return model.Node{}, 0, ErrClosed
	}
	ns := r.nodes[nodeID]
	if ns == nil {
		if len(r.nodes) >= maxNodes {
			return model.Node{}, 0, fmt.Errorf("registry: node limit reached (%d), refusing new node %q", maxNodes, nodeID)
		}
		ns = &nodeState{planes: make(map[int]planeState)}
		ns.node = model.Node{
			ID:           nodeID,
			Enabled:      true,
			Weight:       1,
			BreakerState: model.BreakerClosed,
			CreatedAt:    now,
			UpdatedAt:    now,
			FirstSeen:    now,
		}
		r.nodes[nodeID] = ns
	}
	ns.epoch++
	if ns.epoch == 0 { // wrap guard; 0 is reserved for control frames
		ns.epoch = 1
	}
	ns.planes[meta.PlaneIndex] = planeState{meta: meta, attachedAt: now}

	n := &ns.node
	if meta.Alias != "" {
		n.Alias = clampString(meta.Alias, 128)
	}
	if meta.Region != "" {
		n.Region = clampString(meta.Region, 128)
	}
	if meta.ISPLabel != "" {
		n.ISPLabel = clampString(meta.ISPLabel, 128)
	}
	if len(meta.Tags) > 0 {
		tags := make([]string, 0, minInt(len(meta.Tags), 64))
		for _, tag := range meta.Tags {
			if len(tags) >= 64 || tag == "" {
				continue
			}
			tags = append(tags, clampString(tag, 64))
		}
		n.Tags = tags
	}
	if meta.Weight > 0 {
		n.Weight = clampWeight(meta.Weight)
	}
	if meta.Version != "" {
		n.Version = meta.Version
	}
	if meta.Transport != "" {
		n.Transport = meta.Transport
	}
	if meta.EgressV4 != "" || meta.EgressV6 != "" {
		n.EgressIP = model.EgressIP{
			V4:        meta.EgressV4,
			V6:        meta.EgressV6,
			Source:    "peer",
			UpdatedAt: now,
		}
	}
	// Capabilities/compression are negotiated per plane during HELLO; the most
	// recent plane wins and all planes of one node share the same build.
	if len(meta.Capabilities) > 0 {
		n.Capabilities = append([]string(nil), meta.Capabilities...)
	}
	n.Compression = meta.Compression
	n.Runtime = clampString(meta.Runtime, 16)
	n.UpdateCapable = meta.UpdateCapable
	n.Planes = len(ns.planes)
	n.Online = true
	n.LastHeartbeat = now
	n.UpdatedAt = now
	r.applyOverrideLocked(n)
	r.recomputeLocked()
	r.logger.Info("plane attached",
		"node_id", nodeID, "plane_index", meta.PlaneIndex, "epoch", ns.epoch,
		"planes", n.Planes, "transport", meta.Transport)
	return r.snapshotLocked(ns), ns.epoch, nil
}

// DetachPlane removes one plane. The node goes offline when the last plane is
// detached; the node record itself is kept so the panel can show history.
func (r *Registry) DetachPlane(nodeID string, planeIndex int) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	ns := r.nodes[nodeID]
	if ns == nil {
		return
	}
	if _, ok := ns.planes[planeIndex]; !ok {
		return
	}
	delete(ns.planes, planeIndex)
	ns.node.Planes = len(ns.planes)
	ns.node.Online = len(ns.planes) > 0
	ns.node.UpdatedAt = time.Now()
	r.recomputeLocked()
	r.logger.Info("plane detached", "node_id", nodeID, "plane_index", planeIndex,
		"planes", ns.node.Planes, "online", ns.node.Online)
}

// SetNodeOnline overrides the derived online flag. It is used by the tunnel when
// a session is judged dead before its plane is detached.
func (r *Registry) SetNodeOnline(nodeID string, online bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	ns := r.nodes[nodeID]
	if ns == nil {
		return
	}
	ns.node.Online = online
	ns.node.UpdatedAt = time.Now()
	r.recomputeLocked()
}

// UpdateStats applies a STATS report from a node.
func (r *Registry) UpdateStats(nodeID string, st protocol.Stats) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	ns := r.nodes[nodeID]
	if ns == nil {
		return
	}
	n := &ns.node
	n.Inflight = st.Inflight
	if n.Inflight < 0 {
		n.Inflight = 0
	}
	if n.Inflight > maxInflight {
		n.Inflight = maxInflight
	}
	if st.BytesIn <= uint64(maxStatBytes) {
		n.BytesIn = st.BytesIn
	} else {
		n.BytesIn = uint64(maxStatBytes)
	}
	if st.BytesOut <= uint64(maxStatBytes) {
		n.BytesOut = st.BytesOut
	} else {
		n.BytesOut = uint64(maxStatBytes)
	}
	if st.LatencyMS > 0 {
		latency := st.LatencyMS
		if latency > maxStatMS {
			latency = maxStatMS
		}
		if n.LatencyEWMA <= 0 {
			n.LatencyEWMA = latency
		} else {
			n.LatencyEWMA = latencyAlpha*latency + (1-latencyAlpha)*n.LatencyEWMA
		}
	}
	if st.Version != "" {
		n.Version = clampString(st.Version, 64)
	}
	if st.Transport != "" {
		n.Transport = st.Transport
	}
	if st.Runtime != "" {
		n.Runtime = clampString(st.Runtime, 16)
	}
	if st.Update != nil {
		r.applyNodeUpdateLocked(n, st.Update)
	}
	egressChanged := false
	if st.EgressV4 != "" && st.EgressV4 != n.EgressIP.V4 {
		n.EgressIP.V4 = st.EgressV4
		egressChanged = true
	}
	if st.EgressV6 != "" && st.EgressV6 != n.EgressIP.V6 {
		n.EgressIP.V6 = st.EgressV6
		egressChanged = true
	}
	if egressChanged {
		n.EgressIP.Source = "stats"
		n.EgressIP.UpdatedAt = now
	}
	n.LastHeartbeat = now
	n.UpdatedAt = now
	if egressChanged {
		r.recomputeLocked()
	}
}

// UpdateNodeUpdate applies an immediate UPDATE_STATUS frame from a node.
func (r *Registry) UpdateNodeUpdate(nodeID string, st protocol.UpdateStatus) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	ns := r.nodes[nodeID]
	if ns == nil {
		return
	}
	r.applyNodeUpdateLocked(&ns.node, &st)
	ns.node.UpdatedAt = time.Now()
}

func (r *Registry) applyNodeUpdateLocked(n *model.Node, st *protocol.UpdateStatus) {
	if st == nil {
		return
	}
	state := clampString(strings.TrimSpace(st.State), 32)
	if state == "" {
		state = protocol.UpdateIdle
	}
	updatedAt := time.Now()
	if st.UpdatedAt > 0 {
		updatedAt = time.UnixMilli(st.UpdatedAt)
	}
	n.Update = &model.NodeUpdate{
		State:          state,
		CurrentVersion: clampString(st.CurrentVersion, 64),
		TargetVersion:  clampString(st.TargetVersion, 64),
		Progress:       st.Progress,
		Message:        clampString(st.Message, 256),
		Error:          clampString(st.Error, 1024),
		UpdatedAt:      updatedAt,
	}
	if st.Progress < 0 {
		n.Update.Progress = 0
	}
	if st.Progress > 100 {
		n.Update.Progress = 100
	}
}

// ClearNodeUpdate removes a stale node update status. It is used by the panel
// when a node was updated manually or an old helper left a transient state.
func (r *Registry) ClearNodeUpdate(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	ns := r.nodes[nodeID]
	if ns == nil {
		return false
	}
	ns.node.Update = nil
	ns.node.UpdatedAt = time.Now()
	return true
}

// Get returns a snapshot of one node.
func (r *Registry) Get(nodeID string) (model.Node, bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return model.Node{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ns := r.nodes[nodeID]
	if ns == nil {
		return model.Node{}, false
	}
	return r.snapshotLocked(ns), true
}

// List returns every known node sorted by id.
func (r *Registry) List() []model.Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Node, 0, len(r.nodes))
	for _, ns := range r.nodes {
		out = append(out, r.snapshotLocked(ns))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SetEnabled enables or disables a node and persists the operator override.
func (r *Registry) SetEnabled(nodeID string, enabled bool) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ErrEmptyNodeID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	ov, exists := r.overrides[nodeID]
	if !exists {
		if ns := r.nodes[nodeID]; ns != nil {
			n := &ns.node
			ov = model.NodeOverride{
				ID:       nodeID,
				Alias:    n.Alias,
				Region:   n.Region,
				ISPLabel: n.ISPLabel,
				Tags:     append([]string(nil), n.Tags...),
				Weight:   n.Weight,
			}
		} else {
			ov = model.NodeOverride{ID: nodeID}
		}
	}
	ov.Enabled = enabled
	ov.UpdatedAt = time.Now()
	return r.setOverrideLocked(ov)
}

// UpdateNodeOverride stores an operator override. Operator values take priority
// over values reported by the node. The record replaces the previous override
// for the same node.
func (r *Registry) UpdateNodeOverride(ov model.NodeOverride) error {
	ov.ID = strings.TrimSpace(ov.ID)
	if ov.ID == "" {
		return ErrEmptyNodeID
	}
	ov.Tags = append([]string(nil), ov.Tags...)
	ov.UpdatedAt = time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	return r.setOverrideLocked(ov)
}

// setOverrideLocked persists ov, rolls back on failure and applies it.
func (r *Registry) setOverrideLocked(ov model.NodeOverride) error {
	prev, had := r.overrides[ov.ID]
	r.overrides[ov.ID] = ov
	if err := r.saveOverridesLocked(); err != nil {
		if had {
			r.overrides[ov.ID] = prev
		} else {
			delete(r.overrides, ov.ID)
		}
		return err
	}
	if ns := r.nodes[ov.ID]; ns != nil {
		r.applyOverrideLocked(&ns.node)
		ns.node.UpdatedAt = time.Now()
		r.recomputeLocked()
	}
	r.logger.Info("node override updated", "node_id", ov.ID, "enabled", ov.Enabled,
		"weight", ov.Weight, "alias", ov.Alias)
	return nil
}

// SetGroupsResolver installs a callback that computes group membership for node
// snapshots. The callback must be pure and must not call back into the registry.
func (r *Registry) SetGroupsResolver(fn func(*model.Node) []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groupsResolver = fn
}

// OnlineCount returns the number of online nodes.
func (r *Registry) OnlineCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.online
}

// UniqueEgressCount returns the number of distinct public egress endpoints among
// online nodes.
func (r *Registry) UniqueEgressCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.uniqueEgress
}

// Count returns the number of known nodes (online or not).
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nodes)
}

// Epoch returns the latest registration epoch of a node (0 when unknown).
func (r *Registry) Epoch(nodeID string) uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ns := r.nodes[strings.TrimSpace(nodeID)]
	if ns == nil {
		return 0
	}
	return ns.epoch
}

// Close releases the registry. It is idempotent.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *Registry) applyOverrideLocked(n *model.Node) {
	ov, ok := r.overrides[n.ID]
	if !ok {
		return
	}
	n.Alias = clampString(ov.Alias, 128)
	n.Region = clampString(ov.Region, 128)
	n.ISPLabel = clampString(ov.ISPLabel, 128)
	if len(ov.Tags) > 64 {
		ov.Tags = ov.Tags[:64]
	}
	tags := make([]string, 0, len(ov.Tags))
	for _, tag := range ov.Tags {
		if tag == "" {
			continue
		}
		tags = append(tags, clampString(tag, 64))
	}
	n.Tags = tags
	// Weight is a scheduler multiplier; a zero value (for example from a
	// partial override created by SetEnabled for a not-yet-connected node)
	// must not disable weighted routing.
	n.Weight = clampWeight(ov.Weight)
	n.Enabled = ov.Enabled
}

func (r *Registry) snapshotLocked(ns *nodeState) model.Node {
	n := ns.node
	n.Planes = len(ns.planes)
	n.Tags = append([]string(nil), ns.node.Tags...)
	n.Capabilities = append([]string(nil), ns.node.Capabilities...)
	n.Groups = append([]string(nil), ns.node.Groups...)
	if r.groupsResolver != nil {
		n.Groups = r.groupsResolver(&n)
	}
	return n
}

// recomputeLocked recalculates online/unique-egress counters and duplicate
// egress markers. Caller holds r.mu.
func (r *Registry) recomputeLocked() {
	r.online = 0
	online := make([]*nodeState, 0, len(r.nodes))
	for _, ns := range r.nodes {
		ns.node.DuplicateOf = ""
		if ns.node.Online {
			r.online++
			online = append(online, ns)
		}
	}
	sort.Slice(online, func(i, j int) bool {
		a, b := online[i].node, online[j].node
		if !a.FirstSeen.Equal(b.FirstSeen) {
			return a.FirstSeen.Before(b.FirstSeen)
		}
		return a.ID < b.ID
	})
	canonical := make(map[string]string, len(online))
	egress := make(map[string]struct{}, len(online))
	for _, ns := range online {
		key := egressKey(ns.node.EgressIP)
		if key == "" {
			continue
		}
		if first, ok := canonical[key]; ok {
			ns.node.DuplicateOf = first
			continue
		}
		canonical[key] = ns.node.ID
		egress[key] = struct{}{}
	}
	r.uniqueEgress = len(egress)
	if r.metrics != nil {
		r.metrics.NodesOnline.Set(float64(r.online))
		r.metrics.UniqueEgressIPs.Set(float64(r.uniqueEgress))
		r.metrics.SetNodeCount(int64(len(r.nodes)))
	}
}

// egressKey is the identity used for duplicate detection: IPv4 is preferred
// because virtually every deployment probes it, IPv6 is the fallback.
func egressKey(e model.EgressIP) string {
	if v4 := strings.TrimSpace(e.V4); v4 != "" {
		return v4
	}
	return strings.TrimSpace(e.V6)
}

func (r *Registry) saveOverridesLocked() error {
	if r.store == nil {
		return nil
	}
	list := make([]model.NodeOverride, 0, len(r.overrides))
	for _, ov := range r.overrides {
		list = append(list, ov)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	if err := r.store.Save(list); err != nil {
		return fmt.Errorf("registry: persist overrides %s: %w", r.storePath, err)
	}
	return nil
}
