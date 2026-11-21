package registry

import (
	"time"

	"proxygw/internal/model"
)

// UpdateGeo stores the resolved geolocation for a node. It is called by the
// server metadata enricher after an MMDB/provider lookup; the lookup itself
// never happens on the proxy request hot path.
func (r *Registry) UpdateGeo(nodeID string, g model.Geo) bool {
	nodeID = trimID(nodeID)
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
	now := time.Now().UTC()
	if g.UpdatedAt.IsZero() {
		g.UpdatedAt = now
	}
	if g.Sources == nil {
		g.Sources = map[string]model.FieldSource{}
	}
	ns.node.Geo = g
	ns.node.UpdatedAt = now
	return true
}

// UpdateEgress stores a node egress address discovered outside of STATS (for
// example from the tunnel peer address or a manual override) and refreshes the
// duplicate-egress markers.
func (r *Registry) UpdateEgress(nodeID string, e model.EgressIP) bool {
	nodeID = trimID(nodeID)
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
	changed := false
	if e.V4 != "" && e.V4 != ns.node.EgressIP.V4 {
		ns.node.EgressIP.V4 = e.V4
		changed = true
	}
	if e.V6 != "" && e.V6 != ns.node.EgressIP.V6 {
		ns.node.EgressIP.V6 = e.V6
		changed = true
	}
	if !changed {
		return false
	}
	ns.node.EgressIP.Source = e.Source
	if !e.UpdatedAt.IsZero() {
		ns.node.EgressIP.UpdatedAt = e.UpdatedAt
	} else {
		ns.node.EgressIP.UpdatedAt = time.Now().UTC()
	}
	ns.node.UpdatedAt = time.Now().UTC()
	r.recomputeLocked()
	return true
}

// NodeEgress returns the current egress snapshot for a node.
func (r *Registry) NodeEgress(nodeID string) (model.EgressIP, bool) {
	nodeID = trimID(nodeID)
	if nodeID == "" {
		return model.EgressIP{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ns := r.nodes[nodeID]
	if ns == nil {
		return model.EgressIP{}, false
	}
	return ns.node.EgressIP, true
}

func trimID(id string) string {
	for len(id) > 0 && (id[0] == ' ' || id[0] == '\t') {
		id = id[1:]
	}
	for len(id) > 0 && (id[len(id)-1] == ' ' || id[len(id)-1] == '\t') {
		id = id[:len(id)-1]
	}
	return id
}
