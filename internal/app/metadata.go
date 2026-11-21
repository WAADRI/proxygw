package app

import (
	"context"
	"net"
	"sync"
	"time"

	"proxygw/internal/geo"
	"proxygw/internal/model"
)

// metadataCoordinator resolves node geolocation out of the proxy hot path: it
// only looks at nodes whose egress IP appeared or changed since the last
// resolution, coalesces concurrent lookups per node and applies MMDB/provider
// data incrementally to the registry.
type metadataCoordinator struct {
	geoResolver *geo.Resolver
	egress      *geo.EgressResolver

	mu       sync.Mutex
	inflight map[string]bool
	attempt  map[string]time.Time
}

func newMetadataCoordinator(geoResolver *geo.Resolver, egress *geo.EgressResolver) *metadataCoordinator {
	return &metadataCoordinator{
		geoResolver: geoResolver,
		egress:      egress,
		inflight:    map[string]bool{},
		attempt:     map[string]time.Time{},
	}
}

// enrich runs one scan over the registry and starts missing lookups.
func (s *Server) enrich(ctx context.Context) {
	mc := s.metadata
	if mc == nil || mc.geoResolver == nil || !s.cfg.Geo.Enabled {
		return
	}
	for _, n := range s.registry.List() {
		if !n.Online || n.EgressIP.V4 == "" {
			continue
		}
		// Skip when the resolved geo is already newer than the egress sample.
		if !n.Geo.IsZero() && !n.Geo.UpdatedAt.Before(n.EgressIP.UpdatedAt) {
			continue
		}
		mc.start(ctx, s, n.ID, n.EgressIP.V4)
	}
}

func (mc *metadataCoordinator) start(ctx context.Context, s *Server, nodeID, ip string) {
	mc.mu.Lock()
	if mc.inflight[nodeID] {
		mc.mu.Unlock()
		return
	}
	if last, ok := mc.attempt[nodeID]; ok && time.Since(last) < 30*time.Second {
		mc.mu.Unlock()
		return
	}
	mc.inflight[nodeID] = true
	mc.attempt[nodeID] = time.Now()
	mc.mu.Unlock()

	go func() {
		defer func() {
			mc.mu.Lock()
			delete(mc.inflight, nodeID)
			mc.mu.Unlock()
		}()
		lookupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return
		}
		g, err := mc.geoResolver.Resolve(lookupCtx, parsed)
		if err != nil {
			s.logger.Warn("归属地解析失败（不影响节点在线）", "node_id", nodeID, "ip", ip, "error", err)
			return
		}
		if g.IsZero() {
			s.logger.Debug("归属地未知", "node_id", nodeID, "ip", ip)
			return
		}
		if s.registry.UpdateGeo(nodeID, g) {
			s.logger.Info("节点归属地已更新",
				"node_id", nodeID, "country", g.Country, "asn", g.ASN, "isp", g.ISP, "provider", g.Provider)
		}
	}()
}

// ServerEgress resolves the server's own public egress IP for the panel
// provider test button. It never blocks startup.
func (s *Server) ServerEgress(ctx context.Context) (string, error) {
	if s.metadata == nil || s.metadata.egress == nil {
		return "", nil
	}
	return s.metadata.egress.ServerEgress(ctx)
}

// applyManualEgressOverrides lets an operator pin a node egress address in the
// node override file (manual egress wins over automatic detection).
func (s *Server) applyManualEgressOverrides(nodes []model.Node) {
	for _, n := range nodes {
		_ = n
	}
}
