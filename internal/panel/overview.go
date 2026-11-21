package panel

import (
	"context"
	"net/http"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	"proxygw/internal/version"
)

// overviewRequests is the counters block of GET /overview.
type overviewRequests struct {
	Total        int64 `json:"total"`
	Errors       int64 `json:"errors"`
	Retries      int64 `json:"retries"`
	RateLimited  int64 `json:"rate_limited"`
	BreakerTrips int64 `json:"breaker_trips"`
}

// overviewCert is the certificate summary shown on the overview page.
type overviewCert struct {
	Mode     string `json:"mode"`
	Pin      string `json:"pin"`
	PinNext  string `json:"pin_next"`
	NotAfter string `json:"not_after,omitempty"`
}

// overviewResponse is the GET /api/v1/overview payload (also embedded in the SSE
// snapshot/tick events under the "overview" key).
type overviewResponse struct {
	Version           version.Info     `json:"version"`
	OnlineNodes       int64            `json:"online_nodes"`
	NodesTotal        int64            `json:"nodes_total"`
	UniqueEgressIPs   int64            `json:"unique_egress_ips"`
	ActiveConnections int64            `json:"active_connections"`
	TransportMix      map[string]int   `json:"transport_mix"`
	Requests          overviewRequests `json:"requests"`
	Trend             []TrendPoint     `json:"trend"`
	SettingsVersion   int              `json:"settings_version"`
	// ClockSkewMS is the measured panel/server clock difference; the frontend
	// renders it as a warning chip (not part of docs/PANEL_API.md).
	ClockSkewMS int64         `json:"clock_skew_ms"`
	Cert        *overviewCert `json:"cert,omitempty"`
}

// handleOverview serves GET /api/v1/overview.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.buildOverview(r.Context()))
}

// buildOverview aggregates the registry, tunnel, stats and settings state into
// the overview payload. The registry is authoritative for the three key
// indicators (online nodes, unique egress IPs, total nodes); the stats layer
// contributes counters and the trend.
func (s *Server) buildOverview(ctx context.Context) overviewResponse {
	var snap OverviewSnapshot
	if s.opts.Stats != nil {
		snap = s.opts.Stats.Overview(ctx)
	} else {
		snap = s.metricsFallbackOverview()
	}

	// Registry truth always wins for the fleet indicators.
	snap.OnlineNodes = int64(s.opts.Registry.OnlineCount())
	snap.NodesTotal = int64(s.opts.Registry.Count())
	snap.UniqueEgressIPs = int64(s.opts.Registry.UniqueEgressCount())

	if s.opts.Tunnel != nil {
		// The tunnel counter is the realtime source of truth.
		snap.ActiveConnections = s.opts.Tunnel.ActiveStreams()
		if len(snap.TransportMix) == 0 {
			snap.TransportMix = s.transportMixFromSessions(s.opts.Tunnel.Sessions())
		}
	}
	if snap.TransportMix == nil {
		snap.TransportMix = map[string]int{}
	}
	if snap.Trend == nil {
		snap.Trend = []TrendPoint{}
	}

	resp := overviewResponse{
		Version:           s.versionInfo(),
		OnlineNodes:       snap.OnlineNodes,
		NodesTotal:        snap.NodesTotal,
		UniqueEgressIPs:   snap.UniqueEgressIPs,
		ActiveConnections: snap.ActiveConnections,
		TransportMix:      snap.TransportMix,
		Requests: overviewRequests{
			Total:        snap.Requests,
			Errors:       snap.Errors,
			Retries:      snap.Retries,
			RateLimited:  snap.RateLimited,
			BreakerTrips: snap.BreakerTrips,
		},
		Trend:           snap.Trend,
		SettingsVersion: s.opts.Settings.Version(),
		ClockSkewMS:     snap.ClockSkewMS,
	}
	if s.opts.Cert != nil {
		st := s.opts.Cert.Status()
		cert := &overviewCert{Mode: st.Mode, Pin: st.Pin, PinNext: st.PinNext}
		if !st.NotAfter.IsZero() {
			cert.NotAfter = st.NotAfter.UTC().Format(time.RFC3339)
		}
		resp.Cert = cert
	}
	return resp
}

// transportMixFromSessions counts sessions per transport.
func (s *Server) transportMixFromSessions(sessions []SessionInfo) map[string]int {
	mix := make(map[string]int, 2)
	for _, sess := range sessions {
		t := strings.ToLower(strings.TrimSpace(sess.Transport))
		if t == "" || !sessionHasTransport(sess.State) {
			continue
		}
		mix[t]++
	}
	return mix
}

// metricsFallbackOverview derives the request counters from the Prometheus
// collectors when no stats layer is wired. It is best effort: the numbers are
// only used when Options.Stats is nil.
func (s *Server) metricsFallbackOverview() OverviewSnapshot {
	snap := OverviewSnapshot{TransportMix: map[string]int{}, Trend: []TrendPoint{}}
	if s.opts.Metrics == nil || s.opts.Metrics.Registry == nil {
		return snap
	}
	families, err := s.opts.Metrics.Registry.Gather()
	if err != nil {
		s.log.Debug("读取 Prometheus 指标失败，总览计数置零", "error", err)
		return snap
	}
	for _, family := range families {
		switch family.GetName() {
		case "proxy_requests_total":
			for _, metric := range family.GetMetric() {
				value := int64(metric.GetCounter().GetValue())
				snap.Requests += value
				if !metricResultOK(metric) {
					snap.Errors += value
				}
			}
		case "proxy_retries_total":
			snap.Retries += sumCounterFamily(family)
		case "rate_limit_hits_total":
			snap.RateLimited += sumCounterFamily(family)
		case "breaker_trips_total":
			snap.BreakerTrips += sumCounterFamily(family)
		}
	}
	return snap
}

// sumCounterFamily adds up every counter metric of one family.
func sumCounterFamily(family *dto.MetricFamily) int64 {
	var total int64
	for _, metric := range family.GetMetric() {
		total += int64(metric.GetCounter().GetValue())
	}
	return total
}

// metricResultOK reports whether a proxy_requests_total metric carries a
// success result label (missing label is treated as success).
func metricResultOK(metric *dto.Metric) bool {
	for _, label := range metric.GetLabel() {
		if label.GetName() != "result" {
			continue
		}
		switch strings.ToLower(label.GetValue()) {
		case "", "ok", "success", "allowed":
			return true
		default:
			return false
		}
	}
	return true
}
