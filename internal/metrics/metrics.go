// Package metrics exposes Prometheus collectors for the proxy gateway. It
// keeps label cardinality under control: node labels are only emitted while the
// fleet is small, otherwise they collapse into buckets; credential labels are
// only emitted for credentials explicitly registered by the panel.
package metrics

import (
	"hash/fnv"
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns every collector of the server.
type Metrics struct {
	Registry *prometheus.Registry

	ProxyRequestsTotal  *prometheus.CounterVec
	ProxyDuration       *prometheus.HistogramVec
	ProxyActiveConns    prometheus.Gauge
	ProxyRetriesTotal   *prometheus.CounterVec
	RateLimitHits       *prometheus.CounterVec
	BreakerTripsTotal   *prometheus.CounterVec
	NodesOnline         prometheus.Gauge
	UniqueEgressIPs     prometheus.Gauge
	NodesTotal          prometheus.Gauge
	TunnelBytesTotal    *prometheus.CounterVec
	TunnelOpenSeconds   *prometheus.HistogramVec
	TunnelOpenErrors    *prometheus.CounterVec
	TunnelStreams       *prometheus.GaugeVec
	TunnelSessionState  *prometheus.GaugeVec
	TunnelWindowStalls  *prometheus.CounterVec
	TunnelReconnects    *prometheus.CounterVec
	SessionTakeovers    *prometheus.CounterVec
	TunnelPlanes        *prometheus.GaugeVec
	GeoLookupsTotal     *prometheus.CounterVec
	GeoLookupDuration   *prometheus.HistogramVec
	DNSPassthroughTotal *prometheus.CounterVec
	WebhookAlertsTotal  *prometheus.CounterVec

	nodeCount atomic.Int64
	// credentialAllow is the set of credential ids explicitly allowed as label
	// values; all other credentials collapse to "other" to bound cardinality.
	credentialAllow atomic.Value // map[string]struct{}
}

// New builds a metrics set with its own registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		ProxyRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_requests_total", Help: "Proxy requests handled, by protocol, node, credential and result.",
		}, []string{"protocol", "node", "credential", "result"}),
		ProxyDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "End-to-end proxy request duration.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 15, 60},
		}, []string{"protocol", "node"}),
		ProxyActiveConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_active_connections", Help: "Currently active proxy connections.",
		}),
		ProxyRetriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_retries_total", Help: "Transparent retries before the response commit point.",
		}, []string{"node"}),
		RateLimitHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rate_limit_hits_total", Help: "Rate limiter backpressure events.",
		}, []string{"scope"}),
		BreakerTripsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "breaker_trips_total", Help: "Circuit breaker open transitions.",
		}, []string{"node"}),
		NodesOnline: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nodes_online", Help: "Nodes with at least one ready session.",
		}),
		UniqueEgressIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "egress_unique_ips", Help: "Unique egress public IPs across online nodes.",
		}),
		NodesTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nodes_total", Help: "Known nodes.",
		}),
		TunnelBytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunnel_bytes_total", Help: "Bytes carried through tunnels, by direction.",
		}, []string{"direction", "node"}),
		TunnelOpenSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tunnel_open_seconds",
			Help:    "OPEN to ACK latency for tunnel streams.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"node", "transport"}),
		TunnelOpenErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunnel_open_errors_total", Help: "Failed stream opens by mapped error code.",
		}, []string{"node", "code"}),
		TunnelStreams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tunnel_streams", Help: "Tunnel streams by state.",
		}, []string{"node", "state"}),
		TunnelSessionState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tunnel_session_state", Help: "Sessions by state (1 for the current state).",
		}, []string{"node", "state"}),
		TunnelWindowStalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunnel_window_stalls_total", Help: "Window stalls that triggered a stream reset.",
		}, []string{"node"}),
		TunnelReconnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunnel_reconnects_total", Help: "Node reconnects by reason.",
		}, []string{"node", "reason"}),
		SessionTakeovers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "session_takeovers_total", Help: "Same client_id session takeovers by result.",
		}, []string{"node", "result"}),
		TunnelPlanes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tunnel_planes", Help: "Ready transport planes per node.",
		}, []string{"node"}),
		GeoLookupsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "geo_lookups_total", Help: "Geolocation lookups by provider and result.",
		}, []string{"provider", "result"}),
		GeoLookupDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "geo_lookup_duration_seconds",
			Help:    "Geolocation provider latency.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5},
		}, []string{"provider"}),
		DNSPassthroughTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_passthrough_total", Help: "DNS queries forwarded by nodes by result.",
		}, []string{"node", "result"}),
		WebhookAlertsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_alerts_total", Help: "Alert webhook deliveries by result.",
		}, []string{"result"}),
	}
	reg.MustRegister(
		m.ProxyRequestsTotal, m.ProxyDuration, m.ProxyActiveConns, m.ProxyRetriesTotal,
		m.RateLimitHits, m.BreakerTripsTotal, m.NodesOnline, m.UniqueEgressIPs, m.NodesTotal,
		m.TunnelBytesTotal, m.TunnelOpenSeconds, m.TunnelOpenErrors, m.TunnelStreams,
		m.TunnelSessionState, m.TunnelWindowStalls, m.TunnelReconnects, m.SessionTakeovers,
		m.TunnelPlanes, m.GeoLookupsTotal, m.GeoLookupDuration, m.DNSPassthroughTotal,
		m.WebhookAlertsTotal,
	)
	m.credentialAllow.Store(map[string]struct{}{})
	return m
}

// SetCredentialLabelAllowlist configures which credential ids may appear as
// metric label values. Everything else becomes "other".
func (m *Metrics) SetCredentialLabelAllowlist(ids []string) {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	m.credentialAllow.Store(set)
}

// CredentialLabel returns the safe label value for a credential id.
func (m *Metrics) CredentialLabel(id string) string {
	if id == "" {
		return "anonymous"
	}
	set, _ := m.credentialAllow.Load().(map[string]struct{})
	if _, ok := set[id]; ok {
		return id
	}
	return "other"
}

// SetNodeCount publishes the fleet size and switches node label collapse.
func (m *Metrics) SetNodeCount(n int64) {
	m.nodeCount.Store(n)
	m.NodesTotal.Set(float64(n))
}

// NodeLabel returns a bounded-cardinality node label value. While the fleet is
// small the node id is used directly; above the threshold values collapse into
// 64 stable buckets as required by the cardinality policy.
func (m *Metrics) NodeLabel(nodeID string) string {
	if nodeID == "" {
		return "none"
	}
	if m.nodeCount.Load() < 500 {
		return nodeID
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(nodeID))
	return "bucket-" + itoa(int(h.Sum32()%64))
}

// Handler returns the /metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
