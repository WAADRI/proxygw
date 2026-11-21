package panel

import (
	"net"
	"net/http"
	"testing"
	"time"

	"proxygw/internal/audit"
)

// TestOverview checks the aggregated overview payload.
func TestOverview(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	env.tunnel.mu.Lock()
	env.tunnel.sessions = []SessionInfo{
		{NodeID: "node-a", Transport: "quic", State: "ready", Planes: 2},
		{NodeID: "node-b", Transport: "ws", State: "ready", Planes: 1},
	}
	env.tunnel.mu.Unlock()

	var overview overviewResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/overview", nil, &overview); status != http.StatusOK {
		t.Fatalf("overview status=%d", status)
	}
	if overview.OnlineNodes != 2 || overview.NodesTotal != 3 || overview.UniqueEgressIPs != 2 {
		t.Fatalf("fleet indicators: online=%d total=%d unique=%d", overview.OnlineNodes, overview.NodesTotal, overview.UniqueEgressIPs)
	}
	if overview.ActiveConnections != 7 {
		t.Fatalf("active_connections=%d want tunnel value 7", overview.ActiveConnections)
	}
	if overview.TransportMix["quic"] != 1 || overview.TransportMix["ws"] != 1 {
		t.Fatalf("transport_mix=%v", overview.TransportMix)
	}
	if overview.Requests.Total != 12345 || overview.Requests.Errors != 12 ||
		overview.Requests.Retries != 3 || overview.Requests.RateLimited != 1 || overview.Requests.BreakerTrips != 2 {
		t.Fatalf("requests=%+v", overview.Requests)
	}
	if len(overview.Trend) != 1 || overview.Trend[0].Requests != 120 {
		t.Fatalf("trend=%+v", overview.Trend)
	}
	if overview.SettingsVersion != 0 {
		t.Fatalf("settings_version=%d", overview.SettingsVersion)
	}
	if overview.ClockSkewMS != 250 {
		t.Fatalf("clock_skew_ms=%d want 250", overview.ClockSkewMS)
	}
	if overview.Version.Version != "test" || overview.Version.GoVersion == "" {
		t.Fatalf("version=%+v", overview.Version)
	}
	if overview.Cert == nil || overview.Cert.Mode != "pin" || overview.Cert.Pin == "" {
		t.Fatalf("cert=%+v", overview.Cert)
	}
}

// TestTunnelSessions checks the session mapping and the transport mix.
func TestTunnelSessions(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	connected := testNow.Add(-10 * time.Minute)
	env.tunnel.mu.Lock()
	env.tunnel.sessions = []SessionInfo{
		{NodeID: "node-b", Alias: "beta", Transport: "ws", State: "ready", Planes: 1, Epoch: 3,
			ConnectedSince: connected, LastHeartbeat: testNow},
		{NodeID: "node-a", Alias: "alpha", Transport: "quic", State: "ready", Planes: 2, Epoch: 7,
			LastError: "temporary", ConnectedSince: connected, LastHeartbeat: testNow},
		// Offline placeholder reported by the app adapter: listed but not counted
		// in the transport mix.
		{NodeID: "node-c", Alias: "gamma", Transport: "quic", State: "offline"},
	}
	env.tunnel.mu.Unlock()

	var resp tunnelSessionsResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/tunnel/sessions", nil, &resp); status != http.StatusOK {
		t.Fatalf("tunnel sessions status=%d", status)
	}
	if len(resp.Items) != 3 {
		t.Fatalf("items=%+v", resp.Items)
	}
	if resp.Items[0].NodeID != "node-a" || resp.Items[0].NodeAlias != "alpha" {
		t.Fatalf("not sorted by node id: %+v", resp.Items)
	}
	if resp.Items[0].Planes != 2 || resp.Items[0].Epoch != 7 || resp.Items[0].LastError != "temporary" {
		t.Fatalf("first session=%+v", resp.Items[0])
	}
	if resp.TransportMix["quic"] != 1 || resp.TransportMix["ws"] != 1 {
		t.Fatalf("transport_mix=%v (offline session must not count)", resp.TransportMix)
	}
}

// TestTunnelSessionsWithoutTunnel checks the empty 200 shape.
func TestTunnelSessionsWithoutTunnel(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	client := env.loginClient(t)
	var resp tunnelSessionsResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/tunnel/sessions", nil, &resp); status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if resp.Items == nil || len(resp.Items) != 0 {
		t.Fatalf("items=%v", resp.Items)
	}
	if resp.TransportMix["quic"] != 0 || resp.TransportMix["ws"] != 0 {
		t.Fatalf("transport_mix=%v", resp.TransportMix)
	}
}

// TestCertEndpoints covers status, rotate-pin and reload.
func TestCertEndpoints(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var cert certResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/cert", nil, &cert); status != http.StatusOK {
		t.Fatalf("cert status=%d", status)
	}
	if cert.Mode != "pin" || cert.Pin == "" || cert.CertPath == "" || cert.NotAfter == "" {
		t.Fatalf("cert=%+v", cert)
	}
	if _, err := time.Parse(time.RFC3339, cert.NotAfter); err != nil {
		t.Fatalf("not_after=%q: %v", cert.NotAfter, err)
	}

	var rotated certRotatePinResponse
	if status := client.doJSON(http.MethodPost, "/api/v1/cert/rotate-pin", nil, &rotated); status != http.StatusOK {
		t.Fatalf("rotate status=%d", status)
	}
	if rotated.Pin != env.cert.rotatePin || rotated.Message == "" {
		t.Fatalf("rotate=%+v", rotated)
	}
	env.cert.mu.Lock()
	wasRotated := env.cert.rotated
	env.cert.mu.Unlock()
	if !wasRotated {
		t.Fatalf("cert manager RotatePin not called")
	}

	var reloaded map[string]bool
	if status := client.doJSON(http.MethodPost, "/api/v1/cert/reload", nil, &reloaded); status != http.StatusOK || !reloaded["ok"] {
		t.Fatalf("reload status=%d resp=%v", status, reloaded)
	}
	env.cert.mu.Lock()
	wasReloaded := env.cert.reloaded
	env.cert.mu.Unlock()
	if !wasReloaded {
		t.Fatalf("cert manager Reload not called")
	}

	events, err := env.auditLog.Query(audit.Filter{Action: "cert.rotate_pin"})
	if err != nil || len(events) != 1 {
		t.Fatalf("cert.rotate_pin audit=%v err=%v", events, err)
	}
	events, err = env.auditLog.Query(audit.Filter{Action: "cert.reload"})
	if err != nil || len(events) != 1 {
		t.Fatalf("cert.reload audit=%v err=%v", events, err)
	}
}

// TestCertWithoutManager checks the 503 degradation.
func TestCertWithoutManager(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	client := env.loginClient(t)
	resp, data := client.do(http.MethodGet, "/api/v1/cert", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 body=%s", resp.StatusCode, data)
	}
}

// TestGeoProviders covers provider listing, toggling and testing.
func TestGeoProviders(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var providers geoProvidersResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/geo/providers", nil, &providers); status != http.StatusOK {
		t.Fatalf("providers status=%d", status)
	}
	if len(providers.Items) != 2 || providers.Items[0].Preset != "mmdb" || providers.Items[0].Priority != 1 {
		t.Fatalf("providers=%+v", providers.Items)
	}

	var updated ProviderStatus
	status := client.doJSON(http.MethodPatch, "/api/v1/geo/providers/ipinfo", map[string]any{"enabled": false}, &updated)
	if status != http.StatusOK || updated.Name != "ipinfo" || updated.Enabled {
		t.Fatalf("patch status=%d resp=%+v", status, updated)
	}
	env.geo.mu.Lock()
	setTo, wasSet := env.geo.setCalls["ipinfo"]
	env.geo.mu.Unlock()
	if !wasSet || setTo {
		t.Fatalf("SetProviderEnabled not called correctly: %v %v", wasSet, setTo)
	}

	resp, data := client.do(http.MethodPatch, "/api/v1/geo/providers/nope", map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider status=%d body=%s", resp.StatusCode, data)
	}
	resp, data = client.do(http.MethodPatch, "/api/v1/geo/providers/mmdb", map[string]any{})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("missing enabled status=%d body=%s", resp.StatusCode, data)
	}

	// Test provider with an explicit IP.
	env.geo.mu.Lock()
	env.geo.testResult = &ProviderTestResult{
		Provider:   "ipinfo",
		IP:         "198.51.100.9",
		RawSnippet: `{"country":"JP"}`,
		Result:     map[string]any{"country": "JP"},
		DurationMS: 12.5,
		HitPaths:   map[string]string{"country": "$.country"},
	}
	env.geo.mu.Unlock()
	var tested ProviderTestResult
	status = client.doJSON(http.MethodPost, "/api/v1/geo/providers/ipinfo/test", map[string]string{"ip": "198.51.100.9"}, &tested)
	if status != http.StatusOK || tested.Provider != "ipinfo" || tested.Result["country"] != "JP" {
		t.Fatalf("test status=%d resp=%+v", status, tested)
	}
	if tested.DurationMS != 12.5 || tested.RawSnippet == "" {
		t.Fatalf("test resp=%+v", tested)
	}
	env.geo.mu.Lock()
	lastIP := env.geo.lastIP
	env.geo.mu.Unlock()
	if lastIP == nil || !lastIP.Equal(net.ParseIP("198.51.100.9")) {
		t.Fatalf("TestProvider ip=%v", lastIP)
	}

	// Invalid IP and empty IP (empty means server egress -> nil).
	resp, data = client.do(http.MethodPost, "/api/v1/geo/providers/ipinfo/test", map[string]string{"ip": "not-an-ip"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad ip status=%d body=%s", resp.StatusCode, data)
	}
	env.geo.mu.Lock()
	env.geo.lastIP = net.ParseIP("1.1.1.1")
	env.geo.mu.Unlock()
	client.mustStatus(http.MethodPost, "/api/v1/geo/providers/ipinfo/test", map[string]any{}, http.StatusOK)
	env.geo.mu.Lock()
	lastIP = env.geo.lastIP
	env.geo.mu.Unlock()
	if lastIP != nil {
		t.Fatalf("empty ip should pass nil, got %v", lastIP)
	}
}

// TestGeoProvidersWithoutResolver checks the empty list degradation.
func TestGeoProvidersWithoutResolver(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	client := env.loginClient(t)
	var providers geoProvidersResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/geo/providers", nil, &providers); status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if providers.Items == nil || len(providers.Items) != 0 {
		t.Fatalf("items=%v", providers.Items)
	}
	resp, _ := client.do(http.MethodPost, "/api/v1/geo/providers/mmdb/test", map[string]any{})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("test without resolver status=%d", resp.StatusCode)
	}
}

// TestStatsTopN checks the TopN endpoint contract.
func TestStatsTopN(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var resp topNResponse
	status := client.doJSON(http.MethodGet, "/api/v1/stats/topn?window=30m&n=5", nil, &resp)
	if status != http.StatusOK {
		t.Fatalf("topn status=%d", status)
	}
	if resp.Windows != "30m" || len(resp.Targets) != 1 || resp.Targets[0].Target != "example.com:443" {
		t.Fatalf("topn=%+v", resp)
	}
	if len(resp.Nodes) != 1 || len(resp.Credentials) != 1 {
		t.Fatalf("topn nodes/creds=%+v %+v", resp.Nodes, resp.Credentials)
	}
	env.stats.mu.Lock()
	window, n := env.stats.window, env.stats.n
	env.stats.mu.Unlock()
	if window != "30m" || n != 5 {
		t.Fatalf("stats called with window=%q n=%d", window, n)
	}

	// Defaults.
	client.doJSON(http.MethodGet, "/api/v1/stats/topn", nil, &resp)
	env.stats.mu.Lock()
	window, n = env.stats.window, env.stats.n
	env.stats.mu.Unlock()
	if window != "15m" || n != 10 {
		t.Fatalf("defaults window=%q n=%d", window, n)
	}

	for _, query := range []string{"window=bogus", "n=0", "n=101", "n=x"} {
		resp2, data := client.do(http.MethodGet, "/api/v1/stats/topn?"+query, nil)
		if resp2.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s status=%d want 422 body=%s", query, resp2.StatusCode, data)
		}
	}
}

// TestStatsTopNWithoutStats checks the 503 degradation.
func TestStatsTopNWithoutStats(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	client := env.loginClient(t)
	resp, data := client.do(http.MethodGet, "/api/v1/stats/topn", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 body=%s", resp.StatusCode, data)
	}
}

// TestAuditQuery checks filters, defaults and validation for the audit API.
func TestAuditQuery(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	// Produce two auditable writes: one group create and one node kick.
	client.mustStatus(http.MethodPost, "/api/v1/groups", map[string]any{"name": "audit-group"}, http.StatusOK)
	client.mustStatus(http.MethodPost, "/api/v1/nodes/node-b/kick", nil, http.StatusOK)

	var all auditResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/audit", nil, &all); status != http.StatusOK {
		t.Fatalf("audit status=%d", status)
	}
	if len(all.Items) < 3 {
		// login + group.create + node.kick
		t.Fatalf("audit items=%d want >=3", len(all.Items))
	}
	for _, event := range all.Items {
		if event.Result == "" || event.Action == "" {
			t.Fatalf("event missing fields: %+v", event)
		}
	}
	if all.Items[0].Actor != "admin" {
		t.Fatalf("newest event actor=%q", all.Items[0].Actor)
	}

	var filtered auditResponse
	client.doJSON(http.MethodGet, "/api/v1/audit?action=GROUP.CREATE", nil, &filtered)
	if len(filtered.Items) != 1 || filtered.Items[0].Object == "" {
		t.Fatalf("action filter=%+v", filtered.Items)
	}

	// Actor filter and limit.
	client.doJSON(http.MethodGet, "/api/v1/audit?actor=admin&limit=1", nil, &filtered)
	if len(filtered.Items) != 1 {
		t.Fatalf("limit filter returned %d items", len(filtered.Items))
	}

	// Time window: everything is in the future relative to the audit's clock.
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	client.doJSON(http.MethodGet, "/api/v1/audit?since="+future, nil, &filtered)
	if len(filtered.Items) != 0 {
		t.Fatalf("since filter returned %d items", len(filtered.Items))
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	client.doJSON(http.MethodGet, "/api/v1/audit?since="+past, nil, &filtered)
	if len(filtered.Items) == 0 {
		t.Fatalf("since filter dropped everything")
	}

	for _, query := range []string{"limit=0", "limit=abc", "since=bogus", "until=bogus"} {
		resp, data := client.do(http.MethodGet, "/api/v1/audit?"+query, nil)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s status=%d want 422 body=%s", query, resp.StatusCode, data)
		}
	}
}
