package panel

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"proxygw/internal/audit"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/registry"
)

// seedNodes installs the standard node fixture used by the node tests.
func seedNodes(t *testing.T, env *testEnv) {
	t.Helper()
	env.addNode("node-a", "alpha", true, func(meta *registry.PlaneMeta) {
		meta.Tags = []string{"tokyo"}
		meta.ISPLabel = "NTT"
		meta.EgressV4 = "203.0.113.10"
	})
	env.addNode("node-b", "beta", true, func(meta *registry.PlaneMeta) {
		meta.Tags = []string{"osaka"}
		meta.ISPLabel = "KDDI"
		meta.EgressV4 = "203.0.113.11"
		meta.Transport = model.TransportWS
	})
	env.addNode("node-c", "gamma", false, func(meta *registry.PlaneMeta) {
		meta.Tags = []string{"tokyo"}
		meta.EgressV4 = "203.0.113.12"
	})
}

// TestNodesListAndFilters covers filters, summary and stable pagination.
func TestNodesListAndFilters(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	// node-d shares node-a's egress IP and must be marked as a duplicate.
	env.addNode("node-d", "delta", true, func(meta *registry.PlaneMeta) {
		meta.Tags = []string{"tokyo"}
		meta.EgressV4 = "203.0.113.10"
	})
	client := env.loginClient(t)

	var list nodesListResponse
	status := client.doJSON(http.MethodGet, "/api/v1/nodes", nil, &list)
	if status != http.StatusOK {
		t.Fatalf("nodes status=%d", status)
	}
	if list.Total != 4 || len(list.Items) != 4 {
		t.Fatalf("total=%d items=%d want 4", list.Total, len(list.Items))
	}
	if list.Summary.Nodes != 4 || list.Summary.Online != 3 || list.Summary.UniqueEgressIPs != 2 {
		t.Fatalf("summary=%+v", list.Summary)
	}
	// Stable order is alias then id: alpha, beta, delta, gamma.
	wantAliases := []string{"alpha", "beta", "delta", "gamma"}
	for i, want := range wantAliases {
		if got := list.Items[i].Alias; got != want {
			t.Fatalf("items[%d].alias=%q want %q", i, got, want)
		}
	}

	// Search on the alias.
	var search nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?q=alp", nil, &search)
	if search.Total != 1 || search.Items[0].ID != "node-a" {
		t.Fatalf("search total=%d items=%+v", search.Total, search.Items)
	}

	// ISP filter uses the manual isp_label.
	var isp nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?isp=ntt", nil, &isp)
	if isp.Total != 1 || isp.Items[0].ID != "node-a" {
		t.Fatalf("isp total=%d", isp.Total)
	}

	// Group filter relies on the registry groups resolver.
	group, err := env.groups.Upsert(model.Group{Name: "tokyo", Match: model.GroupMatch{TagsAny: []string{"tokyo"}}})
	if err != nil {
		t.Fatalf("Upsert group: %v", err)
	}
	var grouped nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?group="+group.ID, nil, &grouped)
	if grouped.Total != 3 {
		t.Fatalf("group filter total=%d want 3", grouped.Total)
	}

	// Online tri-state filter.
	var online nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?online=1", nil, &online)
	if online.Total != 3 {
		t.Fatalf("online total=%d want 3", online.Total)
	}
	var offline nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?online=0", nil, &offline)
	if offline.Total != 1 || offline.Items[0].ID != "node-c" {
		t.Fatalf("offline total=%d items=%+v", offline.Total, offline.Items)
	}

	// unique=1 hides the duplicate egress node.
	var unique nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?unique=1", nil, &unique)
	if unique.Total != 3 {
		t.Fatalf("unique total=%d want 3", unique.Total)
	}
	for _, node := range unique.Items {
		if node.ID == "node-d" {
			t.Fatalf("duplicate node-d should be hidden by unique=1")
		}
		if node.DuplicateOf != "" {
			t.Fatalf("node %s still duplicate_of=%q", node.ID, node.DuplicateOf)
		}
	}

	// Filters with no Geo data (registry has no geo setter in this milestone).
	for _, query := range []string{"country=JP", "asn=AS15169"} {
		var filtered nodesListResponse
		client.doJSON(http.MethodGet, "/api/v1/nodes?"+query, nil, &filtered)
		if filtered.Total != 0 || len(filtered.Items) != 0 {
			t.Fatalf("%s total=%d want 0", query, filtered.Total)
		}
	}

	// Pagination is deterministic.
	var page2 nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?page=2&size=2", nil, &page2)
	if page2.Total != 4 || len(page2.Items) != 2 || page2.Items[0].ID != "node-d" {
		t.Fatalf("page2 total=%d items=%v", page2.Total, nodeIDs(page2.Items))
	}
	var page3 nodesListResponse
	client.doJSON(http.MethodGet, "/api/v1/nodes?page=3&size=2", nil, &page3)
	if len(page3.Items) != 0 {
		t.Fatalf("page3 items=%v", nodeIDs(page3.Items))
	}

	// Invalid paging/filter parameters are 422.
	for _, query := range []string{"page=0", "size=0", "size=501", "page=x", "asn=abc", "online=maybe", "unique=2"} {
		resp, data := client.do(http.MethodGet, "/api/v1/nodes?"+query, nil)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s status=%d want 422 body=%s", query, resp.StatusCode, data)
		}
	}
}

// nodeIDs extracts the node ids of a list.
func nodeIDs(nodes []model.Node) []string {
	out := make([]string, len(nodes))
	for i, node := range nodes {
		out[i] = node.ID
	}
	return out
}

// TestNodePatch checks the operator override update and its audit record.
func TestNodePatch(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	var updated model.Node
	status := client.doJSON(http.MethodPatch, "/api/v1/nodes/node-a", map[string]any{
		"alias":  "alpha-2",
		"weight": 7,
		"tags":   []string{"tokyo", "edge"},
		"region": "JP-13",
	}, &updated)
	if status != http.StatusOK {
		t.Fatalf("patch status=%d", status)
	}
	if updated.Alias != "alpha-2" || updated.Weight != 7 || updated.Region != "JP-13" {
		t.Fatalf("updated=%+v", updated)
	}
	if len(updated.Tags) != 2 || updated.Tags[1] != "edge" {
		t.Fatalf("tags=%v", updated.Tags)
	}
	stored, ok := env.reg.Get("node-a")
	if !ok || stored.Alias != "alpha-2" || stored.Weight != 7 {
		t.Fatalf("registry not updated: %+v", stored)
	}

	// Disabling the node must not force it offline, only un-schedulable.
	var disabled model.Node
	status = client.doJSON(http.MethodPatch, "/api/v1/nodes/node-a", map[string]any{"enabled": false}, &disabled)
	if status != http.StatusOK || disabled.Enabled {
		t.Fatalf("disable status=%d enabled=%v", status, disabled.Enabled)
	}
	if !disabled.Online {
		t.Fatalf("disable should keep the online flag")
	}

	events, err := env.auditLog.Query(audit.Filter{Action: "node.update"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("node.update audit events=%d want 2", len(events))
	}
	if events[0].Actor != "admin" || events[0].Object != "node-a" {
		t.Fatalf("audit event=%+v", events[0])
	}

	// Unknown node and invalid payloads.
	resp, data := client.do(http.MethodPatch, "/api/v1/nodes/nope", map[string]any{"alias": "x"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown node status=%d want 404 body=%s", resp.StatusCode, data)
	}
	for _, body := range []map[string]any{
		{"weight": -1},
		{"tags": []string{""}},
		{"alias": strings.Repeat("a", 200)},
		{},
	} {
		resp, data = client.do(http.MethodPatch, "/api/v1/nodes/node-b", body)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("patch %v status=%d want 422 body=%s", body, resp.StatusCode, data)
		}
	}
}

// TestNodeUpdateRejectsDocker verifies Docker nodes are rejected before the
// update backend is consulted.
func TestNodeUpdateRejectsDocker(t *testing.T) {
	env := newTestEnv(t)
	env.addNode("node-docker", "docker-node", true, func(meta *registry.PlaneMeta) {
		meta.Runtime = "docker"
		meta.UpdateCapable = false
	})
	client := env.loginClient(t)

	resp, data := client.do(http.MethodPost, "/api/v1/nodes/node-docker/update", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("docker update status=%d want 409 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "node_update_not_allowed" {
		t.Fatalf("error=%q want node_update_not_allowed body=%s", code, data)
	}

	// A binary node reaches the update backend; with the fake environment it is
	// not wired, so the endpoint must degrade to 503 instead of panicking.
	env.addNode("node-binary", "binary-node", true, func(meta *registry.PlaneMeta) {
		meta.Runtime = "binary"
		meta.UpdateCapable = true
	})
	resp, data = client.do(http.MethodPost, "/api/v1/nodes/node-binary/update", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("binary update status=%d want 503 body=%s", resp.StatusCode, data)
	}
}

// TestNodeKick checks forced offline via the tunnel plus the registry flag.
func TestNodeKick(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	var result map[string]bool
	status := client.doJSON(http.MethodPost, "/api/v1/nodes/node-b/kick", map[string]string{"reason": "revoked"}, &result)
	if status != http.StatusOK || !result["ok"] {
		t.Fatalf("kick status=%d result=%v", status, result)
	}
	if node, _ := env.reg.Get("node-b"); node.Online {
		t.Fatalf("node-b still online after kick")
	}
	env.tunnel.mu.Lock()
	gotKicks := append([]string(nil), env.tunnel.kicks...)
	env.tunnel.mu.Unlock()
	if len(gotKicks) != 1 || gotKicks[0] != "node-b:revoked" {
		t.Fatalf("tunnel kicks=%v", gotKicks)
	}
	events, err := env.auditLog.Query(audit.Filter{Action: "node.kick"})
	if err != nil || len(events) != 1 {
		t.Fatalf("node.kick audit events=%v err=%v", events, err)
	}

	resp, data := client.do(http.MethodPost, "/api/v1/nodes/nope/kick", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("kick unknown status=%d body=%s", resp.StatusCode, data)
	}
}

// TestNodeProbe checks ping and node-side probe mapping plus validation.
func TestNodeProbe(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	env.tunnel.mu.Lock()
	env.tunnel.pingLatency = 12500 * time.Microsecond
	env.tunnel.mu.Unlock()

	var ping probeResponse
	status := client.doJSON(http.MethodPost, "/api/v1/nodes/node-a/probe", map[string]string{"kind": "ping"}, &ping)
	if status != http.StatusOK || !ping.OK {
		t.Fatalf("ping status=%d resp=%+v", status, ping)
	}
	if ping.LatencyMS != 12.5 {
		t.Fatalf("ping latency=%v want 12.5", ping.LatencyMS)
	}
	if ping.Detail != "pong" {
		t.Fatalf("ping detail=%q", ping.Detail)
	}

	env.tunnel.mu.Lock()
	env.tunnel.probeResult = &protocol.ProbeResult{
		OK: true, LatencyMS: 3.5, Detail: "dial ok", Result: []byte("hello"),
	}
	env.tunnel.mu.Unlock()
	var tcping probeResponse
	status = client.doJSON(http.MethodPost, "/api/v1/nodes/node-a/probe", map[string]string{
		"kind": "tcping", "target": "example.com:443",
	}, &tcping)
	if status != http.StatusOK || !tcping.OK || tcping.LatencyMS != 3.5 {
		t.Fatalf("tcping status=%d resp=%+v", status, tcping)
	}
	decoded, err := base64.StdEncoding.DecodeString(tcping.ResultB64)
	if err != nil || string(decoded) != "hello" {
		t.Fatalf("result_b64=%q err=%v", tcping.ResultB64, err)
	}

	events, err := env.auditLog.Query(audit.Filter{Action: "node.probe"})
	if err != nil || len(events) != 2 {
		t.Fatalf("node.probe audit events=%v err=%v", events, err)
	}

	// Validation failures.
	for _, body := range []map[string]string{
		{"kind": "bogus"},
		{"kind": "tcping"},
		{"kind": "http", "target": "example.com", "payload_b64": "%%%"},
	} {
		resp, data := client.do(http.MethodPost, "/api/v1/nodes/node-a/probe", body)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("probe %v status=%d want 422 body=%s", body, resp.StatusCode, data)
		}
	}
}

// TestInstallCommandAndTemplate checks the command carries the pin but never a
// real node token.
func TestInstallCommandAndTemplate(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	var command installCommandResponse
	status := client.doJSON(http.MethodGet, "/api/v1/nodes/node-a/install-command", nil, &command)
	if status != http.StatusOK {
		t.Fatalf("install-command status=%d", status)
	}
	if command.ServerURL != env.opts.ServerURL {
		t.Fatalf("server_url=%q want %q", command.ServerURL, env.opts.ServerURL)
	}
	if command.Pin != env.cert.status.Pin {
		t.Fatalf("pin=%q want %q", command.Pin, env.cert.status.Pin)
	}
	if !strings.Contains(command.Command, "install-node.sh") {
		t.Fatalf("command=%q", command.Command)
	}
	if !strings.Contains(command.Command, env.opts.ServerURL) {
		t.Fatalf("command missing server url: %q", command.Command)
	}
	if !strings.Contains(command.Command, env.cert.status.Pin) {
		t.Fatalf("command missing pin: %q", command.Command)
	}
	if !strings.Contains(command.Command, tokenPlaceholder) {
		t.Fatalf("command missing token placeholder: %q", command.Command)
	}
	if strings.Contains(command.Command, "np-") || strings.Contains(strings.ToLower(command.Command), "bearer") {
		t.Fatalf("command looks like it leaks a token: %q", command.Command)
	}

	var template installTemplateResponse
	status = client.doJSON(http.MethodGet, "/api/v1/nodes/install-template", nil, &template)
	if status != http.StatusOK {
		t.Fatalf("install-template status=%d", status)
	}
	for name, text := range map[string]string{"linux": template.Linux, "windows": template.Windows} {
		if !strings.Contains(text, tokenPlaceholder) {
			t.Fatalf("%s template missing token placeholder: %q", name, text)
		}
		if !strings.Contains(text, env.cert.status.Pin) {
			t.Fatalf("%s template missing pin: %q", name, text)
		}
		if !strings.Contains(text, env.opts.ServerURL) {
			t.Fatalf("%s template missing server url: %q", name, text)
		}
	}
}

// TestInstallCommandWithoutCert checks placeholder rendering when the cert
// manager is not wired.
func TestInstallCommandWithoutCert(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	seedNodes(t, env)
	client := env.loginClient(t)

	var command installCommandResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/nodes/node-a/install-command", nil, &command); status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if command.Pin != "" {
		t.Fatalf("pin=%q want empty", command.Pin)
	}
	if !strings.Contains(command.Command, pinPlaceholder) {
		t.Fatalf("command=%q want pin placeholder", command.Command)
	}
}
