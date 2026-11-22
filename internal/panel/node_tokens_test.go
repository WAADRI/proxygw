package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestNodeTokenEndpoints(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	// Empty list initially.
	var list nodeTokenListResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/nodes/tokens", nil, &list); status != http.StatusOK {
		t.Fatalf("initial list status=%d", status)
	}
	if len(list.Items) != 0 {
		t.Fatalf("initial list = %+v, want empty", list.Items)
	}

	// Issue one token. The clear-text token is returned once.
	var issued nodeTokenIssueResponse
	status := client.doJSON(http.MethodPost, "/api/v1/nodes/tokens", map[string]string{
		"node_id": "node-99",
		"note":    "Hunan mobile",
	}, &issued)
	if status != http.StatusCreated {
		t.Fatalf("issue status=%d want 201", status)
	}
	if issued.Token == "" || !strings.Contains(issued.Token, "node-99") {
		t.Fatalf("issued token = %q", issued.Token)
	}
	if issued.Node.NodeID != "node-99" || issued.Node.Note != "Hunan mobile" || issued.Node.Revoked {
		t.Fatalf("issued node = %+v", issued.Node)
	}

	// The list endpoint must never expose a token digest/hash.
	data := client.mustStatus(http.MethodGet, "/api/v1/nodes/tokens", nil, http.StatusOK)
	if strings.Contains(string(data), "token_hash") || strings.Contains(string(data), issued.Token) {
		t.Fatalf("list leaked token material: %s", data)
	}
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].NodeID != "node-99" || list.Items[0].Revoked {
		t.Fatalf("list = %+v", list.Items)
	}

	// Revoke: token metadata becomes revoked and live sessions are kicked.
	client.mustStatus(http.MethodDelete, "/api/v1/nodes/tokens/node-99", nil, http.StatusOK)
	if err := json.Unmarshal(client.mustStatus(http.MethodGet, "/api/v1/nodes/tokens", nil, http.StatusOK), &list); err != nil {
		t.Fatalf("decode list after revoke: %v", err)
	}
	if len(list.Items) != 1 || !list.Items[0].Revoked {
		t.Fatalf("list after revoke = %+v", list.Items)
	}
	env.tunnel.mu.Lock()
	kicks := append([]string(nil), env.tunnel.kicks...)
	env.tunnel.mu.Unlock()
	if len(kicks) != 1 || kicks[0] != "node-99:token_revoked" {
		t.Fatalf("kicks = %+v, want node-99:token_revoked", kicks)
	}

	// Validation: Chinese node IDs are rejected by the panel contract.
	data = client.mustStatus(http.MethodPost, "/api/v1/nodes/tokens", map[string]string{
		"node_id": "99号节点",
	}, http.StatusUnprocessableEntity)
	if code := errorCode(t, data); code != "validation_failed" {
		t.Fatalf("invalid node id error code = %q", code)
	}
	// Wildcard IDs must not be issuable from the panel.
	if status := client.doJSON(http.MethodPost, "/api/v1/nodes/tokens", map[string]string{"node_id": "*"}, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("wildcard issue status=%d want 422", status)
	}
}

func TestNodeTokenEndpointsUnavailableWithoutBackend(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	client := env.loginClient(t)
	if status := client.doJSON(http.MethodGet, "/api/v1/nodes/tokens", nil, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("list without backend status=%d want 503", status)
	}
	if status := client.doJSON(http.MethodPost, "/api/v1/nodes/tokens", map[string]string{"node_id": "node-1"}, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("issue without backend status=%d want 503", status)
	}
}
