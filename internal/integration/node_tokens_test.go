package integration

import (
	"net/http"
	"testing"

	"proxygw/internal/config"
	"proxygw/internal/model"
)

// TestE2ENodeTokenIssueAndRevoke exercises the panel token endpoints against
// the real nodesauth store, then proves the issued token can register a node and
// that revocation kicks that node offline.
func TestE2ENodeTokenIssueAndRevoke(t *testing.T) {
	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Admin.PasswordHash = e2eAdminPasswordHash(t)
	})
	panel := newE2EPanel(t, srv)
	panel.login(e2eAdminUser, e2eAdminPass)

	var issued struct {
		Token string `json:"token"`
		Node  struct {
			NodeID  string `json:"node_id"`
			Note    string `json:"note"`
			Revoked bool   `json:"revoked"`
		} `json:"node"`
	}
	panel.doJSON(http.MethodPost, "/api/v1/nodes/tokens", map[string]any{
		"node_id": "node-token-test",
		"note":    "integration token",
	}, http.StatusCreated, &issued)
	if issued.Token == "" {
		t.Fatal("issue returned an empty token")
	}
	if issued.Node.NodeID != "node-token-test" || issued.Node.Note != "integration token" || issued.Node.Revoked {
		t.Fatalf("issued node = %+v", issued.Node)
	}

	// The issued token must authenticate a new node with the matching client ID.
	_ = startE2EClient(t, srv, "node-token-test", nil, func(cfg *config.ClientConfig) {
		cfg.Token = issued.Token
		cfg.Transport = model.TransportWS
		cfg.Planes = 1
	})
	e2eWaitNodeOnline(t, srv, "node-token-test")

	var list struct {
		Items []struct {
			NodeID  string `json:"node_id"`
			Revoked bool   `json:"revoked"`
		} `json:"items"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/nodes/tokens", nil, http.StatusOK, &list)
	found := false
	for _, item := range list.Items {
		if item.NodeID == "node-token-test" {
			found = true
			if item.Revoked {
				t.Fatalf("freshly issued token is marked revoked: %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("issued token missing from list: %+v", list.Items)
	}

	panel.doJSON(http.MethodDelete, "/api/v1/nodes/tokens/node-token-test", nil, http.StatusOK, nil)
	e2eWaitNodeOffline(t, srv, "node-token-test")
}
