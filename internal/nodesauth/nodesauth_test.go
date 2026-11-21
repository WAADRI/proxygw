package nodesauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxygw/internal/config"
	"proxygw/internal/model"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

func staticCfg(tokens ...config.StaticNodeToken) config.NodesAuthConfig {
	return config.NodesAuthConfig{Tokens: tokens}
}

func TestStaticTokenAuthentication(t *testing.T) {
	a, err := New(staticCfg(
		config.StaticNodeToken{NodeID: "node-a", Token: "token-a", Note: "primary"},
		config.StaticNodeToken{NodeID: "node-b", Token: "token-b"},
	), "", quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()

	if err := a.Authenticate("node-a", "token-a"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if err := a.Authenticate("node-b", "token-b"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	cases := []struct{ name, node, token string }{
		{"wrong token", "node-a", "token-b"},
		{"empty token", "node-a", ""},
		{"unknown node", "node-c", "token-a"},
		{"case sensitive", "node-a", "TOKEN-A"},
		{"trailing space", "node-a", "token-a "},
	}
	for _, tc := range cases {
		if err := a.Authenticate(tc.node, tc.token); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%s: got %v want ErrUnauthorized", tc.name, err)
		}
	}
	if err := a.Authenticate("", "token-a"); !errors.Is(err, ErrInvalidNodeID) {
		t.Errorf("empty node id: got %v want ErrInvalidNodeID", err)
	}
}

func TestWildcardTokenBindsToFirstNode(t *testing.T) {
	// Auto-issued (dynamic) wildcard tokens are bound to the first node id.
	a, err := New(config.NodesAuthConfig{}, "", quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	shared, err := a.Issue(NodeIDWildcard, "bootstrap enrollment token")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := a.Authenticate("any-node", shared); err != nil {
		t.Fatalf("wildcard token rejected on first use: %v", err)
	}
	if err := a.Authenticate("another-node", shared); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("shared token must be bound to its first node, got %v", err)
	}
	if err := a.Authenticate("any-node", shared); err != nil {
		t.Fatalf("bound shared token must keep working for its node: %v", err)
	}
}

func TestStaticWildcardTokenIsSharedSecretMode(t *testing.T) {
	a, err := New(staticCfg(
		config.StaticNodeToken{NodeID: NodeIDWildcard, Token: "shared"},
		config.StaticNodeToken{NodeID: "node-a", Token: "dedicated"},
	), "", quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	// Explicitly configured wildcard tokens are an opt-in shared-secret mode.
	if err := a.Authenticate("any-node", "shared"); err != nil {
		t.Fatalf("static wildcard token rejected: %v", err)
	}
	if err := a.Authenticate("node-a", "dedicated"); err != nil {
		t.Fatalf("dedicated token rejected: %v", err)
	}
	if err := a.Authenticate("other-node", "shared"); err != nil {
		t.Fatalf("static shared secret should work for multiple nodes: %v", err)
	}
	if err := a.Authenticate("any-node", "dedicated"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("dedicated token must not authenticate another node: %v", err)
	}
}

func TestMTLS(t *testing.T) {
	cfg := config.NodesAuthConfig{MTLS: true, Tokens: []config.StaticNodeToken{{NodeID: "node-a", Token: "tok"}}}
	a, err := New(cfg, "", quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	if !a.MTLSEnabled() {
		t.Fatal("MTLSEnabled should report true")
	}
	// With per-node tokens configured, mTLS must present the matching token too
	// so the certificate identity is bound to the node id.
	if err := a.AuthenticateWithMTLS("node-a", "", true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("mTLS without token must fail when tokens are configured, got %v", err)
	}
	if err := a.AuthenticateWithMTLS("node-a", "tok", true); err != nil {
		t.Fatalf("mTLS + token rejected: %v", err)
	}
	if err := a.AuthenticateWithMTLS("never-seen-node", "", true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("mTLS alone must not authenticate an unknown node, got %v", err)
	}
	if err := a.AuthenticateWithMTLS("node-a", "tok", false); err != nil {
		t.Fatalf("token-only auth rejected: %v", err)
	}
	if err := a.AuthenticateWithMTLS("node-a", "", false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("without mTLS empty token must fail: %v", err)
	}
	if err := a.Revoke("node-a"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := a.AuthenticateWithMTLS("node-a", "tok", true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revocation must win over mTLS: %v", err)
	}
}

func TestMTLSOnlyNoTokens(t *testing.T) {
	a, err := New(config.NodesAuthConfig{MTLS: true}, "", quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	if err := a.AuthenticateWithMTLS("node-a", "", true); err != nil {
		t.Fatalf("mTLS-only deployment should accept certificate identity: %v", err)
	}
	if err := a.AuthenticateWithMTLS("node-a", "", false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("without mTLS empty token must fail: %v", err)
	}
}

func TestIssueRevokeAndPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-tokens.json")
	a, err := New(staticCfg(config.StaticNodeToken{NodeID: "static-node", Token: "static-token"}), path, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, err := a.Issue("dynamic-node", "issued from panel")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != TokenBytes {
		t.Fatalf("issued token: len=%d err=%v", len(raw), err)
	}
	if err := a.Authenticate("dynamic-node", token); err != nil {
		t.Fatalf("issued token rejected: %v", err)
	}
	if err := a.Authenticate("static-node", "static-token"); err != nil {
		t.Fatalf("static token rejected: %v", err)
	}
	// The persisted document must contain the digest but never the token.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if strings.Contains(string(blob), token) {
		t.Fatal("state file contains the clear text token")
	}
	if !strings.Contains(string(blob), "token_hash") {
		t.Fatal("state file does not persist a token digest")
	}
	// List never exposes digests.
	for _, tok := range a.List() {
		if tok.TokenHash != "" {
			t.Fatalf("List exposed a token hash: %+v", tok)
		}
	}
	list := a.List()
	if len(list) != 2 {
		t.Fatalf("List size = %d, want 2 (%+v)", len(list), list)
	}
	if list[0].NodeID != "dynamic-node" || list[1].NodeID != "static-node" {
		t.Fatalf("List order not deterministic: %+v", list)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := a.Issue("x", ""); !errors.Is(err, ErrClosed) {
		t.Fatalf("Issue after close: got %v want ErrClosed", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// Restart: the dynamic token must survive, the static token is still valid
	// and a revoke issued afterwards must survive as well.
	a2, err := New(staticCfg(config.StaticNodeToken{NodeID: "static-node", Token: "static-token"}), path, quietLogger())
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}
	if err := a2.Authenticate("dynamic-node", token); err != nil {
		t.Fatalf("issued token lost after restart: %v", err)
	}
	if err := a2.Revoke("dynamic-node"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	a2.Close()

	a3, err := New(config.NodesAuthConfig{}, path, quietLogger())
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}
	defer a3.Close()
	if err := a3.Authenticate("dynamic-node", token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revocation lost after restart: %v", err)
	}
	// Re-issuing lifts the revocation.
	token2, err := a3.Issue("dynamic-node", "rotated")
	if err != nil {
		t.Fatalf("re-Issue: %v", err)
	}
	if err := a3.Authenticate("dynamic-node", token2); err != nil {
		t.Fatalf("re-issued token rejected: %v", err)
	}
	if err := a3.Authenticate("dynamic-node", token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token must stay invalid after rotation: %v", err)
	}
}

func TestIssueWithoutPersistence(t *testing.T) {
	a, err := New(config.NodesAuthConfig{}, "", quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	token, err := a.Issue("node-a", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := a.Authenticate("node-a", token); err != nil {
		t.Fatalf("issued token rejected: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(staticCfg(config.StaticNodeToken{NodeID: "", Token: "x"}), "", quietLogger()); err == nil {
		t.Fatal("empty node id must be rejected")
	}
	if _, err := New(staticCfg(config.StaticNodeToken{NodeID: "a", Token: ""}), "", quietLogger()); err == nil {
		t.Fatal("empty token must be rejected")
	}
	if _, err := New(staticCfg(
		config.StaticNodeToken{NodeID: "a", Token: "x"},
		config.StaticNodeToken{NodeID: "a", Token: "y"},
	), "", quietLogger()); err == nil {
		t.Fatal("duplicate static node token must be rejected")
	}
}

func TestCorruptStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-tokens.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.NodesAuthConfig{}, path, quietLogger()); err == nil {
		t.Fatal("corrupt state without backup must fail closed")
	}
	// A corrupt main file with a valid backup must recover from the backup.
	doc := persisted{Tokens: []model.NodeToken{{NodeID: "node-a", TokenHash: strings.Repeat("ab", 32)}}}
	good, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", good, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(config.NodesAuthConfig{}, path, quietLogger())
	if err != nil {
		t.Fatalf("backup recovery failed: %v", err)
	}
	a.Close()
}
