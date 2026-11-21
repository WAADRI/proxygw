package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"proxygw/internal/audit"
)

// TestGroupCRUD covers group creation, member preview and updates.
func TestGroupCRUD(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	var created groupResponse
	status := client.doJSON(http.MethodPost, "/api/v1/groups", map[string]any{
		"name":        "tokyo",
		"description": "Tokyo edges",
		"match":       map[string]any{"tags_any": []string{"tokyo"}},
	}, &created)
	if status != http.StatusOK {
		t.Fatalf("create status=%d", status)
	}
	if created.ID == "" || created.Name != "tokyo" {
		t.Fatalf("created=%+v", created)
	}
	if created.MemberCount != 2 {
		t.Fatalf("member_count=%d want 2 (node-a and node-c)", created.MemberCount)
	}

	var list groupsListResponse
	client.doJSON(http.MethodGet, "/api/v1/groups", nil, &list)
	if len(list.Items) != 1 || list.Items[0].MemberCount != 2 {
		t.Fatalf("groups list=%+v", list.Items)
	}

	var members groupMembersResponse
	client.doJSON(http.MethodGet, "/api/v1/groups/"+created.ID+"/members", nil, &members)
	if members.Count != 2 || len(members.Nodes) != 2 {
		t.Fatalf("members=%+v", members)
	}

	// PATCH replaces the selector: no node matches a JP region anymore.
	var updated groupResponse
	status = client.doJSON(http.MethodPatch, "/api/v1/groups/"+created.ID, map[string]any{
		"name":  "tokyo-2",
		"match": map[string]any{"regions_any": []string{"JP"}},
	}, &updated)
	if status != http.StatusOK || updated.Name != "tokyo-2" {
		t.Fatalf("patch status=%d updated=%+v", status, updated)
	}
	if updated.MemberCount != 0 {
		t.Fatalf("member_count after patch=%d want 0", updated.MemberCount)
	}

	// Validation failures.
	resp, data := client.do(http.MethodPost, "/api/v1/groups", map[string]any{"name": "tokyo-2"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("duplicate name status=%d body=%s", resp.StatusCode, data)
		}
	}
	resp, data = client.do(http.MethodPost, "/api/v1/groups", map[string]any{"name": ""})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("empty name status=%d body=%s", resp.StatusCode, data)
	}
	var envelope errorResponse
	_ = json.Unmarshal(data, &envelope)
	if len(envelope.FieldErrors) == 0 || envelope.FieldErrors[0].Field != "name" {
		t.Fatalf("field_errors=%+v", envelope.FieldErrors)
	}

	// Unknown group ids.
	resp, _ = client.do(http.MethodPatch, "/api/v1/groups/g_missing", map[string]any{"name": "x"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("patch unknown status=%d", resp.StatusCode)
	}
	resp, _ = client.do(http.MethodGet, "/api/v1/groups/g_missing/members", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("members unknown status=%d", resp.StatusCode)
	}
}

// TestGroupDeleteConflict checks the 409 when a credential references a group.
func TestGroupDeleteConflict(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	var group groupResponse
	client.doJSON(http.MethodPost, "/api/v1/groups", map[string]any{
		"name":  "edge",
		"match": map[string]any{"tags_any": []string{"tokyo"}},
	}, &group)

	resp, data := client.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username":          "bob",
		"generate_password": true,
		"groups":            []string{group.ID},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create credential status=%d body=%s", resp.StatusCode, data)
	}

	resp, data = client.do(http.MethodDelete, "/api/v1/groups/"+group.ID, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete referenced group status=%d want 409 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "group_in_use" {
		t.Fatalf("error=%q want group_in_use (%s)", code, data)
	}

	// Remove the group binding from the credential, then the delete succeeds.
	var creds credentialsListResponse
	client.doJSON(http.MethodGet, "/api/v1/credentials", nil, &creds)
	credID := creds.Items[0].ID
	status := client.doJSON(http.MethodPatch, "/api/v1/credentials/"+credID, map[string]any{
		"groups": []string{},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("clear credential groups status=%d", status)
	}
	client.mustStatus(http.MethodDelete, "/api/v1/groups/"+group.ID, nil, http.StatusOK)
	var list groupsListResponse
	client.doJSON(http.MethodGet, "/api/v1/groups", nil, &list)
	if len(list.Items) != 0 {
		t.Fatalf("groups after delete=%+v", list.Items)
	}
}

// TestCredentialCRUD covers creation (one-time password), listing (no hash),
// password rotation, kick-sessions and deletion.
func TestCredentialCRUD(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	resp, data := client.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username":          "alice",
		"generate_password": true,
		"max_concurrent":    5,
		"bandwidth_kbps":    2048,
		"allowed_protocols": []string{"http", "connect"},
		"source_cidrs":      []string{"10.0.0.0/8"},
		"note":              "unit test",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s", resp.StatusCode, data)
	}
	if strings.Contains(string(data), "password_hash") {
		t.Fatalf("create response leaks password_hash: %s", data)
	}
	var created credentialWriteResponse
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.Password == "" {
		t.Fatalf("generated password missing from create response")
	}
	if created.Credential.ID == "" || created.Credential.Username != "alice" {
		t.Fatalf("credential=%+v", created.Credential)
	}
	if !created.Credential.Enabled {
		t.Fatalf("new credential should be enabled by default")
	}
	if created.Credential.MaxConcurrent != 5 || created.Credential.BandwidthKbps != 2048 {
		t.Fatalf("limits not applied: %+v", created.Credential)
	}
	if _, err := env.creds.Verify("alice", created.Password); err != nil {
		t.Fatalf("generated password does not verify: %v", err)
	}

	// List must not contain the hash or the plain password.
	resp, data = client.do(http.MethodGet, "/api/v1/credentials", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d", resp.StatusCode)
	}
	if strings.Contains(string(data), "password_hash") || strings.Contains(string(data), created.Password) {
		t.Fatalf("list response leaks secrets: %s", data)
	}

	// Rotate the password.
	var updated credentialWriteResponse
	status := client.doJSON(http.MethodPatch, "/api/v1/credentials/"+created.Credential.ID, map[string]any{
		"password": "new-secret-pw",
	}, &updated)
	if status != http.StatusOK {
		t.Fatalf("patch status=%d", status)
	}
	if _, err := env.creds.Verify("alice", "new-secret-pw"); err != nil {
		t.Fatalf("rotated password does not verify: %v", err)
	}
	if _, err := env.creds.Verify("alice", created.Password); err == nil {
		t.Fatalf("old password still verifies")
	}

	// Disable the credential.
	status = client.doJSON(http.MethodPatch, "/api/v1/credentials/"+created.Credential.ID, map[string]any{
		"enabled": false,
	}, &updated)
	if status != http.StatusOK {
		t.Fatalf("disable status=%d", status)
	}
	if updated.Credential.Enabled {
		t.Fatalf("enabled should be false")
	}
	if _, err := env.creds.Verify("alice", "new-secret-pw"); err == nil {
		t.Fatalf("disabled credential still verifies")
	}

	// Usage endpoint returns counters (never the hash).
	var usage credentialUsageResponse
	status = client.doJSON(http.MethodGet, "/api/v1/credentials/"+created.Credential.ID+"/usage", nil, &usage)
	if status != http.StatusOK {
		t.Fatalf("usage status=%d", status)
	}
	if usage.BytesIn != 0 || usage.ActiveConnections != 0 {
		t.Fatalf("usage=%+v", usage)
	}

	// kick-sessions counts the kicked sessions and writes an audit record.
	var kicked kickCredentialSessionsResponse
	status = client.doJSON(http.MethodPost, "/api/v1/credentials/"+created.Credential.ID+"/kick-sessions", nil, &kicked)
	if status != http.StatusOK || kicked.Kicked != 1 {
		t.Fatalf("kick-sessions status=%d resp=%+v", status, kicked)
	}
	events, err := env.auditLog.Query(audit.Filter{Action: "credential.kick_sessions"})
	if err != nil || len(events) != 1 {
		t.Fatalf("credential.kick_sessions audit=%v err=%v", events, err)
	}

	// Delete also kicks the sessions.
	client.mustStatus(http.MethodDelete, "/api/v1/credentials/"+created.Credential.ID, nil, http.StatusOK)
	if _, ok := env.creds.Get(created.Credential.ID); ok {
		t.Fatalf("credential still present after delete")
	}
	env.kickMu.Lock()
	kicks := env.kickCounts[created.Credential.ID]
	env.kickMu.Unlock()
	if kicks != 2 {
		t.Fatalf("KickCredential calls=%d want 2", kicks)
	}

	// Error cases: duplicate username, missing password, unknown ids.
	client.mustStatus(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username": "carol", "password": "carol-pass-1",
	}, http.StatusOK)
	resp, data = client.do(http.MethodPost, "/api/v1/credentials", map[string]any{"username": "carol", "password": "another-password"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate username status=%d body=%s", resp.StatusCode, data)
	}
	// An omitted password on create is auto-generated and returned once.
	resp, data = client.do(http.MethodPost, "/api/v1/credentials", map[string]any{"username": "dave"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auto password status=%d body=%s", resp.StatusCode, data)
	}
	var autoGen credentialWriteResponse
	if err := json.Unmarshal(data, &autoGen); err != nil || autoGen.Password == "" {
		t.Fatalf("auto generated password missing: %s err=%v", data, err)
	}
	if _, err := env.creds.Verify("dave", autoGen.Password); err != nil {
		t.Fatalf("auto generated password does not verify: %v", err)
	}
	resp, _ = client.do(http.MethodPatch, "/api/v1/credentials/does-not-exist", map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("patch unknown status=%d", resp.StatusCode)
	}
	resp, _ = client.do(http.MethodDelete, "/api/v1/credentials/does-not-exist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete unknown status=%d", resp.StatusCode)
	}
}

// TestCredentialVisibleNodes checks the realtime visible node count for the
// all-groups and group-bound cases.
func TestCredentialVisibleNodes(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	var group groupResponse
	client.doJSON(http.MethodPost, "/api/v1/groups", map[string]any{
		"name":  "tokyo",
		"match": map[string]any{"tags_any": []string{"tokyo"}},
	}, &group)

	// No groups: the credential sees every node.
	var all credentialWriteResponse
	client.doJSON(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username": "all-groups", "generate_password": true,
	}, &all)

	var visible visibleNodesResponse
	status := client.doJSON(http.MethodGet, "/api/v1/credentials/"+all.Credential.ID+"/visible-nodes", nil, &visible)
	if status != http.StatusOK || visible.Count != 3 || len(visible.Nodes) != 3 {
		t.Fatalf("visible all status=%d count=%d", status, visible.Count)
	}

	// Bound to the tokyo group: only node-a and node-c.
	var bound credentialWriteResponse
	client.doJSON(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username": "bound", "generate_password": true, "groups": []string{group.ID},
	}, &bound)
	status = client.doJSON(http.MethodGet, "/api/v1/credentials/"+bound.Credential.ID+"/visible-nodes", nil, &visible)
	if status != http.StatusOK || visible.Count != 2 {
		t.Fatalf("visible bound status=%d count=%d nodes=%v", status, visible.Count, nodeIDs(visible.Nodes))
	}

	resp, _ := client.do(http.MethodGet, "/api/v1/credentials/missing/visible-nodes", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown credential status=%d", resp.StatusCode)
	}
}

// TestCredentialExplicitPassword checks create with an explicit password.
func TestCredentialExplicitPassword(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var created credentialWriteResponse
	status := client.doJSON(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username": "dave",
		"password": "explicit-pass-1",
		"groups":   []string{},
	}, &created)
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if created.Password != "" {
		t.Fatalf("explicit password must not be echoed once: %q", created.Password)
	}
	if _, err := env.creds.Verify("dave", "explicit-pass-1"); err != nil {
		t.Fatalf("explicit password does not verify: %v", err)
	}
	// Too-short passwords are rejected.
	resp, data := client.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username": "shorty", "password": "short",
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("short password status=%d body=%s", resp.StatusCode, data)
	}
}
