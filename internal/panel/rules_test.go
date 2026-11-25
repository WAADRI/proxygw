package panel

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"proxygw/internal/acl"
	"proxygw/internal/model"
)

// TestACLCRUDAndEngineEffect verifies that ACL changes are compiled into the
// running engine immediately.
func TestACLCRUDAndEngineEffect(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	// Empty list with the configured default action.
	var list aclListResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/rules/acl", nil, &list); status != http.StatusOK {
		t.Fatalf("acl get status=%d", status)
	}
	if len(list.Items) != 0 || list.DefaultAction != model.ActionAllow {
		t.Fatalf("initial acl=%+v", list)
	}

	// Create a deny rule; the engine must reject matching targets immediately.
	var rule model.ACLRule
	status := client.doJSON(http.MethodPost, "/api/v1/rules/acl", map[string]any{
		"order":   1,
		"action":  "deny",
		"domains": []string{"blocked.example"},
		"ports":   []string{"443"},
		"note":    "unit test",
	}, &rule)
	if status != http.StatusOK {
		t.Fatalf("acl create status=%d", status)
	}
	if rule.ID == "" {
		t.Fatalf("created rule has no id: %+v", rule)
	}
	target := model.RequestTarget{Protocol: model.ProtoHTTP, Host: "blocked.example", Port: 443}
	var denied *acl.DeniedError
	if err := env.aclEng.Check(target); !errors.As(err, &denied) {
		t.Fatalf("engine did not deny blocked.example: err=%v", err)
	}
	if err := env.aclEng.Check(model.RequestTarget{Protocol: model.ProtoHTTP, Host: "allowed.example", Port: 443}); err != nil {
		t.Fatalf("engine denied unrelated target: %v", err)
	}

	// PATCH to allow; the engine follows.
	status = client.doJSON(http.MethodPatch, "/api/v1/rules/acl/"+rule.ID, map[string]any{"action": "allow"}, nil)
	if status != http.StatusOK {
		t.Fatalf("acl patch status=%d", status)
	}
	if err := env.aclEng.Check(target); err != nil {
		t.Fatalf("engine still denies after allow patch: %v", err)
	}

	// DELETE clears the engine rule.
	client.mustStatus(http.MethodDelete, "/api/v1/rules/acl/"+rule.ID, nil, http.StatusOK)
	var after aclListResponse
	client.doJSON(http.MethodGet, "/api/v1/rules/acl", nil, &after)
	if len(after.Items) != 0 {
		t.Fatalf("acl after delete=%+v", after.Items)
	}

	// Unknown ids are 404.
	resp, _ := client.do(http.MethodPatch, "/api/v1/rules/acl/does-not-exist", map[string]any{"action": "deny"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("patch unknown status=%d", resp.StatusCode)
	}
	resp, _ = client.do(http.MethodDelete, "/api/v1/rules/acl/does-not-exist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete unknown status=%d", resp.StatusCode)
	}
}

// TestACLReplaceAndValidation checks full replacement and rollback on invalid
// input (the engine must keep the previous rules).
func TestACLReplaceAndValidation(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var created model.ACLRule
	client.doJSON(http.MethodPost, "/api/v1/rules/acl", map[string]any{
		"order": 1, "action": "deny", "domains": []string{"bad.example"},
	}, &created)

	// A malformed domain fails compilation: 422 and nothing changes.
	resp, data := client.do(http.MethodPut, "/api/v1/rules/acl", map[string]any{
		"items": []map[string]any{{"action": "deny", "domains": []string{"not a host!!"}}},
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid put status=%d want 422 body=%s", resp.StatusCode, data)
	}
	var envelope errorResponse
	if err := jsonUnmarshal(data, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.Error != "validation_failed" || len(envelope.FieldErrors) == 0 {
		t.Fatalf("envelope=%+v", envelope)
	}
	var stored aclListResponse
	client.doJSON(http.MethodGet, "/api/v1/rules/acl", nil, &stored)
	if len(stored.Items) != 1 || stored.Items[0].ID != created.ID {
		t.Fatalf("acl changed after invalid replace: %+v", stored.Items)
	}

	// Missing items field is rejected.
	resp, data = client.do(http.MethodPut, "/api/v1/rules/acl", map[string]any{})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("missing items status=%d body=%s", resp.StatusCode, data)
	}

	// A valid replacement is applied.
	resp, data = client.do(http.MethodPut, "/api/v1/rules/acl", map[string]any{
		"items": []map[string]any{
			{"order": 1, "action": "allow", "domains": []string{"ok.example"}},
			{"order": 2, "action": "deny", "domains": []string{"hidden.example"}},
		},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid put status=%d body=%s", resp.StatusCode, data)
	}
	var replaced aclListResponse
	if err := jsonUnmarshal(data, &replaced); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if len(replaced.Items) != 2 || replaced.Items[0].Order != 1 {
		t.Fatalf("replaced=%+v", replaced.Items)
	}
	var denied *acl.DeniedError
	if err := env.aclEng.Check(model.RequestTarget{Protocol: model.ProtoHTTP, Host: "hidden.example", Port: 443}); !errors.As(err, &denied) {
		t.Fatalf("engine did not pick up replacement: err=%v", err)
	}
	// Clear everything again.
	client.mustStatus(http.MethodPut, "/api/v1/rules/acl", map[string]any{"items": []any{}}, http.StatusOK)
	if err := env.aclEng.Check(model.RequestTarget{Protocol: model.ProtoHTTP, Host: "hidden.example", Port: 443}); err != nil {
		t.Fatalf("engine still denies after clearing: %v", err)
	}
}

func TestACLRouteRuleForcedGroups(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)
	var rule model.ACLRule
	status := client.doJSON(http.MethodPost, "/api/v1/rules/acl", map[string]any{
		"order":       1,
		"action":      "route",
		"domains":     []string{"cn.example"},
		"node_groups": []string{"cn-edge"},
	}, &rule)
	if status != http.StatusOK {
		t.Fatalf("route create status=%d", status)
	}
	target := model.RequestTarget{Protocol: model.ProtoHTTP, Host: "cn.example", Port: 443}
	groups, err := env.aclEng.ForcedGroups(target)
	if err != nil || len(groups) != 1 || groups[0] != "cn-edge" {
		t.Fatalf("forced groups=%v err=%v", groups, err)
	}
}

// TestACLForcedList checks the built-in forced deny list exposure.
func TestACLForcedList(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var forced aclForcedResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/rules/acl/forced", nil, &forced); status != http.StatusOK {
		t.Fatalf("forced status=%d", status)
	}
	if len(forced.Items) < 3 {
		t.Fatalf("forced list too short: %+v", forced.Items)
	}
	names := make([]string, len(forced.Items))
	for i, item := range forced.Items {
		names[i] = item.Name
		if item.Reason == "" {
			t.Fatalf("forced item %q has no reason", item.Name)
		}
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "cloud_metadata") || !strings.Contains(joined, "high_risk_ports") {
		t.Fatalf("forced names=%v", names)
	}
}

// TestStickySourceIPRuleCRUD checks the source-IP dimension accepted by the
// panel API and sent to the scheduler.
func TestStickySourceIPRuleCRUD(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var created model.StickyRule
	status := client.doJSON(http.MethodPost, "/api/v1/rules/sticky", map[string]any{
		"note":         "source bypass",
		"enabled":      true,
		"source_cidrs": []string{"203.0.113.7", "2001:db8::/32"},
	}, &created)
	if status != http.StatusOK {
		t.Fatalf("create source rule status=%d", status)
	}
	if len(created.SourceCIDRs) != 2 || created.SourceCIDRs[0] != "203.0.113.7" {
		t.Fatalf("created source_cidrs=%v", created.SourceCIDRs)
	}
	env.sched.mu.Lock()
	synced := append([]model.StickyRule(nil), env.sched.lastRules...)
	env.sched.mu.Unlock()
	if len(synced) != 1 || len(synced[0].SourceCIDRs) != 2 {
		t.Fatalf("scheduler source rules=%+v", synced)
	}

	client.doJSON(http.MethodPost, "/api/v1/rules/sticky/preview", map[string]any{
		"source_ip": "203.0.113.7",
		"host":      "example.com",
		"port":      443,
	}, nil)

	resp, data := client.do(http.MethodPost, "/api/v1/rules/sticky/preview", map[string]any{
		"source_ip": "not-an-ip",
		"host":      "example.com",
		"port":      443,
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid source ip status=%d body=%s", resp.StatusCode, data)
	}
	client.mustStatus(http.MethodDelete, "/api/v1/rules/sticky/"+created.ID, nil, http.StatusOK)
}

// TestStickyCRUDAndSync checks sticky rule CRUD, scheduler hot reload and the
// dry-run preview.
func TestStickyCRUDAndSync(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var created model.StickyRule
	status := client.doJSON(http.MethodPost, "/api/v1/rules/sticky", map[string]any{
		"note":    "bank bypass",
		"enabled": true,
		"target":  map[string]any{"domains": []string{"*.bank.com"}},
	}, &created)
	if status != http.StatusOK {
		t.Fatalf("sticky create status=%d", status)
	}
	if created.ID == "" || !created.Enabled {
		t.Fatalf("created sticky=%+v", created)
	}
	env.sched.mu.Lock()
	synced := append([]model.StickyRule(nil), env.sched.lastRules...)
	env.sched.mu.Unlock()
	if len(synced) != 1 || synced[0].ID != created.ID {
		t.Fatalf("scheduler rules=%+v", synced)
	}

	// PATCH disables the rule and hot reloads.
	var updated model.StickyRule
	if status := client.doJSON(http.MethodPatch, "/api/v1/rules/sticky/"+created.ID, map[string]any{"enabled": false}, &updated); status != http.StatusOK {
		t.Fatalf("sticky patch status=%d", status)
	}
	if updated.Enabled {
		t.Fatalf("sticky rule still enabled: %+v", updated)
	}
	env.sched.mu.Lock()
	synced = append([]model.StickyRule(nil), env.sched.lastRules...)
	env.sched.mu.Unlock()
	if len(synced) != 1 || synced[0].Enabled {
		t.Fatalf("scheduler not hot reloaded: %+v", synced)
	}

	// Preview uses the injected scheduler and adds the rule note as reason.
	env.sched.mu.Lock()
	env.sched.preview = StickyPreview{Hit: true, RuleID: created.ID, ForcedNodeID: "node-a"}
	env.sched.mu.Unlock()
	var preview stickyPreviewResponse
	status = client.doJSON(http.MethodPost, "/api/v1/rules/sticky/preview", map[string]any{
		"host": "api.bank.com", "port": 443, "node_id": "node-a", "groups": []string{"g1"},
	}, &preview)
	if status != http.StatusOK || !preview.Hit {
		t.Fatalf("preview status=%d resp=%+v", status, preview)
	}
	if preview.RuleID != created.ID || preview.ForcedNodeID != "node-a" {
		t.Fatalf("preview=%+v", preview)
	}
	if !strings.Contains(preview.Reason, "bank bypass") {
		t.Fatalf("preview reason=%q", preview.Reason)
	}

	// A scheduler compile failure rolls the store back and returns 422.
	env.sched.mu.Lock()
	env.sched.setErr = errors.New("rules: sticky[0]: invalid cidr")
	env.sched.mu.Unlock()
	resp, data := client.do(http.MethodPost, "/api/v1/rules/sticky", map[string]any{
		"note":   "broken",
		"target": map[string]any{"cidrs": []string{"203.0.113.0/24"}},
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("rollback status=%d want 422 body=%s", resp.StatusCode, data)
	}
	var list stickyListResponse
	client.doJSON(http.MethodGet, "/api/v1/rules/sticky", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != created.ID {
		t.Fatalf("store not rolled back: %+v", list.Items)
	}
	env.sched.mu.Lock()
	env.sched.setErr = nil
	env.sched.mu.Unlock()

	// Empty rules are rejected by the store.
	resp, data = client.do(http.MethodPost, "/api/v1/rules/sticky", map[string]any{"note": "nothing"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("empty rule status=%d body=%s", resp.StatusCode, data)
	}
	// Unknown ids are 404.
	resp, _ = client.do(http.MethodPatch, "/api/v1/rules/sticky/st_missing", map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("patch unknown status=%d", resp.StatusCode)
	}

	// Delete removes the rule from the scheduler too.
	client.mustStatus(http.MethodDelete, "/api/v1/rules/sticky/"+created.ID, nil, http.StatusOK)
	env.sched.mu.Lock()
	remaining := len(env.sched.lastRules)
	env.sched.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("scheduler still has %d sticky rules", remaining)
	}
}

// TestStickyPreviewWithoutScheduler checks the 503 degradation.
func TestStickyPreviewWithoutScheduler(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noFakes: true})
	client := env.loginClient(t)

	resp, data := client.do(http.MethodPost, "/api/v1/rules/sticky/preview", map[string]any{"host": "example.com", "port": 443})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("preview status=%d want 503 body=%s", resp.StatusCode, data)
	}

	// Sticky CRUD still works without a scheduler (store only).
	client.mustStatus(http.MethodPost, "/api/v1/rules/sticky", map[string]any{
		"note": "no-sched", "target": map[string]any{"domains": []string{"x.example"}},
	}, http.StatusOK)
}

// TestStickyCreateWithoutNote checks that the panel derives a note because the
// rules store requires one for new rules (the UI marks it optional).
func TestStickyCreateWithoutNote(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var created model.StickyRule
	status := client.doJSON(http.MethodPost, "/api/v1/rules/sticky", map[string]any{
		"enabled": true,
		"target":  map[string]any{"domains": []string{"bank.example"}},
	}, &created)
	if status != http.StatusOK {
		t.Fatalf("create without note status=%d", status)
	}
	if !strings.Contains(created.Note, "bank.example") {
		t.Fatalf("derived note=%q", created.Note)
	}
}

// TestPreviewValidation checks the preview request validation.
func TestPreviewValidation(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)
	resp, data := client.do(http.MethodPost, "/api/v1/rules/sticky/preview", map[string]any{"port": 70000})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad port status=%d body=%s", resp.StatusCode, data)
	}
}
