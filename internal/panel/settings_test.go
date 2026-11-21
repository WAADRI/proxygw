package panel

import (
	"net/http"
	"testing"

	"proxygw/internal/audit"
	"proxygw/internal/model"
)

// settingsAuditFilter selects one audit action.
func settingsAuditFilter(action string) audit.Filter { return audit.Filter{Action: action} }

// defaultSettingsMap builds the JSON body for PUT /settings.
func defaultSettingsMap() map[string]any {
	return map[string]any{"settings": model.DefaultSettings()}
}

// TestSettingsGet checks the initial settings snapshot.
func TestSettingsGet(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var resp settingsResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/settings", nil, &resp); status != http.StatusOK {
		t.Fatalf("settings status=%d", status)
	}
	if resp.Version != 0 {
		t.Fatalf("version=%d want 0", resp.Version)
	}
	if resp.Current.Scheduler.Strategy != model.StrategyFastest {
		t.Fatalf("strategy=%q", resp.Current.Scheduler.Strategy)
	}
	if resp.Defaults.Scheduler.Strategy != model.StrategyFastest {
		t.Fatalf("defaults=%+v", resp.Defaults)
	}
	if resp.History == nil {
		t.Fatalf("history must be an empty array, not null")
	}
	if len(resp.History) != 0 {
		t.Fatalf("history=%+v", resp.History)
	}
}

// TestSettingsPutValidation checks that an invalid settings document is
// rejected with 422 and leaves the effective settings untouched.
func TestSettingsPutValidation(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	invalid := model.DefaultSettings()
	invalid.Scheduler.Strategy = "bogus"
	resp, data := client.do(http.MethodPut, "/api/v1/settings", map[string]any{"settings": invalid})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid put status=%d want 422 body=%s", resp.StatusCode, data)
	}
	var envelope errorResponse
	if err := jsonUnmarshal(data, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.Error != "validation_failed" {
		t.Fatalf("error=%q", envelope.Error)
	}
	if len(envelope.FieldErrors) == 0 || envelope.FieldErrors[0].Field != "scheduler.strategy" {
		t.Fatalf("field_errors=%+v", envelope.FieldErrors)
	}

	// Old value stays in effect.
	var after settingsResponse
	client.doJSON(http.MethodGet, "/api/v1/settings", nil, &after)
	if after.Version != 0 || after.Current.Scheduler.Strategy != model.StrategyFastest {
		t.Fatalf("settings changed after invalid put: version=%d strategy=%q", after.Version, after.Current.Scheduler.Strategy)
	}

	// Unknown fields are rejected too.
	body := defaultSettingsMap()
	body["extra"] = "nope"
	resp, data = client.do(http.MethodPut, "/api/v1/settings", body)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field status=%d body=%s", resp.StatusCode, data)
	}

	// Missing settings wrapper.
	resp, data = client.do(http.MethodPut, "/api/v1/settings", model.DefaultSettings())
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("missing wrapper status=%d body=%s", resp.StatusCode, data)
	}
}

// TestSettingsPutUndoReset covers the hot reload, undo and reset flow.
func TestSettingsPutUndoReset(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	changed := model.DefaultSettings()
	changed.Scheduler.Strategy = model.StrategyRandom
	changed.Limits.GlobalDownKbps = 4096
	changed.Compression = true

	var mutation settingsMutationResponse
	status := client.doJSON(http.MethodPut, "/api/v1/settings", map[string]any{"settings": changed}, &mutation)
	if status != http.StatusOK {
		t.Fatalf("put status=%d", status)
	}
	if mutation.Version != 1 {
		t.Fatalf("version=%d want 1", mutation.Version)
	}
	if mutation.Current.Scheduler.Strategy != model.StrategyRandom || mutation.Current.Limits.GlobalDownKbps != 4096 {
		t.Fatalf("current=%+v", mutation.Current)
	}

	var got settingsResponse
	client.doJSON(http.MethodGet, "/api/v1/settings", nil, &got)
	if got.Version != 1 || got.Current.Compression != true {
		t.Fatalf("settings get=%+v", got)
	}
	if len(got.History) != 1 || got.History[0].Version != 0 || got.History[0].UpdatedBy != "admin" {
		t.Fatalf("history=%+v", got.History)
	}

	// Undo restores the previous version.
	status = client.doJSON(http.MethodPost, "/api/v1/settings/undo", nil, &mutation)
	if status != http.StatusOK {
		t.Fatalf("undo status=%d", status)
	}
	if mutation.Current.Scheduler.Strategy != model.StrategyFastest || mutation.Version != 2 {
		t.Fatalf("undo result=%+v", mutation)
	}

	// Reset restores the configured defaults.
	status = client.doJSON(http.MethodPost, "/api/v1/settings/reset", nil, &mutation)
	if status != http.StatusOK {
		t.Fatalf("reset status=%d", status)
	}
	if mutation.Version != 3 || mutation.Current.Limits.GlobalDownKbps != 0 {
		t.Fatalf("reset result=%+v", mutation)
	}

	// Audit records exist for all three mutations.
	for _, action := range []string{"settings.update", "settings.undo", "settings.reset"} {
		events, err := env.auditLog.Query(settingsAuditFilter(action))
		if err != nil {
			t.Fatalf("audit %s: %v", action, err)
		}
		if len(events) == 0 {
			t.Fatalf("missing audit record for %s", action)
		}
	}
}

// TestSettingsUndoWithoutHistory checks the 409 conflict.
func TestSettingsUndoWithoutHistory(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)
	resp, data := client.do(http.MethodPost, "/api/v1/settings/undo", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("undo status=%d want 409 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "conflict" {
		t.Fatalf("error=%q want conflict", code)
	}
}
