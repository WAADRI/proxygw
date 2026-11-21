package settings

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxygw/internal/model"
)

func TestApplyPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime-overrides.json")
	defaults := model.DefaultSettings()
	m, err := NewManager(path, defaults, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Current().Scheduler.Strategy != model.StrategyFastest {
		t.Fatalf("defaults wrong: %+v", m.Current().Scheduler)
	}
	next := defaults
	next.Scheduler.Strategy = model.StrategyRandom
	next.Scheduler.Sticky.TTL = model.D(5 * time.Minute)
	if err := m.Apply(next, "tester"); err != nil {
		t.Fatal(err)
	}
	// Reload from disk.
	m2, err := NewManager(path, defaults, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Current().Scheduler.Strategy != model.StrategyRandom || m2.Version() != 1 {
		t.Fatalf("reload = %+v version=%d", m2.Current().Scheduler, m2.Version())
	}
}

func TestInvalidApplyKeepsOld(t *testing.T) {
	m, err := NewManager("", model.DefaultSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := m.Current()
	bad.Scheduler.Strategy = "bogus"
	if err := m.Apply(bad, "tester"); err == nil {
		t.Fatal("invalid settings must be rejected")
	}
	if m.Current().Scheduler.Strategy != model.StrategyFastest {
		t.Fatalf("old settings clobbered: %+v", m.Current().Scheduler)
	}
}

func TestUndo(t *testing.T) {
	m, err := NewManager("", model.DefaultSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Undo("tester"); err == nil {
		t.Fatal("undo without history must fail")
	}
	next := m.Current()
	next.Scheduler.Strategy = model.StrategyWeighted
	if err := m.Apply(next, "a"); err != nil {
		t.Fatal(err)
	}
	again := m.Current()
	again.Scheduler.Strategy = model.StrategyLeastInflight
	if err := m.Apply(again, "b"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Undo("c")
	if err != nil {
		t.Fatal(err)
	}
	if got.Scheduler.Strategy != model.StrategyWeighted {
		t.Fatalf("undo = %q", got.Scheduler.Strategy)
	}
	if len(m.History()) != 1 {
		t.Fatalf("history = %d", len(m.History()))
	}
}

func TestPersistedInvalidFileFallsBackToDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime-overrides.json")
	// Write a settings file with an invalid strategy.
	data := `{"version":3,"current":{"scheduler":{"strategy":"nope","sticky":{"enabled":true,"ttl":"10m","max_keys_per_node":1000},"breaker":{"failure_threshold":5,"failure_rate":0.5,"min_samples":20,"open_timeout":"30s"},"retry":{"enabled":true,"max_attempts":2}},"limits":{"global_down_kbps":0,"per_node_down_kbps":0,"per_credential_down_kbps":0,"max_streams_per_node":1000},"timeouts":{"open":"10s","read_header":"10s","idle":"30m","write_block":"30s","linger":"30s","drain":"10s","window_stall":"30s","dial_target":"10s"},"compression_enabled":false,"default_acl_action":"allow"}}` + "\n"
	if err := writeFile(path, data); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(path, model.DefaultSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Current().Scheduler.Strategy != model.StrategyFastest || m.Version() != 0 {
		t.Fatalf("invalid persisted settings must fall back: %+v v%d", m.Current().Scheduler, m.Version())
	}
}

func TestDecodeOverride(t *testing.T) {
	data := []byte(`{"scheduler":{"strategy":"random","sticky":{"enabled":true,"ttl":"10m","max_keys_per_node":1000},"breaker":{"failure_threshold":5,"failure_rate":0.5,"min_samples":20,"open_timeout":"30s"},"retry":{"enabled":true,"max_attempts":2}},"limits":{"global_down_kbps":0,"per_node_down_kbps":0,"per_credential_down_kbps":0,"max_streams_per_node":1000},"timeouts":{"open":"10s","read_header":"10s","idle":"30m","write_block":"30s","linger":"30s","drain":"10s","window_stall":"30s","dial_target":"10s"},"compression_enabled":false,"default_acl_action":"allow"}`)
	s, err := DecodeOverride(data)
	if err != nil || s.Scheduler.Strategy != model.StrategyRandom {
		t.Fatalf("decode = %+v, %v", s.Scheduler, err)
	}
	if _, err := DecodeOverride([]byte(`{"unknown":1}`)); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
