package app

import (
	"io"
	"log/slog"
	"testing"

	"proxygw/internal/auth"
	"proxygw/internal/model"
)

func TestPanelDepsRecordsCredentialUsage(t *testing.T) {
	store, err := auth.NewCredentialStore("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hash, err := auth.HashPassword("panel-pass-123")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := store.Create(model.Credential{Username: "usage-user", PasswordHash: hash, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	d := newPanelDeps()
	d.credStore = store
	d.onRequestStart(cred.ID, "http", "example.com:443", "node-a")
	d.onRequestEnd(cred.ID, "http", "example.com:443", "node-a", 10, 20, nil)
	got, ok := store.Get(cred.ID)
	if !ok {
		t.Fatal("credential disappeared")
	}
	if got.BytesIn != 10 || got.BytesOut != 20 || got.LastUsedAt == nil {
		t.Fatalf("credential usage = %+v", got)
	}
}

func TestPanelDepsTracksActiveRequests(t *testing.T) {
	d := newPanelDeps()
	d.onRequestStart("cred-a", "http", "example.com:443", "node-a")
	d.onRequestStart("cred-a", "http", "example.com:443", "node-a")
	d.mu.Lock()
	if d.active != 2 {
		t.Fatalf("active after two starts = %d, want 2", d.active)
	}
	d.mu.Unlock()
	d.onRequestEnd("cred-a", "http", "example.com:443", "node-a", 10, 20, nil)
	d.mu.Lock()
	if d.active != 1 {
		t.Fatalf("active after one end = %d, want 1", d.active)
	}
	d.mu.Unlock()
	d.onRequestEnd("cred-a", "http", "example.com:443", "node-a", 10, 20, nil)
	d.mu.Lock()
	if d.active != 0 {
		t.Fatalf("active after all ends = %d, want 0", d.active)
	}
	if len(d.activeByCred) != 0 {
		t.Fatalf("activeByCred = %v, want empty", d.activeByCred)
	}
	d.mu.Unlock()
}
