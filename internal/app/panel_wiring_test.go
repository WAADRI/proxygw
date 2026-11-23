package app

import (
	"testing"
)

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
