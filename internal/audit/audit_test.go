package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxygw/internal/model"
)

func TestQueryRingNewestPage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := New(path, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if err := s.Log(model.AuditEvent{Action: "e", Object: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.Query(Filter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 200 || items[0].Object != "299" || items[199].Object != "100" {
		t.Fatalf("ring page len=%d first=%q last=%q", len(items), items[0].Object, items[len(items)-1].Object)
	}
}

func TestQueryFileTailFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := New(path, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		action := "skip"
		if i%3 == 0 {
			action = "hit"
		}
		if err := s.Log(model.AuditEvent{Action: action, Object: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// Force the file path instead of the in-memory ring.
	s.mu.Lock()
	s.ring = nil
	s.mu.Unlock()
	items, err := s.Query(Filter{Action: "HIT", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || items[0].Object != "27" || items[1].Object != "24" || items[2].Object != "21" {
		t.Fatalf("tail filter = %+v", items)
	}
}

func TestAuditRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s, err := NewWithOptions(path, true, Options{MaxSize: 1, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Log(model.AuditEvent{Action: "rotate", Object: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated backup missing: %v", err)
	}
	items, err := s.Query(Filter{Action: "rotate", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Object != "2" {
		t.Fatalf("post-rotation query = %+v", items)
	}
}

func TestLogAndQueryPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s, err := New(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Log(model.AuditEvent{Action: "login", Actor: "admin", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log(model.AuditEvent{Action: "credential.update", Actor: "admin", Object: "cred-1",
		Detail: map[string]string{"password": "secret", "note": "hi"}}); err != nil {
		t.Fatal(err)
	}
	all, err := s.Query(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("query all = %d", len(all))
	}
	if all[0].Action != "credential.update" {
		t.Fatalf("expected newest first, got %+v", all[0])
	}
	if all[0].Detail["password"] != "[redacted]" || all[0].Detail["note"] != "hi" {
		t.Fatalf("detail redaction failed: %+v", all[0].Detail)
	}
	if all[0].ID == "" || all[0].Time.IsZero() {
		t.Fatalf("id/time not filled: %+v", all[0])
	}
	got, err := s.Query(Filter{Action: "login"})
	if err != nil || len(got) != 1 || got[0].Actor != "admin" {
		t.Fatalf("filter = %+v, %v", got, err)
	}
	got, err = s.Query(Filter{Actor: "nobody"})
	if err != nil || len(got) != 0 {
		t.Fatalf("actor filter = %+v, %v", got, err)
	}
	now := time.Now().UTC()
	got, err = s.Query(Filter{Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: 1})
	if err != nil || len(got) != 1 {
		t.Fatalf("time filter = %+v, %v", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "credential.update") {
		t.Fatalf("file content: %v", err)
	}
}

func TestQueryMissingFile(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "x.jsonl"), true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Query(Filter{})
	if err != nil || len(got) != 0 {
		t.Fatalf("query missing = %+v, %v", got, err)
	}
}

func TestInMemoryRing(t *testing.T) {
	s, err := New("", false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s.LogSimple("test", "obj", "actor", "", "ok", nil); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Query(Filter{})
	if err != nil || len(got) != 5 {
		t.Fatalf("ring = %d, %v", len(got), err)
	}
}
