package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxygw/internal/model"
)

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
