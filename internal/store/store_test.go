// Package store tests the crash-safe JSON persistence layer.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type doc struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

func TestLoadMissingReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	s := New[doc](filepath.Join(dir, "x.json"))
	got, warnings, err := s.Load(doc{Name: "fallback"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Name != "fallback" {
		t.Fatalf("expected fallback, got %+v", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestSaveLoadRoundTripAndBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	s := New[doc](path)
	if err := s.Save(doc{Name: "one", Values: []string{"a"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, warnings, err := s.Load(doc{})
	if err != nil || got.Name != "one" || len(warnings) != 0 {
		t.Fatalf("Load = %+v, %v, %v", got, warnings, err)
	}
	// Second save must create a backup containing the previous version.
	if err := s.Save(doc{Name: "two", Values: []string{"b"}}); err != nil {
		t.Fatalf("Save2: %v", err)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var prev doc
	if err := json.Unmarshal(bak, &prev); err != nil {
		t.Fatalf("backup json: %v", err)
	}
	if prev.Name != "one" {
		t.Fatalf("backup should contain previous doc, got %+v", prev)
	}
}

func TestLoadFallsBackToBackupOnCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	s := New[doc](path)
	if err := s.Save(doc{Name: "good"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Create a backup, then corrupt the main file.
	if err := s.Save(doc{Name: "newer"}); err != nil { // creates .bak with "good"
		t.Fatalf("Save2: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	got, warnings, err := s.Load(doc{})
	if err != nil {
		t.Fatalf("Load should recover from backup: %v", err)
	}
	if got.Name != "good" {
		t.Fatalf("expected backup content, got %+v", got)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "备份") {
		t.Fatalf("expected backup warning, got %v", warnings)
	}
}

func TestLoadBothCorruptReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte("also bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New[doc](path)
	if _, _, err := s.Load(doc{}); err == nil {
		t.Fatal("expected error when main and backup are corrupt")
	}
}

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("got %q", got)
	}
	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func TestUpdatePersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	s := New[doc](path)
	if _, _, err := s.Update(doc{Name: "init"}, func(d *doc) error {
		d.Values = append(d.Values, "v1")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Load(doc{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "init" || len(got.Values) != 1 || got.Values[0] != "v1" {
		t.Fatalf("unexpected doc %+v", got)
	}
}
