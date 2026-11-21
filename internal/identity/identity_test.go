package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()
	id1, gen1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !gen1 {
		t.Fatal("first call should generate an id")
	}
	if !ValidClientID(id1) {
		t.Fatalf("generated id invalid: %q", id1)
	}
	id2, gen2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gen2 || id2 != id1 {
		t.Fatalf("id must be stable: %q vs %q", id1, id2)
	}
	data, err := os.ReadFile(filepath.Join(dir, ClientIDFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("id file empty")
	}
}

func TestLoadOrCreateRegeneratesCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ClientIDFile), []byte("bad id with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, gen, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !gen || !ValidClientID(id) {
		t.Fatalf("expected regenerated id, got %q gen=%v", id, gen)
	}
}

func TestValidClientID(t *testing.T) {
	for _, ok := range []string{"node-1", "a", "NODE_1.x:2"} {
		if !ValidClientID(ok) {
			t.Fatalf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "has space", "slash/x", string(make([]byte, 65))} {
		if ValidClientID(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}
