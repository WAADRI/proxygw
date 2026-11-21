package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxygw/internal/model"
)

func newFileStore(t *testing.T) (*CredentialStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	s, err := NewCredentialStore(path, testLogger())
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func newMemoryStore(t *testing.T) *CredentialStore {
	t.Helper()
	s, err := NewCredentialStore("", testLogger())
	if err != nil {
		t.Fatalf("NewCredentialStore(memory): %v", err)
	}
	return s
}

func mkCredential(t *testing.T, username, password string) model.Credential {
	t.Helper()
	return model.Credential{
		Username:     username,
		PasswordHash: mustCheapHash(t, password),
		Enabled:      true,
		Note:         "test credential",
	}
}

func readCredentialFile(t *testing.T, path string) []model.Credential {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []model.Credential
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return out
}

func TestCredentialCRUDAndPersistence(t *testing.T) {
	store, path := newFileStore(t)

	alice, err := store.Create(mkCredential(t, "alice", "alice-pass"))
	if err != nil {
		t.Fatalf("Create(alice): %v", err)
	}
	if !strings.HasPrefix(alice.ID, "cred-") {
		t.Fatalf("generated id = %q, want cred- prefix", alice.ID)
	}
	if alice.CreatedAt.IsZero() || alice.UpdatedAt.IsZero() {
		t.Fatal("Create did not set timestamps")
	}
	bob, err := store.Create(mkCredential(t, "bob", "bob-pass"))
	if err != nil {
		t.Fatalf("Create(bob): %v", err)
	}

	// List redacts hashes and returns defensive copies.
	list := store.List()
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
	for _, c := range list {
		if c.PasswordHash != "" {
			t.Errorf("List exposed password hash for %q", c.Username)
		}
	}
	list[0].Username = "mutated"
	if _, ok := store.GetByUsername("mutated"); ok {
		t.Fatal("List returned a slice that aliases store state")
	}

	// Get returns the raw record.
	raw, ok := store.Get(alice.ID)
	if !ok {
		t.Fatal("Get(alice) not found")
	}
	if raw.PasswordHash == "" || raw.PasswordHash != alice.PasswordHash {
		t.Fatal("Get did not return the stored password hash")
	}
	if got, ok := store.GetByUsername("ALICE"); !ok || got.ID != alice.ID {
		t.Fatalf("GetByUsername is not case-insensitive: %+v, %v", got, ok)
	}
	if _, ok := store.Get("missing"); ok {
		t.Fatal("Get(missing) returned ok")
	}

	// Update preserves CreatedAt and keeps the hash when it is left empty.
	updatedRaw := raw
	updatedRaw.Note = "updated note"
	updatedRaw.Enabled = false
	updatedRaw.PasswordHash = ""
	updatedRaw.Groups = []string{" g1 ", "g2"}
	updatedRaw.SourceCIDRs = []string{"10.0.0.0/8", "192.168.1.5"}
	updatedRaw.AllowedProtocols = []string{"HTTP", "connect", "http"}
	updated, err := store.Update(updatedRaw)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !updated.CreatedAt.Equal(alice.CreatedAt) {
		t.Errorf("Update changed CreatedAt: %v -> %v", alice.CreatedAt, updated.CreatedAt)
	}
	if updated.PasswordHash != alice.PasswordHash {
		t.Error("Update did not preserve the password hash")
	}
	if updated.Note != "updated note" || updated.Enabled {
		t.Errorf("Update did not apply fields: %+v", updated)
	}
	if len(updated.Groups) != 2 || updated.Groups[0] != "g1" {
		t.Errorf("groups not normalized: %v", updated.Groups)
	}
	if len(updated.SourceCIDRs) != 2 || updated.SourceCIDRs[1] != "192.168.1.5/32" {
		t.Errorf("source cidrs not normalized: %v", updated.SourceCIDRs)
	}
	if len(updated.AllowedProtocols) != 2 || updated.AllowedProtocols[0] != "http" {
		t.Errorf("protocols not normalized: %v", updated.AllowedProtocols)
	}

	// Uniqueness is enforced case-insensitively.
	if _, err := store.Create(mkCredential(t, "Alice", "x-pass")); err == nil {
		t.Fatal("Create(duplicate username) succeeded")
	}
	// Invalid inputs are rejected.
	invalid := []model.Credential{
		{Username: "", PasswordHash: mustCheapHash(t, "x"), Enabled: true},
		{Username: "bad name", PasswordHash: mustCheapHash(t, "x"), Enabled: true},
		{Username: "carol", PasswordHash: "", Enabled: true},
		{Username: "carol", PasswordHash: "plaintext", Enabled: true},
		{Username: "carol", PasswordHash: mustCheapHash(t, "x"), Enabled: true, SourceCIDRs: []string{"not-a-cidr"}},
		{Username: "carol", PasswordHash: mustCheapHash(t, "x"), Enabled: true, AllowedProtocols: []string{"ftp"}},
	}
	for i, c := range invalid {
		if _, err := store.Create(c); err == nil {
			t.Errorf("Create invalid case %d succeeded", i)
		}
	}
	if _, err := store.Update(model.Credential{ID: "missing-id", Username: "x"}); err == nil {
		t.Fatal("Update(missing) succeeded")
	}
	if err := store.Delete("missing-id"); err == nil {
		t.Fatal("Delete(missing) succeeded")
	}

	// Delete removes it from memory and disk.
	if err := store.Delete(bob.ID); err != nil {
		t.Fatalf("Delete(bob): %v", err)
	}
	if _, ok := store.Get(bob.ID); ok {
		t.Fatal("deleted credential still returned by Get")
	}

	// A fresh store must see exactly the persisted state.
	reloaded, err := NewCredentialStore(path, testLogger())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer reloaded.Close()
	reloadedList := reloaded.List()
	if len(reloadedList) != 1 {
		t.Fatalf("reloaded List len = %d, want 1", len(reloadedList))
	}
	if reloadedList[0].ID != alice.ID || reloadedList[0].Note != "updated note" {
		t.Fatalf("reloaded credential mismatch: %+v", reloadedList[0])
	}
	if got := readCredentialFile(t, path); len(got) != 1 {
		t.Fatalf("persisted file has %d records, want 1", len(got))
	}
	// The persisted file contains hash material, never a plain password.
	rawFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	if strings.Contains(string(rawFile), "alice-pass") {
		t.Fatal("credentials file contains a plain password")
	}
}

func TestCredentialVerifyClassification(t *testing.T) {
	store := newMemoryStore(t)

	if _, err := store.Create(mkCredential(t, "alice", "alice-pass")); err != nil {
		t.Fatalf("Create(alice): %v", err)
	}
	bob := mkCredential(t, "bob", "bob-pass")
	bob.Enabled = false
	if _, err := store.Create(bob); err != nil {
		t.Fatalf("Create(bob): %v", err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	carol := mkCredential(t, "carol", "carol-pass")
	carol.ExpiresAt = &past
	if _, err := store.Create(carol); err != nil {
		t.Fatalf("Create(carol): %v", err)
	}
	future := time.Now().UTC().Add(time.Hour)
	dave := mkCredential(t, "dave", "dave-pass")
	dave.ExpiresAt = &future
	if _, err := store.Create(dave); err != nil {
		t.Fatalf("Create(dave): %v", err)
	}

	// Success returns the full record.
	got, err := store.Verify("alice", "alice-pass")
	if err != nil {
		t.Fatalf("Verify(alice): %v", err)
	}
	if got.ID == "" || got.PasswordHash == "" {
		t.Fatalf("Verify returned incomplete credential: %+v", got)
	}

	// Wrong password.
	var ve *VerifyError
	_, err = store.Verify("alice", "wrong")
	if err == nil {
		t.Fatal("Verify(wrong password) succeeded")
	}
	if !errors.As(err, &ve) || ve.Kind != VerifyBadPassword || ve.Username != "alice" {
		t.Fatalf("wrong verify error: %+v", err)
	}

	// Unknown user; its message must not reveal that the user is unknown.
	_, noUserErr := store.Verify("nobody", "whatever")
	if !errors.As(noUserErr, &ve) || ve.Kind != VerifyNoCredential {
		t.Fatalf("unknown user verify error: %+v", noUserErr)
	}
	if noUserErr.Error() != err.Error() {
		t.Fatalf("error text reveals user existence: %q vs %q", noUserErr.Error(), err.Error())
	}

	// Disabled outranks password verification.
	_, err = store.Verify("bob", "bob-pass")
	if !errors.As(err, &ve) || ve.Kind != VerifyDisabled {
		t.Fatalf("disabled verify error: %+v", err)
	}

	// Expired outranks password verification (wrong password still reports expired).
	for _, pw := range []string{"carol-pass", "wrong"} {
		_, err = store.Verify("carol", pw)
		if !errors.As(err, &ve) || ve.Kind != VerifyExpired {
			t.Fatalf("expired verify error for pw %q: %+v", pw, err)
		}
	}

	// A future expiry is fine.
	if _, err := store.Verify("dave", "dave-pass"); err != nil {
		t.Fatalf("Verify(dave): %v", err)
	}
}

func TestEnsureBootstrap(t *testing.T) {
	store, path := newFileStore(t)

	username, password, generated, err := store.EnsureBootstrap()
	if err != nil {
		t.Fatalf("EnsureBootstrap: %v", err)
	}
	if !generated {
		t.Fatal("first EnsureBootstrap did not generate")
	}
	if !strings.HasPrefix(username, "np-") || len(username) > 16 {
		t.Fatalf("bootstrap username = %q", username)
	}
	if len(password) != 24 {
		t.Fatalf("bootstrap password length = %d, want 24", len(password))
	}
	if _, err := store.Verify(username, password); err != nil {
		t.Fatalf("bootstrap credential cannot authenticate: %v", err)
	}

	// Second call must not generate again.
	username2, password2, generated2, err := store.EnsureBootstrap()
	if err != nil {
		t.Fatalf("second EnsureBootstrap: %v", err)
	}
	if generated2 || username2 != "" || password2 != "" {
		t.Fatalf("second EnsureBootstrap generated again: %q %q %v", username2, password2, generated2)
	}

	// The plain password must not be persisted.
	rawFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if strings.Contains(string(rawFile), password) {
		t.Fatal("credentials file contains the bootstrap plain password")
	}
	if got := readCredentialFile(t, path); len(got) != 1 {
		t.Fatalf("persisted credentials = %d, want 1", len(got))
	}

	// Restart: no new credential, the same password still authenticates.
	reloaded, err := NewCredentialStore(path, testLogger())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer reloaded.Close()
	if _, _, generated3, err := reloaded.EnsureBootstrap(); err != nil || generated3 {
		t.Fatalf("EnsureBootstrap after restart: generated=%v err=%v", generated3, err)
	}
	if _, err := reloaded.Verify(username, password); err != nil {
		t.Fatalf("bootstrap credential invalid after restart: %v", err)
	}
}

func TestEnsureBootstrapMemoryStore(t *testing.T) {
	store := newMemoryStore(t)
	_, _, generated, err := store.EnsureBootstrap()
	if err != nil || !generated {
		t.Fatalf("memory EnsureBootstrap: generated=%v err=%v", generated, err)
	}
	if _, _, generated2, err := store.EnsureBootstrap(); err != nil || generated2 {
		t.Fatalf("second memory EnsureBootstrap: generated=%v err=%v", generated2, err)
	}
}

func TestMarkUsedThrottleAndCloseFlush(t *testing.T) {
	store, path := newFileStore(t)
	cred, err := store.Create(mkCredential(t, "usage", "usage-pass"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Make the throttle deterministic: without Close/Flush nothing may be
	// written no matter how long the burst takes.
	if store.flushInterval != time.Second {
		t.Fatalf("default flush interval = %v, want 1s", store.flushInterval)
	}
	store.flushInterval = time.Hour

	// Unknown ids are a silent no-op (credential may be deleted concurrently).
	if err := store.MarkUsed("missing", 1, 1); err != nil {
		t.Fatalf("MarkUsed(unknown id) = %v", err)
	}

	const calls = 40
	for i := 0; i < calls; i++ {
		if err := store.MarkUsed(cred.ID, 10, 20); err != nil {
			t.Fatalf("MarkUsed: %v", err)
		}
	}
	// In-memory view is immediately current.
	got, _ := store.Get(cred.ID)
	if got.BytesIn != calls*10 || got.BytesOut != calls*20 {
		t.Fatalf("in-memory usage = %d/%d, want %d/%d", got.BytesIn, got.BytesOut, calls*10, calls*20)
	}
	if got.LastUsedAt == nil {
		t.Fatal("MarkUsed did not set LastUsedAt")
	}
	// Within one second nothing was written: the burst above is throttled.
	persisted := readCredentialFile(t, path)
	if len(persisted) != 1 || persisted[0].BytesIn != 0 {
		t.Fatalf("MarkUsed burst was not throttled: %+v", persisted)
	}

	// Close must flush the accumulated usage.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	persisted = readCredentialFile(t, path)
	if len(persisted) != 1 {
		t.Fatalf("persisted records = %d", len(persisted))
	}
	if persisted[0].BytesIn != calls*10 || persisted[0].BytesOut != calls*20 || persisted[0].LastUsedAt == nil {
		t.Fatalf("Close did not flush usage: %+v", persisted[0])
	}
}

func TestLoadCorruptMainFallsBackToBackup(t *testing.T) {
	store, path := newFileStore(t)
	cred, err := store.Create(mkCredential(t, "backup", "backup-pass"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// First save wrote the main file; the update moves the previous version to
	// credentials.json.bak and writes the new version to the main file.
	cred.Note = "version-2"
	if _, err := store.Update(cred); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("corrupt main: %v", err)
	}

	reloaded, err := NewCredentialStore(path, testLogger())
	if err != nil {
		t.Fatalf("NewCredentialStore with corrupt main: %v", err)
	}
	defer reloaded.Close()
	list := reloaded.List()
	if len(list) != 1 || list[0].ID != cred.ID {
		t.Fatalf("backup fallback loaded %+v", list)
	}
	if list[0].Note != "test credential" {
		t.Fatalf("backup fallback note = %q, want the previous version", list[0].Note)
	}

	// Missing main file also falls back to the backup.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove main: %v", err)
	}
	reloaded2, err := NewCredentialStore(path, testLogger())
	if err != nil {
		t.Fatalf("NewCredentialStore with missing main: %v", err)
	}
	defer reloaded2.Close()
	if len(reloaded2.List()) != 1 {
		t.Fatal("missing-main fallback did not load the backup")
	}
}

func TestLoadBothCorruptFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path, testLogger())
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	if _, err := store.Create(mkCredential(t, "broken", "broken-pass")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("corrupt main: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("garbage too"), 0o600); err != nil {
		t.Fatalf("corrupt backup: %v", err)
	}
	if _, err := NewCredentialStore(path, testLogger()); err == nil {
		t.Fatal("NewCredentialStore succeeded with both files corrupt")
	}
}

func TestCredentialStoreClosed(t *testing.T) {
	store := newMemoryStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := store.Create(mkCredential(t, "late", "late-pass")); err == nil {
		t.Fatal("Create after Close succeeded")
	}
	if _, err := store.Update(model.Credential{ID: "x", Username: "x"}); err == nil {
		t.Fatal("Update after Close succeeded")
	}
	if err := store.Delete("x"); err == nil {
		t.Fatal("Delete after Close succeeded")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Reads remain available after close.
	_ = store.List()
}
