package auth

import (
	"fmt"
	"sync"
	"testing"

	"proxygw/internal/model"
)

// TestConcurrentCredentialOperations exercises Verify, MarkUsed, List, Get and a
// metadata read concurrently. Run with -race; the test fails on any data race or
// on counter loss.
func TestConcurrentCredentialOperations(t *testing.T) {
	store := newMemoryStore(t)
	cred, err := store.Create(model.Credential{
		Username:     "concurrent",
		PasswordHash: mustCheapHash(t, "concurrent-pass"),
		Enabled:      true,
		Groups:       []string{"g1", "g2"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const goroutines = 50
	const markBytesIn = 10
	const markBytesOut = 20
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*3)
	for i := 0; i < goroutines; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			got, err := store.Verify("concurrent", "concurrent-pass")
			if err != nil {
				errCh <- fmt.Errorf("Verify: %w", err)
				return
			}
			if got.ID != cred.ID {
				errCh <- fmt.Errorf("Verify returned id %q, want %q", got.ID, cred.ID)
			}
		}()
		go func() {
			defer wg.Done()
			if err := store.MarkUsed(cred.ID, markBytesIn, markBytesOut); err != nil {
				errCh <- fmt.Errorf("MarkUsed: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			if n := len(store.List()); n != 1 {
				errCh <- fmt.Errorf("List len = %d, want 1", n)
			}
			if _, ok := store.Get(cred.ID); !ok {
				errCh <- fmt.Errorf("Get(%q) not found", cred.ID)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	got, ok := store.Get(cred.ID)
	if !ok {
		t.Fatal("credential disappeared")
	}
	if got.BytesIn != goroutines*markBytesIn || got.BytesOut != goroutines*markBytesOut {
		t.Fatalf("usage = %d/%d, want %d/%d", got.BytesIn, got.BytesOut,
			goroutines*markBytesIn, goroutines*markBytesOut)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
