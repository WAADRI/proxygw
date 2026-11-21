// Package identity manages the persistent node identity of the client binary.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"proxygw/internal/store"
)

// ClientIDFile is the file name inside the state directory.
const ClientIDFile = "client-id"

// LoadOrCreate returns the persistent client id, generating and persisting a
// random one when the state directory does not contain it yet. The returned
// bool reports whether the id was generated during this call.
func LoadOrCreate(stateDir string) (id string, generated bool, err error) {
	if strings.TrimSpace(stateDir) == "" {
		return "", false, fmt.Errorf("identity: empty state directory")
	}
	path := filepath.Join(stateDir, ClientIDFile)
	if data, readErr := os.ReadFile(path); readErr == nil {
		id = strings.TrimSpace(string(data))
		if ValidClientID(id) {
			return id, false, nil
		}
		// A corrupted id file is regenerated rather than blocking startup.
	}
	id, err = GenerateClientID()
	if err != nil {
		return "", false, err
	}
	if err := store.WriteFileAtomic(path, []byte(id+"\n"), 0o600); err != nil {
		return "", false, fmt.Errorf("identity: persist client id: %w", err)
	}
	return id, true, nil
}

// GenerateClientID returns a random 128-bit hex identifier.
func GenerateClientID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("identity: generate client id: %w", err)
	}
	return "node-" + hex.EncodeToString(buf), nil
}

// ValidClientID mirrors config validation: 1-64 chars of [A-Za-z0-9_.:-].
func ValidClientID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}
