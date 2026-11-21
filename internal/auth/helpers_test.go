package auth

import (
	"io"
	"log/slog"
	"testing"

	"golang.org/x/crypto/argon2"
)

// testLogger discards output so test runs stay quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mustCheapHash returns a syntactically valid argon2id PHC hash with deliberately
// small parameters. Only password_test.go exercises the production parameters;
// CRUD/concurrency/admin tests use cheap hashes so the suite stays fast.
func mustCheapHash(t *testing.T, password string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 1024, 1, 32)
	return encodeArgon2ID(salt, key, 1024, 1, 1)
}
