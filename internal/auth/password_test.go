package auth

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordAndVerify(t *testing.T) {
	const password = "Corr3ct-Horse-Battery-Staple!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if strings.Contains(hash, password) {
		t.Fatalf("hash leaks the plain password: %q", hash)
	}
	const wantPrefix = "$argon2id$v=19$m=65536,t=3,p=2$"
	if !strings.HasPrefix(hash, wantPrefix) {
		t.Fatalf("unexpected PHC prefix: %q", hash)
	}
	if !PasswordHashSupported(hash) {
		t.Fatalf("PasswordHashSupported(%q) = false", hash)
	}
	ok, err := VerifyPassword(hash, password)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword(correct) = %v, %v", ok, err)
	}
	ok, err = VerifyPassword(hash, password+"x")
	if err != nil {
		t.Fatalf("VerifyPassword(wrong) unexpected error: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword(wrong) = true")
	}
	// A fresh salt must produce a different hash for the same password.
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword second: %v", err)
	}
	if hash2 == hash {
		t.Fatal("two hashes of the same password are identical (salt reuse)")
	}
}

func TestHashPasswordRejectsEmptyAndLong(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("HashPassword(\"\") should fail")
	}
	if _, err := HashPassword(strings.Repeat("a", maxPasswordLength+1)); err == nil {
		t.Fatal("HashPassword(over-long) should fail")
	}
}

func TestVerifyPasswordArgon2CustomParams(t *testing.T) {
	// The verifier must honour the parameters stored in the PHC string, not
	// only the defaults used by HashPassword.
	hash := mustCheapHash(t, "custom-params")
	ok, err := VerifyPassword(hash, "custom-params")
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v", ok, err)
	}
	if ok, _ := VerifyPassword(hash, "other"); ok {
		t.Fatal("wrong password accepted for custom parameter hash")
	}
}

func TestVerifyPasswordCorruptHashes(t *testing.T) {
	corrupt := []string{
		"",
		"plaintext",
		"$argon2id$",
		"$argon2id$v=19$m=65536,t=3,p=2",
		"$argon2id$v=99$m=65536,t=3,p=2$" + strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=notanumber,t=3,p=2$" + strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=65536$" + strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=999999999,t=3,p=2$" + strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=65536,t=3,p=2$" + strings.Repeat("*", 22) + "$" + strings.Repeat("A", 43),
		// Valid base64 but a 5-byte salt: rejected by the length bound.
		"$argon2id$v=19$m=65536,t=3,p=2$" + base64.RawStdEncoding.EncodeToString([]byte("short")) + "$" + strings.Repeat("A", 43),
		"$2b$not-a-real-bcrypt-hash",
	}
	for _, encoded := range corrupt {
		ok, err := VerifyPassword(encoded, "whatever")
		if ok {
			t.Errorf("VerifyPassword(%q) returned true", encoded)
		}
		if err == nil {
			t.Errorf("VerifyPassword(%q) returned no error", encoded)
		}
	}
}

func TestVerifyPasswordBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("bcrypt-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	encoded := string(hash)
	if !PasswordHashSupported(encoded) {
		t.Fatalf("PasswordHashSupported(bcrypt) = false for %q", encoded)
	}
	ok, err := VerifyPassword(encoded, "bcrypt-password")
	if err != nil || !ok {
		t.Fatalf("VerifyPassword(bcrypt correct) = %v, %v", ok, err)
	}
	ok, err = VerifyPassword(encoded, "wrong")
	if err != nil || ok {
		t.Fatalf("VerifyPassword(bcrypt wrong) = %v, %v", ok, err)
	}
}

func TestPasswordHashSupported(t *testing.T) {
	cases := []struct {
		hash string
		want bool
	}{
		{mustCheapHash(t, "x"), true},
		{"$2b$10$" + strings.Repeat("A", 53), true},
		{"", false},
		{"$argon2id$v=19$m=65536,t=3,p=2$short$short", false},
		{"$argon2i$v=19$m=65536,t=3,p=2$" + strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43), false},
		{"$2b$99$" + strings.Repeat("A", 53), false},
	}
	for _, tc := range cases {
		if got := PasswordHashSupported(tc.hash); got != tc.want {
			t.Errorf("PasswordHashSupported(%q) = %v, want %v", tc.hash, got, tc.want)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	pw, err := GeneratePassword(24)
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if len(pw) != 24 {
		t.Fatalf("length = %d, want 24", len(pw))
	}
	for _, r := range pw {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			t.Fatalf("password contains non URL-safe char %q: %q", r, pw)
		}
	}
	pw2, err := GeneratePassword(24)
	if err != nil {
		t.Fatalf("GeneratePassword second: %v", err)
	}
	if pw == pw2 {
		t.Fatal("two generated passwords are identical")
	}
	if _, err := GeneratePassword(0); err == nil {
		t.Fatal("GeneratePassword(0) should fail")
	}
	if _, err := GeneratePassword(maxGeneratedLength + 1); err == nil {
		t.Fatal("GeneratePassword(too long) should fail")
	}
}
