package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// TestTOTPRFC6238Vectors checks the HMAC-SHA1 implementation against the
// reference test vectors of RFC 6238 appendix B (secret "12345678901234567890").
func TestTOTPRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	vectors := []struct {
		unixSeconds int64
		want        string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, v := range vectors {
		got := totpCode(key, uint64(v.unixSeconds/30), 8)
		if got != v.want {
			t.Errorf("totpCode(T=%d) = %q, want %q", v.unixSeconds, got, v.want)
		}
	}
}

func totpTestSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
}

func TestTOTPSecretNormalization(t *testing.T) {
	secret := totpTestSecret()
	if secret != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("unexpected base32 test secret %q", secret)
	}
	messy := strings.ToLower(secret[:16]) + " " + strings.ToLower(secret[16:])
	normalized, err := normalizeTOTPSecret(messy)
	if err != nil {
		t.Fatalf("normalizeTOTPSecret: %v", err)
	}
	if normalized != secret {
		t.Fatalf("normalized = %q, want %q", normalized, secret)
	}
	if got, err := normalizeTOTPSecret(""); err != nil || got != "" {
		t.Fatalf("empty secret: %q, %v", got, err)
	}
	for _, bad := range []string{"not base32!", "AAAA", strings.Repeat("A", 100)} {
		if _, err := normalizeTOTPSecret(bad); err == nil {
			t.Errorf("normalizeTOTPSecret(%q) accepted an invalid secret", bad)
		}
	}
}

func TestValidTOTPWindow(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := totpTestSecret()
	now := time.Unix(59, 0) // time step 1
	codeAt := func(counter int64) string { return totpCode(key, uint64(counter), totpDigits) }

	if codeAt(1) != "287082" {
		t.Fatalf("current code = %q, want 287082", codeAt(1))
	}
	// +/- one time step is accepted.
	for _, counter := range []int64{0, 1, 2} {
		if !validTOTP(secret, codeAt(counter), now) {
			t.Errorf("code for counter %d rejected at T=59", counter)
		}
	}
	// Two steps away is rejected.
	for _, counter := range []int64{-2, 3, 4} {
		if validTOTP(secret, codeAt(counter), now) {
			t.Errorf("code for counter %d accepted at T=59", counter)
		}
	}
	// Malformed codes never panic.
	for _, code := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if validTOTP(secret, code, now) {
			t.Errorf("malformed code %q accepted", code)
		}
	}
	// Surrounding whitespace is tolerated.
	if !validTOTP(secret, " 287082 ", now) {
		t.Error("code with surrounding whitespace rejected")
	}
	if validTOTP(secret, "287082", time.Unix(-100, 0)) {
		t.Error("negative timestamps must not panic or validate")
	}
}
