package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP parameters. SHA1 and 6 digits are the interoperability defaults of RFC
// 6238 and what every authenticator application supports out of the box.
const (
	totpPeriod = 30 // seconds per time step
	totpDigits = 6
	totpWindow = 1 // accept +/- 1 time step to tolerate clock skew
)

// normalizeTOTPSecret uppercases, strips spaces and validates a base32 secret.
// An empty secret means "TOTP disabled" and is valid.
func normalizeTOTPSecret(raw string) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	if s == "" {
		return "", nil
	}
	if len(s) < 16 || len(s) > 64 {
		return "", fmt.Errorf("TOTP 密钥长度非法：base32 编码后需为 16-64 个字符")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("TOTP 密钥不是合法的 base32: %w", err)
	}
	if len(key) < 10 {
		return "", fmt.Errorf("TOTP 密钥过短（至少 10 字节）")
	}
	return s, nil
}

// decodeTOTPSecret decodes an already normalized base32 secret.
func decodeTOTPSecret(secret string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
}

// totpCode computes the RFC 6238 code for counter (unix time / period) using
// HMAC-SHA1 and the requested number of decimal digits.
func totpCode(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// validTOTP reports whether code is the current TOTP code for secret at time
// now, allowing +/- one time step of clock skew. The comparison is constant
// time; malformed codes are rejected without panicking.
func validTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil || len(key) == 0 {
		return false
	}
	counter := now.Unix() / totpPeriod
	for delta := int64(-totpWindow); delta <= totpWindow; delta++ {
		c := counter + delta
		if c < 0 {
			continue
		}
		candidate := totpCode(key, uint64(c), totpDigits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
