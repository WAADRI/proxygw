// Package certs implements the proxygw transport identity layer: server
// identity certificate generation and hot reload, SPKI certificate pinning,
// CA based verification and mTLS.
//
// The server only ever holds one identity certificate, shared by the QUIC
// tunnel, the wss tunnel and the panel. Trust is established in one of three
// modes:
//
//   - pin: the client pins the SHA-256 of the certificate's SubjectPublicKeyInfo
//     (SPKI), so re-issuing a certificate with the same key pair is transparent
//     to the whole fleet. Multiple pins may be active at once to support key
//     rotation windows.
//   - ca: standard CA based verification against the system roots or a custom
//     CA bundle.
//   - insecure: verification disabled, development only, always warns loudly.
package certs

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// PinPrefix is the canonical prefix of an SPKI SHA-256 pin. A pin always looks
// like "sha256/<standard base64 of the 32 byte digest>".
const PinPrefix = "sha256/"

// SPKIPin returns the canonical pin of cert: the SHA-256 digest of the
// DER-encoded SubjectPublicKeyInfo, base64 (standard encoding) and prefixed
// with "sha256/".
//
// Pinning the SPKI instead of the whole certificate means that re-issuing a
// certificate while keeping the same key pair does not change the pin, so a
// fleet of nodes keeps working across certificate renewals.
func SPKIPin(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certs: SPKIPin: 证书为 nil")
	}
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "", errors.New("certs: SPKIPin: 证书缺少 SubjectPublicKeyInfo 数据")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:]), nil
}

// ParsePin normalizes an SPKI SHA-256 pin. Accepted input forms:
//
//	sha256/<base64>   canonical
//	<base64>          standard or URL-safe, padded or unpadded
//	sha256/<hex>      64 hex characters
//	<hex>             64 hex characters
//
// Whitespace around the value and a case-insensitive "sha256/" or "sha256:"
// prefix are tolerated. The returned value is always canonical
// ("sha256/" + standard base64).
func ParsePin(s string) (string, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return "", errors.New("certs: pin 为空")
	}
	if len(raw) >= len(PinPrefix) && strings.EqualFold(raw[:len(PinPrefix)], PinPrefix) {
		raw = raw[len(PinPrefix):]
	} else if len(raw) >= len("sha256:") && strings.EqualFold(raw[:len("sha256:")], "sha256:") {
		raw = raw[len("sha256:"):]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("certs: 无效的 pin %q：缺少摘要值", s)
	}
	// Hexadecimal input is auto-normalized; check it before base64 because all
	// hex characters are also valid base64 characters.
	if len(raw) == 2*sha256.Size && isHexString(raw) {
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			return "", fmt.Errorf("certs: 无效的 pin %q：十六进制解析失败: %w", s, err)
		}
		return canonicalPin(decoded, s)
	}
	decoded, err := decodeBase64Lenient(raw)
	if err != nil {
		return "", fmt.Errorf("certs: 无效的 pin %q：应为 sha256/<base64>（32 字节）或 64 位十六进制: %w", s, err)
	}
	return canonicalPin(decoded, s)
}

// decodeBase64Lenient accepts the four common base64 alphabets/paddings because
// pins are often copied from browsers, shell scripts or web panels.
func decodeBase64Lenient(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var firstErr error
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(s)
		if err == nil {
			return decoded, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func canonicalPin(decoded []byte, original string) (string, error) {
	if len(decoded) != sha256.Size {
		return "", fmt.Errorf("certs: 无效的 pin %q：摘要应为 %d 字节，实际 %d 字节", original, sha256.Size, len(decoded))
	}
	return PinPrefix + base64.StdEncoding.EncodeToString(decoded), nil
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// pinEqual compares two canonical pins in constant time. Callers must pass
// normalized pins for the length shortcut to be constant-time for real input.
func pinEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// PinMismatchError is returned when a pinned peer certificate does not match any
// of the expected SPKI pins. It carries both sides of the comparison so the
// operator can tell a key rotation apart from an interception attempt.
type PinMismatchError struct {
	// Addr is the dialed target or overridden server name, when known.
	Addr string
	// Expected lists the configured, normalized pins.
	Expected []string
	// Actual lists the observed, normalized pins.
	Actual []string
}

// Error implements error. The message always contains the expected and the
// actual fingerprints plus Chinese troubleshooting advice.
func (e *PinMismatchError) Error() string {
	if e == nil {
		return "certs: <nil PinMismatchError>"
	}
	var b strings.Builder
	b.WriteString("TLS 公钥指纹（SPKI pin）校验失败")
	if e.Addr != "" {
		b.WriteString("：目标 ")
		b.WriteString(e.Addr)
	}
	b.WriteString("。期望指纹：")
	if len(e.Expected) == 0 {
		b.WriteString("（未配置）")
	} else {
		b.WriteString(strings.Join(e.Expected, " 或 "))
	}
	b.WriteString("；实际指纹：")
	if len(e.Actual) == 0 {
		b.WriteString("（对端未提供证书）")
	} else {
		b.WriteString(strings.Join(e.Actual, "，"))
	}
	b.WriteString("。排查建议：")
	b.WriteString("1) 确认连接的地址正确且未被中间人劫持；")
	b.WriteString("2) 确认服务端密钥是否被更换——只重签证书（保留密钥）不会改变指纹，换密钥才会；")
	b.WriteString("3) 若正在轮换密钥，请把服务端 pin_next 下发到节点并同时保留新旧两枚 pin；")
	b.WriteString("4) 核对无误后更新配置 tls.pins 再重连；")
	b.WriteString("5) pin 模式不会降级为“不校验证书”，请勿尝试关闭校验。")
	return b.String()
}

// IsPinMismatch reports whether err (or any wrapped error) is a
// *PinMismatchError.
func IsPinMismatch(err error) bool {
	var target *PinMismatchError
	return errors.As(err, &target)
}

// pinFromRawCerts parses the leaf certificate supplied by the peer and returns
// its canonical SPKI pin. The TLS verify callback must do this itself because
// rawCerts contains DER data, not parsed certificates.
func pinFromRawCerts(rawCerts [][]byte) (string, error) {
	if len(rawCerts) == 0 {
		return "", errors.New("certs: 对端未提供任何证书，无法校验 SPKI pin")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("certs: 解析对端叶子证书失败: %w", err)
	}
	return SPKIPin(leaf)
}
