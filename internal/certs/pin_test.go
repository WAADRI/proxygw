package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParsePinVariants(t *testing.T) {
	digest := sha256.Sum256([]byte("proxygw test pin material"))
	canonical := PinPrefix + base64.StdEncoding.EncodeToString(digest[:])
	hexDigest := hex.EncodeToString(digest[:])
	rawBase64 := base64.StdEncoding.EncodeToString(digest[:])
	urlBase64 := base64.URLEncoding.EncodeToString(digest[:])
	rawStdNoPad := base64.RawStdEncoding.EncodeToString(digest[:])

	cases := []struct {
		name string
		in   string
	}{
		{"canonical", canonical},
		{"bare base64", rawBase64},
		{"sha256 prefix + hex", "sha256/" + hexDigest},
		{"bare hex", hexDigest},
		{"uppercase hex", strings.ToUpper(hexDigest)},
		{"sha256 colon + hex", "sha256:" + hexDigest},
		{"url safe base64", "sha256/" + urlBase64},
		{"unpadded base64", "sha256/" + rawStdNoPad},
		{"leading/trailing whitespace", "  " + canonical + "\n\t"},
		{"uppercase prefix", "SHA256/" + rawBase64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePin(tc.in)
			if err != nil {
				t.Fatalf("ParsePin(%q) 返回错误: %v", tc.in, err)
			}
			if got != canonical {
				t.Fatalf("ParsePin(%q) = %q，期望 %q", tc.in, got, canonical)
			}
		})
	}
}

func TestParsePinInvalid(t *testing.T) {
	tooShort := base64.StdEncoding.EncodeToString([]byte("short"))
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"spaces", "   "},
		{"prefix only", "sha256/"},
		{"garbage", "not-a-pin!"},
		{"wrong digest length", "sha256/" + tooShort},
		{"odd hex", "sha256/" + strings.Repeat("a", 63)},
		{"bad characters", "sha256/abc$def"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParsePin(tc.in); err == nil {
				t.Fatalf("ParsePin(%q) = %q，期望错误", tc.in, got)
			}
		})
	}
}

func TestSPKIPinFromGeneratedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, _, pin, err := GenerateIdentity([]string{"example.com"}, []string{"127.0.0.1"}, dir)
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	cert := pemCert(t, certData)
	got, err := SPKIPin(cert)
	if err != nil {
		t.Fatalf("SPKIPin 失败: %v", err)
	}
	if got != pin {
		t.Fatalf("SPKIPin = %q，GenerateIdentity 返回 %q", got, pin)
	}
	normalized, err := ParsePin(pin)
	if err != nil || normalized != pin {
		t.Fatalf("生成的 pin 不是规范形式: %q, err=%v", pin, err)
	}
}

func TestSPKIPinNilAndMissingSPKI(t *testing.T) {
	if _, err := SPKIPin(nil); err == nil {
		t.Fatal("SPKIPin(nil) 期望错误")
	}
	if _, err := SPKIPin(&x509.Certificate{}); err == nil {
		t.Fatal("SPKIPin(缺少 SPKI) 期望错误")
	}
}

func TestPinMismatchError(t *testing.T) {
	expected := randomPin(t)
	actual := randomPin(t)
	err := &PinMismatchError{Addr: "node.example.com:443", Expected: []string{expected}, Actual: []string{actual}}
	msg := err.Error()
	for _, want := range []string{expected, actual, "排查建议", "node.example.com:443", "期望指纹", "实际指纹"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息缺少 %q: %s", want, msg)
		}
	}
	if !IsPinMismatch(err) {
		t.Fatal("IsPinMismatch 对 *PinMismatchError 应返回 true")
	}
	if !IsPinMismatch(fmt.Errorf("握手失败: %w", err)) {
		t.Fatal("IsPinMismatch 对包装后的错误应返回 true")
	}
	if IsPinMismatch(errors.New("other")) || IsPinMismatch(nil) {
		t.Fatal("IsPinMismatch 对无关错误/nil 应返回 false")
	}
	// Empty slices must still yield a useful Chinese message.
	empty := (&PinMismatchError{}).Error()
	if !strings.Contains(empty, "未配置") || !strings.Contains(empty, "对端未提供证书") {
		t.Fatalf("空字段错误信息不完整: %s", empty)
	}
	var nilErr *PinMismatchError
	if got := nilErr.Error(); got == "" {
		t.Fatal("nil PinMismatchError.Error() 不应为空")
	}
}

func TestPinEqual(t *testing.T) {
	pin := randomPin(t)
	if !pinEqual(pin, pin) {
		t.Fatal("相同 pin 应相等")
	}
	if pinEqual(pin, randomPin(t)) {
		t.Fatal("不同 pin 不应相等")
	}
	if pinEqual(pin, "sha256/") {
		t.Fatal("长度不同的 pin 不应相等")
	}
}
