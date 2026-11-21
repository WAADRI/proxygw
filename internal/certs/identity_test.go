package certs

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testYearTolerance = 10 * time.Minute

func TestGenerateIdentity(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"Example.COM", "example.com", "panel.example.com", ""}
	ips := []string{"127.0.0.1", "127.0.0.1", "::1"}
	now := time.Now()
	certPath, keyPath, pin, err := GenerateIdentity(hosts, ips, dir)
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	if want := filepath.Join(dir, CertFileName); certPath != want {
		t.Fatalf("证书路径 = %q，期望 %q", certPath, want)
	}
	if want := filepath.Join(dir, KeyFileName); keyPath != want {
		t.Fatalf("私钥路径 = %q，期望 %q", keyPath, want)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("证书文件不存在: %v", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("私钥文件不存在: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := keyInfo.Mode().Perm(); perm != 0o600 {
			t.Fatalf("私钥权限 = %04o，期望 0600", perm)
		}
		certInfo, err := os.Stat(certPath)
		if err != nil {
			t.Fatalf("stat 证书失败: %v", err)
		}
		if perm := certInfo.Mode().Perm(); perm != 0o644 {
			t.Fatalf("证书权限 = %04o，期望 0644", perm)
		}
	}

	// Private key: ECDSA P-256, PEM encoded.
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取私钥失败: %v", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("私钥 PEM 类型不正确: %v", block)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
	if got := key.Curve.Params().Name; got != "P-256" {
		t.Fatalf("私钥曲线 = %q，期望 P-256", got)
	}

	// Certificate contents.
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	cert := pemCert(t, certData)
	if cert.IsCA {
		t.Fatal("自签身份证书不应是 CA")
	}
	if !cert.BasicConstraintsValid {
		t.Fatal("自签身份证书应设置 BasicConstraintsValid")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("KeyUsage 缺少 DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("KeyUsage 缺少 KeyEncipherment")
	}
	if !hasExtKeyUsage(cert, x509.ExtKeyUsageServerAuth) || !hasExtKeyUsage(cert, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("ExtKeyUsage = %v，期望包含 ServerAuth 与 ClientAuth", cert.ExtKeyUsage)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("序列号无效: %v", cert.SerialNumber)
	}
	if delta := cert.NotAfter.Sub(now.Add(certValidity)); delta > testYearTolerance || delta < -testYearTolerance {
		t.Fatalf("NotAfter 与 now+1 年相差过大: %v", delta)
	}
	if delta := cert.NotBefore.Sub(now.Add(-clockSkewBackdate)); delta > testYearTolerance || delta < -testYearTolerance {
		t.Fatalf("NotBefore 与 now-1h 相差过大: %v", delta)
	}
	if want := certValidity + clockSkewBackdate; cert.NotAfter.Sub(cert.NotBefore) != want {
		t.Fatalf("证书有效期 = %v，期望 %v", cert.NotAfter.Sub(cert.NotBefore), want)
	}
	wantDNS := map[string]bool{"example.com": true, "panel.example.com": true}
	if len(cert.DNSNames) != len(wantDNS) {
		t.Fatalf("DNSNames = %v，期望去重后的 %v", cert.DNSNames, wantDNS)
	}
	for _, name := range cert.DNSNames {
		if !wantDNS[name] {
			t.Fatalf("意外的 DNS SAN %q", name)
		}
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %v，期望去重后的 127.0.0.1 与 ::1", cert.IPAddresses)
	}
	if got, err := SPKIPin(cert); err != nil || got != pin {
		t.Fatalf("SPKIPin(cert) = %q, err=%v，期望 %q", got, err, pin)
	}

	// A second generation must use a fresh key (different pin).
	_, _, otherPin, err := GenerateIdentity(hosts, ips, t.TempDir())
	if err != nil {
		t.Fatalf("第二次 GenerateIdentity 失败: %v", err)
	}
	if otherPin == pin {
		t.Fatal("两次生成的 pin 不应相同")
	}
}

func TestGenerateIdentityClassifiesIPSANs(t *testing.T) {
	certPath, _, _, err := GenerateIdentity([]string{"192.0.2.10", "localhost"}, nil, t.TempDir())
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	cert := pemCert(t, data)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "localhost" {
		t.Fatalf("DNSNames = %v，期望仅 localhost", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IPAddresses = %v，期望 192.0.2.10", cert.IPAddresses)
	}
}

func TestGenerateIdentityInvalidIP(t *testing.T) {
	_, _, _, err := GenerateIdentity(nil, []string{"not-an-ip"}, t.TempDir())
	if err == nil {
		t.Fatal("无效 IP 期望错误")
	}
	if !strings.Contains(err.Error(), "无效的 IP") {
		t.Fatalf("错误信息缺少上下文: %v", err)
	}
}

func TestGenerateIdentityEmptySANs(t *testing.T) {
	certPath, _, pin, err := GenerateIdentity(nil, nil, t.TempDir())
	if err != nil {
		t.Fatalf("未配置 SAN 时 GenerateIdentity 失败: %v", err)
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	cert := pemCert(t, data)
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Fatalf("空 SAN 输入产生了 SAN: dns=%v ip=%v", cert.DNSNames, cert.IPAddresses)
	}
	if cert.Subject.CommonName != "proxygw" {
		t.Fatalf("CommonName = %q，期望 proxygw", cert.Subject.CommonName)
	}
	if _, err := ParsePin(pin); err != nil {
		t.Fatalf("生成的 pin 无效: %v", err)
	}
}

func TestGenerateAdditionalKey(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost"}
	ips := []string{"127.0.0.1"}
	_, _, basePin, err := GenerateIdentity(hosts, ips, dir)
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	certPath, keyPath, nextPin, err := GenerateAdditionalKey(hosts, ips, dir)
	if err != nil {
		t.Fatalf("GenerateAdditionalKey 失败: %v", err)
	}
	wantDir := filepath.Join(dir, NextDirName)
	if filepath.Dir(certPath) != wantDir {
		t.Fatalf("轮换证书路径 = %q，期望位于 %q", certPath, wantDir)
	}
	if filepath.Dir(keyPath) != wantDir {
		t.Fatalf("轮换私钥路径 = %q，期望位于 %q", keyPath, wantDir)
	}
	if nextPin == basePin {
		t.Fatal("轮换密钥的 pin 不应等于当前身份 pin")
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取轮换证书失败: %v", err)
	}
	cert := pemCert(t, data)
	if cert.DNSNames[0] != "localhost" {
		t.Fatalf("轮换证书 SAN = %v", cert.DNSNames)
	}
	if got, err := SPKIPin(cert); err != nil || got != nextPin {
		t.Fatalf("轮换证书 SPKIPin = %q, err=%v，期望 %q", got, err, nextPin)
	}
}

func TestSameKeyReissueKeepsPin(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost"}
	ips := []string{"127.0.0.1"}
	certPath, keyPath, pin, err := GenerateIdentity(hosts, ips, dir)
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	oldCertData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	oldCert := pemCert(t, oldCertData)
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取私钥失败: %v", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		t.Fatal("私钥不是 PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
	// Re-issue a certificate for the SAME key with a later validity window,
	// emulating "renew the certificate, keep the key pair".
	newDER, err := selfSignedCertificate(hosts, ips, key, time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatalf("用同一私钥重新签发证书失败: %v", err)
	}
	newCert, err := x509.ParseCertificate(newDER)
	if err != nil {
		t.Fatalf("解析新证书失败: %v", err)
	}
	oldPin, err := SPKIPin(oldCert)
	if err != nil {
		t.Fatalf("SPKIPin 失败: %v", err)
	}
	newPin, err := SPKIPin(newCert)
	if err != nil {
		t.Fatalf("SPKIPin 失败: %v", err)
	}
	if oldPin != pin || newPin != pin {
		t.Fatalf("保留私钥重签后 pin 变化: old=%q new=%q expected=%q", oldPin, newPin, pin)
	}
	if oldCert.SerialNumber.Cmp(newCert.SerialNumber) == 0 {
		t.Fatal("重新签发的证书应有新的随机序列号")
	}
	if !newCert.NotAfter.After(oldCert.NotAfter) {
		t.Fatal("重新签发的证书 NotAfter 应更晚")
	}
	// The re-issued certificate parses and round-trips through a manager.
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newDER}), 0o644)
	m := newServerManager(t, ServerOptions{Mode: "pin", CertFile: certPath, KeyFile: keyPath, Dir: dir, Logger: quietLogger()})
	if got := m.Status().Pin; got != pin {
		t.Fatalf("重签证书后 Manager pin = %q，期望 %q", got, pin)
	}
	if got := m.Status().NotAfter; !got.Equal(newCert.NotAfter) {
		t.Fatalf("Manager NotAfter = %v，期望 %v", got, newCert.NotAfter)
	}
}

func TestIdentityDirDefaults(t *testing.T) {
	if got := identityDir("", false); got != filepath.Join("state", "certs") {
		t.Fatalf("identityDir(\"\", false) = %q，期望 state/certs", got)
	}
	if got := identityDir(" /tmp/ids ", true); got != filepath.Join("/tmp/ids", NextDirName) {
		t.Fatalf("identityDir(next) = %q", got)
	}
	if filepath.Clean(DefaultDir) != filepath.Join("state", "certs") {
		t.Fatalf("DefaultDir = %q，期望 state/certs", DefaultDir)
	}
}

func hasExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, got := range cert.ExtKeyUsage {
		if got == usage {
			return true
		}
	}
	return false
}
