package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewServerManagerAutoGeneratesPinIdentity(t *testing.T) {
	dir := t.TempDir()
	m := newServerManager(t, ServerOptions{
		Mode:   "pin",
		Dir:    dir,
		Hosts:  []string{"localhost"},
		IPs:    []string{"127.0.0.1"},
		Logger: quietLogger(),
	})
	status := m.Status()
	if status.Mode != "pin" {
		t.Fatalf("Mode = %q", status.Mode)
	}
	if status.CertPath != filepath.Join(dir, CertFileName) {
		t.Fatalf("CertPath = %q", status.CertPath)
	}
	if status.KeyPath != filepath.Join(dir, KeyFileName) {
		t.Fatalf("KeyPath = %q", status.KeyPath)
	}
	if _, err := ParsePin(status.Pin); err != nil {
		t.Fatalf("Status().Pin 不是合法 pin: %v", err)
	}
	if status.PinNext != "" || status.LastError != "" {
		t.Fatalf("初始 PinNext/LastError 应为空: %+v", status)
	}
	if status.LastReload.IsZero() {
		t.Fatal("初始 LastReload 不应为零值")
	}
	if delta := time.Until(status.NotAfter); delta < certValidity-testYearTolerance {
		t.Fatalf("NotAfter 距今 %v，期望约 1 年", delta)
	}
	if _, err := os.Stat(status.CertPath); err != nil {
		t.Fatalf("自动生成的证书缺失: %v", err)
	}
	if _, err := os.Stat(status.KeyPath); err != nil {
		t.Fatalf("自动生成的私钥缺失: %v", err)
	}

	cfg := m.TLSConfig()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v，期望 TLS 1.2", cfg.MinVersion)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("TLSConfig 缺少 GetCertificate")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v，期望 NoClientCert", cfg.ClientAuth)
	}
	if m.ClientCAs() != nil {
		t.Fatal("未启用 mTLS 时 ClientCAs 应为 nil")
	}
	pair, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || pair == nil || pair.Leaf == nil {
		t.Fatalf("GetCertificate 失败: pair=%v err=%v", pair, err)
	}
	if got, err := SPKIPin(pair.Leaf); err != nil || got != status.Pin {
		t.Fatalf("GetCertificate 返回的证书 pin = %q, err=%v，期望 %q", got, err, status.Pin)
	}
}

func TestNewServerManagerRestartKeepsPin(t *testing.T) {
	dir := t.TempDir()
	opts := ServerOptions{Mode: "pin", Dir: dir, Hosts: []string{"localhost"}, Logger: quietLogger()}
	first := newServerManager(t, opts)
	firstPin := first.Status().Pin
	if err := first.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	second := newServerManager(t, opts)
	if second.Status().Pin != firstPin {
		t.Fatalf("重启后 pin 变化: %q -> %q（不应重新生成密钥）", firstPin, second.Status().Pin)
	}
}

func TestNewServerManagerInsecureWarns(t *testing.T) {
	var buf bytes.Buffer
	m := newServerManager(t, ServerOptions{Mode: "insecure", Dir: t.TempDir(), Logger: captureLogger(&buf)})
	if m.Status().Mode != "insecure" {
		t.Fatalf("Mode = %q", m.Status().Mode)
	}
	if !strings.Contains(buf.String(), "安全警告") || !strings.Contains(buf.String(), "insecure") {
		t.Fatalf("insecure 模式缺少告警日志: %s", buf.String())
	}
}

func TestNewServerManagerCAMode(t *testing.T) {
	ca := newTestCA(t, "proxygw test ca")
	certPEM, keyPEM := ca.sign(t, []string{"localhost"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth)
	dir := t.TempDir()
	certPath := filepath.Join(dir, CertFileName)
	keyPath := filepath.Join(dir, KeyFileName)
	writeFile(t, certPath, certPEM, 0o644)
	writeFile(t, keyPath, keyPEM, 0o600)
	m := newServerManager(t, ServerOptions{
		Mode:     "ca",
		CertFile: certPath,
		KeyFile:  keyPath,
		Dir:      dir,
		Logger:   quietLogger(),
	})
	status := m.Status()
	if status.Mode != "ca" {
		t.Fatalf("Mode = %q", status.Mode)
	}
	leaf := pemCert(t, certPEM)
	if want, err := SPKIPin(leaf); err != nil || status.Pin != want {
		t.Fatalf("CA 模式 pin = %q, err=%v，期望 %q", status.Pin, err, want)
	}
	if !status.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("NotAfter = %v，期望 %v", status.NotAfter, leaf.NotAfter)
	}
}

func TestNewServerManagerValidation(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		opts ServerOptions
	}{
		{"invalid mode", ServerOptions{Mode: "bogus", Dir: dir}},
		{"cert without key", ServerOptions{Mode: "pin", CertFile: filepath.Join(dir, "c.pem"), Dir: dir}},
		{"key without cert", ServerOptions{Mode: "pin", KeyFile: filepath.Join(dir, "k.pem"), Dir: dir}},
		{"ca without explicit files", ServerOptions{Mode: "ca", Dir: dir}},
		{"ca with missing files", ServerOptions{Mode: "ca", CertFile: filepath.Join(dir, "missing.crt"), KeyFile: filepath.Join(dir, "missing.key"), Dir: dir}},
		{"invalid pin_next", ServerOptions{Mode: "pin", Dir: dir, PinNext: "not-a-pin"}},
		{"invalid client auth", ServerOptions{Mode: "pin", Dir: dir, ClientAuth: "sometimes"}},
		{"client auth require without ca", ServerOptions{Mode: "pin", Dir: dir, ClientAuth: "require"}},
		{"client auth require with unreadable ca", ServerOptions{Mode: "pin", Dir: dir, ClientAuth: "require", CAFile: filepath.Join(dir, "missing-ca.pem")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.opts.Dir == dir {
				tc.opts.Dir = t.TempDir()
				if tc.opts.CertFile != "" && strings.HasPrefix(tc.opts.CertFile, dir) {
					tc.opts.CertFile = filepath.Join(tc.opts.Dir, filepath.Base(tc.opts.CertFile))
				}
				if tc.opts.KeyFile != "" && strings.HasPrefix(tc.opts.KeyFile, dir) {
					tc.opts.KeyFile = filepath.Join(tc.opts.Dir, filepath.Base(tc.opts.KeyFile))
				}
				if tc.opts.CAFile != "" && strings.HasPrefix(tc.opts.CAFile, dir) {
					tc.opts.CAFile = filepath.Join(tc.opts.Dir, filepath.Base(tc.opts.CAFile))
				}
			}
			if tc.opts.Logger == nil {
				tc.opts.Logger = quietLogger()
			}
			m, err := NewServerManager(tc.opts)
			if err == nil {
				_ = m.Close()
				t.Fatalf("期望 NewServerManager 返回错误，实际成功")
			}
		})
	}
}

func TestNewServerManagerIncompleteIdentity(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _, err := GenerateIdentity([]string{"localhost"}, nil, dir)
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("删除私钥失败: %v", err)
	}
	_, err = NewServerManager(ServerOptions{Mode: "pin", CertFile: certPath, KeyFile: keyPath, Dir: dir, Logger: quietLogger()})
	if err == nil {
		t.Fatal("证书存在但私钥缺失时期望报错（不得静默重建）")
	}
	if !strings.Contains(err.Error(), "不完整") {
		t.Fatalf("错误信息缺少上下文: %v", err)
	}
}

func TestServerPinNext(t *testing.T) {
	dir := t.TempDir()
	_, _, nextPin, err := GenerateAdditionalKey([]string{"localhost"}, []string{"127.0.0.1"}, dir)
	if err != nil {
		t.Fatalf("GenerateAdditionalKey 失败: %v", err)
	}
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: dir, PinNext: nextPin, Logger: quietLogger()})
	if got := m.Status().PinNext; got != nextPin {
		t.Fatalf("PinNext = %q，期望 %q", got, nextPin)
	}

	// Hex input must be normalized to the canonical form.
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(nextPin, PinPrefix))
	if err != nil {
		t.Fatalf("解码 pin 失败: %v", err)
	}
	hexPin := hex.EncodeToString(digest)
	m2 := newServerManager(t, ServerOptions{Mode: "pin", Dir: t.TempDir(), PinNext: hexPin, Logger: quietLogger()})
	if got := m2.Status().PinNext; got != nextPin {
		t.Fatalf("hex pin_next 归一化 = %q，期望 %q", got, nextPin)
	}
}

func TestServerExpiryWarning(t *testing.T) {
	ca := newTestCA(t, "proxygw test ca")
	dir, certPath, keyPath, _ := writeCAIdentity(t, ca, []string{"localhost"}, []string{"127.0.0.1"})
	var buf bytes.Buffer
	m := newServerManager(t, ServerOptions{
		Mode:     "ca",
		CertFile: certPath,
		KeyFile:  keyPath,
		Dir:      dir,
		Logger:   captureLogger(&buf),
	})
	_ = m
	if !strings.Contains(buf.String(), "30 天内过期") {
		t.Fatalf("短期证书应触发到期告警日志: %s", buf.String())
	}
}

func TestServerMTLSClientCAs(t *testing.T) {
	ca := newTestCA(t, "proxygw test ca")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caPath, ca.pem, 0o644)
	m := newServerManager(t, ServerOptions{
		Mode:       "pin",
		Dir:        t.TempDir(),
		CAFile:     caPath,
		ClientAuth: "require",
		Logger:     quietLogger(),
	})
	if m.ClientCAs() == nil {
		t.Fatal("client_auth=require 时 ClientCAs 不应为 nil")
	}
	cfg := m.TLSConfig()
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v，期望 RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("TLSConfig().ClientCAs 不应为 nil")
	}
}

func TestPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _, err := GenerateIdentity([]string{"localhost"}, nil, dir)
	if err != nil {
		t.Fatalf("GenerateIdentity 失败: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod 私钥失败: %v", err)
	}
	var buf bytes.Buffer
	m, err := NewServerManager(ServerOptions{
		Mode:     "pin",
		CertFile: certPath,
		KeyFile:  keyPath,
		Dir:      dir,
		Logger:   captureLogger(&buf),
	})
	if runtime.GOOS == "windows" {
		// Windows os.FileMode permissions do not reflect ACLs: warning only.
		if err != nil {
			t.Fatalf("Windows 上权限检查应仅告警，实际报错: %v", err)
		}
		_ = m.Close()
		if !strings.Contains(buf.String(), "私钥文件权限过宽") {
			t.Fatalf("Windows 上期望出现私钥权限告警日志: %s", buf.String())
		}
		return
	}
	if err == nil {
		_ = m.Close()
		t.Fatal("过宽私钥权限应拒绝启动")
	}
	if !strings.Contains(err.Error(), "权限") || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("错误信息应给出明确修复建议: %v", err)
	}
}

func TestTLSConfigCloneAndGetCertificate(t *testing.T) {
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: t.TempDir(), Logger: quietLogger()})
	first := m.TLSConfig()
	if first.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v", first.MinVersion)
	}
	first.NextProtos = []string{"proxygw/1"}
	second := m.TLSConfig()
	if second.NextProtos != nil {
		t.Fatalf("TLSConfig 返回的配置不应共享 NextProtos: %v", second.NextProtos)
	}
	if m.base.NextProtos != nil {
		t.Fatalf("内部基础配置被调用方修改: %v", m.base.NextProtos)
	}
	second.NextProtos = []string{"http/1.1"}
	if first.NextProtos[0] != "proxygw/1" {
		t.Fatalf("克隆配置相互影响: %v", first.NextProtos)
	}
}

func TestReloadSwapsCertificate(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost"}
	ips := []string{"127.0.0.1"}
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: dir, Hosts: hosts, IPs: ips, Logger: quietLogger()})
	oldPin := m.Status().Pin
	oldReload := m.Status().LastReload
	newPin := rotateServerKey(t, m, hosts, ips)
	if newPin == oldPin {
		t.Fatal("换密钥后 pin 不应相同")
	}
	status := m.Status()
	if status.Pin != newPin {
		t.Fatalf("Status().Pin = %q，期望 %q", status.Pin, newPin)
	}
	if status.LastError != "" {
		t.Fatalf("成功重载后 LastError 应为空: %q", status.LastError)
	}
	if !status.LastReload.After(oldReload) {
		t.Fatalf("LastReload 未更新: %v -> %v", oldReload, status.LastReload)
	}

	addr, _ := startTLSServer(t, m.TLSConfig())
	good, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{newPin}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("构造新 pin 客户端失败: %v", err)
	}
	if err := dialTLSAndRead(t, good, addr); err != nil {
		t.Fatalf("新 pin 连接失败（服务端未使用新证书）: %v", err)
	}
	stale, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{oldPin}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("构造旧 pin 客户端失败: %v", err)
	}
	if err := dialTLSAndRead(t, stale, addr); err == nil {
		t.Fatal("旧 pin 连接应失败")
	} else if !IsPinMismatch(err) {
		t.Fatalf("旧 pin 连接应返回 *PinMismatchError，实际: %v", err)
	}
}

func TestReloadFailureKeepsOldCertificate(t *testing.T) {
	dir := t.TempDir()
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: dir, Hosts: []string{"localhost"}, IPs: []string{"127.0.0.1"}, Logger: quietLogger()})
	goodPin := m.Status().Pin
	certData, err := os.ReadFile(m.certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	keyData, err := os.ReadFile(m.keyPath)
	if err != nil {
		t.Fatalf("读取私钥失败: %v", err)
	}

	// Corrupted certificate: reload must fail and the old identity must stay.
	writeFile(t, m.certPath, []byte("-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----\n"), 0o644)
	if err := m.Reload(); err == nil {
		t.Fatal("损坏的证书应导致 Reload 失败")
	}
	status := m.Status()
	if status.Pin != goodPin {
		t.Fatalf("重载失败后 pin 被改变: %q -> %q", goodPin, status.Pin)
	}
	if status.LastError == "" {
		t.Fatal("重载失败后 Status().LastError 应记录原因")
	}

	// Restore the certificate, corrupt the key instead.
	writeFile(t, m.certPath, certData, 0o644)
	writeFile(t, m.keyPath, []byte("not a key"), 0o600)
	if err := m.Reload(); err == nil {
		t.Fatal("损坏的私钥应导致 Reload 失败")
	}
	writeFile(t, m.keyPath, keyData, 0o600)
	if m.Status().Pin != goodPin {
		t.Fatalf("连续重载失败后 pin 被改变: %q", m.Status().Pin)
	}

	// The old certificate must still be served to new connections.
	addr, _ := startTLSServer(t, m.TLSConfig())
	cfg, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{goodPin}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}
	if err := dialTLSAndRead(t, cfg, addr); err != nil {
		t.Fatalf("重载失败后旧证书应继续可用: %v", err)
	}
}

func TestWatchHotReload(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost"}
	ips := []string{"127.0.0.1"}
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: dir, Hosts: hosts, IPs: ips, HotReload: true, Logger: quietLogger()})
	oldPin := m.Status().Pin

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Watch(ctx)
	}()
	waitFor(t, 2*time.Second, "Watch 进入轮询", func() bool { return m.watching.Load() })

	// Replace the active files without calling Reload: Watch must pick them up.
	certPath, keyPath, newPin, err := GenerateAdditionalKey(hosts, ips, dir)
	if err != nil {
		t.Fatalf("GenerateAdditionalKey 失败: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取轮换证书失败: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取轮换私钥失败: %v", err)
	}
	writeFile(t, m.certPath, certPEM, 0o644)
	writeFile(t, m.keyPath, keyPEM, 0o600)

	if newPin == oldPin {
		t.Fatal("新密钥 pin 不应等于旧 pin")
	}
	waitFor(t, 5*time.Second, "Watch 自动重载新证书", func() bool {
		return m.Status().Pin == newPin
	})
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ctx 取消后 Watch 未在 100ms 内返回")
	}
	if err := m.Status().LastError; err != "" {
		t.Fatalf("成功热重载后 LastError 应为空: %q", err)
	}
}

func TestWatchWithoutHotReloadBlocksUntilCancel(t *testing.T) {
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: t.TempDir(), HotReload: false, Logger: quietLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Watch(ctx)
	}()
	waitFor(t, 2*time.Second, "Watch 启动", func() bool { return m.watching.Load() })
	select {
	case <-done:
		t.Fatal("未启用热重载时 Watch 不应提前返回")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ctx 取消后 Watch 未在 100ms 内返回")
	}
}

func TestManagerClose(t *testing.T) {
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: t.TempDir(), HotReload: true, Logger: quietLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Watch(ctx)
	}()
	waitFor(t, 2*time.Second, "Watch 启动", func() bool { return m.watching.Load() })
	if err := m.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("重复 Close 应幂等: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close 后 Watch 未返回")
	}
	if err := m.Reload(); err == nil {
		t.Fatal("Close 后 Reload 应报错")
	}
}

func TestWatchNilContext(t *testing.T) {
	m := newServerManager(t, ServerOptions{Mode: "pin", Dir: t.TempDir(), Logger: quietLogger()})
	// Must return immediately, not panic or block.
	m.Watch(nil)
}
