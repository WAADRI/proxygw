package certs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pinServerForClient starts a TLS server with a fresh pin-mode manager and
// returns the manager, the dial address and its pin.
func pinServerForClient(t *testing.T) (*Manager, string, string) {
	t.Helper()
	m := newServerManager(t, ServerOptions{
		Mode:   "pin",
		Dir:    t.TempDir(),
		Hosts:  []string{"localhost"},
		IPs:    []string{"127.0.0.1"},
		Logger: quietLogger(),
	})
	addr, _ := startTLSServer(t, m.TLSConfig())
	return m, addr, m.Status().Pin
}

func TestPinClientSuccess(t *testing.T) {
	m, addr, pin := pinServerForClient(t)
	_ = m
	cfg, err := ClientTLSConfig(ClientOptions{
		Mode:       "pin",
		Pins:       []string{pin},
		ServerName: "proxygw.test",
		Logger:     quietLogger(),
	})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("pin 模式必须设置 InsecureSkipVerify=true，以便由 VerifyPeerCertificate 自行校验 SPKI")
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("pin 模式必须禁用会话复用，避免恢复连接跳过 VerifyPeerCertificate")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v，期望 TLS 1.2", cfg.MinVersion)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("pin 模式必须设置 VerifyPeerCertificate")
	}
	if err := dialTLSAndRead(t, cfg, addr); err != nil {
		t.Fatalf("正确 pin 连接失败: %v", err)
	}
}

func TestPinClientMismatch(t *testing.T) {
	_, addr, serverPin := pinServerForClient(t)
	wrong := randomPin(t)
	cfg, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{wrong}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	dialErr := dialTLSAndRead(t, cfg, addr)
	if dialErr == nil {
		t.Fatal("错误 pin 连接必须硬失败")
	}
	if !IsPinMismatch(dialErr) {
		t.Fatalf("错误 pin 应返回 *PinMismatchError，实际: %v", dialErr)
	}
	var mismatch *PinMismatchError
	if !errors.As(dialErr, &mismatch) {
		t.Fatalf("errors.As 未取到 *PinMismatchError: %v", dialErr)
	}
	if len(mismatch.Expected) != 1 || mismatch.Expected[0] != wrong {
		t.Fatalf("Expected = %v，期望 %q", mismatch.Expected, wrong)
	}
	if len(mismatch.Actual) != 1 || mismatch.Actual[0] != serverPin {
		t.Fatalf("Actual = %v，期望 %q", mismatch.Actual, serverPin)
	}
	msg := dialErr.Error()
	for _, want := range []string{wrong, serverPin, "期望指纹", "实际指纹", "排查建议"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息缺少 %q: %s", want, msg)
		}
	}
}

func TestPinClientMultiplePinsRotationWindow(t *testing.T) {
	_, addr, serverPin := pinServerForClient(t)
	wrongA := randomPin(t)
	wrongB := randomPin(t)
	cases := [][]string{
		{wrongA, serverPin},
		{serverPin, wrongA},
		{wrongA, wrongB, serverPin},
	}
	for _, pins := range cases {
		cfg, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: pins, Logger: quietLogger()})
		if err != nil {
			t.Fatalf("ClientTLSConfig(%v) 失败: %v", pins, err)
		}
		if err := dialTLSAndRead(t, cfg, addr); err != nil {
			t.Fatalf("多 pin（含正确 pin）连接失败 pins=%v: %v", pins, err)
		}
	}
	cfg, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{wrongA, wrongB}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if err := dialTLSAndRead(t, cfg, addr); !IsPinMismatch(err) {
		t.Fatalf("全部错误 pin 应返回 pin 不匹配错误，实际: %v", err)
	}
}

func TestPinClientAcceptsHexPin(t *testing.T) {
	_, addr, serverPin := pinServerForClient(t)
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(serverPin, PinPrefix))
	if err != nil {
		t.Fatalf("解码 pin 失败: %v", err)
	}
	hexPin := hex.EncodeToString(digest)
	cfg, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{hexPin}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig(hex pin) 失败: %v", err)
	}
	if err := dialTLSAndRead(t, cfg, addr); err != nil {
		t.Fatalf("十六进制 pin 连接失败: %v", err)
	}
}

func TestClientPinModeValidation(t *testing.T) {
	if _, err := ClientTLSConfig(ClientOptions{Mode: "pin", Logger: quietLogger()}); err == nil {
		t.Fatal("pin 模式无 pin 且未启用 TOFU 时应报错")
	}
	if _, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{"garbage"}, Logger: quietLogger()}); err == nil {
		t.Fatal("非法 pin 应报错")
	}
	if _, err := ClientTLSConfig(ClientOptions{Mode: "bogus", Logger: quietLogger()}); err == nil {
		t.Fatal("非法模式应报错")
	}
	// Empty mode defaults to pin and therefore still requires a pin.
	if _, err := ClientTLSConfig(ClientOptions{Logger: quietLogger()}); err == nil {
		t.Fatal("空模式默认 pin，缺少 pin 时应报错")
	}
}

func TestPinVerifierRejectsNoCertificates(t *testing.T) {
	cfg, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{randomPin(t)}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("rawCerts 为空时校验必须失败")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{{0x01, 0x02}}, nil); err == nil {
		t.Fatal("无法解析的证书必须导致校验失败")
	}
}

// writeCAIdentity writes a CA signed server identity and its CA bundle.
func writeCAIdentity(t *testing.T, ca *testCA, hosts, ips []string) (dir, certPath, keyPath, caPath string) {
	t.Helper()
	certPEM, keyPEM := ca.sign(t, hosts, ips, x509.ExtKeyUsageServerAuth)
	dir = t.TempDir()
	certPath = filepath.Join(dir, CertFileName)
	keyPath = filepath.Join(dir, KeyFileName)
	writeFile(t, certPath, certPEM, 0o644)
	writeFile(t, keyPath, keyPEM, 0o600)
	caPath = filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, ca.pem, 0o644)
	return dir, certPath, keyPath, caPath
}

func TestCAModeClientVerifiesCustomCA(t *testing.T) {
	ca := newTestCA(t, "proxygw client ca")
	dir, certPath, keyPath, caPath := writeCAIdentity(t, ca, []string{"localhost"}, []string{"127.0.0.1"})
	m := newServerManager(t, ServerOptions{Mode: "ca", CertFile: certPath, KeyFile: keyPath, Dir: dir, Logger: quietLogger()})
	addr, _ := startTLSServer(t, m.TLSConfig())

	cfg, err := ClientTLSConfig(ClientOptions{Mode: "ca", CAFile: caPath, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("ca 模式禁止 InsecureSkipVerify")
	}
	if cfg.RootCAs == nil {
		t.Fatal("配置 CAFile 时 RootCAs 不应为 nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v，期望 TLS 1.2", cfg.MinVersion)
	}
	if err := dialTLSAndRead(t, cfg, addr); err != nil {
		t.Fatalf("自定义 CA 校验连接失败: %v", err)
	}
}

func TestCAModeClientRejectsOtherCA(t *testing.T) {
	serverCA := newTestCA(t, "proxygw server ca")
	otherCA := newTestCA(t, "proxygw other ca")
	dir, certPath, keyPath, _ := writeCAIdentity(t, serverCA, []string{"localhost"}, []string{"127.0.0.1"})
	otherCAPath := filepath.Join(dir, "other-ca.pem")
	writeFile(t, otherCAPath, otherCA.pem, 0o644)
	m := newServerManager(t, ServerOptions{Mode: "ca", CertFile: certPath, KeyFile: keyPath, Dir: dir, Logger: quietLogger()})
	addr, _ := startTLSServer(t, m.TLSConfig())

	cfg, err := ClientTLSConfig(ClientOptions{Mode: "ca", CAFile: otherCAPath, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	err = dialTLSAndRead(t, cfg, addr)
	if err == nil {
		t.Fatal("使用不匹配 CA 的连接必须失败")
	}
	if IsPinMismatch(err) {
		t.Fatalf("CA 校验失败不应被报告为 pin 不匹配: %v", err)
	}
}

func TestCAModeServerNameOverride(t *testing.T) {
	ca := newTestCA(t, "proxygw client ca")
	// Certificate is only valid for the DNS name, not for 127.0.0.1.
	dir, certPath, keyPath, caPath := writeCAIdentity(t, ca, []string{"localhost"}, nil)
	m := newServerManager(t, ServerOptions{Mode: "ca", CertFile: certPath, KeyFile: keyPath, Dir: dir, Logger: quietLogger()})
	addr, _ := startTLSServer(t, m.TLSConfig())

	withOverride, err := ClientTLSConfig(ClientOptions{Mode: "ca", CAFile: caPath, ServerName: "localhost", Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if withOverride.ServerName != "localhost" {
		t.Fatalf("ServerName = %q", withOverride.ServerName)
	}
	if err := dialTLSAndRead(t, withOverride, addr); err != nil {
		t.Fatalf("ServerName 覆盖为 localhost 后连接失败: %v", err)
	}
	// Without the override the dialed IP is used as the expected name and the
	// certificate (DNS SAN only) does not match.
	withoutOverride, err := ClientTLSConfig(ClientOptions{Mode: "ca", CAFile: caPath, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if err := dialTLSAndRead(t, withoutOverride, addr); err == nil {
		t.Fatal("缺少 ServerName 覆盖时 IP 地址不匹配证书 SAN，连接应失败")
	}
}

func TestCAModeMissingOrInvalidCAFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := ClientTLSConfig(ClientOptions{Mode: "ca", CAFile: filepath.Join(dir, "missing.pem"), Logger: quietLogger()}); err == nil {
		t.Fatal("CA 文件不存在时应报错")
	}
	garbage := filepath.Join(dir, "garbage.pem")
	writeFile(t, garbage, []byte("not a certificate"), 0o644)
	if _, err := ClientTLSConfig(ClientOptions{Mode: "ca", CAFile: garbage, Logger: quietLogger()}); err == nil {
		t.Fatal("CA 文件内容非法时应报错")
	}
}

func TestInsecureModeWarns(t *testing.T) {
	_, addr, _ := pinServerForClient(t)
	var buf bytes.Buffer
	cfg, err := ClientTLSConfig(ClientOptions{Mode: "insecure", Logger: captureLogger(&buf)})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("insecure 模式必须设置 InsecureSkipVerify")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Fatal("insecure 模式不应设置自定义校验")
	}
	if err := dialTLSAndRead(t, cfg, addr); err != nil {
		t.Fatalf("insecure 模式连接失败: %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "安全警告") || !strings.Contains(logs, "insecure") {
		t.Fatalf("insecure 模式缺少醒目中文告警: %s", logs)
	}
}

func TestTOFURecordsAndEnforcesPin(t *testing.T) {
	hosts := []string{"localhost"}
	ips := []string{"127.0.0.1"}
	m, addr, serverPin := pinServerForClient(t)
	tofuDir := t.TempDir()
	var buf bytes.Buffer

	first, err := ClientTLSConfig(ClientOptions{
		Mode:            "pin",
		TrustOnFirstUse: true,
		TOFUDir:         tofuDir,
		Logger:          captureLogger(&buf),
	})
	if err != nil {
		t.Fatalf("TOFU 首次 ClientTLSConfig 失败: %v", err)
	}
	if first.VerifyPeerCertificate == nil {
		t.Fatal("TOFU 模式必须设置 VerifyPeerCertificate")
	}
	if err := dialTLSAndRead(t, first, addr); err != nil {
		t.Fatalf("TOFU 首次连接失败: %v", err)
	}
	pinFile := filepath.Join(tofuDir, TOFUFileName)
	data, err := os.ReadFile(pinFile)
	if err != nil {
		t.Fatalf("TOFU 指纹文件未写入: %v", err)
	}
	recorded, err := ParsePin(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("TOFU 文件内容不是合法 pin: %v", err)
	}
	if recorded != serverPin {
		t.Fatalf("TOFU 记录 pin = %q，期望 %q", recorded, serverPin)
	}
	logs := buf.String()
	if !strings.Contains(logs, "安全警告") || !strings.Contains(logs, "TOFU") {
		t.Fatalf("TOFU 模式缺少醒目中文告警: %s", logs)
	}

	// A "restarted" node loads the persisted pin and connects successfully.
	second, err := ClientTLSConfig(ClientOptions{Mode: "pin", TrustOnFirstUse: true, TOFUDir: tofuDir, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("TOFU 重启 ClientTLSConfig 失败: %v", err)
	}
	if err := dialTLSAndRead(t, second, addr); err != nil {
		t.Fatalf("TOFU 重启后连接失败: %v", err)
	}

	// Rotate the server key: the recorded pin must now hard fail.
	newPin := rotateServerKey(t, m, hosts, ips)
	if newPin == serverPin {
		t.Fatal("轮换后的 pin 不应相同")
	}
	afterRotation, err := ClientTLSConfig(ClientOptions{Mode: "pin", TrustOnFirstUse: true, TOFUDir: tofuDir, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("轮换后 ClientTLSConfig 失败: %v", err)
	}
	dialErr := dialTLSAndRead(t, afterRotation, addr)
	if dialErr == nil {
		t.Fatal("服务端换密钥后 TOFU 连接必须失败")
	}
	if !IsPinMismatch(dialErr) {
		t.Fatalf("TOFU 不匹配应返回 *PinMismatchError，实际: %v", dialErr)
	}
	msg := dialErr.Error()
	if !strings.Contains(msg, serverPin) || !strings.Contains(msg, newPin) {
		t.Fatalf("TOFU 不匹配错误应包含新旧指纹: %s", msg)
	}
	// The old in-memory client also fails (no silent downgrade).
	if err := dialTLSAndRead(t, second, addr); !IsPinMismatch(err) {
		t.Fatalf("旧 TOFU 客户端在换密钥后应失败，实际: %v", err)
	}
}

func TestTOFUCorruptFileFailsClosed(t *testing.T) {
	tofuDir := t.TempDir()
	writeFile(t, filepath.Join(tofuDir, TOFUFileName), []byte("garbage"), 0o600)
	if _, err := ClientTLSConfig(ClientOptions{Mode: "pin", TrustOnFirstUse: true, TOFUDir: tofuDir, Logger: quietLogger()}); err == nil {
		t.Fatal("损坏的 TOFU 指纹文件应导致失败（fail closed）")
	}
}

func TestTOFUWithExplicitPinPrefersPin(t *testing.T) {
	_, addr, serverPin := pinServerForClient(t)
	tofuDir := t.TempDir()
	var buf bytes.Buffer
	cfg, err := ClientTLSConfig(ClientOptions{
		Mode:            "pin",
		Pins:            []string{serverPin},
		TrustOnFirstUse: true,
		TOFUDir:         tofuDir,
		Logger:          captureLogger(&buf),
	})
	if err != nil {
		t.Fatalf("ClientTLSConfig 失败: %v", err)
	}
	if err := dialTLSAndRead(t, cfg, addr); err != nil {
		t.Fatalf("显式 pin 连接失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tofuDir, TOFUFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("配置显式 pin 时不应写 TOFU 文件")
	}
	if !strings.Contains(buf.String(), "trust_on_first_use") {
		t.Fatalf("显式 pin 优先时应提示 TOFU 被忽略: %s", buf.String())
	}
}

func TestClientMTLS(t *testing.T) {
	ca := newTestCA(t, "proxygw mtls ca")
	serverDir, serverCert, serverKey, caPath := writeCAIdentity(t, ca, []string{"localhost"}, []string{"127.0.0.1"})
	m := newServerManager(t, ServerOptions{
		Mode:       "ca",
		CertFile:   serverCert,
		KeyFile:    serverKey,
		CAFile:     caPath,
		ClientAuth: "require",
		Dir:        serverDir,
		Logger:     quietLogger(),
	})
	addr, _ := startTLSServer(t, m.TLSConfig())
	serverPin := m.Status().Pin

	clientCertPEM, clientKeyPEM := ca.sign(t, []string{"proxygw-node"}, nil, x509.ExtKeyUsageClientAuth)
	clientDir := t.TempDir()
	clientCert := filepath.Join(clientDir, "client.crt")
	clientKey := filepath.Join(clientDir, "client.key")
	writeFile(t, clientCert, clientCertPEM, 0o644)
	writeFile(t, clientKey, clientKeyPEM, 0o600)
	pinClient := func() *tls.Config {
		cfg, err := ClientTLSConfig(ClientOptions{
			Mode:     "pin",
			Pins:     []string{serverPin},
			CertFile: clientCert,
			KeyFile:  clientKey,
			Logger:   quietLogger(),
		})
		if err != nil {
			t.Fatalf("构造 mTLS 客户端失败: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("mTLS 客户端未加载证书")
		}
		return cfg
	}
	if err := dialTLSAndRead(t, pinClient(), addr); err != nil {
		t.Fatalf("携带客户端证书的 mTLS 连接失败: %v", err)
	}

	noCert, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{serverPin}, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("构造无证书客户端失败: %v", err)
	}
	if err := dialTLSAndRead(t, noCert, addr); err == nil {
		t.Fatal("未携带客户端证书时 mTLS 连接必须失败")
	}
}

func TestClientMTLSFilesMustBePaired(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	writeFile(t, certPath, []byte("dummy"), 0o644)
	if _, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{randomPin(t)}, CertFile: certPath, Logger: quietLogger()}); err == nil {
		t.Fatal("只配置客户端 cert_file 应报错")
	}
	if _, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{randomPin(t)}, KeyFile: filepath.Join(dir, "client.key"), Logger: quietLogger()}); err == nil {
		t.Fatal("只配置客户端 key_file 应报错")
	}
	if _, err := ClientTLSConfig(ClientOptions{Mode: "pin", Pins: []string{randomPin(t)}, CertFile: filepath.Join(dir, "missing.crt"), KeyFile: filepath.Join(dir, "missing.key"), Logger: quietLogger()}); err == nil {
		t.Fatal("客户端证书文件不存在时应报错")
	}
}

func TestClientMTLSKeyPermissions(t *testing.T) {
	ca := newTestCA(t, "proxygw mtls ca")
	clientCertPEM, clientKeyPEM := ca.sign(t, []string{"proxygw-node"}, nil, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writeFile(t, certPath, clientCertPEM, 0o644)
	writeFile(t, keyPath, clientKeyPEM, 0o600)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod 失败: %v", err)
	}
	var buf bytes.Buffer
	_, err := ClientTLSConfig(ClientOptions{
		Mode:     "pin",
		Pins:     []string{randomPin(t)},
		CertFile: certPath,
		KeyFile:  keyPath,
		Logger:   captureLogger(&buf),
	})
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("Windows 上客户端私钥权限应仅告警: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("客户端私钥权限过宽应报错")
	}
	if !strings.Contains(err.Error(), "权限") {
		t.Fatalf("错误信息缺少权限说明: %v", err)
	}
}
