package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// quietLogger discards all log output so tests only fail on assertions.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger keeps log output in buf for assertions.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newServerManager is a helper that fails the test when construction fails.
func newServerManager(t *testing.T, opts ServerOptions) *Manager {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = quietLogger()
	}
	m, err := NewServerManager(opts)
	if err != nil {
		t.Fatalf("NewServerManager(%+v) 失败: %v", opts, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// writeFile writes data atomically enough for tests and forces perm.
func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("创建目录 %s 失败: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s 失败: %v", path, err)
	}
}

// randomPin returns a syntactically valid canonical pin unrelated to any key.
func randomPin(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("生成随机 pin 失败: %v", err)
	}
	return PinPrefix + base64.StdEncoding.EncodeToString(buf)
}

// startTLSServer accepts TLS connections and writes a single byte after a
// successful handshake. The manager certificate (via GetCertificate) is served
// for every new handshake, so hot reloads are visible without restarting.
func startTLSServer(t *testing.T, cfg *tls.Config) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	tlsLn := tls.NewListener(ln, cfg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						return
					}
				}
				_, _ = c.Write([]byte("K"))
			}(conn)
		}
	}()
	stopOnce := false
	stop = func() {
		if stopOnce {
			return
		}
		stopOnce = true
		_ = tlsLn.Close()
		<-done
	}
	t.Cleanup(stop)
	return tlsLn.Addr().String(), stop
}

// dialTLSAndRead performs a full TLS handshake and reads one byte. Reading is
// required for failures that the server only reports after the client Finished
// message (for example a rejected mTLS client certificate).
func dialTLSAndRead(t *testing.T, cfg *tls.Config, addr string) error {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("设置读超时失败: %v", err)
	}
	var buf [1]byte
	_, err = io.ReadFull(conn, buf[:])
	return err
}

// waitFor polls cond until it becomes true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时（%s）: %s", timeout, what)
}

// testCA is a throwaway certificate authority used by CA/mTLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 CA 私钥失败: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("生成 CA 序列号失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"proxygw-test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试 CA 失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析测试 CA 失败: %v", err)
	}
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// sign issues a leaf certificate for the given SANs and extended key usage.
func (ca *testCA) sign(t *testing.T, hosts, ips []string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成叶子私钥失败: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("生成叶子序列号失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "proxygw test leaf", Organization: []string{"proxygw-test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		DNSNames:              hosts,
		IPAddresses:           parseTestIPs(t, ips),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("签发叶子证书失败: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码叶子私钥失败: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func parseTestIPs(t *testing.T, values []string) []net.IP {
	t.Helper()
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			t.Fatalf("测试中无效的 IP %q", value)
		}
		out = append(out, ip)
	}
	return out
}

// rotateServerKey generates a fresh key pair into dir/next, copies it over the
// manager's active cert/key files and reloads. It returns the new pin.
func rotateServerKey(t *testing.T, m *Manager, hosts, ips []string) string {
	t.Helper()
	certPath, keyPath, pin, err := GenerateAdditionalKey(hosts, ips, m.dir)
	if err != nil {
		t.Fatalf("生成轮换密钥失败: %v", err)
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
	if err := m.Reload(); err != nil {
		t.Fatalf("重载轮换密钥失败: %v", err)
	}
	if got := m.Status().Pin; got != pin {
		t.Fatalf("重载后 pin = %q，期望 %q", got, pin)
	}
	return pin
}

// pemCert parses the first certificate in data.
func pemCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("PEM 中未找到证书")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	return cert
}
