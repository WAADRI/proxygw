package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxygw/internal/store"
)

const (
	// DefaultDir is the identity directory used when none is configured. It is
	// intentionally relative so that a zero-config development server keeps its
	// state under the working directory.
	DefaultDir = "state/certs"
	// CertFileName is the certificate file name inside an identity directory.
	CertFileName = "server.crt"
	// KeyFileName is the private key file name inside an identity directory.
	KeyFileName = "server.key"
	// NextDirName is the subdirectory under an identity directory that holds a
	// pre-generated key pair for a key rotation window.
	NextDirName = "next"

	certValidity      = 365 * 24 * time.Hour
	clockSkewBackdate = time.Hour
)

// issuedIdentity is the result of generating one self-signed key pair.
type issuedIdentity struct {
	certPath string
	keyPath  string
	pin      string
}

// loadedIdentity is a certificate/key pair loaded from disk together with its
// canonical pin. The value is immutable and published through an atomic pointer
// so TLS handshakes always see a consistent pair.
type loadedIdentity struct {
	pair     *tls.Certificate
	pin      string
	notAfter time.Time
}

// GenerateIdentity creates a new ECDSA P-256 self-signed server identity in dir
// and returns the certificate path, the private key path and the SPKI pin.
// Existing files at those paths are overwritten, which makes this the explicit
// "rotate the key pair" operation.
//
// The private key is written with mode 0600 and the certificate with 0644. Both
// writes are atomic (temp file + fsync + rename).
func GenerateIdentity(hosts, ips []string, dir string) (certPath, keyPath, pin string, err error) {
	target := identityDir(dir, false)
	issued, err := generateIdentity(target, hosts, ips)
	if err != nil {
		return "", "", "", err
	}
	return issued.certPath, issued.keyPath, issued.pin, nil
}

// GenerateAdditionalKey generates a fresh key pair into dir/next and returns its
// paths and pin. The server advertises the pin as pin_next so nodes can accept
// both the current and the next identity during a key rotation window.
func GenerateAdditionalKey(hosts, ips []string, dir string) (certPath, keyPath, pin string, err error) {
	target := identityDir(dir, true)
	issued, err := generateIdentity(target, hosts, ips)
	if err != nil {
		return "", "", "", err
	}
	return issued.certPath, issued.keyPath, issued.pin, nil
}

func identityDir(dir string, next bool) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = DefaultDir
	}
	if next {
		return filepath.Join(dir, NextDirName)
	}
	return filepath.Clean(dir)
}

// generateIdentity writes a new self-signed pair into dir.
func generateIdentity(dir string, hosts, ips []string) (*issuedIdentity, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("certs: 证书目录不能为空")
	}
	return generateIdentityAt(filepath.Join(dir, CertFileName), filepath.Join(dir, KeyFileName), hosts, ips)
}

// generateIdentityAt writes a new self-signed pair to explicit cert/key paths.
// It is used when the operator configured cert_file/key_file but the files do
// not exist yet in a mode that allows auto-generation.
func generateIdentityAt(certPath, keyPath string, hosts, ips []string) (*issuedIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certs: 生成 ECDSA P-256 私钥: %w", err)
	}
	der, err := selfSignedCertificate(hosts, ips, key, time.Now())
	if err != nil {
		return nil, err
	}
	keyPEM, err := marshalECPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if certPEM == nil {
		return nil, errors.New("certs: PEM 编码证书失败")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, fmt.Errorf("certs: 创建证书目录 %s: %w", filepath.Dir(certPath), err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("certs: 创建私钥目录 %s: %w", filepath.Dir(keyPath), err)
	}
	if err := store.WriteFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("certs: 写入私钥 %s: %w", keyPath, err)
	}
	if err := store.WriteFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("certs: 写入证书 %s: %w", certPath, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certs: 解析新生成证书: %w", err)
	}
	pin, err := SPKIPin(leaf)
	if err != nil {
		return nil, err
	}
	return &issuedIdentity{certPath: certPath, keyPath: keyPath, pin: pin}, nil
}

// selfSignedCertificate builds a DER encoded self-signed certificate for key.
// It is split out from generateIdentity so tests (and future rotation helpers)
// can re-issue a certificate for an existing key without touching the pin.
func selfSignedCertificate(hosts, ips []string, key *ecdsa.PrivateKey, now time.Time) ([]byte, error) {
	if key == nil {
		return nil, errors.New("certs: 签发证书时私钥为 nil")
	}
	dnsNames, ipAddrs, err := normalizeSANs(hosts, ips)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"proxygw"}, CommonName: commonName(dnsNames, ipAddrs)},
		NotBefore:             now.Add(-clockSkewBackdate),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("certs: 签发自签证书: %w", err)
	}
	return der, nil
}

// normalizeSANs trims, deduplicates and classifies the configured SAN entries.
// Host entries that parse as IP addresses are moved to the IP SAN list so the
// resulting certificate is valid for them. Invalid explicit IPs are errors
// because silently dropping them would produce a certificate that cannot be
// verified for the configured address.
func normalizeSANs(hosts, ips []string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ipAddrs []net.IP
	seenDNS := make(map[string]bool)
	seenIP := make(map[string]bool)
	addIP := func(ip net.IP) {
		key := ip.String()
		if seenIP[key] {
			return
		}
		seenIP[key] = true
		ipAddrs = append(ipAddrs, ip)
	}
	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			addIP(ip)
			continue
		}
		host = strings.ToLower(host)
		if seenDNS[host] {
			continue
		}
		seenDNS[host] = true
		dnsNames = append(dnsNames, host)
	}
	for _, raw := range ips {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, nil, fmt.Errorf("certs: 无效的 IP 地址 %q（无法用于证书 SAN）", raw)
		}
		addIP(ip)
	}
	return dnsNames, ipAddrs, nil
}

// commonName picks a short human readable subject for the generated
// certificate. The SAN list is what actually matters for verification.
func commonName(dnsNames []string, ipAddrs []net.IP) string {
	name := ""
	switch {
	case len(dnsNames) > 0:
		name = dnsNames[0]
	case len(ipAddrs) > 0:
		name = ipAddrs[0].String()
	default:
		return "proxygw"
	}
	const maxCN = 64 // RFC 5280 ub-common-name
	if runes := []rune(name); len(runes) > maxCN {
		name = string(runes[:maxCN])
	}
	return name
}

func randomSerial() (*big.Int, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("certs: 生成证书序列号: %w", err)
	}
	serial := new(big.Int).SetBytes(buf)
	if serial.Sign() == 0 {
		// Astronomically unlikely; a zero serial is invalid per RFC 5280.
		serial.SetInt64(1)
	}
	return serial, nil
}

func marshalECPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("certs: 编码 ECDSA 私钥: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if pemBytes == nil {
		return nil, errors.New("certs: PEM 编码私钥失败")
	}
	return pemBytes, nil
}

// checkPrivateKeyPermissions rejects world/group readable private keys on POSIX
// systems. Go on Windows reports a synthesized permission set (0644/0666) that
// does not reflect ACLs, so Windows gets a warning instead of a hard failure.
func checkPrivateKeyPermissions(path string, logger *slog.Logger) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("certs: 无法访问私钥文件 %s: %w", path, err)
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if runtime.GOOS == "windows" {
		logger.Warn("私钥文件权限过宽（Windows 上 os.FileMode 权限位不可靠，仅告警）；请用 ACL 限制该文件仅服务账号可读",
			"path", path, "mode", fmt.Sprintf("%04o", perm))
		return nil
	}
	return fmt.Errorf("certs: 私钥文件 %s 权限为 %04o，组/其他用户可访问，安全策略拒绝启动；请执行 chmod 600 %s 后重试", path, perm, path)
}

// loadIdentity loads and validates a certificate/key pair from disk.
func loadIdentity(certPath, keyPath string, logger *slog.Logger) (*loadedIdentity, error) {
	if err := checkPrivateKeyPermissions(keyPath, logger); err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("certs: 加载证书/私钥（证书 %s，私钥 %s）: %w", certPath, keyPath, err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("certs: 证书文件 %s 未包含任何证书", certPath)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("certs: 解析证书 %s: %w", certPath, err)
	}
	pin, err := SPKIPin(leaf)
	if err != nil {
		return nil, fmt.Errorf("certs: 计算证书 %s 的 SPKI pin: %w", certPath, err)
	}
	pair.Leaf = leaf
	return &loadedIdentity{pair: &pair, pin: pin, notAfter: leaf.NotAfter}, nil
}

// loadCertPool reads a PEM (or single DER) CA bundle into a new pool.
func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certs: 读取 CA 文件 %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(data) {
		return pool, nil
	}
	// Accept a single DER encoded certificate as a convenience; PEM is the
	// documented format but some tooling emits DER.
	if cert, derErr := x509.ParseCertificate(data); derErr == nil {
		pool.AddCert(cert)
		return pool, nil
	}
	return nil, fmt.Errorf("certs: CA 文件 %s 不包含任何可解析的 PEM/DER 证书", path)
}
