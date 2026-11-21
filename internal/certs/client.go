package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"proxygw/internal/store"
)

// TOFUFileName is the file inside ClientOptions.TOFUDir that persists the pin
// recorded by trust-on-first-use.
const TOFUFileName = "tofu-pin"

// ClientOptions configures how a node verifies the server identity.
type ClientOptions struct {
	Mode            string   // "pin" | "ca" | "insecure"
	Pins            []string // accepted SPKI pins (current + next during rotation)
	CAFile          string   // custom CA bundle for ca mode; empty means system roots
	ServerName      string   // SNI override / expected server name
	TrustOnFirstUse bool     // record the peer pin on first connect when no pin is configured
	TOFUDir         string   // directory holding the persisted TOFU pin
	CertFile        string   // optional mTLS client certificate
	KeyFile         string   // private key for CertFile
	Logger          *slog.Logger
}

// ClientTLSConfig builds the TLS configuration used by the node to verify the
// server. The returned config is safe to clone for both QUIC (ALPN set by the
// caller) and wss listeners.
func ClientTLSConfig(opts ClientOptions) (*tls.Config, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = "pin"
	}
	serverName := strings.TrimSpace(opts.ServerName)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	// Optional client certificate (mTLS). Both files or neither.
	certFile := strings.TrimSpace(opts.CertFile)
	keyFile := strings.TrimSpace(opts.KeyFile)
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("certs: 客户端 mTLS 需要同时配置 tls.cert_file 与 tls.key_file（只配置其中一个是无效的）")
	}
	if certFile != "" {
		if err := checkPrivateKeyPermissions(keyFile, logger); err != nil {
			return nil, err
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("certs: 加载客户端 mTLS 证书/私钥（证书 %s，私钥 %s）: %w", certFile, keyFile, err)
		}
		cfg.Certificates = []tls.Certificate{pair}
		logger.Info("已加载客户端 mTLS 证书", "cert", certFile)
	}

	switch mode {
	case "pin":
		if err := applyPinMode(cfg, opts, logger); err != nil {
			return nil, err
		}
	case "ca":
		if err := applyCAMode(cfg, opts, logger); err != nil {
			return nil, err
		}
	case "insecure":
		cfg.InsecureSkipVerify = true
		logger.Warn("安全警告：tls.mode=insecure，已关闭服务端证书校验，任何中间人都可劫持连接，仅限本地开发，切勿用于生产")
	default:
		return nil, fmt.Errorf("certs: 无效的 tls.mode %q（可选 pin/ca/insecure）", opts.Mode)
	}
	return cfg, nil
}

// applyPinMode configures SPKI pin verification.
//
// Go's TLS stack requires InsecureSkipVerify=true for a client that wants to
// perform its own key-based trust decision: the standard chain/hostname
// verification is not applicable to self-signed pin-mode servers. This is NOT
// "skipping verification": the VerifyPeerCertificate callback below parses the
// leaf certificate, computes its SPKI SHA-256 pin and compares it in constant
// time against every configured pin, hard failing on a mismatch.
func applyPinMode(cfg *tls.Config, opts ClientOptions, logger *slog.Logger) error {
	normalized := make([]string, 0, len(opts.Pins))
	seen := make(map[string]bool, len(opts.Pins))
	for i, raw := range opts.Pins {
		pin, err := ParsePin(raw)
		if err != nil {
			return fmt.Errorf("certs: 第 %d 枚 tls.pins 无效: %w", i+1, err)
		}
		if seen[pin] {
			continue
		}
		seen[pin] = true
		normalized = append(normalized, pin)
	}
	if len(normalized) == 0 && !opts.TrustOnFirstUse {
		return errors.New("certs: pin 模式需要至少一枚 SPKI pin（tls.pins），或显式启用 tls.trust_on_first_use 完成首次信任")
	}
	cfg.InsecureSkipVerify = true
	// VerifyPeerCertificate is not invoked on resumed TLS sessions (no
	// certificates are exchanged then), so session resumption must be disabled
	// to guarantee that every connection is pin verified.
	cfg.SessionTicketsDisabled = true
	addr := cfg.ServerName
	if len(normalized) > 0 {
		expected := append([]string(nil), normalized...)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			actual, err := pinFromRawCerts(rawCerts)
			if err != nil {
				return err
			}
			for _, want := range expected {
				if pinEqual(want, actual) {
					return nil
				}
			}
			return &PinMismatchError{Addr: addr, Expected: expected, Actual: []string{actual}}
		}
		logger.Info("TLS pin 校验已启用（SPKI SHA-256）", "pins", len(expected), "server_name", addr)
		if opts.TrustOnFirstUse {
			logger.Warn("注意：已配置显式 pin，tls.trust_on_first_use 将被忽略（显式 pin 优先级更高）")
		}
		return nil
	}
	// TOFU bootstrap: no pin configured yet, remember the first peer pin.
	store, err := newTOFUStore(opts, logger)
	if err != nil {
		return err
	}
	cfg.VerifyPeerCertificate = store.verify
	return nil
}

// applyCAMode configures standard CA based verification.
func applyCAMode(cfg *tls.Config, opts ClientOptions, logger *slog.Logger) error {
	// pin mode never reaches this branch; ca mode must use the standard verifier.
	cfg.InsecureSkipVerify = false
	caFile := strings.TrimSpace(opts.CAFile)
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return err
		}
		cfg.RootCAs = pool
		logger.Info("TLS CA 校验已启用（自定义 CA）", "ca_file", caFile, "server_name", cfg.ServerName)
	} else {
		logger.Info("TLS CA 校验已启用（系统根证书）", "server_name", cfg.ServerName)
	}
	if opts.TrustOnFirstUse {
		logger.Warn("注意：ca 模式下 tls.trust_on_first_use 无意义（证书链校验已覆盖信任链），已忽略")
	}
	return nil
}

// tofuStore implements the trust-on-first-use pin record. It is safe for
// concurrent use by parallel handshakes.
type tofuStore struct {
	mu     sync.Mutex
	pin    string // canonical pin; empty means "not recorded yet"
	path   string
	addr   string
	logger *slog.Logger
}

func newTOFUStore(opts ClientOptions, logger *slog.Logger) (*tofuStore, error) {
	dir := strings.TrimSpace(opts.TOFUDir)
	if dir == "" {
		dir = DefaultDir
	}
	path := filepath.Join(dir, TOFUFileName)
	store := &tofuStore{path: path, addr: strings.TrimSpace(opts.ServerName), logger: logger}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		pin, parseErr := ParsePin(strings.TrimSpace(string(data)))
		if parseErr != nil {
			return nil, fmt.Errorf("certs: TOFU 指纹文件 %s 内容无效（删除该文件可重新首次信任，但请先确认服务端身份）: %w", path, parseErr)
		}
		store.pin = pin
		logger.Warn("安全警告：tls.trust_on_first_use 已启用，已加载历史 TOFU 指纹；生产环境请显式配置 tls.pins",
			"path", path, "pin", pin)
	case errors.Is(err, os.ErrNotExist):
		logger.Warn("安全警告：已启用 tls.trust_on_first_use（TOFU）；首次连接将无条件信任服务端公钥指纹并写入本地，无法防御首次连接的中间人攻击，生产环境请显式配置 tls.pins",
			"path", path)
	default:
		return nil, fmt.Errorf("certs: 读取 TOFU 指纹文件 %s: %w", path, err)
	}
	return store, nil
}

// verify implements tls.Config.VerifyPeerCertificate for TOFU mode.
func (s *tofuStore) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	actual, err := pinFromRawCerts(rawCerts)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pin != "" {
		if pinEqual(s.pin, actual) {
			return nil
		}
		return &PinMismatchError{Addr: s.addr, Expected: []string{s.pin}, Actual: []string{actual}}
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("certs: 创建 TOFU 目录 %s: %w", filepath.Dir(s.path), err)
	}
	if err := store.WriteFileAtomic(s.path, []byte(actual+"\n"), 0o600); err != nil {
		return fmt.Errorf("certs: 写入 TOFU 指纹文件 %s 失败，已中止连接（不信任未记录指纹的服务端）: %w", s.path, err)
	}
	s.pin = actual
	s.logger.Warn("安全警告：TOFU 首次信任并记录服务端公钥指纹，后续连接将强制校验；请尽快把该指纹显式写入节点配置",
		"path", s.path, "pin", actual)
	return nil
}
