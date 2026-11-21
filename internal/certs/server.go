package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// watchInterval is how often Watch polls the certificate and key files.
const watchInterval = time.Second

// expiryWarningWindow is how long before NotAfter the manager starts warning
// about an upcoming certificate expiry.
const expiryWarningWindow = 30 * 24 * time.Hour

// ServerOptions configures the server identity manager.
type ServerOptions struct {
	Mode       string // "pin" | "ca" | "insecure"
	CertFile   string
	KeyFile    string
	CAFile     string   // client CA bundle used for mTLS verification
	Dir        string   // self-signed identity directory; empty means state/certs
	PinNext    string   // optional next SPKI pin advertised during key rotation
	HotReload  bool     // poll cert/key files and reload automatically
	ClientAuth string   // "none" | "require"
	Hosts      []string // DNS SANs for auto-generated certificates
	IPs        []string // IP SANs for auto-generated certificates
	Logger     *slog.Logger
}

// Status is an immutable snapshot of the server identity state. LastError keeps
// the most recent reload failure so the panel can display why a reload was
// rejected while the previous certificate stays active.
type Status struct {
	Mode       string
	Pin        string
	PinNext    string
	CertPath   string
	KeyPath    string
	NotAfter   time.Time
	LastReload time.Time
	LastError  string
}

// Manager owns the server identity certificate and exposes it through a
// *tls.Config whose GetCertificate callback swaps certificates atomically.
type Manager struct {
	opts ServerOptions
	log  *slog.Logger

	mode     string
	certPath string
	keyPath  string
	dir      string

	base      *tls.Config
	clientCAs *x509.CertPool

	current  atomic.Pointer[loadedIdentity]
	status   atomic.Pointer[Status]
	watching atomic.Bool

	reloadMu  sync.Mutex
	closeOnce sync.Once
	watchStop chan struct{}
	closed    atomic.Bool
}

// NewServerManager loads (or, in pin/insecure mode, generates) the server
// identity and returns a manager configured for the requested mode.
//
// In ca mode an explicit certificate and key are mandatory; pin and insecure
// modes generate an ECDSA P-256 self-signed identity on first start when the
// files are absent.
func NewServerManager(opts ServerOptions) (*Manager, error) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	switch mode {
	case "":
		mode = "pin"
	case "pin", "ca", "insecure":
	default:
		return nil, fmt.Errorf("certs: 无效的 tls.mode %q（可选 pin/ca/insecure）", opts.Mode)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dir := strings.TrimSpace(opts.Dir)
	if dir == "" {
		dir = DefaultDir
	}
	certFile := strings.TrimSpace(opts.CertFile)
	keyFile := strings.TrimSpace(opts.KeyFile)
	switch {
	case certFile != "" && keyFile == "":
		return nil, errors.New("certs: tls.cert_file 已配置但 tls.key_file 为空，两者必须同时提供")
	case certFile == "" && keyFile != "":
		return nil, errors.New("certs: tls.key_file 已配置但 tls.cert_file 为空，两者必须同时提供")
	case certFile == "":
		certFile = filepath.Join(dir, CertFileName)
		keyFile = filepath.Join(dir, KeyFileName)
	}
	if mode == "ca" && strings.TrimSpace(opts.CertFile) == "" {
		return nil, errors.New("certs: ca 模式要求显式配置 tls.cert_file 与 tls.key_file（ACME 或手工签发的证书），不会自动生成自签证书")
	}
	if mode == "ca" {
		// Fail early with a precise message instead of letting tls.LoadX509KeyPair
		// report a combined error, and never generate identity files in ca mode.
		if err := requireReadable(certFile, "证书"); err != nil {
			return nil, err
		}
		if err := requireReadable(keyFile, "私钥"); err != nil {
			return nil, err
		}
	}
	if mode == "pin" || mode == "insecure" {
		generated, err := ensureIdentityFiles(certFile, keyFile, opts.Hosts, opts.IPs)
		if err != nil {
			return nil, err
		}
		if generated {
			logger.Info("未找到 TLS 身份证书，已自动生成 ECDSA P-256 自签证书（有效期 1 年，私钥权限 0600）",
				"mode", mode, "cert", certFile, "key", keyFile)
		}
	}

	identity, err := loadIdentity(certFile, keyFile, logger)
	if err != nil {
		return nil, err
	}

	pinNext, err := normalizePinNext(opts.PinNext)
	if err != nil {
		return nil, err
	}

	clientAuth, clientCAs, err := buildClientAuth(opts, logger)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		opts:      opts,
		log:       logger,
		mode:      mode,
		certPath:  certFile,
		keyPath:   keyFile,
		dir:       dir,
		clientCAs: clientCAs,
		watchStop: make(chan struct{}),
	}
	m.current.Store(identity)
	m.base = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: clientAuth,
		ClientCAs:  clientCAs,
		// Certificates is intentionally left empty: GetCertificate is the single
		// source of truth so that hot reloads are visible to new handshakes
		// without rebuilding listeners.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			current := m.current.Load()
			if current == nil || current.pair == nil {
				return nil, errors.New("certs: TLS 身份证书尚未加载")
			}
			return current.pair, nil
		},
	}
	now := time.Now()
	m.status.Store(&Status{
		Mode:       mode,
		Pin:        identity.pin,
		PinNext:    pinNext,
		CertPath:   certFile,
		KeyPath:    keyFile,
		NotAfter:   identity.notAfter,
		LastReload: now,
	})
	logger.Info("TLS 身份证书已加载",
		"mode", mode,
		"cert", certFile,
		"key", keyFile,
		"pin", identity.pin,
		"not_after", identity.notAfter,
		"hot_reload", opts.HotReload,
		"client_auth", strings.ToLower(strings.TrimSpace(opts.ClientAuth)))
	warnIfExpiring(logger, certFile, identity.notAfter)
	if pinNext != "" {
		logger.Info("已配置下一枚轮换 pin（pin_next），节点可同时信任新旧两枚指纹", "pin_next", pinNext)
	}
	if mode == "insecure" {
		logger.Warn("安全警告：tls.mode=insecure，服务端身份不被校验，仅限回环/本地开发环境，严禁用于生产")
	}
	return m, nil
}

// requireReadable verifies that path refers to a readable regular file.
func requireReadable(path, what string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("certs: %s文件 %s 不存在（ca 模式不会自动生成）", what, path)
		}
		return fmt.Errorf("certs: 无法访问%s文件 %s: %w", what, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("certs: %s路径 %s 是目录，不是文件", what, path)
	}
	return nil
}

// ensureIdentityFiles generates a self-signed identity when both files are
// missing. A half-present identity is an error: silently regenerating would
// change the advertised pin without an explicit rotation.
func ensureIdentityFiles(certPath, keyPath string, hosts, ips []string) (generated bool, err error) {
	certExists, err := fileExists(certPath)
	if err != nil {
		return false, err
	}
	keyExists, err := fileExists(keyPath)
	if err != nil {
		return false, err
	}
	switch {
	case certExists && keyExists:
		return false, nil
	case certExists != keyExists:
		missing, present := certPath, keyPath
		if keyExists {
			missing, present = certPath, keyPath
		} else {
			missing, present = keyPath, certPath
		}
		return false, fmt.Errorf("certs: TLS 身份文件不完整：%s 存在但 %s 缺失；为避免指纹意外变化，拒绝自动重建，请恢复缺失文件或同时删除两者后重启以重新生成", present, missing)
	}
	if _, err := generateIdentityAt(certPath, keyPath, hosts, ips); err != nil {
		return false, err
	}
	return true, nil
}

func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return false, fmt.Errorf("certs: 期望文件路径 %s，但它是目录", path)
		}
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("certs: 检查文件 %s: %w", path, err)
}

// normalizePinNext validates and canonicalizes an optional pin_next value.
func normalizePinNext(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	pin, err := ParsePin(raw)
	if err != nil {
		return "", fmt.Errorf("certs: 无效的 tls.pin_next: %w", err)
	}
	return pin, nil
}

// buildClientAuth maps the client_auth option to TLS primitives and loads the
// client CA bundle when mTLS is required.
func buildClientAuth(opts ServerOptions, logger *slog.Logger) (tls.ClientAuthType, *x509.CertPool, error) {
	value := strings.ToLower(strings.TrimSpace(opts.ClientAuth))
	switch value {
	case "", "none":
		return tls.NoClientCert, nil, nil
	case "require":
		caFile := strings.TrimSpace(opts.CAFile)
		if caFile == "" {
			return tls.NoClientCert, nil, errors.New("certs: tls.client_auth=require 需要配置客户端 CA 文件（tls.ca_file）")
		}
		pool, err := loadCertPool(caFile)
		if err != nil {
			return tls.NoClientCert, nil, fmt.Errorf("certs: 加载 mTLS 客户端 CA: %w", err)
		}
		logger.Info("已启用 mTLS：新连接必须提供客户端证书", "ca_file", caFile)
		return tls.RequireAndVerifyClientCert, pool, nil
	default:
		return tls.NoClientCert, nil, fmt.Errorf("certs: 无效的 tls.client_auth %q（可选 none/require）", opts.ClientAuth)
	}
}

// TLSConfig returns a clone of the server TLS configuration. The returned value
// carries a GetCertificate callback that always serves the currently loaded
// identity, so callers may keep it for the lifetime of a listener. Callers can
// safely mutate the clone (for example to set NextProtos) without affecting the
// manager or other callers.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil || m.base == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return m.base.Clone()
}

// Status returns the current identity snapshot.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	current := m.status.Load()
	if current == nil {
		return Status{}
	}
	return *current
}

// ClientCAs returns the client CA pool used for mTLS, or nil when client
// authentication is disabled.
func (m *Manager) ClientCAs() *x509.CertPool {
	if m == nil {
		return nil
	}
	return m.clientCAs
}

// Reload re-reads the certificate and key from disk. On failure the previously
// loaded certificate stays active and the error is recorded in Status().LastError
// (and logged as a warning) so an operator sees why an ACME renewal was not
// picked up.
func (m *Manager) Reload() error {
	if m == nil {
		return errors.New("certs: 证书管理器为 nil")
	}
	if m.closed.Load() {
		return errors.New("certs: 证书管理器已关闭")
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	identity, err := loadIdentity(m.certPath, m.keyPath, m.log)
	if err != nil {
		m.setLastError(err)
		m.log.Warn("TLS 身份证书重载失败，继续使用旧证书", "cert", m.certPath, "key", m.keyPath, "error", err)
		return fmt.Errorf("certs: 重载 TLS 身份证书失败: %w", err)
	}
	previous := m.current.Swap(identity)
	m.updateStatus(func(s *Status) {
		s.Pin = identity.pin
		s.NotAfter = identity.notAfter
		s.LastReload = time.Now()
		s.LastError = ""
	})
	pinChanged := previous != nil && previous.pin != identity.pin
	m.log.Info("TLS 身份证书已重载", "cert", m.certPath, "pin", identity.pin, "pin_changed", pinChanged, "not_after", identity.notAfter)
	warnIfExpiring(m.log, m.certPath, identity.notAfter)
	return nil
}

// warnIfExpiring emits operator facing warnings when the active certificate is
// already expired or expires within expiryWarningWindow. Expiry itself never
// refuses to serve: an operator may still need the process up to finish an ACME
// renewal, and pin mode ignores certificate validity.
func warnIfExpiring(logger *slog.Logger, certPath string, notAfter time.Time) {
	remaining := time.Until(notAfter)
	switch {
	case remaining <= 0:
		logger.Warn("TLS 证书已过期，请立即续签后再对外服务", "cert", certPath, "not_after", notAfter)
	case remaining < expiryWarningWindow:
		logger.Warn("TLS 证书将在 30 天内过期，请及时续签（保留密钥重签不会改变 pin）",
			"cert", certPath, "not_after", notAfter, "remaining", remaining.Round(time.Hour))
	}
}

// setLastError records a reload failure without disturbing the active
// certificate. The status pointer is copied so readers never observe a partial
// update.
func (m *Manager) setLastError(err error) {
	m.updateStatus(func(s *Status) {
		s.LastError = err.Error()
	})
}

// SetPinNext updates the advertised next SPKI pin (key rotation window). The
// panel calls it after generating a new key pair so nodes can accept the
// upcoming pin before the server switches to it.
func (m *Manager) SetPinNext(pin string) error {
	normalized, err := normalizePinNext(pin)
	if err != nil {
		return err
	}
	m.updateStatus(func(st *Status) { st.PinNext = normalized })
	return nil
}
func (m *Manager) updateStatus(mutate func(*Status)) {
	for {
		current := m.status.Load()
		var next *Status
		if current == nil {
			next = &Status{Mode: m.mode, CertPath: m.certPath, KeyPath: m.keyPath}
		} else {
			copied := *current
			next = &copied
		}
		mutate(next)
		if m.status.CompareAndSwap(current, next) {
			return
		}
	}
}

// Watch polls the certificate and key files every second and reloads them when
// their modification time or size changes. It is a no-op (it just blocks) when
// HotReload is disabled. Watch returns when ctx is cancelled or the manager is
// closed; run it in its own goroutine.
func (m *Manager) Watch(ctx context.Context) {
	if m == nil || ctx == nil {
		return
	}
	if !m.opts.HotReload {
		m.watching.Store(true)
		defer m.watching.Store(false)
		select {
		case <-ctx.Done():
		case <-m.watchStop:
		}
		return
	}
	last := currentFileStamp(m.certPath, m.keyPath)
	m.watching.Store(true)
	defer m.watching.Store(false)
	m.log.Info("已启用 TLS 证书热重载，每秒检查证书/私钥文件变更", "cert", m.certPath, "key", m.keyPath)
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.watchStop:
			return
		case <-ticker.C:
			current := currentFileStamp(m.certPath, m.keyPath)
			if current == last {
				continue
			}
			// Remember the observed stamp even when the reload fails: the reload
			// error is surfaced in Status().LastError and the next file change
			// triggers another attempt instead of retrying a bad file every second.
			last = current
			if err := m.Reload(); err != nil {
				m.log.Warn("TLS 证书热重载失败，继续使用旧证书（文件再次变化时重试）", "error", err)
			}
		}
	}
}

// Close stops Watch loops and prevents further manual reloads. It is idempotent.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		close(m.watchStop)
	})
	return nil
}

// fileStamp captures the fields observed by the hot reload watcher.
type fileStamp struct {
	certMod  int64 // UnixNano; -1 when the file cannot be stat'ed
	certSize int64
	keyMod   int64
	keySize  int64
}

func currentFileStamp(certPath, keyPath string) fileStamp {
	certMod, certSize := fileStampOf(certPath)
	keyMod, keySize := fileStampOf(keyPath)
	return fileStamp{certMod: certMod, certSize: certSize, keyMod: keyMod, keySize: keySize}
}

// fileStampOf returns the modification time and size of path, or (-1, -1) when
// the file cannot be stat'ed (missing file, permission problem, ...).
func fileStampOf(path string) (modNanos, size int64) {
	info, err := os.Stat(path)
	if err != nil {
		return -1, -1
	}
	return info.ModTime().UnixNano(), info.Size()
}
