package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"proxygw/internal/logx"
	"proxygw/internal/model"
)

// ClientTLSConfig configures how the node verifies the server identity.
type ClientTLSConfig struct {
	Mode            string   `yaml:"mode"` // pin | ca | insecure
	Pin             string   `yaml:"pin"`
	Pins            []string `yaml:"pins"` // rotation window: current + next
	CAFile          string   `yaml:"ca_file"`
	ServerName      string   `yaml:"server_name"` // override for SNI / cert verification
	TrustOnFirstUse bool     `yaml:"trust_on_first_use"`
	CertFile        string   `yaml:"cert_file"` // optional client certificate (mTLS)
	KeyFile         string   `yaml:"key_file"`
	Dir             string   `yaml:"dir"` // TOFU pin persistence directory
}

// ClientEgressConfig configures egress IP detection on the node.
type ClientEgressConfig struct {
	ManualV4   string   `yaml:"manual_v4" env:"EGRESS_IP"`
	ManualV6   string   `yaml:"manual_v6" env:"EGRESS_IP6"`
	EchoURLsV4 []string `yaml:"echo_urls_v4"`
	EchoURLsV6 []string `yaml:"echo_urls_v6"`
}

// ClientSecurityConfig holds explicit opt-outs for development warnings.
type ClientSecurityConfig struct {
	AllowInsecureDefaults bool `yaml:"allow_insecure_defaults" env:"ALLOW_INSECURE_DEFAULTS"`
}

// ClientConfig is the node configuration. Behavioural parameters that must not
// drift between nodes (heartbeat, handshake timeout, internal concurrency) are
// intentionally absent: writing them in the config file produces a warning and
// they are ignored.
type ClientConfig struct {
	ServerURL    string               `yaml:"server_url" env:"SERVER_URL"`
	Token        string               `yaml:"token" env:"AUTH_TOKEN"`
	ClientID     string               `yaml:"client_id" env:"CLIENT_ID"`
	Alias        string               `yaml:"alias" env:"ALIAS"`
	Tags         []string             `yaml:"tags" env:"TAGS"`
	Region       string               `yaml:"region" env:"REGION"`
	ISPLabel     string               `yaml:"isp_label" env:"ISP_LABEL"`
	Weight       int                  `yaml:"weight" env:"WEIGHT"`
	Transport    string               `yaml:"transport" env:"TRANSPORT"`
	QUICFallback model.Duration       `yaml:"quic_fallback" env:"QUIC_FALLBACK"` // 1-5s, QUIC -> wss fallback threshold
	Planes       int                  `yaml:"planes" env:"PLANES"`
	StateDir     string               `yaml:"state_dir" env:"STATE_DIR"`
	Compression  bool                 `yaml:"compression" env:"COMPRESSION"`
	Log          logx.Config          `yaml:"log"`
	TLS          ClientTLSConfig      `yaml:"tls"`
	Egress       ClientEgressConfig   `yaml:"egress"`
	Security     ClientSecurityConfig `yaml:"security"`
}

// DefaultClientConfig returns the node defaults.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Weight:       100,
		Transport:    model.TransportAuto,
		QUICFallback: model.D(time.Second * 2),
		Planes:       2,
		StateDir:     "./state",
		Compression:  true,
		Log:          logx.Config{Level: "info", Format: "json"},
		TLS:          ClientTLSConfig{Mode: "pin"},
		Egress: ClientEgressConfig{
			EchoURLsV4: []string{
				"https://api.ipify.org",
				"https://icanhazip.com",
				"https://cloudflare.com/cdn-cgi/trace",
			},
			EchoURLsV6: []string{
				"https://api64.ipify.org",
				"https://icanhazip.com",
				"https://cloudflare.com/cdn-cgi/trace",
			},
		},
	}
}

// Fixed client keys that must not be configurable (node behaviour drift).
var ignoredClientKeys = map[string]bool{
	"heartbeat":          true,
	"heartbeat_interval": true,
	"handshake_timeout":  true,
	"hello_timeout":      true,
	"dial_timeout":       true,
	"timeouts":           true,
	"concurrency":        true,
	"max_concurrent":     true,
	"reconnect_interval": true,
	"backoff":            true,
	"keepalive":          true,
	"keepalive_interval": true,
}

// LoadClient loads the node configuration from path (empty = defaults only),
// applies environment overrides, ignores and warns about fixed behaviour keys,
// then validates.
func LoadClient(path string) (*ClientConfig, []string, error) {
	cfg := DefaultClientConfig()
	var warnings []string
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil, fmt.Errorf("config: file %s does not exist", path)
			}
			return nil, nil, err
		}
		// Detect and strip forbidden fixed-behaviour keys before strict decode.
		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for k := range raw {
			if ignoredClientKeys[strings.ToLower(k)] {
				warnings = append(warnings, fmt.Sprintf("配置警告：客户端行为参数 %q 固定内置、不允许配置，已忽略", k))
				delete(raw, k)
			}
		}
		cleaned, err := yaml.Marshal(raw)
		if err != nil {
			return nil, nil, err
		}
		dec := yaml.NewDecoder(strings.NewReader(string(cleaned)))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if err := applyClientEnv(cfg); err != nil {
		return nil, nil, err
	}
	if cfg.TLS.Dir == "" {
		cfg.TLS.Dir = filepath.Join(cfg.StateDir, "certs")
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	return cfg, append(warnings, cfg.warnings()...), nil
}

// Validate performs complete node configuration validation.
func (c *ClientConfig) Validate() error {
	if strings.TrimSpace(c.ServerURL) == "" {
		return fieldErr("server_url", "must not be empty (for example https://gw.example.com:443)")
	}
	if _, err := ParseServerURL(c.ServerURL); err != nil {
		return fieldErr("server_url", "%v", err)
	}
	if strings.TrimSpace(c.StateDir) == "" {
		return fieldErr("state_dir", "must not be empty")
	}
	if err := c.Log.Validate(); err != nil {
		return err
	}
	if c.Weight < 0 || c.Weight > 10000 {
		return fieldErr("weight", "must be between 0 and 10000")
	}
	switch c.Transport {
	case model.TransportAuto, model.TransportQUIC, model.TransportWS:
	default:
		return fieldErr("transport", "must be auto, quic or ws, got %q", c.Transport)
	}
	if c.QUICFallback < model.D(time.Second) || c.QUICFallback > model.D(time.Second*5) {
		return fieldErr("quic_fallback", "must be between 1s and 5s")
	}
	if c.Planes < 1 || c.Planes > 8 {
		return fieldErr("planes", "must be between 1 and 8")
	}
	if c.ClientID != "" {
		if !validClientID(c.ClientID) {
			return fieldErr("client_id", "must be 1-64 characters of [A-Za-z0-9_.:-]")
		}
	}
	if c.Region != "" && len(c.Region) > 64 {
		return fieldErr("region", "must be at most 64 bytes")
	}
	if len(c.Tags) > 64 {
		return fieldErr("tags", "at most 64 tags are allowed")
	}
	for i, t := range c.Tags {
		if t == "" || len(t) > 64 {
			return fieldErr(fmt.Sprintf("tags[%d]", i), "must be a non-empty tag of at most 64 bytes")
		}
	}
	// TLS.
	switch c.TLS.Mode {
	case "pin", "ca", "insecure":
	default:
		return fieldErr("tls.mode", "must be pin, ca or insecure, got %q", c.TLS.Mode)
	}
	pins := c.TLS.Pins
	if c.TLS.Pin != "" {
		pins = append(pins, c.TLS.Pin)
	}
	for i, p := range pins {
		if _, err := ParsePin(p); err != nil {
			return fieldErr(fmt.Sprintf("tls.pins[%d]", i), "%v", err)
		}
	}
	if c.TLS.Mode == "pin" && len(pins) == 0 && !c.TLS.TrustOnFirstUse {
		return fieldErr("tls.pins", "pin mode requires at least one SPKI pin, or set tls.trust_on_first_use=true for bootstrap")
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fieldErr("tls", "client cert_file and key_file must be provided together")
	}
	if strings.TrimSpace(c.Token) == "" && c.TLS.CertFile == "" {
		return fieldErr("token", "must not be empty unless mTLS client certificates are configured")
	}
	if c.TLS.Mode == "insecure" && !c.Security.AllowInsecureDefaults {
		return fieldErr("tls.mode", "insecure disables certificate verification; explicitly set security.allow_insecure_defaults=true to acknowledge the risk")
	}
	// Egress.
	if c.Egress.ManualV4 != "" {
		ip := net.ParseIP(c.Egress.ManualV4)
		if ip == nil || ip.To4() == nil {
			return fieldErr("egress.manual_v4", "must be a valid IPv4 address")
		}
	}
	if c.Egress.ManualV6 != "" {
		ip := net.ParseIP(c.Egress.ManualV6)
		if ip == nil || ip.To4() != nil {
			return fieldErr("egress.manual_v6", "must be a valid IPv6 address")
		}
	}
	for i, raw := range c.Egress.EchoURLsV4 {
		if err := ValidateRemoteURL(raw, true); err != nil {
			return fieldErr(fmt.Sprintf("egress.echo_urls_v4[%d]", i), "%v", err)
		}
	}
	for i, raw := range c.Egress.EchoURLsV6 {
		if err := ValidateRemoteURL(raw, true); err != nil {
			return fieldErr(fmt.Sprintf("egress.echo_urls_v6[%d]", i), "%v", err)
		}
	}
	if err := CheckWeakSecrets(c.Security.AllowInsecureDefaults, map[string]string{"token": c.Token}); err != nil {
		return err
	}
	return nil
}

func (c *ClientConfig) warnings() []string {
	var out []string
	if c.Security.AllowInsecureDefaults {
		out = append(out, "安全警告：security.allow_insecure_defaults=true，已允许弱令牌/跳过证书校验，切勿用于生产")
	}
	if c.TLS.Mode == "insecure" {
		out = append(out, "安全警告：tls.mode=insecure，证书校验已关闭，仅限本地开发")
	}
	if c.TLS.TrustOnFirstUse && len(c.TLS.Pins) == 0 && c.TLS.Pin == "" {
		out = append(out, "安全警告：已启用 --trust-on-first-use，首次连接将信任服务端指纹；生产环境请显式下发 pin")
	}
	if c.Transport != model.TransportQUIC {
		out = append(out, "提示：transport 非 quic，将优先使用 wss 回退路径")
	}
	return out
}

func validClientID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// ServerEndpoint is the parsed client server URL.
type ServerEndpoint struct {
	Scheme string
	Host   string
	Port   int
	Path   string
	Raw    string
}

// HostPort returns host:port suitable for QUIC dialing.
func (e ServerEndpoint) HostPort() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// WSURL returns the wss:// (or ws://) tunnel URL.
func (e ServerEndpoint) WSURL() string {
	scheme := "wss"
	if e.Scheme == "http" || e.Scheme == "ws" {
		scheme = "ws"
	}
	return scheme + "://" + e.HostPort() + e.Path
}

// HTTPSURL returns the HTTPS base URL (used for health checks in tests/docs).
func (e ServerEndpoint) HTTPSURL() string {
	return "https://" + e.HostPort()
}

// ParseServerURL accepts host:port, https://host[:port], wss://host[:port][/path]
// and http://host[:port] (loopback only). TLS is mandatory in production; the
// wss/ws distinction only selects the fallback transport URL.
func ParseServerURL(raw string) (ServerEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ServerEndpoint{}, fmt.Errorf("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ServerEndpoint{}, fmt.Errorf("invalid URL: %v", err)
	}
	if u.User != nil {
		return ServerEndpoint{}, fmt.Errorf("URL must not contain userinfo")
	}
	switch u.Scheme {
	case "https", "wss", "http", "ws":
	default:
		return ServerEndpoint{}, fmt.Errorf("unsupported scheme %q (want https or wss)", u.Scheme)
	}
	if u.Hostname() == "" {
		return ServerEndpoint{}, fmt.Errorf("URL must contain a host")
	}
	port := DefaultServerPort
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return ServerEndpoint{}, fmt.Errorf("invalid port %q", p)
		}
		port = n
	}
	path := u.Path
	if path == "" || path == "/" {
		path = "/tunnel"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.ContainsAny(path, " \t\r\n") {
		return ServerEndpoint{}, fmt.Errorf("invalid path %q", path)
	}
	if (u.Scheme == "http" || u.Scheme == "ws") && !IsLoopbackHost(u.Hostname()) {
		return ServerEndpoint{}, fmt.Errorf("plain http/ws is only allowed for loopback development endpoints")
	}
	return ServerEndpoint{Scheme: u.Scheme, Host: u.Hostname(), Port: port, Path: path, Raw: raw}, nil
}

// ParsePin normalizes an SPKI SHA-256 pin. Accepted forms:
//
//	sha256/<base64>   (canonical)
//	<base64>
//	sha256/<hex>
//	<hex>              (64 hex chars)
func ParsePin(pin string) (string, error) {
	p := strings.TrimSpace(pin)
	p = strings.TrimPrefix(p, "sha256/")
	p = strings.TrimPrefix(p, "sha256:")
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty pin")
	}
	// Hex input is auto-normalized.
	if isHexString(p) && len(p) == 64 {
		raw, err := hexDecode(p)
		if err != nil {
			return "", err
		}
		return "sha256/" + base64StdEncode(raw), nil
	}
	raw, err := base64StdDecode(p)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid pin %q: want sha256/<base64> (32 bytes) or 64 hex characters", pin)
	}
	return "sha256/" + base64StdEncode(raw), nil
}

func isHexString(s string) bool {
	if len(s) == 0 {
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

// LoadClientFile exists for symmetry with LoadServer; it is used by tests.
func LoadClientFile(path string) (*ClientConfig, []string, error) { return LoadClient(path) }

// ClientFixedWarning is exposed for tests.
func ClientFixedKeys() []string {
	out := make([]string, 0, len(ignoredClientKeys))
	for k := range ignoredClientKeys {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

var clientIDFile = "client-id"

// ClientIDPath returns the persistent node id file inside the state dir.
func (c *ClientConfig) ClientIDPath() string { return filepath.Join(c.StateDir, clientIDFile) }

// EffectiveToken returns the token to send in HELLO.
func (c *ClientConfig) EffectiveToken() string { return strings.TrimSpace(c.Token) }

// NormalizedTags lowercases, trims and dedups tags.
func (c *ClientConfig) NormalizedTags() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range c.Tags {
		v := strings.ToLower(strings.TrimSpace(t))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Ensure helpers for tests.
func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

func base64StdEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func base64StdDecode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// applyClientEnv applies the documented intuitive environment variables of the
// node binary (SERVER_URL, AUTH_TOKEN, CLIENT_ID, TAGS, ...). The client uses an
// explicit, stable list instead of the server's NP_ prefix scheme so that
// onboarding scripts stay simple.
func applyClientEnv(c *ClientConfig) error {
	for name, target := range map[string]*string{
		"SERVER_URL":      &c.ServerURL,
		"AUTH_TOKEN":      &c.Token,
		"CLIENT_ID":       &c.ClientID,
		"ALIAS":           &c.Alias,
		"REGION":          &c.Region,
		"ISP_LABEL":       &c.ISPLabel,
		"TRANSPORT":       &c.Transport,
		"STATE_DIR":       &c.StateDir,
		"LOG_LEVEL":       &c.Log.Level,
		"LOG_FORMAT":      &c.Log.Format,
		"EGRESS_IP":       &c.Egress.ManualV4,
		"EGRESS_IP6":      &c.Egress.ManualV6,
		"TLS_MODE":        &c.TLS.Mode,
		"TLS_PIN":         &c.TLS.Pin,
		"TLS_CA_FILE":     &c.TLS.CAFile,
		"TLS_SERVER_NAME": &c.TLS.ServerName,
		"TLS_CERT_FILE":   &c.TLS.CertFile,
		"TLS_KEY_FILE":    &c.TLS.KeyFile,
	} {
		raw, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		*target = strings.TrimSpace(raw)
	}
	if raw, ok := os.LookupEnv("TAGS"); ok {
		c.Tags = splitCommaList(raw)
	}
	if raw, ok := os.LookupEnv("TLS_PINS"); ok {
		c.TLS.Pins = splitCommaList(raw)
	}
	if raw, ok := os.LookupEnv("WEIGHT"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("env WEIGHT: invalid integer %q", raw)
		}
		c.Weight = n
	}
	if raw, ok := os.LookupEnv("PLANES"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("env PLANES: invalid integer %q", raw)
		}
		c.Planes = n
	}
	if raw, ok := os.LookupEnv("COMPRESSION"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("env COMPRESSION: invalid bool %q", raw)
		}
		c.Compression = b
	}
	if raw, ok := os.LookupEnv("TRUST_ON_FIRST_USE"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("env TRUST_ON_FIRST_USE: invalid bool %q", raw)
		}
		c.TLS.TrustOnFirstUse = b
	}
	if raw, ok := os.LookupEnv("ALLOW_INSECURE_DEFAULTS"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("env ALLOW_INSECURE_DEFAULTS: invalid bool %q", raw)
		}
		c.Security.AllowInsecureDefaults = b
	}
	if raw, ok := os.LookupEnv("EGRESS_ECHO_URLS_V4"); ok {
		c.Egress.EchoURLsV4 = splitCommaList(raw)
	}
	if raw, ok := os.LookupEnv("EGRESS_ECHO_URLS_V6"); ok {
		c.Egress.EchoURLsV6 = splitCommaList(raw)
	}
	return nil
}

func splitCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
