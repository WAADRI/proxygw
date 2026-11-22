package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"proxygw/internal/logx"
	"proxygw/internal/model"
)

// Default network ports. The tunnel and the panel share the TCP listener on
// server.listen_addr; QUIC uses the same port over UDP.
const (
	DefaultServerPort      = 443
	DefaultHTTPProxyPort   = 8080
	DefaultSOCKS5ProxyPort = 1080
	DefaultALPN            = "proxygw/1"
	DefaultListenAddr      = ":443"
	DefaultHTTPProxyListen = ":8080"
	DefaultSOCKS5Listen    = ":1080"
)

// ServerListenConfig describes the shared tunnel/panel TCP listener and the
// QUIC UDP listener on the same port.
type ServerListenConfig struct {
	ListenAddr    string `yaml:"listen_addr"`    // TCP: panel + wss tunnel; UDP: QUIC
	PublicURL     string `yaml:"public_url"`     // external URL used for install commands
	UIEnabled     bool   `yaml:"ui_enabled"`     // panel pages; health/metrics always served
	PanelDomain   string `yaml:"panel_domain"`   // when set, only this Host may reach the panel
	ProxyProtocol bool   `yaml:"proxy_protocol"` // accept PROXY protocol v2 on the TCP tunnel listener
}

// ProxyConfig configures the HTTP and SOCKS5 entry points.
type ProxyConfig struct {
	HTTPListen     string `yaml:"http_listen"`
	SOCKS5Listen   string `yaml:"socks5_listen"`
	AuthMode       string `yaml:"auth_mode"` // none | optional | required
	MaxHeaderBytes int    `yaml:"max_header_bytes"`
	MaxConcurrent  int    `yaml:"max_concurrent"` // 0 = unlimited
}

// TunnelConfig configures the node tunnel layer. Fixed values from the
// timeouts table (handshake 10s, HELLO 5s, heartbeat 15s/3) are code constants
// and intentionally not configurable.
type TunnelConfig struct {
	Transport     string `yaml:"transport"` // auto | quic | ws (server: which transports to accept)
	Planes        int    `yaml:"planes"`    // expected number of planes per node (informational)
	AllowPlainWS  bool   `yaml:"allow_plain_ws"`
	ALPN          string `yaml:"alpn"`
	MaxFrameBytes int    `yaml:"max_frame_bytes"`
	QUICCC        string `yaml:"quic_cc"` // cubic | bbr
	QLogDir       string `yaml:"qlog_dir"`
}

// TLSConfig configures the single server identity certificate used for QUIC,
// wss and the panel.
type TLSConfig struct {
	Mode       string `yaml:"mode"` // pin | ca | insecure
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`     // client CA for mTLS (ca mode)
	Dir        string `yaml:"dir"`         // generated cert directory, defaults to <state_dir>/certs
	PinNext    string `yaml:"pin_next"`    // next SPKI pin advertised during key rotation
	HotReload  bool   `yaml:"hot_reload"`  // watch cert/key files and reload on change
	ClientAuth string `yaml:"client_auth"` // none | require
}

// AdminConfig configures the panel administrator.
type AdminConfig struct {
	Username      string         `yaml:"username"`
	PasswordHash  string         `yaml:"password_hash"` // argon2id or bcrypt; generated on first start when empty
	SessionTTL    model.Duration `yaml:"session_ttl"`
	LoginRateMin  int            `yaml:"login_rate_per_min"`
	LockThreshold int            `yaml:"login_lock_threshold"`
	LockWindow    model.Duration `yaml:"login_lock_window"`
	CookieName    string         `yaml:"cookie_name"`
	TOTPSecret    string         `yaml:"totp_secret"`
}

// StaticNodeToken is a node tunnel credential supplied in the config file.
// Dynamic tokens issued from the panel are persisted in the state directory.
type StaticNodeToken struct {
	NodeID string `yaml:"node_id"`
	Token  string `yaml:"token"`
	Note   string `yaml:"note"`
}

// NodesAuthConfig configures how nodes authenticate to the tunnel.
type NodesAuthConfig struct {
	MTLS   bool              `yaml:"mtls"` // require client certificates (ca mode)
	Tokens []StaticNodeToken `yaml:"tokens"`
}

// EgressConfig configures egress IP echo endpoints. Echo endpoints must return
// a plain text IP (JSON with an "ip" field is also accepted).
type EgressConfig struct {
	EchoURLsV4 []string       `yaml:"echo_urls_v4"`
	EchoURLsV6 []string       `yaml:"echo_urls_v6"`
	Timeout    model.Duration `yaml:"timeout"`
}

// ProviderConfig configures one geolocation provider. Three types are
// supported and response formats are never sniffed automatically:
//
//	preset:   built-in adapter selected by Preset
//	template: user supplied URL + declarative field mapping (JSON path or regex)
//	schema:   user endpoint returning the project defined JSON schema
type ProviderConfig struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`
	Preset   string            `yaml:"preset"`
	URL      string            `yaml:"url"`
	Token    string            `yaml:"token"`
	Headers  map[string]string `yaml:"headers"`
	Fields   map[string]string `yaml:"fields"` // field -> "$.a.b[0]" or "regex:pattern"
	Enabled  bool              `yaml:"enabled"`
	Priority int               `yaml:"priority"`
	Timeout  model.Duration    `yaml:"timeout"`
}

// GeoConfig configures egress IP resolution and geolocation enrichment.
type GeoConfig struct {
	Enabled       bool             `yaml:"enabled"`
	MMDBPath      string           `yaml:"mmdb_path"`
	CacheTTL      model.Duration   `yaml:"cache_ttl"`
	Egress        EgressConfig     `yaml:"egress"`
	Providers     []ProviderConfig `yaml:"providers"`
	RemoteConsent bool             `yaml:"remote_consent"` // required before remote providers are allowed
	MaxConcurrent int              `yaml:"max_concurrent"`
	RatePerMin    int              `yaml:"rate_per_min"`
}

// ObservabilityConfig configures metrics, trend buffers and alerting webhooks.
type ObservabilityConfig struct {
	MetricsEnabled bool           `yaml:"metrics_enabled"`
	MetricsPath    string         `yaml:"metrics_path"`
	WebhookURL     string         `yaml:"webhook_url"`
	WebhookTimeout model.Duration `yaml:"webhook_timeout"`
	TrendRetention model.Duration `yaml:"trend_retention"`
}

// AuditConfig configures the JSONL audit trail.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"` // empty = <state_dir>/runtime-audit.jsonl
}

// SecurityConfig holds explicit opt-outs for development warnings.
type SecurityConfig struct {
	AllowInsecureDefaults bool `yaml:"allow_insecure_defaults"`
}

// ServerConfig is the full server configuration.
type ServerConfig struct {
	StateDir      string              `yaml:"state_dir"`
	Log           logx.Config         `yaml:"log"`
	Server        ServerListenConfig  `yaml:"server"`
	Proxy         ProxyConfig         `yaml:"proxy"`
	Tunnel        TunnelConfig        `yaml:"tunnel"`
	TLS           TLSConfig           `yaml:"tls"`
	Admin         AdminConfig         `yaml:"admin"`
	Nodes         NodesAuthConfig     `yaml:"nodes"`
	Settings      model.Settings      `yaml:"settings"`
	Geo           GeoConfig           `yaml:"geo"`
	Observability ObservabilityConfig `yaml:"observability"`
	Audit         AuditConfig         `yaml:"audit"`
	Security      SecurityConfig      `yaml:"security"`
}

// DefaultServerConfig returns the specification defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		StateDir: "./state",
		Log:      logx.Config{Level: "info", Format: "json"},
		Server: ServerListenConfig{
			ListenAddr: DefaultListenAddr,
			UIEnabled:  true,
		},
		Proxy: ProxyConfig{
			HTTPListen:     DefaultHTTPProxyListen,
			SOCKS5Listen:   DefaultSOCKS5Listen,
			AuthMode:       model.AuthRequired,
			MaxHeaderBytes: 64 * 1024,
		},
		Tunnel: TunnelConfig{
			Transport:     model.TransportAuto,
			Planes:        2,
			ALPN:          DefaultALPN,
			MaxFrameBytes: 64 * 1024,
			QUICCC:        "cubic",
		},
		TLS: TLSConfig{Mode: "pin", HotReload: true, ClientAuth: "none"},
		Admin: AdminConfig{
			Username:      "admin",
			SessionTTL:    model.D(time.Hour * 12),
			LoginRateMin:  10,
			LockThreshold: 5,
			LockWindow:    model.D(time.Minute * 5),
			CookieName:    "np_admin",
		},
		Settings: model.DefaultSettings(),
		Geo: GeoConfig{
			Enabled:  true,
			CacheTTL: model.D(time.Hour * 24),
			Egress: EgressConfig{
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
				Timeout: model.D(time.Second * 2),
			},
			MaxConcurrent: 4,
			RatePerMin:    60,
		},
		Observability: ObservabilityConfig{
			MetricsEnabled: true,
			MetricsPath:    "/metrics",
			WebhookTimeout: model.D(time.Second * 5),
			TrendRetention: model.D(time.Minute * 15),
		},
		Audit: AuditConfig{Enabled: true},
	}
}

// LoadServer loads the server configuration from path (which may be empty for
// defaults only), then applies environment overrides, then validates.
// Returned warnings are meant for the operator's console.
func LoadServer(path string) (*ServerConfig, []string, error) {
	cfg := DefaultServerConfig()
	if path != "" {
		if err := readYAMLFile(path, cfg); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil, fmt.Errorf("config: file %s does not exist", path)
			}
			return nil, nil, err
		}
	}
	if err := applyEnv(cfg, EnvPrefix); err != nil {
		return nil, nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	return cfg, cfg.warnings(), nil
}

// Validate performs the complete startup validation.
func (c *ServerConfig) Validate() error {
	if strings.TrimSpace(c.StateDir) == "" {
		return fieldErr("state_dir", "must not be empty")
	}
	if err := c.Log.Validate(); err != nil {
		return err
	}
	// Listeners.
	if _, _, err := ListenHostPort(c.Server.ListenAddr); err != nil {
		return fieldErr("server.listen_addr", "%v", err)
	}
	panelDomain, err := NormalizePanelDomain(c.Server.PanelDomain)
	if err != nil {
		return fieldErr("server.panel_domain", "%v", err)
	}
	c.Server.PanelDomain = panelDomain
	type listen struct {
		field string
		addr  string
	}
	var listens []listen
	listens = append(listens, listen{"server.listen_addr", c.Server.ListenAddr})
	for _, l := range []listen{{"proxy.http_listen", c.Proxy.HTTPListen}, {"proxy.socks5_listen", c.Proxy.SOCKS5Listen}} {
		if strings.TrimSpace(l.addr) == "" {
			continue
		}
		if _, _, err := ListenHostPort(l.addr); err != nil {
			return fieldErr(l.field, "%v", err)
		}
		listens = append(listens, l)
	}
	if len(listens) < 2 {
		return fieldErr("proxy", "at least one proxy entry point (http_listen or socks5_listen) is required")
	}
	// Reject duplicate TCP listen addresses across components.
	seen := map[string]string{}
	for _, l := range listens {
		key := strings.ToLower(canonicalListen(l.addr))
		if prev, ok := seen[key]; ok {
			return fieldErr(l.field, "duplicate listen address %q (already used by %s)", l.addr, prev)
		}
		seen[key] = l.field
	}
	switch c.Proxy.AuthMode {
	case model.AuthNone, model.AuthOptional, model.AuthRequired:
	default:
		return fieldErr("proxy.auth_mode", "must be none, optional or required, got %q", c.Proxy.AuthMode)
	}
	if c.Proxy.AuthMode == model.AuthNone {
		if !IsLoopbackListen(c.Server.ListenAddr) || (c.Proxy.HTTPListen != "" && !IsLoopbackListen(c.Proxy.HTTPListen)) ||
			(c.Proxy.SOCKS5Listen != "" && !IsLoopbackListen(c.Proxy.SOCKS5Listen)) {
			return fieldErr("proxy.auth_mode", "auth_mode=none is only allowed when every listener is on a loopback address")
		}
	}
	if c.Proxy.MaxHeaderBytes < 1024 || c.Proxy.MaxHeaderBytes > 1024*1024 {
		return fieldErr("proxy.max_header_bytes", "must be between 1024 and 1048576")
	}
	if c.Proxy.MaxConcurrent < 0 || c.Proxy.MaxConcurrent > 1_000_000 {
		return fieldErr("proxy.max_concurrent", "must be between 0 and 1000000")
	}
	// Tunnel.
	switch c.Tunnel.Transport {
	case model.TransportAuto, model.TransportQUIC, model.TransportWS:
	default:
		return fieldErr("tunnel.transport", "must be auto, quic or ws, got %q", c.Tunnel.Transport)
	}
	if c.Tunnel.Planes < 1 || c.Tunnel.Planes > 8 {
		return fieldErr("tunnel.planes", "must be between 1 and 8")
	}
	if strings.TrimSpace(c.Tunnel.ALPN) == "" || len(c.Tunnel.ALPN) > 64 {
		return fieldErr("tunnel.alpn", "must be a non-empty string of at most 64 bytes")
	}
	// The frame size is part of the wire contract: WebSocket peers always chunk
	// at the protocol maximum, so a smaller operator value would cause protocol
	// errors on healthy nodes. Keep it fixed at 64 KiB.
	if c.Tunnel.MaxFrameBytes != 64*1024 {
		return fieldErr("tunnel.max_frame_bytes", "must be 65536 (the protocol frame limit is negotiated and fixed in this version)")
	}
	switch strings.ToLower(c.Tunnel.QUICCC) {
	case "", "cubic", "bbr":
	default:
		return fieldErr("tunnel.quic_cc", "must be cubic or bbr")
	}
	// TLS.
	switch c.TLS.Mode {
	case "pin", "ca", "insecure":
	default:
		return fieldErr("tls.mode", "must be pin, ca or insecure, got %q", c.TLS.Mode)
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fieldErr("tls", "cert_file and key_file must be provided together")
	}
	if c.TLS.Mode == "ca" && c.TLS.CertFile == "" {
		return fieldErr("tls.cert_file", "ca mode requires an explicit certificate and key (for example issued by an ACME client)")
	}
	if c.TLS.Mode == "ca" && c.TLS.CAFile == "" && c.Nodes.MTLS {
		return fieldErr("tls.ca_file", "mTLS requires the client CA bundle (tls.ca_file)")
	}
	if c.TLS.Mode == "insecure" && !IsLoopbackListen(c.Server.ListenAddr) {
		return fieldErr("tls.mode", "insecure is only allowed when the tunnel/panel listener is loopback")
	}
	switch c.TLS.ClientAuth {
	case "", "none", "require":
	default:
		return fieldErr("tls.client_auth", "must be none or require")
	}
	if c.TLS.ClientAuth == "require" && c.TLS.CAFile == "" {
		return fieldErr("tls.ca_file", "client_auth=require needs a client CA bundle")
	}
	if c.TLS.ClientAuth == "require" && c.TLS.Mode != "ca" {
		return fieldErr("tls.mode", "client_auth=require requires tls.mode=ca")
	}
	if c.Nodes.MTLS {
		if c.TLS.ClientAuth != "require" {
			return fieldErr("nodes.mtls", "mtls=true requires tls.client_auth=require")
		}
	}
	// Admin.
	if strings.TrimSpace(c.Admin.Username) == "" {
		return fieldErr("admin.username", "must not be empty")
	}
	if c.Admin.PasswordHash != "" {
		if !ValidPasswordHash(c.Admin.PasswordHash) {
			return fieldErr("admin.password_hash", "unsupported hash format, want argon2id ($argon2id$...) or bcrypt ($2a$/$2b$/$2y$...)")
		}
	}
	if c.Admin.SessionTTL < model.D(time.Minute) || c.Admin.SessionTTL > model.D(time.Hour*24*30) {
		return fieldErr("admin.session_ttl", "must be between 1m and 720h")
	}
	if c.Admin.LoginRateMin < 1 || c.Admin.LoginRateMin > 600 {
		return fieldErr("admin.login_rate_per_min", "must be between 1 and 600")
	}
	if c.Admin.LockThreshold < 1 || c.Admin.LockWindow < model.D(time.Second) {
		return fieldErr("admin", "login_lock_threshold and login_lock_window must be positive")
	}
	if c.Admin.CookieName == "" || strings.ContainsAny(c.Admin.CookieName, " ;=,") {
		return fieldErr("admin.cookie_name", "must be a valid cookie token")
	}
	if _, err := parseTOTPSecret(c.Admin.TOTPSecret); err != nil {
		return err
	}
	// Node authentication.
	nodeIDs := map[string]bool{}
	for i, t := range c.Nodes.Tokens {
		if strings.TrimSpace(t.NodeID) == "" {
			return fieldErr(fmt.Sprintf("nodes.tokens[%d].node_id", i), "must not be empty")
		}
		if nodeIDs[t.NodeID] {
			return fieldErr(fmt.Sprintf("nodes.tokens[%d].node_id", i), "duplicate node_id %q", t.NodeID)
		}
		nodeIDs[t.NodeID] = true
		if strings.TrimSpace(t.Token) == "" {
			return fieldErr(fmt.Sprintf("nodes.tokens[%d].token", i), "must not be empty")
		}
	}
	weak := map[string]string{}
	for i, t := range c.Nodes.Tokens {
		weak[fmt.Sprintf("nodes.tokens[%d].token (node %s)", i, t.NodeID)] = t.Token
	}
	if err := CheckWeakSecrets(c.Security.AllowInsecureDefaults, weak); err != nil {
		return err
	}
	// Runtime settings.
	if err := c.Settings.Validate(); err != nil {
		return fieldErr("settings", "%v", err)
	}
	// Geo.
	if err := c.Geo.Validate(); err != nil {
		return err
	}
	// Observability.
	if c.Observability.MetricsPath == "" || !strings.HasPrefix(c.Observability.MetricsPath, "/") {
		return fieldErr("observability.metrics_path", "must start with /")
	}
	if c.Observability.TrendRetention < model.D(time.Minute) || c.Observability.TrendRetention > model.D(time.Hour) {
		return fieldErr("observability.trend_retention", "must be between 1m and 1h")
	}
	if c.Observability.WebhookTimeout < model.D(time.Second) || c.Observability.WebhookTimeout > model.D(time.Minute) {
		return fieldErr("observability.webhook_timeout", "must be between 1s and 1m")
	}
	if c.Observability.WebhookURL != "" {
		u, err := url.Parse(c.Observability.WebhookURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fieldErr("observability.webhook_url", "must be a valid http(s) URL")
		}
	}
	if c.Server.PublicURL != "" {
		u, err := url.Parse(c.Server.PublicURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !IsLoopbackHost(u.Hostname())) {
			return fieldErr("server.public_url", "must be a valid https URL")
		}
	}
	return nil
}

// warnings returns operator facing advisories after successful validation.
func (c *ServerConfig) warnings() []string {
	var out []string
	if c.Security.AllowInsecureDefaults {
		out = append(out, "安全警告：security.allow_insecure_defaults=true，已跳过弱口令/示例令牌拦截，切勿用于生产")
	}
	if c.Proxy.AuthMode != model.AuthRequired {
		out = append(out, fmt.Sprintf("安全警告：proxy.auth_mode=%s，代理入口未强制认证", c.Proxy.AuthMode))
	}
	if c.TLS.Mode == "insecure" {
		out = append(out, "安全警告：tls.mode=insecure，证书校验已关闭，仅限本地开发")
	}
	if c.TLS.Mode == "pin" {
		out = append(out, "提示：tls.mode=pin 使用自签证书，节点需配置 SPKI 指纹；浏览器访问面板会提示证书不受信任，这是预期行为")
	}
	if c.Tunnel.AllowPlainWS {
		out = append(out, "安全警告：tunnel.allow_plain_ws=true，允许明文 ws:// 隧道，仅限回环/开发环境")
	}
	if c.Nodes.MTLS {
		out = append(out, "提示：节点接入使用 mTLS 双向认证")
	}
	if len(c.Nodes.Tokens) == 0 && !c.Nodes.MTLS {
		out = append(out, "提示：未配置静态节点令牌，启动时将在状态目录生成随机令牌并打印一次")
	}
	if c.Geo.Enabled && len(c.Geo.Providers) > 0 && !c.Geo.RemoteConsent {
		out = append(out, "提示：配置了在线归属地 provider 但 geo.remote_consent=false，远程 provider 不会启用")
	}
	if c.Geo.MMDBPath == "" {
		out = append(out, "提示：未配置 MMDB，归属地信息仅来自在线 provider；国家/城市精度有限")
	}
	return out
}

// Validate checks the geo provider configuration strictly. Response formats are
// never sniffed: every provider must declare its type and mappings.
func (g *GeoConfig) Validate() error {
	if !g.Enabled {
		return nil
	}
	if g.CacheTTL < model.D(time.Minute) || g.CacheTTL > model.D(time.Hour*24*30) {
		return fieldErr("geo.cache_ttl", "must be between 1m and 720h")
	}
	if g.MaxConcurrent < 1 || g.MaxConcurrent > 64 {
		return fieldErr("geo.max_concurrent", "must be between 1 and 64")
	}
	if g.RatePerMin < 0 || g.RatePerMin > 100000 {
		return fieldErr("geo.rate_per_min", "must be between 0 and 100000")
	}
	if g.Egress.Timeout < model.D(time.Second) || g.Egress.Timeout > model.D(time.Second*10) {
		return fieldErr("geo.egress.timeout", "must be between 1s and 10s")
	}
	names := map[string]bool{}
	for i := range g.Providers {
		p := &g.Providers[i]
		field := fmt.Sprintf("geo.providers[%d]", i)
		if p.Name == "" {
			return fieldErr(field+".name", "must not be empty")
		}
		if names[p.Name] {
			return fieldErr(field+".name", "duplicate provider name %q", p.Name)
		}
		names[p.Name] = true
		switch p.Type {
		case "preset":
			if p.Preset == "" {
				return fieldErr(field+".preset", "preset type requires a preset name")
			}
			if !AllowedPresets[p.Preset] {
				return fieldErr(field+".preset", "unknown preset %q (supported: %s)", p.Preset, strings.Join(PresetNames(), ", "))
			}
			if p.Preset != "mmdb" && p.URL == "" {
				return fieldErr(field+".url", "preset %q requires a URL", p.Preset)
			}
		case "template":
			if p.URL == "" {
				return fieldErr(field+".url", "template provider requires a URL")
			}
			if len(p.Fields) == 0 {
				return fieldErr(field+".fields", "template provider requires at least one field mapping")
			}
			for k, v := range p.Fields {
				if !validGeoFieldName(k) {
					return fieldErr(field+".fields", "unsupported field %q", k)
				}
				if v == "" {
					return fieldErr(field+".fields."+k, "mapping must not be empty")
				}
				if !validFieldMapping(v) {
					return fieldErr(field+".fields."+k, "mapping must be a JSON path ($.a.b[0] or bare a.b[0]) or regex:<pattern>, got %q", v)
				}
			}
			if p.URL != "" {
				if err := ValidateRemoteURL(p.URL, false); err != nil {
					return fieldErr(field+".url", "%v", err)
				}
			}
		case "schema":
			if p.URL == "" {
				return fieldErr(field+".url", "schema provider requires a URL")
			}
			if err := ValidateRemoteURL(p.URL, false); err != nil {
				return fieldErr(field+".url", "%v", err)
			}
		default:
			return fieldErr(field+".type", "must be preset, template or schema, got %q", p.Type)
		}
		if p.Timeout != 0 && (p.Timeout < model.D(time.Second) || p.Timeout > model.D(time.Second*10)) {
			return fieldErr(field+".timeout", "must be between 1s and 10s")
		}
	}
	for i, raw := range g.Egress.EchoURLsV4 {
		if err := ValidateRemoteURL(raw, true); err != nil {
			return fieldErr(fmt.Sprintf("geo.egress.echo_urls_v4[%d]", i), "%v", err)
		}
	}
	for i, raw := range g.Egress.EchoURLsV6 {
		if err := ValidateRemoteURL(raw, true); err != nil {
			return fieldErr(fmt.Sprintf("geo.egress.echo_urls_v6[%d]", i), "%v", err)
		}
	}
	return nil
}

// ValidateRemoteURL rejects non-https (unless allowLoopbackHTTP) and overly
// long URLs. DNS/IP based SSRF filtering happens at request time in geo.
func ValidateRemoteURL(raw string, allowLoopbackHTTP bool) error {
	if len(raw) > 2048 {
		return fmt.Errorf("URL longer than 2048 bytes")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if u.Host == "" {
		return fmt.Errorf("URL must contain a host")
	}
	if u.User != nil {
		return fmt.Errorf("URL must not contain userinfo")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && allowLoopbackHTTP && IsLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("only https URLs are allowed, got scheme %q", u.Scheme)
}

func validGeoFieldName(name string) bool {
	switch name {
	case "country", "region", "city", "asn", "asn_org", "isp":
		return true
	}
	return false
}

// validFieldMapping accepts a JSON path with or without the "$." prefix, or a
// "regex:" capture pattern for plain text responses.
func validFieldMapping(v string) bool {
	if strings.HasPrefix(v, "regex:") {
		return len(strings.TrimSpace(strings.TrimPrefix(v, "regex:"))) > 0
	}
	path := strings.TrimPrefix(v, "$.")
	if path == "" {
		return false
	}
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '-', r == '.', r == '[', r == ']':
		default:
			return false
		}
	}
	return true
}

// AlignedPresets lists supported preset provider adapters.
var AlignedPresets = []string{"ipinfo", "ip-api", "ipwho.is", "cloudflare", "mmdb"}

// AllowedPresets is the preset lookup table.
var AllowedPresets = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range AlignedPresets {
		m[p] = true
	}
	return m
}()

// PresetNames returns sorted preset names.
func PresetNames() []string { return append([]string(nil), AlignedPresets...) }

var (
	bcryptHashRe = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
	argonHashRe  = regexp.MustCompile(`^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
	totpSecretRe = regexp.MustCompile(`^[A-Z2-7]{16,64}$`)
)

// ValidPasswordHash reports whether hash looks like argon2id or bcrypt output.
func ValidPasswordHash(hash string) bool {
	return bcryptHashRe.MatchString(hash) || argonHashRe.MatchString(hash)
}

// parseTOTPSecret validates a base32 TOTP secret (empty is allowed).
func parseTOTPSecret(secret string) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if s == "" {
		return "", nil
	}
	if !totpSecretRe.MatchString(s) {
		return "", fieldErr("admin.totp_secret", "must be a base32 secret of 16-64 characters")
	}
	return s, nil
}

func fieldErr(field, format string, args ...any) error {
	return fmt.Errorf("config error at %s: %s", field, fmt.Sprintf(format, args...))
}

func canonicalListen(addr string) string {
	h, p, err := ListenHostPort(addr)
	if err != nil {
		return addr
	}
	switch h {
	case "", "0.0.0.0", "::", "[::]":
		h = "*"
	}
	return h + ":" + strconv.Itoa(p)
}

// Derived state paths. A single state directory holds every persisted object;
// writes use temp file + fsync + atomic rename and keep a .bak copy.
func (c *ServerConfig) EffectiveCertDir() string {
	if c.TLS.Dir != "" {
		return c.TLS.Dir
	}
	return filepath.Join(c.StateDir, "certs")
}
func (c *ServerConfig) CredentialsPath() string { return filepath.Join(c.StateDir, "credentials.json") }
func (c *ServerConfig) GroupsPath() string      { return filepath.Join(c.StateDir, "groups.json") }
func (c *ServerConfig) RulesPath() string       { return filepath.Join(c.StateDir, "rules.json") }
func (c *ServerConfig) NodesPath() string       { return filepath.Join(c.StateDir, "nodes.json") }
func (c *ServerConfig) AdminPath() string       { return filepath.Join(c.StateDir, "admin.json") }
func (c *ServerConfig) NodeTokensPath() string  { return filepath.Join(c.StateDir, "node-tokens.json") }
func (c *ServerConfig) OverridesPath() string {
	return filepath.Join(c.StateDir, "runtime-overrides.json")
}
func (c *ServerConfig) AuditPath() string {
	if c.Audit.Path != "" {
		return c.Audit.Path
	}
	return filepath.Join(c.StateDir, "runtime-audit.jsonl")
}
func (c *ServerConfig) SettingsHistoryPath() string {
	return filepath.Join(c.StateDir, "runtime-overrides.history.json")
}
func (c *ServerConfig) JWTSecretPath() string { return filepath.Join(c.StateDir, "jwt.secret") }
func (c *ServerConfig) TrendPath() string     { return filepath.Join(c.StateDir, "trend.json") }
