package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxygw/internal/model"
)

func validPin(seed byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed
	}
	return "sha256/" + base64.StdEncoding.EncodeToString(b)
}

const strongToken = "np_0123456789abcdef0123456789abcdef"

func TestServerDefaultsPassValidation(t *testing.T) {
	cfg := DefaultServerConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default server config must validate: %v", err)
	}
	if cfg.Settings.Scheduler.Strategy != model.StrategyFastest {
		t.Fatalf("default strategy = %q", cfg.Settings.Scheduler.Strategy)
	}
	if cfg.Proxy.AuthMode != model.AuthRequired {
		t.Fatalf("default auth mode = %q", cfg.Proxy.AuthMode)
	}
}

func TestLoadServerYAMLOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	writeFile(t, path, `
state_dir: `+filepath.ToSlash(dir)+`/state
server:
  listen_addr: 127.0.0.1:18443
  ui_enabled: false
proxy:
  http_listen: 127.0.0.1:18080
  socks5_listen: ""
  auth_mode: required
tunnel:
  transport: ws
  planes: 3
admin:
  username: ops
  password_hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$0123456789abcdefghijklmnopqrstuv"
settings:
  scheduler:
    strategy: random
    sticky:
      ttl: 5m
`)
	cfg, _, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.Server.ListenAddr != "127.0.0.1:18443" || cfg.Server.UIEnabled {
		t.Fatalf("server listen overrides not applied: %+v", cfg.Server)
	}
	if cfg.Proxy.SOCKS5Listen != "" {
		t.Fatalf("socks5 should be disabled, got %q", cfg.Proxy.SOCKS5Listen)
	}
	if cfg.Tunnel.Transport != model.TransportWS || cfg.Tunnel.Planes != 3 {
		t.Fatalf("tunnel overrides not applied: %+v", cfg.Tunnel)
	}
	if cfg.Admin.Username != "ops" {
		t.Fatalf("admin override not applied")
	}
	if cfg.Settings.Scheduler.Strategy != model.StrategyRandom {
		t.Fatalf("settings override not applied: %q", cfg.Settings.Scheduler.Strategy)
	}
	if cfg.Settings.Scheduler.Sticky.TTL.Std() != 5*time.Minute {
		t.Fatalf("sticky ttl = %v", cfg.Settings.Scheduler.Sticky.TTL)
	}
	// Untouched defaults must survive.
	if cfg.Proxy.AuthMode != model.AuthRequired || cfg.Tunnel.Planes != 3 || cfg.Tunnel.ALPN != DefaultALPN {
		t.Fatalf("defaults were clobbered: %+v %+v", cfg.Proxy, cfg.Tunnel)
	}
}

func TestLoadServerEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	writeFile(t, path, `
state_dir: `+filepath.ToSlash(dir)+`/state
server:
  listen_addr: 127.0.0.1:18443
`)
	t.Setenv("NP_SERVER_LISTEN_ADDR", "127.0.0.1:19999")
	t.Setenv("NP_STATE_DIR", filepath.Join(dir, "envstate"))
	t.Setenv("NP_SETTINGS_SCHEDULER_STRATEGY", "least_inflight")
	t.Setenv("NP_SETTINGS_LIMITS_GLOBAL_DOWN_KBPS", "2048")
	t.Setenv("NP_PROXY_AUTH_MODE", "optional")
	cfg, _, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.Server.ListenAddr != "127.0.0.1:19999" {
		t.Fatalf("env must override yaml, got %q", cfg.Server.ListenAddr)
	}
	if cfg.StateDir != filepath.Join(dir, "envstate") {
		t.Fatalf("state dir env override failed: %q", cfg.StateDir)
	}
	if cfg.Settings.Scheduler.Strategy != model.StrategyLeastInflight {
		t.Fatalf("nested settings env override failed: %q", cfg.Settings.Scheduler.Strategy)
	}
	if cfg.Settings.Limits.GlobalDownKbps != 2048 {
		t.Fatalf("nested int env override failed: %d", cfg.Settings.Limits.GlobalDownKbps)
	}
	if cfg.Proxy.AuthMode != model.AuthOptional {
		t.Fatalf("proxy auth mode env override failed: %q", cfg.Proxy.AuthMode)
	}
}

func TestServerValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ServerConfig)
		want   string
	}{
		{"bad port", func(c *ServerConfig) { c.Server.ListenAddr = "127.0.0.1:70000" }, "server.listen_addr"},
		{"auth none on public", func(c *ServerConfig) {
			c.Proxy.AuthMode = model.AuthNone
			c.Server.ListenAddr = "0.0.0.0:18443"
		}, "auth_mode=none"},
		{"duplicate listeners", func(c *ServerConfig) { c.Proxy.HTTPListen = c.Proxy.SOCKS5Listen }, "duplicate listen"},
		{"bad strategy", func(c *ServerConfig) { c.Settings.Scheduler.Strategy = "nope" }, "scheduler.strategy"},
		{"ca without cert", func(c *ServerConfig) { c.TLS.Mode = "ca" }, "tls.cert_file"},
		{"insecure public", func(c *ServerConfig) {
			c.TLS.Mode = "insecure"
			c.Server.ListenAddr = "0.0.0.0:18443"
		}, "insecure"},
		{"weak node token", func(c *ServerConfig) {
			c.Nodes.Tokens = []StaticNodeToken{{NodeID: "n1", Token: "changeme"}}
		}, "weak/example secret"},
		{"bad provider type", func(c *ServerConfig) {
			c.Geo.Providers = []ProviderConfig{{Name: "x", Type: "auto", URL: "https://example.com"}}
		}, "geo.providers[0].type"},
		{"template without fields", func(c *ServerConfig) {
			c.Geo.Providers = []ProviderConfig{{Name: "x", Type: "template", URL: "https://example.com"}}
		}, "fields"},
		{"http provider", func(c *ServerConfig) {
			c.Geo.Providers = []ProviderConfig{{Name: "x", Type: "template", URL: "http://8.8.8.8/x", Fields: map[string]string{"country": "$.c"}}}
		}, "only https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestWeakSecretsMayBeAllowedExplicitly(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Security.AllowInsecureDefaults = true
	cfg.Nodes.Tokens = []StaticNodeToken{{NodeID: "n1", Token: "changeme"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit opt-in should validate, got %v", err)
	}
	cfg.Security.AllowInsecureDefaults = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("weak token must be rejected without explicit opt-in")
	}
}

func TestLoadServerMissingExplicitFile(t *testing.T) {
	if _, _, err := LoadServer(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing explicit config file")
	}
}

func TestClientConfigLoadAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	writeFile(t, path, `
server_url: https://127.0.0.1:18443
token: "`+strongToken+`"
client_id: node-test
tags: ["US-RES", "residential"]
weight: 120
planes: 3
state_dir: `+filepath.ToSlash(dir)+`/state
tls:
  mode: pin
  pins: ["`+validPin(7)+`"]
log:
  level: debug
  format: text
`)
	t.Setenv("AUTH_TOKEN", strongToken)
	t.Setenv("TRANSPORT", "ws")
	cfg, warnings, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Tags[0] != "US-RES" {
		t.Fatalf("tags not parsed: %v", cfg.Tags)
	}
	if cfg.Weight != 120 || cfg.Planes != 3 {
		t.Fatalf("numeric overrides lost: %+v", cfg)
	}
	if cfg.Transport != model.TransportWS {
		t.Fatalf("env transport override lost: %q", cfg.Transport)
	}
	if len(warnings) == 0 {
		t.Fatalf("expected transport hint warning")
	}
	if got := cfg.NormalizedTags(); len(got) != 2 || got[0] != "us-res" {
		t.Fatalf("normalized tags = %v", got)
	}
}

func TestClientIgnoresFixedBehaviourKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	writeFile(t, path, `
server_url: https://127.0.0.1:18443
token: "`+strongToken+`"
tls:
  mode: pin
  pins: ["`+validPin(9)+`"]
heartbeat_interval: 3s
dial_timeout: 1s
`)
	_, warnings, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	joined := strings.Join(warnings, "|")
	if !strings.Contains(joined, "heartbeat_interval") || !strings.Contains(joined, "dial_timeout") {
		t.Fatalf("expected ignored-key warnings, got %v", warnings)
	}
}

func TestClientValidation(t *testing.T) {
	base := func() *ClientConfig {
		c := DefaultClientConfig()
		c.ServerURL = "https://127.0.0.1:18443"
		c.Token = strongToken
		c.TLS.Pin = validPin(1)
		c.StateDir = t.TempDir()
		return c
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid client config rejected: %v", err)
	}
	{
		c := base()
		c.TLS.Mode = "insecure"
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "allow_insecure_defaults") {
			t.Fatalf("insecure mode must require explicit opt-in, got %v", err)
		}
	}
	{
		c := base()
		c.TLS.Pin = ""
		c.TLS.Pins = nil
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "pin mode requires") {
			t.Fatalf("pin mode without pin must fail, got %v", err)
		}
		c.TLS.TrustOnFirstUse = true
		if err := c.Validate(); err != nil {
			t.Fatalf("TOFU should allow empty pin: %v", err)
		}
	}
	{
		c := base()
		c.Token = "short"
		if err := c.Validate(); err == nil {
			t.Fatal("weak token must be rejected")
		}
		c.Security.AllowInsecureDefaults = true
		if err := c.Validate(); err != nil {
			t.Fatalf("explicit opt-in should allow weak token in development: %v", err)
		}
	}
	{
		c := base()
		c.Planes = 9
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "planes") {
			t.Fatalf("planes out of range must fail, got %v", err)
		}
	}
	{
		c := base()
		c.ServerURL = "http://example.com:443"
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("plain http to public host must fail, got %v", err)
		}
	}
}

func TestParseServerURL(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantPath string
	}{
		{"gw.example.com", "gw.example.com", 443, "/tunnel"},
		{"gw.example.com:8443", "gw.example.com", 8443, "/tunnel"},
		{"https://gw.example.com", "gw.example.com", 443, "/tunnel"},
		{"wss://gw.example.com:9443/edge", "gw.example.com", 9443, "/edge"},
		{"http://127.0.0.1:18080", "127.0.0.1", 18080, "/tunnel"},
	}
	for _, tc := range cases {
		ep, err := ParseServerURL(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if ep.Host != tc.wantHost || ep.Port != tc.wantPort || ep.Path != tc.wantPath {
			t.Fatalf("%q => %+v", tc.in, ep)
		}
	}
	for _, bad := range []string{"", "ftp://x", "https://", "http://example.com"} {
		if _, err := ParseServerURL(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestParsePinNormalizesHexAndBase64(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	b64Pin := "sha256/" + base64.StdEncoding.EncodeToString(raw)
	hexPin := ""
	for _, b := range raw {
		const hexdigits = "0123456789abcdef"
		hexPin += string(hexdigits[b>>4]) + string(hexdigits[b&0xf])
	}
	a, err := ParsePin(b64Pin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParsePin(hexPin)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParsePin(strings.TrimPrefix(b64Pin, "sha256/"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a != c {
		t.Fatalf("pin normalization mismatch: %q %q %q", a, b, c)
	}
	if !strings.HasPrefix(a, "sha256/") {
		t.Fatalf("canonical pin must start with sha256/: %q", a)
	}
	if _, err := ParsePin("nope"); err == nil {
		t.Fatal("invalid pin must fail")
	}
}

func TestModelDurationJSONYAML(t *testing.T) {
	d := model.D(90 * time.Second)
	got, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"1m30s"` {
		t.Fatalf("duration json = %s", got)
	}
	var back model.Duration
	if err := json.Unmarshal([]byte(`"2m"`), &back); err != nil {
		t.Fatal(err)
	}
	if back.Std() != 2*time.Minute {
		t.Fatalf("duration round trip = %v", back)
	}
}

func TestDerivedPaths(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.StateDir = "C:/tmp/proxygw"
	if got := cfg.CredentialsPath(); !strings.HasSuffix(got, "credentials.json") {
		t.Fatalf("credentials path = %q", got)
	}
	if got := cfg.EffectiveCertDir(); !strings.Contains(got, "certs") {
		t.Fatalf("cert dir = %q", got)
	}
	cfg.TLS.Dir = "C:/certs-custom"
	if got := cfg.EffectiveCertDir(); got != "C:/certs-custom" {
		t.Fatalf("explicit cert dir ignored: %q", got)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
