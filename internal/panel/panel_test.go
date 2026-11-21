package panel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/crypto/argon2"

	"proxygw/internal/acl"
	"proxygw/internal/audit"
	"proxygw/internal/auth"
	"proxygw/internal/groups"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/registry"
	"proxygw/internal/rules"
	"proxygw/internal/settings"
	"proxygw/internal/version"
)

// testPassword is the administrator password used by every panel test.
const testPassword = "panel-pass-123"

// testNow is the frozen panel clock used by the tests.
var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// cheapPasswordHash builds a syntactically valid argon2id PHC hash with tiny
// parameters so the panel test suite stays fast.
func cheapPasswordHash(t *testing.T, password string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 1024, 1, 1,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// --- fake injected APIs ----------------------------------------------------

type fakeTunnel struct {
	mu          sync.Mutex
	sessions    []SessionInfo
	kicks       []string
	probeResult *protocol.ProbeResult
	probeErr    error
	probeCalls  []string
	pingLatency time.Duration
	pingErr     error
	active      int64
}

func (f *fakeTunnel) Sessions() []SessionInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SessionInfo, len(f.sessions))
	copy(out, f.sessions)
	return out
}

func (f *fakeTunnel) KickNode(nodeID, reason, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kicks = append(f.kicks, nodeID+":"+reason)
	return nil
}

func (f *fakeTunnel) ProbeNode(ctx context.Context, nodeID, kind, target string, payload []byte) (*protocol.ProbeResult, error) {
	f.mu.Lock()
	f.probeCalls = append(f.probeCalls, kind+":"+target)
	result := f.probeResult
	err := f.probeErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (f *fakeTunnel) PingNode(ctx context.Context, nodeID string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pingLatency, f.pingErr
}

func (f *fakeTunnel) NodePlaneCount(nodeID string) int { return 0 }

func (f *fakeTunnel) ActiveStreams() int64 { return f.active }

type fakeGeo struct {
	mu         sync.Mutex
	statuses   []ProviderStatus
	setCalls   map[string]bool
	testResult *ProviderTestResult
	testErr    error
	lastIP     net.IP
}

func (f *fakeGeo) ProviderStatuses() []ProviderStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ProviderStatus, len(f.statuses))
	copy(out, f.statuses)
	return out
}

func (f *fakeGeo) SetProviderEnabled(name string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setCalls == nil {
		f.setCalls = make(map[string]bool)
	}
	for i := range f.statuses {
		if f.statuses[i].Name == name {
			f.statuses[i].Enabled = enabled
			f.setCalls[name] = enabled
			return nil
		}
	}
	return fmt.Errorf("geo: unknown provider %q", name)
}

func (f *fakeGeo) TestProvider(ctx context.Context, name string, ip net.IP) (*ProviderTestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastIP = ip
	return f.testResult, f.testErr
}

type fakeSched struct {
	mu        sync.Mutex
	preview   StickyPreview
	lastRules []model.StickyRule
	setErr    error
	previews  int
}

func (f *fakeSched) PreviewSticky(target model.RequestTarget, nodeID string, groupIDs []string) StickyPreview {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previews++
	return f.preview
}

func (f *fakeSched) SetRules(stickyRules []model.StickyRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.lastRules = append([]model.StickyRule(nil), stickyRules...)
	return nil
}

type fakeCert struct {
	mu        sync.Mutex
	status    CertStatus
	rotatePin string
	rotateErr error
	reloadErr error
	rotated   bool
	reloaded  bool
}

func (f *fakeCert) Status() CertStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeCert) RotatePin() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotated = true
	if f.rotateErr != nil {
		return "", f.rotateErr
	}
	return f.rotatePin, nil
}

func (f *fakeCert) Reload() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloaded = true
	return f.reloadErr
}

type fakeStats struct {
	mu       sync.Mutex
	overview OverviewSnapshot
	targets  []TargetStat
	nodes    []TargetStat
	creds    []TargetStat
	window   string
	n        int
}

func (f *fakeStats) Overview(ctx context.Context) OverviewSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.overview
}

func (f *fakeStats) TopN(ctx context.Context, window string, n int) ([]TargetStat, []TargetStat, []TargetStat) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.window, f.n = window, n
	return f.targets, f.nodes, f.creds
}

// --- test environment ------------------------------------------------------

// testEnvOptions customises newTestEnvWith.
type testEnvOptions struct {
	totpSecret    string
	lockThreshold int
	webFS         fstest.MapFS
	serverURL     string
	noFakes       bool
	noWebFS       bool
}

// testEnv bundles the real domain stores with fake tunnel/geo/sched/cert/stats.
type testEnv struct {
	t   *testing.T
	srv *Server

	admin    *auth.AdminManager
	creds    *auth.CredentialStore
	groups   *groups.Store
	rules    *rules.Store
	reg      *registry.Registry
	aclEng   *acl.Engine
	setMgr   *settings.Manager
	auditLog *audit.Store
	metrics  *metrics.Metrics

	tunnel *fakeTunnel
	geo    *fakeGeo
	sched  *fakeSched
	cert   *fakeCert
	stats  *fakeStats

	kickMu     sync.Mutex
	kickCounts map[string]int

	httpSrv *httptest.Server
	opts    Options
}

// newTestEnv builds an isolated panel environment with one online node "node-a"
// and one offline node "node-b". Every optional API gets a fake unless disabled.
func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvWith(t, testEnvOptions{})
}

// newTestEnvWith builds a panel environment with custom options.
func newTestEnvWith(t *testing.T, envOpts testEnvOptions) *testEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := func() time.Time { return testNow }

	lockThreshold := envOpts.lockThreshold
	if lockThreshold <= 0 {
		lockThreshold = 1000
	}
	admin, err := auth.NewAdminManager(auth.AdminOptions{
		Username:        "admin",
		PasswordHash:    cheapPasswordHash(t, testPassword),
		TOTPSecret:      envOpts.totpSecret,
		SessionTTL:      time.Hour,
		LoginRatePerMin: 1000,
		LockThreshold:   lockThreshold,
		LockWindow:      time.Minute,
		Logger:          logger,
		Now:             clock,
	})
	if err != nil {
		t.Fatalf("NewAdminManager: %v", err)
	}
	credStore, err := auth.NewCredentialStore("", logger)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	groupStore, err := groups.NewStore("", logger)
	if err != nil {
		t.Fatalf("NewStore(groups): %v", err)
	}
	ruleStore, err := rules.NewStore("", logger)
	if err != nil {
		t.Fatalf("NewStore(rules): %v", err)
	}
	setMgr, err := settings.NewManager("", model.DefaultSettings(), logger)
	if err != nil {
		t.Fatalf("NewManager(settings): %v", err)
	}
	metricSet := metrics.New()
	reg, err := registry.New(logger, metricSet, "")
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	reg.SetGroupsResolver(groupStore.Resolver())
	aclEng := acl.New(acl.Options{
		DefaultAction:        func() string { return setMgr.Current().DefaultACLAction },
		AllowLoopbackTargets: true,
	})
	auditLog, err := audit.New("", false)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	env := &testEnv{
		t:          t,
		admin:      admin,
		creds:      credStore,
		groups:     groupStore,
		rules:      ruleStore,
		reg:        reg,
		aclEng:     aclEng,
		setMgr:     setMgr,
		auditLog:   auditLog,
		metrics:    metricSet,
		kickCounts: map[string]int{},
	}

	webFS := envOpts.webFS
	if webFS == nil {
		webFS = fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<!doctype html><html><body>panel</body></html>")},
			"app.js":     &fstest.MapFile{Data: []byte("console.log('panel');")},
			"style.css":  &fstest.MapFile{Data: []byte("body{color:#111}")},
		}
	}
	serverURL := envOpts.serverURL
	if serverURL == "" {
		serverURL = "https://panel.example.com:8443"
	}
	opts := Options{
		Logger:   logger,
		Version:  version.Info{Version: "test", Commit: "c0ffee", BuildTime: "2026-01-02T03:04:05Z"},
		Auth:     credStore,
		Admin:    admin,
		Groups:   groupStore,
		Rules:    ruleStore,
		Registry: reg,
		ACL:      aclEng,
		Settings: setMgr,
		Audit:    auditLog,
		Metrics:  metricSet,
		KickCredential: func(credentialID string) int {
			env.kickMu.Lock()
			defer env.kickMu.Unlock()
			env.kickCounts[credentialID]++
			return env.kickCounts[credentialID]
		},
		ServerURL: serverURL,
		Now:       clock,
	}
	if !envOpts.noWebFS {
		opts.WebFS = webFS
	}
	if !envOpts.noFakes {
		env.tunnel = &fakeTunnel{active: 7, pingLatency: 12 * time.Millisecond}
		env.geo = &fakeGeo{statuses: []ProviderStatus{
			{Name: "mmdb", Type: "preset", Preset: "mmdb", Enabled: true, Healthy: true, Priority: 1},
			{Name: "ipinfo", Type: "template", Preset: "ipinfo", Enabled: true, Healthy: true, Priority: 2},
		}}
		env.sched = &fakeSched{}
		env.cert = &fakeCert{
			status: CertStatus{
				Mode:       "pin",
				Pin:        "sha256/TESTPINAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PinNext:    "",
				CertPath:   "state/certs/server.crt",
				KeyPath:    "state/certs/server.key",
				NotAfter:   testNow.Add(365 * 24 * time.Hour),
				LastReload: testNow,
			},
			rotatePin: "sha256/NEXTPINBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		}
		env.stats = &fakeStats{
			overview: OverviewSnapshot{
				Requests:     12345,
				Errors:       12,
				Retries:      3,
				RateLimited:  1,
				BreakerTrips: 2,
				ClockSkewMS:  250,
				Trend:        []TrendPoint{{TS: testNow.Unix(), Requests: 120, Errors: 1, Active: 7}},
			},
			targets: []TargetStat{{Target: "example.com:443", Count: 9, Bytes: 900, Errors: 1}},
			nodes:   []TargetStat{{Target: "node-a", Count: 9}},
			creds:   []TargetStat{{Target: "alice", Count: 9}},
		}
		opts.Tunnel = env.tunnel
		opts.Geo = env.geo
		opts.Sched = env.sched
		opts.Cert = env.cert
		opts.Stats = env.stats
	}
	env.opts = opts

	srv, err := New(opts)
	if err != nil {
		t.Fatalf("panel.New: %v", err)
	}
	env.srv = srv
	env.httpSrv = httptest.NewServer(srv.Handler())
	t.Cleanup(env.httpSrv.Close)
	t.Cleanup(func() {
		_ = credStore.Close()
		_ = reg.Close()
	})
	return env
}

// addNode attaches a transport plane for a node. When online is false the plane
// is detached immediately so the node stays known but offline.
func (e *testEnv) addNode(nodeID, alias string, online bool, mutate func(*registry.PlaneMeta)) {
	meta := registry.PlaneMeta{
		NodeID:     nodeID,
		Alias:      alias,
		Weight:     1,
		Version:    "1.2.3",
		Transport:  model.TransportQUIC,
		EgressV4:   "203.0.113.10",
		PlaneIndex: 0,
	}
	if mutate != nil {
		mutate(&meta)
	}
	if _, _, err := e.reg.AttachPlane(meta); err != nil {
		e.t.Fatalf("AttachPlane(%s): %v", nodeID, err)
	}
	if !online {
		e.reg.DetachPlane(nodeID, meta.PlaneIndex)
	}
}

// url joins the httptest base URL with an API path.
func (e *testEnv) url(path string) string { return e.httpSrv.URL + path }

// --- API client helpers ----------------------------------------------------

// apiClient is a cookie-jar backed panel API client.
type apiClient struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

// newAPIClient builds a cookie jar client (no login).
func (e *testEnv) newAPIClient(t *testing.T) *apiClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &apiClient{t: t, base: e.httpSrv.URL, http: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

// login logs in and stores the CSRF token on the client.
func (e *testEnv) loginClient(t *testing.T) *apiClient {
	t.Helper()
	client := e.newAPIClient(t)
	resp, data := client.do(http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": testPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", resp.StatusCode, data)
	}
	var session sessionResponse
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatalf("login: decode: %v (%s)", err, data)
	}
	if session.CSRF == "" {
		t.Fatalf("login: empty csrf token")
	}
	client.csrf = session.CSRF
	return client
}

// do performs one request. body is JSON encoded when non-nil and the CSRF token
// is added when set.
func (c *apiClient) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	data, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		c.t.Fatalf("%s %s: read body: %v", method, path, readErr)
	}
	return resp, data
}

// doJSON performs a request and decodes the JSON response into out.
func (c *apiClient) doJSON(method, path string, body any, out any) int {
	c.t.Helper()
	resp, data := c.do(method, path, body)
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: decode response %q: %v", method, path, data, err)
		}
	}
	return resp.StatusCode
}

// mustStatus asserts the response status.
func (c *apiClient) mustStatus(method, path string, body any, want int) []byte {
	c.t.Helper()
	resp, data := c.do(method, path, body)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, resp.StatusCode, want, data)
	}
	return data
}

// errorCode decodes the error envelope code from a response body.
func errorCode(t *testing.T, data []byte) string {
	t.Helper()
	var payload errorResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode error response %q: %v", data, err)
	}
	return payload.Error
}

// jsonUnmarshal is a tiny alias so some tests can avoid importing encoding/json.
func jsonUnmarshal(data []byte, out any) error { return json.Unmarshal(data, out) }

// waitFor polls fn until it returns true or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
