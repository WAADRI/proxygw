// Package integration: support helpers for the M3-M6 process-internal
// end-to-end tests. Everything here is additive: the helpers in
// integration_test.go are reused where convenient but the M3-M6 suite uses its
// own server/client variants so that a finished Run can be observed without
// racing the cleanup path.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"proxygw/internal/app"
	"proxygw/internal/auth"
	"proxygw/internal/config"
	"proxygw/internal/logx"
	"proxygw/internal/model"
)

const (
	e2eAdminUser = "admin"
	// e2eAdminPass is hashed with auth.HashPassword (argon2id) and injected as
	// config.Admin.PasswordHash, so the panel never falls back to the random
	// first-boot password.
	e2eAdminPass = "admin-e2e-password-123"

	e2eHelloBody = "hello-from-origin"
	e2eBigSize   = 64 * 1024
)

// e2eBigBody is the deterministic 64 KiB payload served by /big.
var e2eBigBody = func() []byte {
	unit := []byte("0123456789abcdef")
	out := make([]byte, e2eBigSize)
	for i := range out {
		out[i] = unit[i%len(unit)]
	}
	return out
}()

var (
	e2eAdminHashOnce sync.Once
	e2eAdminHash     string
	e2eAdminHashErr  error
)

// e2eAdminPasswordHash returns the argon2id hash of e2eAdminPass (computed once
// per test binary; argon2id is intentionally expensive).
func e2eAdminPasswordHash(t *testing.T) string {
	t.Helper()
	e2eAdminHashOnce.Do(func() {
		e2eAdminHash, e2eAdminHashErr = auth.HashPassword(e2eAdminPass)
	})
	if e2eAdminHashErr != nil {
		t.Fatalf("hash admin password: %v", e2eAdminHashErr)
	}
	return e2eAdminHash
}

// e2eBcryptHash produces a cheap bcrypt hash for seeded proxy credentials. The
// proxy hot path re-verifies the password on every request; bcrypt.MinCost keeps
// the 30-way concurrency test from serialising on 64 MiB argon2 allocations
// while still exercising the real credential verification code path (the auth
// package accepts both argon2id and bcrypt hashes).
func e2eBcryptHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	return string(hash)
}

// e2eWriteJSON writes value as a compact JSON document (seed helpers).
func e2eWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedE2ECredentials pre-seeds credentials.json before app.NewServer loads it.
// The server only bootstraps a random credential when the store is empty, so
// seeding makes usernames/passwords deterministic.
func seedE2ECredentials(t *testing.T, cfg *config.ServerConfig, creds ...model.Credential) {
	t.Helper()
	now := time.Now().UTC()
	for i := range creds {
		if creds[i].CreatedAt.IsZero() {
			creds[i].CreatedAt = now
		}
		if creds[i].UpdatedAt.IsZero() {
			creds[i].UpdatedAt = now
		}
	}
	e2eWriteJSON(t, cfg.CredentialsPath(), creds)
}

// seedE2EGroups pre-seeds groups.json before app.NewServer loads it.
func seedE2EGroups(t *testing.T, cfg *config.ServerConfig, groups ...model.Group) {
	t.Helper()
	now := time.Now().UTC()
	for i := range groups {
		if groups[i].CreatedAt.IsZero() {
			groups[i].CreatedAt = now
		}
		if groups[i].UpdatedAt.IsZero() {
			groups[i].UpdatedAt = now
		}
	}
	e2eWriteJSON(t, cfg.GroupsPath(), groups)
}

// ---------------------------------------------------------------------------
// server / client lifecycle
// ---------------------------------------------------------------------------

// e2eServer is the M3-M6 variant of testServer. Run's result is published
// through a closed channel plus a mutex-protected error so tests can wait for
// shutdown repeatedly (the shared cleanup path also waits).
type e2eServer struct {
	app    *app.Server
	cfg    *config.ServerConfig
	port   int
	pin    string
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	runErr error
}

// startE2EServer starts a fully wired gateway server on loopback with the same
// defaults as startServer.
func startE2EServer(t *testing.T, mutate func(*config.ServerConfig)) *e2eServer {
	t.Helper()
	cfg := config.DefaultServerConfig()
	port := freePort(t)
	cfg.StateDir = t.TempDir()
	cfg.Server.ListenAddr = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Proxy.HTTPListen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg.Proxy.SOCKS5Listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg.TLS.Mode = "pin"
	cfg.Nodes.Tokens = []config.StaticNodeToken{{NodeID: "*", Token: testToken, Note: "integration"}}
	cfg.Log = logx.Config{Level: "error", Format: "json"}
	cfg.Geo.Enabled = false
	cfg.Observability.MetricsEnabled = true
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("e2e server config invalid: %v", err)
	}
	srv, err := app.NewServer(app.ServerOptions{Config: cfg, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("app.NewServer: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("srv.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	es := &e2eServer{
		app:    srv,
		cfg:    cfg,
		port:   port,
		pin:    srv.CertStatus().Pin,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		err := srv.Run(ctx)
		es.mu.Lock()
		es.runErr = err
		es.mu.Unlock()
		close(es.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-es.done:
		case <-time.After(25 * time.Second):
			t.Log("e2e server shutdown timed out")
		}
	})
	return es
}

// waitRun blocks until Run returned (or fails the test) and returns its error.
func (s *e2eServer) waitRun(t *testing.T, timeout time.Duration) error {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		t.Fatalf("server Run did not return within %s", timeout)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runErr
}

// panelBaseURL is the HTTPS base URL of the shared listener.
func (s *e2eServer) panelBaseURL() string {
	return fmt.Sprintf("https://127.0.0.1:%d", s.port)
}

// e2eClient is a node agent started against an e2eServer.
type e2eClient struct {
	client *app.Client
	cfg    *config.ClientConfig
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	runErr error
}

// startE2EClient starts a node agent. Tests use id/tags to control group
// membership; extra may further tweak the config.
//
// The agent is pinned to QUIC with a single plane and an empty egress echo list:
// the suite must not depend on outbound network access, and registration is
// fastest that way.
func startE2EClient(t *testing.T, srv *e2eServer, id string, tags []string, extra func(*config.ClientConfig)) *e2eClient {
	t.Helper()
	cfg := config.DefaultClientConfig()
	cfg.ServerURL = fmt.Sprintf("https://127.0.0.1:%d", srv.port)
	cfg.Token = testToken
	cfg.ClientID = id
	cfg.Alias = id
	cfg.Tags = append([]string(nil), tags...)
	cfg.StateDir = t.TempDir()
	cfg.TLS.Mode = "pin"
	cfg.TLS.Pin = srv.pin
	cfg.Log = logx.Config{Level: "error", Format: "json"}
	cfg.Transport = model.TransportQUIC
	cfg.Planes = 1
	cfg.Compression = false
	cfg.Egress.EchoURLsV4 = nil
	cfg.Egress.EchoURLsV6 = nil
	if extra != nil {
		extra(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("e2e client %s config invalid: %v", id, err)
	}
	client, err := app.NewClient(app.ClientOptions{Config: cfg, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("app.NewClient(%s): %v", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ec := &e2eClient{client: client, cfg: cfg, cancel: cancel, done: make(chan struct{})}
	go func() {
		err := client.Run(ctx)
		ec.mu.Lock()
		ec.runErr = err
		ec.mu.Unlock()
		close(ec.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-ec.done:
		case <-time.After(25 * time.Second):
			t.Logf("node agent %s shutdown timed out", id)
		}
		_ = client.Close()
	})
	return ec
}

// stop cancels the node agent and waits for a clean (nil error) shutdown.
func (c *e2eClient) stop(t *testing.T) {
	t.Helper()
	c.cancel()
	select {
	case <-c.done:
	case <-time.After(20 * time.Second):
		t.Fatalf("node agent %s did not stop within 20s", c.cfg.ClientID)
	}
	c.mu.Lock()
	err := c.runErr
	c.mu.Unlock()
	if err != nil {
		t.Fatalf("node agent %s stopped with error: %v", c.cfg.ClientID, err)
	}
}

// ---------------------------------------------------------------------------
// registry / group wait helpers
// ---------------------------------------------------------------------------

func e2eContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// e2eWaitNodesOnline waits until at least want nodes are online.
func e2eWaitNodesOnline(t *testing.T, srv *e2eServer, want int) {
	t.Helper()
	waitFor(t, 20*time.Second, fmt.Sprintf("%d nodes online", want), func() bool {
		return srv.app.Registry().OnlineCount() >= want
	})
}

// e2eNodeSnapshot returns the current registry snapshot of one node.
func e2eNodeSnapshot(t *testing.T, srv *e2eServer, id string) model.Node {
	t.Helper()
	node, ok := srv.app.Registry().Get(id)
	if !ok {
		t.Fatalf("registry has no node %q", id)
	}
	return node
}

// e2eWaitNodeOnline waits until the given node is reported online.
func e2eWaitNodeOnline(t *testing.T, srv *e2eServer, id string) {
	t.Helper()
	waitFor(t, 20*time.Second, "node "+id+" online", func() bool {
		node, ok := srv.app.Registry().Get(id)
		return ok && node.Online
	})
}

// e2eWaitNodeOffline waits until the given node is reported offline.
func e2eWaitNodeOffline(t *testing.T, srv *e2eServer, id string) {
	t.Helper()
	waitFor(t, 20*time.Second, "node "+id+" offline", func() bool {
		node, ok := srv.app.Registry().Get(id)
		return ok && !node.Online
	})
}

// e2eWaitNodeGroup waits until the registry resolves the group for the node.
func e2eWaitNodeGroup(t *testing.T, srv *e2eServer, nodeID, groupID string) {
	t.Helper()
	waitFor(t, 15*time.Second, "node "+nodeID+" in group "+groupID, func() bool {
		node, ok := srv.app.Registry().Get(nodeID)
		return ok && e2eContains(node.Groups, groupID)
	})
}

// ---------------------------------------------------------------------------
// local origin servers
// ---------------------------------------------------------------------------

// e2eOrigin hosts the plain HTTP and the TLS origin used by proxy tests.
type e2eOrigin struct {
	plain *httptest.Server
	tls   *httptest.Server
}

// newE2EOrigin starts the local origin servers and registers their cleanup.
func newE2EOrigin(t *testing.T) *e2eOrigin {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "e2e")
		_, _ = io.WriteString(w, e2eHelloBody)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Echo-Len", strconv.Itoa(len(body)))
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if len(body) > 0 {
			_, _ = w.Write(body)
		}
	})
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		for i, part := range []string{"chunk-one;", "chunk-two;", "chunk-three"} {
			if _, err := io.WriteString(w, part); err != nil {
				return
			}
			flusher.Flush()
			if i == 0 {
				// A small pause makes the chunked framing observable end to end.
				time.Sleep(5 * time.Millisecond)
			}
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(e2eBigBody)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(e2eBigBody)
	})
	plain := httptest.NewServer(mux)
	t.Cleanup(plain.Close)
	tlsSrv := httptest.NewTLSServer(mux)
	t.Cleanup(tlsSrv.Close)
	return &e2eOrigin{plain: plain, tls: tlsSrv}
}

// splitURLHostPort parses host and port out of an httptest server URL.
func splitURLHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse origin URL %q: %v", raw, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse origin port in %q: %v", raw, err)
	}
	return u.Hostname(), port
}

func e2eJoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ---------------------------------------------------------------------------
// panel API client
// ---------------------------------------------------------------------------

// e2ePanel is an authenticated (or not) panel API client with its own cookie
// jar and a self-signed-tolerant TLS transport.
type e2ePanel struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

// newE2EPanel builds a panel client for the given server.
func newE2EPanel(t *testing.T, srv *e2eServer) *e2ePanel {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- test server uses a self-signed pin-mode certificate
	t.Cleanup(transport.CloseIdleConnections)
	return &e2ePanel{
		t:    t,
		base: srv.panelBaseURL(),
		http: &http.Client{Transport: transport, Jar: jar, Timeout: 20 * time.Second},
	}
}

// raw performs one request without adding the CSRF header (unless csrf is set
// explicitly by the caller through setCSRF).
func (p *e2ePanel) raw(method, path string, body any) (int, []byte, http.Header) {
	p.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			p.t.Fatalf("marshal panel body for %s %s: %v", method, path, err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, p.base+path, reader)
	if err != nil {
		p.t.Fatalf("build panel request %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.csrf != "" {
		req.Header.Set("X-CSRF-Token", p.csrf)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		p.t.Fatalf("panel request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		p.t.Fatalf("read panel response %s %s: %v", method, path, err)
	}
	return resp.StatusCode, data, resp.Header
}

// request performs one credentialed request and returns status/body/headers.
func (p *e2ePanel) request(method, path string, body any) (int, []byte, http.Header) {
	p.t.Helper()
	return p.raw(method, path, body)
}

// doJSON performs one request, requires wantStatus and decodes the JSON body
// into out when out is non-nil.
func (p *e2ePanel) doJSON(method, path string, body any, wantStatus int, out any) []byte {
	p.t.Helper()
	status, data, _ := p.request(method, path, body)
	if status != wantStatus {
		p.t.Fatalf("%s %s status = %d, want %d; body: %s", method, path, status, wantStatus, truncateForLog(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			p.t.Fatalf("%s %s: decode response %q: %v", method, path, truncateForLog(data), err)
		}
	}
	return data
}

// login authenticates the administrator and records the CSRF token.
func (p *e2ePanel) login(user, password string) {
	p.t.Helper()
	var sess struct {
		Username string `json:"username"`
		CSRF     string `json:"csrf"`
	}
	p.doJSON(http.MethodPost, "/api/v1/login", map[string]any{
		"username": user,
		"password": password,
	}, http.StatusOK, &sess)
	if sess.Username != user {
		p.t.Fatalf("login response username = %q, want %q", sess.Username, user)
	}
	if sess.CSRF == "" {
		p.t.Fatalf("login response carries no csrf token")
	}
	p.csrf = sess.CSRF
}

// clearCSRF mimics a browser that lost the double-submit token.
func (p *e2ePanel) clearCSRF() { p.csrf = "" }

func truncateForLog(data []byte) string {
	const limit = 600
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + "...(truncated)"
}

// e2eNodeItem is the subset of GET /api/v1/nodes items the suite asserts on.
type e2eNodeItem struct {
	ID      string   `json:"id"`
	Alias   string   `json:"alias"`
	Tags    []string `json:"tags"`
	Groups  []string `json:"groups"`
	Online  bool     `json:"online"`
	Enabled bool     `json:"enabled"`
	Planes  int      `json:"planes"`
}

// e2eNodesResponse is the GET /api/v1/nodes payload (subset).
type e2eNodesResponse struct {
	Items   []e2eNodeItem `json:"items"`
	Total   int           `json:"total"`
	Summary struct {
		Nodes           int `json:"nodes"`
		Online          int `json:"online"`
		UniqueEgressIPs int `json:"unique_egress_ips"`
	} `json:"summary"`
}

// e2eStatItem is one TopN row.
type e2eStatItem struct {
	Target string `json:"target"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
	Errors int64  `json:"errors"`
}

// e2eTopNResponse is the GET /api/v1/stats/topn payload.
type e2eTopNResponse struct {
	Targets     []e2eStatItem `json:"targets"`
	Nodes       []e2eStatItem `json:"nodes"`
	Credentials []e2eStatItem `json:"credentials"`
}

// topNNodes returns the node_id -> request count map observed through the panel
// statistics hook. It is the strongest available assertion for "which node
// served the request": OnRequestEnd records the serving node id here.
func (p *e2ePanel) topNNodes() map[string]int64 {
	p.t.Helper()
	var resp e2eTopNResponse
	p.doJSON(http.MethodGet, "/api/v1/stats/topn?window=15m&n=10", nil, http.StatusOK, &resp)
	out := make(map[string]int64, len(resp.Nodes))
	for _, item := range resp.Nodes {
		out[item.Target] = item.Count
	}
	return out
}

// waitTopNNodes polls the TopN node counters until nodeID reaches want or the
// timeout expires. OnRequestEnd accounting runs on the response path, so the
// counter can lag the client-observed response by a scheduling tick; waiting
// here keeps the assertion about "which node served the requests" while
// avoiding a timing flake on slow/loaded CI runners. It returns the last
// observed map either way so callers can produce a useful failure message.
func (p *e2ePanel) waitTopNNodes(nodeID string, want int64, timeout time.Duration) map[string]int64 {
	p.t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]int64
	for {
		last = p.topNNodes()
		if last[nodeID] >= want || time.Now().After(deadline) {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitTopNNodesAbove polls the TopN node counters until nodeID exceeds above or
// the timeout expires, then returns the last observed map. Same rationale as
// waitTopNNodes: OnRequestEnd accounting is asynchronous with respect to the
// client-visible response.
func (p *e2ePanel) waitTopNNodesAbove(nodeID string, above int64, timeout time.Duration) map[string]int64 {
	p.t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]int64
	for {
		last = p.topNNodes()
		if last[nodeID] > above || time.Now().After(deadline) {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// settingsState is the decoded GET /api/v1/settings payload.
type e2eSettingsState struct {
	Current map[string]any `json:"current"`
	Version int            `json:"version"`
}

// getSettings returns the current settings as a generic map.
func (p *e2ePanel) getSettings() e2eSettingsState {
	p.t.Helper()
	var resp struct {
		Current json.RawMessage `json:"current"`
		Version int             `json:"version"`
	}
	p.doJSON(http.MethodGet, "/api/v1/settings", nil, http.StatusOK, &resp)
	var current map[string]any
	if err := json.Unmarshal(resp.Current, &current); err != nil {
		p.t.Fatalf("decode current settings: %v", err)
	}
	return e2eSettingsState{Current: current, Version: resp.Version}
}

// strategy reads scheduler.strategy out of the GET /settings payload.
func (p *e2ePanel) strategy() string {
	p.t.Helper()
	state := p.getSettings()
	scheduler, ok := state.Current["scheduler"].(map[string]any)
	if !ok {
		p.t.Fatalf("settings.scheduler is not an object: %v", state.Current["scheduler"])
	}
	strategy, _ := scheduler["strategy"].(string)
	return strategy
}

// cloneSettings deep-copies a decoded settings object.
func cloneSettings(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	return out
}

// withStrategy returns a copy of settings with scheduler.strategy replaced.
func withStrategy(t *testing.T, settings map[string]any, strategy string) map[string]any {
	t.Helper()
	out := cloneSettings(t, settings)
	scheduler, ok := out["scheduler"].(map[string]any)
	if !ok {
		t.Fatalf("settings.scheduler is not an object: %v", out["scheduler"])
	}
	scheduler["strategy"] = strategy
	return out
}

// ---------------------------------------------------------------------------
// proxy entry clients
// ---------------------------------------------------------------------------

// e2eProxyURL builds http://user:pass@host:port for http.ProxyURL.
func e2eProxyURL(addr, user, password string) *url.URL {
	u := &url.URL{Scheme: "http", Host: addr}
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	return u
}

// newE2EProxyClient builds an HTTP client whose transport speaks through the
// gateway HTTP proxy. The transport is closed through a cleanup so the proxy
// server can drain quickly at test teardown.
func newE2EProxyClient(t *testing.T, proxy *url.URL, keepAlive bool) *http.Client {
	t.Helper()
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxy),
		DisableKeepAlives:   !keepAlive,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     5 * time.Second,
		// #nosec G402 -- a manually crafted CONNECT helper handles TLS; this
		// client only speaks plain HTTP through the proxy.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}

// e2eGET performs a GET and fails the test on transport errors.
func e2eGET(t *testing.T, client *http.Client, rawURL string) (int, []byte) {
	t.Helper()
	status, body, err := e2eTryGET(client, rawURL)
	if err != nil {
		t.Fatalf("GET %s through proxy: %v", rawURL, err)
	}
	return status, body
}

// e2eTryGET performs a GET and returns transport errors to the caller.
func e2eTryGET(client *http.Client, rawURL string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// e2eTraceGET performs a GET and reports whether the client transport reused an
// already established connection to the proxy (keep-alive proof).
func e2eTraceGET(t *testing.T, client *http.Client, rawURL string) (int, []byte, bool) {
	t.Helper()
	var (
		mu   sync.Mutex
		info httptrace.GotConnInfo
	)
	trace := &httptrace.ClientTrace{GotConn: func(got httptrace.GotConnInfo) {
		mu.Lock()
		info = got
		mu.Unlock()
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build traced GET: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("traced GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read traced GET body: %v", err)
	}
	mu.Lock()
	reused := info.Reused
	mu.Unlock()
	return resp.StatusCode, body, reused
}

// e2eRawProxyRequest writes a raw HTTP request to the HTTP proxy entry point and
// parses the status line/headers (used for the 407 no-credential assertion).
func e2eRawProxyRequest(t *testing.T, proxyAddr, requestText string) (int, http.Header) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, requestText); err != nil {
		t.Fatalf("write raw proxy request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read raw proxy response: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header
}

// e2eBufferedConn prepends bytes already buffered by a bufio.Reader.
type e2eBufferedConn struct {
	net.Conn
	br *bufio.Reader
}

// Read implements io.Reader, draining the buffered reader first.
func (c *e2eBufferedConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// e2eManualConnect performs a raw CONNECT against the HTTP proxy (curl
// equivalent): it returns the established tunnel connection together with the
// CONNECT status code so the caller can layer TLS on top.
func e2eManualConnect(t *testing.T, proxyAddr, user, password, targetHost string, targetPort int) (net.Conn, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy %s: %v", proxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	authority := e2eJoinHostPort(targetHost, targetPort)
	var head strings.Builder
	fmt.Fprintf(&head, "CONNECT %s HTTP/1.1\r\n", authority)
	fmt.Fprintf(&head, "Host: %s\r\n", authority)
	if user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		fmt.Fprintf(&head, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	head.WriteString("\r\n")
	if _, err := io.WriteString(conn, head.String()); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT status line: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(fields) < 2 {
		_ = conn.Close()
		t.Fatalf("malformed CONNECT status line %q", statusLine)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		_ = conn.Close()
		t.Fatalf("parse CONNECT status %q: %v", statusLine, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if status != http.StatusOK {
		_ = conn.Close()
		return nil, status
	}
	return &e2eBufferedConn{Conn: conn, br: br}, status
}

// e2eTLSGet performs an HTTPS GET over an already established CONNECT tunnel
// (the tunnel is not a TLS connection yet; tls.Client wraps it here).
func e2eTLSGet(t *testing.T, tunnel net.Conn, host string, port int, path string) (int, []byte) {
	t.Helper()
	// #nosec G402 -- local httptest TLS origin uses a self-signed certificate.
	tlsConn := tls.Client(tunnel, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake over CONNECT tunnel: %v", err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, e2eJoinHostPort(host, port))
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read HTTPS response over tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTPS body over tunnel: %v", err)
	}
	return resp.StatusCode, body
}

// ---------------------------------------------------------------------------
// SOCKS5 client (RFC 1928 / RFC 1929)
// ---------------------------------------------------------------------------

const (
	e2eSocksVersion  = 0x05
	e2eSocksNoAuth   = 0x00
	e2eSocksUserPass = 0x02
	e2eSocksNoMethod = 0xFF
	e2eSocksAuthVer  = 0x01
	e2eSocksCmdConn  = 0x01
	e2eSocksAtypIPv4 = 0x01
	e2eSocksAtypDom  = 0x03
)

// e2eSocksGreet connects and sends the method offer, returning the connection
// and the method selected by the proxy.
func e2eSocksGreet(t *testing.T, proxyAddr string, methods []byte) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy %s: %v", proxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	greeting := append([]byte{e2eSocksVersion, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 method reply: %v", err)
	}
	if reply[0] != e2eSocksVersion {
		_ = conn.Close()
		t.Fatalf("SOCKS5 reply version = %#x", reply[0])
	}
	return conn, reply[1]
}

// e2eSocksAuth performs the RFC 1929 username/password sub-negotiation and
// returns the status byte (0 = success).
func e2eSocksAuth(t *testing.T, conn net.Conn, user, password string) byte {
	t.Helper()
	request := []byte{e2eSocksAuthVer, byte(len(user))}
	request = append(request, user...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write SOCKS5 credentials: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("read SOCKS5 auth reply: %v", err)
	}
	if reply[0] != e2eSocksAuthVer {
		t.Fatalf("SOCKS5 auth reply version = %#x", reply[0])
	}
	return reply[1]
}

// e2eSocksConnectRequest sends a CONNECT request and returns the reply byte
// (0x00 = succeeded); it consumes the bound address on success.
func e2eSocksConnectRequest(t *testing.T, conn net.Conn, host string, port int) byte {
	t.Helper()
	request := []byte{e2eSocksVersion, e2eSocksCmdConn, 0x00}
	if ip := net.ParseIP(host).To4(); ip != nil {
		request = append(request, e2eSocksAtypIPv4)
		request = append(request, ip...)
	} else {
		request = append(request, e2eSocksAtypDom, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write SOCKS5 CONNECT: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatalf("read SOCKS5 CONNECT reply: %v", err)
	}
	if head[0] != e2eSocksVersion {
		t.Fatalf("SOCKS5 CONNECT reply version = %#x", head[0])
	}
	if head[1] != 0x00 {
		return head[1]
	}
	switch head[3] {
	case e2eSocksAtypIPv4:
		var rest [6]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			t.Fatalf("read SOCKS5 IPv4 bind address: %v", err)
		}
	case e2eSocksAtypDom:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatalf("read SOCKS5 domain length: %v", err)
		}
		rest := make([]byte, int(length[0])+2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			t.Fatalf("read SOCKS5 domain bind address: %v", err)
		}
	default:
		var rest [18]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			t.Fatalf("read SOCKS5 IPv6 bind address: %v", err)
		}
	}
	return 0x00
}

// e2eSocksDial performs a full SOCKS5 CONNECT handshake (with optional
// username/password authentication) and returns the established tunnel.
func e2eSocksDial(t *testing.T, proxyAddr, user, password, targetHost string, targetPort int) net.Conn {
	t.Helper()
	methods := []byte{e2eSocksNoAuth}
	if user != "" {
		methods = []byte{e2eSocksUserPass}
	}
	conn, method := e2eSocksGreet(t, proxyAddr, methods)
	if method == e2eSocksNoMethod {
		_ = conn.Close()
		t.Fatalf("SOCKS5 proxy accepted no offered method")
	}
	if user != "" {
		if method != e2eSocksUserPass {
			_ = conn.Close()
			t.Fatalf("SOCKS5 selected method %#x, want username/password", method)
		}
		if status := e2eSocksAuth(t, conn, user, password); status != 0 {
			_ = conn.Close()
			t.Fatalf("SOCKS5 authentication failed with status %#x", status)
		}
	} else if method != e2eSocksNoAuth {
		_ = conn.Close()
		t.Fatalf("SOCKS5 selected method %#x, want no-auth", method)
	}
	if reply := e2eSocksConnectRequest(t, conn, targetHost, targetPort); reply != 0 {
		_ = conn.Close()
		t.Fatalf("SOCKS5 CONNECT reply = %#x", reply)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// e2eHTTPOverConn performs one HTTP/1.1 request over an established tunnel and
// reads the response.
func e2eHTTPOverConn(t *testing.T, conn net.Conn, host string, port int, path string) (int, []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, e2eJoinHostPort(host, port))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read HTTP response over tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP body over tunnel: %v", err)
	}
	return resp.StatusCode, body
}
