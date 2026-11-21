package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
)

// TestM3E2EProxyEntries covers the three proxy entry points end to end through
// the real app wiring: plain HTTP requests (keep-alive included), CONNECT to a
// local TLS origin, SOCKS5 CONNECT with username/password authentication, the
// no-auth SOCKS5 mode and the authentication failure responses.
func TestM3E2EProxyEntries(t *testing.T) {
	t.Setenv("NP_ACL_ALLOW_LOOPBACK_TARGETS", "1")
	origin := newE2EOrigin(t)
	plainHost, plainPort := splitURLHostPort(t, origin.plain.URL)
	tlsHost, tlsPort := splitURLHostPort(t, origin.tls.URL)

	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Admin.PasswordHash = e2eAdminPasswordHash(t)
	})
	_ = startE2EClient(t, srv, "node-a", []string{"taga"}, nil)
	e2eWaitNodesOnline(t, srv, 1)

	httpAddr, socksAddr := srv.app.ProxyAddrs()
	if httpAddr == "" || socksAddr == "" {
		t.Fatalf("proxy entry points not bound: http=%q socks=%q", httpAddr, socksAddr)
	}

	// Configure the proxy account through the panel API (group g1 selects the
	// tagged node; credential userA is bound to g1).
	panel := newE2EPanel(t, srv)
	panel.login(e2eAdminUser, e2eAdminPass)
	var group struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	panel.doJSON(http.MethodPost, "/api/v1/groups", map[string]any{
		"name":  "e2e-proxy-group",
		"match": map[string]any{"tags_any": []string{"taga"}},
	}, http.StatusOK, &group)
	if group.ID == "" {
		t.Fatal("panel created a group without an id")
	}
	var created struct {
		Credential struct {
			ID       string   `json:"id"`
			Username string   `json:"username"`
			Groups   []string `json:"groups"`
			Enabled  bool     `json:"enabled"`
		} `json:"credential"`
	}
	panel.doJSON(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username": "userA",
		"password": "userA-pass-123",
		"groups":   []string{group.ID},
		"enabled":  true,
	}, http.StatusOK, &created)
	if created.Credential.Username != "userA" || !created.Credential.Enabled {
		t.Fatalf("panel credential = %+v", created.Credential)
	}
	e2eWaitNodeGroup(t, srv, "node-a", group.ID)

	client := newE2EProxyClient(t, e2eProxyURL(httpAddr, "userA", "userA-pass-123"), true)

	t.Run("http_get_and_keepalive", func(t *testing.T) {
		status, body, reused := e2eTraceGET(t, client, origin.plain.URL+"/hello")
		if status != http.StatusOK {
			t.Fatalf("first GET status = %d, want 200", status)
		}
		if string(body) != e2eHelloBody {
			t.Fatalf("first GET body = %q, want %q", body, e2eHelloBody)
		}
		if reused {
			t.Fatal("first request unexpectedly reused a proxy connection")
		}
		status, body, reused = e2eTraceGET(t, client, origin.plain.URL+"/hello")
		if status != http.StatusOK || string(body) != e2eHelloBody {
			t.Fatalf("second GET = %d %q", status, body)
		}
		if !reused {
			t.Fatal("second request did not reuse the same proxy connection (keep-alive broken)")
		}
	})

	t.Run("http_post_64k_echo", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, origin.plain.URL+"/echo", bytes.NewReader(e2eBigBody))
		if err != nil {
			t.Fatalf("build POST request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST through proxy: %v", err)
		}
		defer resp.Body.Close()
		var got bytes.Buffer
		if _, err := got.ReadFrom(resp.Body); err != nil {
			t.Fatalf("read POST echo body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST status = %d, want 200", resp.StatusCode)
		}
		if !bytes.Equal(got.Bytes(), e2eBigBody) {
			t.Fatalf("POST echo mismatch: got %d bytes, want %d", got.Len(), len(e2eBigBody))
		}
	})

	t.Run("http_chunked_response", func(t *testing.T) {
		status, body := e2eGET(t, client, origin.plain.URL+"/chunked")
		if status != http.StatusOK {
			t.Fatalf("chunked GET status = %d, want 200", status)
		}
		const want = "chunk-one;chunk-two;chunk-three"
		if string(body) != want {
			t.Fatalf("chunked body = %q, want %q", body, want)
		}
	})

	t.Run("connect_tls_origin", func(t *testing.T) {
		tunnel, status := e2eManualConnect(t, httpAddr, "userA", "userA-pass-123", tlsHost, tlsPort)
		if status != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", status)
		}
		defer tunnel.Close()
		code, body := e2eTLSGet(t, tunnel, tlsHost, tlsPort, "/hello")
		if code != http.StatusOK {
			t.Fatalf("HTTPS GET over CONNECT status = %d, want 200", code)
		}
		if string(body) != e2eHelloBody {
			t.Fatalf("HTTPS body over CONNECT = %q, want %q", body, e2eHelloBody)
		}
	})

	t.Run("socks5_username_password", func(t *testing.T) {
		conn := e2eSocksDial(t, socksAddr, "userA", "userA-pass-123", plainHost, plainPort)
		defer conn.Close()
		status, body := e2eHTTPOverConn(t, conn, plainHost, plainPort, "/hello")
		if status != http.StatusOK {
			t.Fatalf("SOCKS5 GET status = %d, want 200", status)
		}
		if string(body) != e2eHelloBody {
			t.Fatalf("SOCKS5 GET body = %q, want %q", body, e2eHelloBody)
		}
	})

	t.Run("auth_failures", func(t *testing.T) {
		// HTTP proxy without credentials: 407 + Proxy-Authenticate.
		plainAuthority := e2eJoinHostPort(plainHost, plainPort)
		requestText := "GET " + origin.plain.URL + "/hello HTTP/1.1\r\n" +
			"Host: " + plainAuthority + "\r\n" +
			"Connection: close\r\n\r\n"
		status, header := e2eRawProxyRequest(t, httpAddr, requestText)
		if status != http.StatusProxyAuthRequired {
			t.Fatalf("HTTP proxy without credentials status = %d, want 407", status)
		}
		if header.Get("Proxy-Authenticate") == "" {
			t.Fatal("407 response carries no Proxy-Authenticate header")
		}

		// HTTP proxy with a wrong password: 407.
		badClient := newE2EProxyClient(t, e2eProxyURL(httpAddr, "userA", "wrong-password"), true)
		status, body := e2eGET(t, badClient, origin.plain.URL+"/hello")
		if status != http.StatusProxyAuthRequired {
			t.Fatalf("HTTP proxy wrong password status = %d, want 407 (body %q)", status, body)
		}

		// SOCKS5 in required mode with only the no-auth method: 0xFF + close.
		conn, method := e2eSocksGreet(t, socksAddr, []byte{e2eSocksNoAuth})
		_ = conn.Close()
		if method != e2eSocksNoMethod {
			t.Fatalf("SOCKS5 required mode selected method %#x, want 0xFF", method)
		}

		// SOCKS5 wrong password: non-zero RFC 1929 status.
		conn, method = e2eSocksGreet(t, socksAddr, []byte{e2eSocksUserPass})
		if method != e2eSocksUserPass {
			_ = conn.Close()
			t.Fatalf("SOCKS5 selected method %#x, want username/password", method)
		}
		authStatus := e2eSocksAuth(t, conn, "userA", "wrong-password")
		_ = conn.Close()
		if authStatus == 0 {
			t.Fatal("SOCKS5 accepted a wrong password")
		}
	})

	t.Run("socks5_no_auth_mode", func(t *testing.T) {
		noAuthSrv := startE2EServer(t, func(cfg *config.ServerConfig) {
			cfg.Proxy.AuthMode = model.AuthNone
		})
		_ = startE2EClient(t, noAuthSrv, "node-none", nil, nil)
		e2eWaitNodesOnline(t, noAuthSrv, 1)
		_, noAuthSocksAddr := noAuthSrv.app.ProxyAddrs()
		if noAuthSocksAddr == "" {
			t.Fatal("no-auth server bound no SOCKS5 listener")
		}
		conn := e2eSocksDial(t, noAuthSocksAddr, "", "", plainHost, plainPort)
		defer conn.Close()
		status, body := e2eHTTPOverConn(t, conn, plainHost, plainPort, "/hello")
		if status != http.StatusOK {
			t.Fatalf("no-auth SOCKS5 GET status = %d, want 200", status)
		}
		if string(body) != e2eHelloBody {
			t.Fatalf("no-auth SOCKS5 body = %q, want %q", body, e2eHelloBody)
		}
	})
}

// TestM3E2EFailClosedGroupIsolation verifies the fail-closed guarantee: a
// credential bound to a group that only contains node-a must never be routed to
// node-b, and once node-a is offline requests fail with 503 instead of selecting
// another node.
func TestM3E2EFailClosedGroupIsolation(t *testing.T) {
	t.Setenv("NP_ACL_ALLOW_LOOPBACK_TARGETS", "1")
	origin := newE2EOrigin(t)

	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Admin.PasswordHash = e2eAdminPasswordHash(t)
		seedE2EGroups(t, cfg, model.Group{
			ID:    "g1",
			Name:  "only-node-a",
			Match: model.GroupMatch{TagsAny: []string{"taga"}},
		})
		seedE2ECredentials(t, cfg, model.Credential{
			ID:           "cred-fail-closed",
			Username:     "failuser",
			PasswordHash: e2eBcryptHash(t, "fail-pass-123"),
			Groups:       []string{"g1"},
			Enabled:      true,
		})
	})
	nodeA := startE2EClient(t, srv, "node-a", []string{"taga"}, nil)
	_ = startE2EClient(t, srv, "node-b", []string{"tagb"}, nil)
	e2eWaitNodesOnline(t, srv, 2)
	e2eWaitNodeGroup(t, srv, "node-a", "g1")
	// node-b must never become a member of g1.
	if nodeB := e2eNodeSnapshot(t, srv, "node-b"); e2eContains(nodeB.Groups, "g1") {
		t.Fatalf("node-b unexpectedly belongs to g1: %v", nodeB.Groups)
	}

	httpAddr, _ := srv.app.ProxyAddrs()
	panel := newE2EPanel(t, srv)
	panel.login(e2eAdminUser, e2eAdminPass)
	client := newE2EProxyClient(t, e2eProxyURL(httpAddr, "failuser", "fail-pass-123"), false)

	const rounds = 10
	for i := 0; i < rounds; i++ {
		status, body := e2eGET(t, client, origin.plain.URL+"/hello")
		if status != http.StatusOK || string(body) != e2eHelloBody {
			t.Fatalf("request %d through g1 = %d %q, want 200 %q", i, status, body, e2eHelloBody)
		}
	}
	served := panel.waitTopNNodes("node-a", int64(rounds), 5*time.Second)
	if served["node-a"] < rounds {
		t.Fatalf("node-a served %d requests, want %d (all served counts: %v)", served["node-a"], rounds, served)
	}
	if served["node-b"] != 0 {
		t.Fatalf("node-b served %d requests, want 0 (fail-closed group isolation broken): %v", served["node-b"], served)
	}

	// OnRequestEnd accounting: the overview counters observe every request.
	var overview struct {
		Requests struct {
			Total  int64 `json:"total"`
			Errors int64 `json:"errors"`
		} `json:"requests"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		panel.doJSON(http.MethodGet, "/api/v1/overview", nil, http.StatusOK, &overview)
		if overview.Requests.Total >= rounds || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if overview.Requests.Total < rounds {
		t.Fatalf("overview requests.total = %d, want >= %d", overview.Requests.Total, rounds)
	}
	if overview.Requests.Errors != 0 {
		t.Fatalf("overview requests.errors = %d after only successful requests", overview.Requests.Errors)
	}

	// Take node-a offline. The registry must report it offline and the panel
	// must reflect it.
	nodeA.stop(t)
	e2eWaitNodeOffline(t, srv, "node-a")
	var nodesResp e2eNodesResponse
	panel.doJSON(http.MethodGet, "/api/v1/nodes", nil, http.StatusOK, &nodesResp)
	nodeAOffline := false
	for _, node := range nodesResp.Items {
		if node.ID == "node-a" && !node.Online {
			nodeAOffline = true
		}
	}
	if !nodeAOffline {
		t.Fatalf("panel /nodes does not report node-a offline: %+v", nodesResp.Items)
	}

	// With the only g1 node offline the request must fail closed with 503 and
	// must never fall back to node-b.
	status, body, err := e2eTryGET(client, origin.plain.URL+"/hello")
	if err != nil {
		t.Fatalf("fail-closed request errored at transport level: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed status = %d (body %q), want 503", status, body)
	}
	if after := panel.topNNodes(); after["node-b"] != 0 {
		t.Fatalf("node-b was used after fail-closed: %v", after)
	}
	var overviewAfter struct {
		Requests struct {
			Errors int64 `json:"errors"`
		} `json:"requests"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/overview", nil, http.StatusOK, &overviewAfter)
	errorsDeadline := time.Now().Add(5 * time.Second)
	for overviewAfter.Requests.Errors <= overview.Requests.Errors && time.Now().Before(errorsDeadline) {
		time.Sleep(20 * time.Millisecond)
		panel.doJSON(http.MethodGet, "/api/v1/overview", nil, http.StatusOK, &overviewAfter)
	}
	if overviewAfter.Requests.Errors <= overview.Requests.Errors {
		t.Fatalf("overview requests.errors = %d after a fail-closed 503, want > %d",
			overviewAfter.Requests.Errors, overview.Requests.Errors)
	}

	// Restart node-a; the same credential must recover.
	_ = startE2EClient(t, srv, "node-a", []string{"taga"}, nil)
	e2eWaitNodeOnline(t, srv, "node-a")
	waitFor(t, 15*time.Second, "requests recover after node-a restart", func() bool {
		status, body, err := e2eTryGET(client, origin.plain.URL+"/hello")
		return err == nil && status == http.StatusOK && string(body) == e2eHelloBody
	})
	recovered := panel.waitTopNNodesAbove("node-a", rounds, 5*time.Second)
	if recovered["node-a"] <= rounds {
		t.Fatalf("node-a served count = %d after recovery, want > %d: %v", recovered["node-a"], rounds, recovered)
	}
}

// TestM5E2EPanelAPI covers the M5/M6 panel HTTP contract: authentication, CSRF,
// node/group/settings/audit/overview endpoints, generated credentials, security
// headers and the settings 422/undo semantics.
func TestM5E2EPanelAPI(t *testing.T) {
	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Admin.PasswordHash = e2eAdminPasswordHash(t)
	})
	_ = startE2EClient(t, srv, "node-a", []string{"taga"}, nil)
	_ = startE2EClient(t, srv, "node-b", []string{"tagb"}, nil)
	e2eWaitNodesOnline(t, srv, 2)

	panel := newE2EPanel(t, srv)

	// Unauthenticated API access is a 401.
	if status, _, _ := panel.raw(http.MethodGet, "/api/v1/nodes", nil); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /nodes status = %d, want 401", status)
	}
	if status, _, _ := panel.raw(http.MethodGet, "/api/v1/session", nil); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /session status = %d, want 401", status)
	}

	// Wrong password is rejected and audited.
	status, body, _ := panel.raw(http.MethodPost, "/api/v1/login", map[string]any{
		"username": e2eAdminUser,
		"password": "wrong-password",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong password login status = %d, want 401 (body %q)", status, body)
	}

	// Correct login issues the session cookie and the CSRF token.
	panel.login(e2eAdminUser, e2eAdminPass)
	var session struct {
		Username string `json:"username"`
		CSRF     string `json:"csrf"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/session", nil, http.StatusOK, &session)
	if session.CSRF != panel.csrf {
		t.Fatalf("GET /session csrf = %q, login csrf = %q", session.CSRF, panel.csrf)
	}

	// Write requests without the CSRF header are rejected with 403.
	panel.clearCSRF()
	status, body, _ = panel.raw(http.MethodPost, "/api/v1/groups", map[string]any{"name": "no-csrf-group"})
	if status != http.StatusForbidden {
		t.Fatalf("POST /groups without CSRF status = %d, want 403 (body %q)", status, body)
	}
	if !bytes.Contains(body, []byte("csrf_invalid")) {
		t.Fatalf("403 response does not carry csrf_invalid: %q", body)
	}
	panel.csrf = session.CSRF

	// Nodes: both clients are registered and online.
	var nodesResp e2eNodesResponse
	panel.doJSON(http.MethodGet, "/api/v1/nodes", nil, http.StatusOK, &nodesResp)
	if nodesResp.Total != 2 || len(nodesResp.Items) != 2 {
		t.Fatalf("GET /nodes total=%d items=%d, want 2", nodesResp.Total, len(nodesResp.Items))
	}
	if nodesResp.Summary.Online != 2 {
		t.Fatalf("GET /nodes summary.online = %d, want 2", nodesResp.Summary.Online)
	}

	// Group CRUD.
	var group struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	panel.doJSON(http.MethodPost, "/api/v1/groups", map[string]any{
		"name":        "e2e-panel-group",
		"description": "created by the M5 end-to-end suite",
	}, http.StatusOK, &group)
	if group.ID == "" || group.Name != "e2e-panel-group" {
		t.Fatalf("created group = %+v", group)
	}
	var groups struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/groups", nil, http.StatusOK, &groups)
	foundGroup := false
	for _, item := range groups.Items {
		if item.ID == group.ID {
			foundGroup = true
		}
	}
	if !foundGroup {
		t.Fatalf("GET /groups does not list the created group %q", group.ID)
	}

	// Settings: invalid strategy is a 422 and leaves the old value untouched.
	state := panel.getSettings()
	initialStrategy := strategyOfSettings(t, state.Current)
	invalid := withStrategy(t, state.Current, "bogus")
	status, body, _ = panel.request(http.MethodPut, "/api/v1/settings", map[string]any{"settings": invalid})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("PUT /settings invalid status = %d, want 422 (body %q)", status, body)
	}
	if !bytes.Contains(body, []byte("validation_failed")) {
		t.Fatalf("invalid settings response does not carry validation_failed: %q", body)
	}
	if got := panel.strategy(); got != initialStrategy {
		t.Fatalf("strategy changed after invalid PUT: %q, want %q", got, initialStrategy)
	}

	// Settings: a valid hot update applies immediately.
	valid := withStrategy(t, state.Current, model.StrategyRandom)
	var mutated struct {
		Current model.Settings `json:"current"`
		Version int            `json:"version"`
	}
	panel.doJSON(http.MethodPut, "/api/v1/settings", map[string]any{"settings": valid}, http.StatusOK, &mutated)
	if mutated.Current.Scheduler.Strategy != model.StrategyRandom {
		t.Fatalf("PUT /settings current.strategy = %q, want random", mutated.Current.Scheduler.Strategy)
	}
	if mutated.Version <= state.Version {
		t.Fatalf("settings version did not advance: %d -> %d", state.Version, mutated.Version)
	}
	if got := srv.app.Settings().Current().Scheduler.Strategy; got != model.StrategyRandom {
		t.Fatalf("live settings strategy = %q, want random", got)
	}
	if got := panel.strategy(); got != model.StrategyRandom {
		t.Fatalf("GET /settings strategy = %q, want random", got)
	}

	// Settings undo restores the previous version.
	var undone struct {
		Current model.Settings `json:"current"`
		Version int            `json:"version"`
	}
	panel.doJSON(http.MethodPost, "/api/v1/settings/undo", nil, http.StatusOK, &undone)
	if undone.Current.Scheduler.Strategy != initialStrategy {
		t.Fatalf("after undo strategy = %q, want %q", undone.Current.Scheduler.Strategy, initialStrategy)
	}
	if got := panel.strategy(); got != initialStrategy {
		t.Fatalf("GET /settings strategy after undo = %q, want %q", got, initialStrategy)
	}

	// Audit: login and settings.update are recorded; no plaintext passwords.
	status, auditBody, _ := panel.request(http.MethodGet, "/api/v1/audit?limit=500", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /audit status = %d, want 200", status)
	}
	var audit struct {
		Items []struct {
			Action string `json:"action"`
			Result string `json:"result"`
		} `json:"items"`
	}
	if err := json.Unmarshal(auditBody, &audit); err != nil {
		t.Fatalf("decode /audit: %v", err)
	}
	foundLogin, foundSettings := false, false
	for _, item := range audit.Items {
		if item.Action == "login" && item.Result == "ok" {
			foundLogin = true
		}
		if item.Action == "settings.update" {
			foundSettings = true
		}
	}
	if !foundLogin {
		t.Fatalf("audit log does not contain a successful login: %+v", audit.Items)
	}
	if !foundSettings {
		t.Fatalf("audit log does not contain settings.update: %+v", audit.Items)
	}
	if bytes.Contains(auditBody, []byte(e2eAdminPass)) {
		t.Fatal("audit log leaks the administrator password")
	}
	if bytes.Contains(auditBody, []byte("wrong-password")) {
		t.Fatal("audit log leaks the plaintext password of a failed login")
	}

	// Overview exposes the three key indicators.
	status, overviewBody, _ := panel.raw(http.MethodGet, "/api/v1/overview", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /overview status = %d, want 200", status)
	}
	var overview map[string]json.RawMessage
	if err := json.Unmarshal(overviewBody, &overview); err != nil {
		t.Fatalf("decode /overview: %v", err)
	}
	for _, key := range []string{"online_nodes", "unique_egress_ips", "active_connections"} {
		if _, ok := overview[key]; !ok {
			t.Fatalf("GET /overview is missing key %q: %s", key, overviewBody)
		}
	}
	var onlineNodes int64
	if err := json.Unmarshal(overview["online_nodes"], &onlineNodes); err != nil {
		t.Fatalf("decode overview.online_nodes: %v", err)
	}
	if onlineNodes < 1 {
		t.Fatalf("overview.online_nodes = %d, want >= 1", onlineNodes)
	}

	// Tunnel sessions list both nodes.
	var sessions struct {
		Items []struct {
			NodeID string `json:"node_id"`
		} `json:"items"`
		TransportMix map[string]int `json:"transport_mix"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/tunnel/sessions", nil, http.StatusOK, &sessions)
	if len(sessions.Items) != 2 {
		t.Fatalf("GET /tunnel/sessions items = %d, want 2", len(sessions.Items))
	}
	if _, ok := sessions.TransportMix["quic"]; !ok {
		t.Fatalf("GET /tunnel/sessions transport_mix has no quic key: %+v", sessions.TransportMix)
	}

	// Certificate pin is exposed.
	var cert struct {
		Mode string `json:"mode"`
		Pin  string `json:"pin"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/cert", nil, http.StatusOK, &cert)
	if cert.Pin == "" || cert.Mode != "pin" {
		t.Fatalf("GET /cert = %+v", cert)
	}

	// Credential CRUD with a server generated password.
	var newCred struct {
		Credential struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Enabled  bool   `json:"enabled"`
		} `json:"credential"`
		Password string `json:"password"`
	}
	panel.doJSON(http.MethodPost, "/api/v1/credentials", map[string]any{
		"username":          "panel-generated",
		"generate_password": true,
		"enabled":           true,
	}, http.StatusOK, &newCred)
	if newCred.Credential.ID == "" || !newCred.Credential.Enabled {
		t.Fatalf("created credential = %+v", newCred.Credential)
	}
	if len(newCred.Password) < 16 {
		t.Fatalf("generated password too short: %d chars", len(newCred.Password))
	}
	var credList struct {
		Items []struct {
			Username string `json:"username"`
		} `json:"items"`
	}
	panel.doJSON(http.MethodGet, "/api/v1/credentials", nil, http.StatusOK, &credList)
	foundCred := false
	for _, item := range credList.Items {
		if item.Username == "panel-generated" {
			foundCred = true
		}
	}
	if !foundCred {
		t.Fatal("GET /credentials does not list the created credential")
	}
	panel.doJSON(http.MethodDelete, "/api/v1/credentials/"+newCred.Credential.ID, nil, http.StatusOK, nil)

	// Security headers are applied to API responses.
	_, _, header := panel.raw(http.MethodGet, "/api/v1/overview", nil)
	if got := header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := header.Get("Content-Security-Policy"); got == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	if got := header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

// strategyOfSettings extracts scheduler.strategy from a decoded settings map.
func strategyOfSettings(t *testing.T, settings map[string]any) string {
	t.Helper()
	scheduler, ok := settings["scheduler"].(map[string]any)
	if !ok {
		t.Fatalf("settings.scheduler is not an object: %v", settings["scheduler"])
	}
	strategy, _ := scheduler["strategy"].(string)
	return strategy
}

// TestM3M6E2EStickyAndFailover verifies session stickiness across two nodes and
// the transparent retry/failover behaviour when the pinned node disappears.
func TestM3M6E2EStickyAndFailover(t *testing.T) {
	t.Setenv("NP_ACL_ALLOW_LOOPBACK_TARGETS", "1")
	origin := newE2EOrigin(t)

	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Admin.PasswordHash = e2eAdminPasswordHash(t)
		seedE2ECredentials(t, cfg, model.Credential{
			ID:           "cred-sticky",
			Username:     "stickyuser",
			PasswordHash: e2eBcryptHash(t, "sticky-pass-123"),
			Enabled:      true,
		})
	})
	nodeA := startE2EClient(t, srv, "node-a", []string{"taga"}, nil)
	_ = startE2EClient(t, srv, "node-b", []string{"tagb"}, nil)
	e2eWaitNodesOnline(t, srv, 2)

	httpAddr, _ := srv.app.ProxyAddrs()
	panel := newE2EPanel(t, srv)
	panel.login(e2eAdminUser, e2eAdminPass)

	// Make the routing configuration explicit: strategy=fastest, sticky enabled.
	settingsState := panel.getSettings()
	stickySettings := withStrategy(t, settingsState.Current, model.StrategyFastest)
	scheduler, ok := stickySettings["scheduler"].(map[string]any)
	if !ok {
		t.Fatalf("settings.scheduler is not an object: %v", stickySettings["scheduler"])
	}
	sticky, ok := scheduler["sticky"].(map[string]any)
	if !ok {
		t.Fatalf("settings.scheduler.sticky is not an object: %v", scheduler["sticky"])
	}
	sticky["enabled"] = true
	panel.doJSON(http.MethodPut, "/api/v1/settings", map[string]any{"settings": stickySettings}, http.StatusOK, nil)
	if got := panel.strategy(); got != model.StrategyFastest {
		t.Fatalf("strategy = %q, want fastest", got)
	}

	// DisableKeepAlives forces a fresh proxy connection (and thus a fresh
	// scheduler decision) for every request, so the assertion really exercises
	// stickiness instead of HTTP upstream stream reuse.
	client := newE2EProxyClient(t, e2eProxyURL(httpAddr, "stickyuser", "sticky-pass-123"), false)

	const rounds = 10
	for i := 0; i < rounds; i++ {
		status, body := e2eGET(t, client, origin.plain.URL+"/hello")
		if status != http.StatusOK || string(body) != e2eHelloBody {
			t.Fatalf("sticky request %d = %d %q, want 200 %q", i, status, body, e2eHelloBody)
		}
	}
	before := panel.topNNodes()
	stickyDeadline := time.Now().Add(5 * time.Second)
	for before["node-a"] < rounds && before["node-b"] < rounds && time.Now().Before(stickyDeadline) {
		time.Sleep(20 * time.Millisecond)
		before = panel.topNNodes()
	}
	pinned := ""
	switch {
	case before["node-a"] == rounds && before["node-b"] == 0:
		pinned = "node-a"
	case before["node-b"] == rounds && before["node-a"] == 0:
		pinned = "node-b"
	default:
		t.Fatalf("sticky requests did not stay on one node: %v", before)
	}
	t.Logf("sticky pinned to %s", pinned)

	// Take node-a down and issue a request immediately: it must either
	// transparently fail over to node-b or return a definite proxy error
	// quickly; it must never hang.
	const survivor = "node-b"
	nodeA.stop(t)

	start := time.Now()
	status, body, err := e2eTryGET(client, origin.plain.URL+"/hello")
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("request after node loss hung for %v (limit 10s)", elapsed)
	}
	if err != nil {
		t.Fatalf("request after node loss failed at transport level after %v: %v", elapsed, err)
	}
	switch status {
	case http.StatusOK:
		if string(body) != e2eHelloBody {
			t.Fatalf("failover body = %q, want %q", body, e2eHelloBody)
		}
		t.Logf("immediate request failed over transparently after %v", elapsed)
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		t.Logf("immediate request returned definite proxy error %d after %v", status, elapsed)
	default:
		t.Fatalf("request after node loss status = %d (body %q), want 200/502/503/504", status, body)
	}

	// Once node-a is reported offline, requests must recover through node-b.
	e2eWaitNodeOffline(t, srv, "node-a")
	waitFor(t, 15*time.Second, "requests served by the surviving node", func() bool {
		status, body, err := e2eTryGET(client, origin.plain.URL+"/hello")
		return err == nil && status == http.StatusOK && string(body) == e2eHelloBody
	})
	after := panel.waitTopNNodesAbove(survivor, before[survivor], 5*time.Second)
	if after[survivor] <= before[survivor] {
		t.Fatalf("surviving node %s served count did not increase: before=%v after=%v", survivor, before, after)
	}
}

// TestM3M6E2EConcurrentAndGracefulShutdown runs 30 concurrent 64 KiB responses
// through the proxy, verifies all of them and the tunnel stream accounting, then
// checks that cancelling the server context makes Run return nil within 15s and
// releases the proxy listeners.
func TestM3M6E2EConcurrentAndGracefulShutdown(t *testing.T) {
	t.Setenv("NP_ACL_ALLOW_LOOPBACK_TARGETS", "1")
	origin := newE2EOrigin(t)

	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		seedE2ECredentials(t, cfg, model.Credential{
			ID:           "cred-bulk",
			Username:     "bulkuser",
			PasswordHash: e2eBcryptHash(t, "bulk-pass-123"),
			Enabled:      true,
		})
	})
	_ = startE2EClient(t, srv, "node-bulk", nil, nil)
	e2eWaitNodesOnline(t, srv, 1)

	httpAddr, socksAddr := srv.app.ProxyAddrs()
	client := newE2EProxyClient(t, e2eProxyURL(httpAddr, "bulkuser", "bulk-pass-123"), false)

	const concurrent = 30
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			status, body, err := e2eTryGET(client, origin.plain.URL+"/big")
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("request %d: %v", idx, err))
				mu.Unlock()
				return
			}
			if status != http.StatusOK {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("request %d: status %d", idx, status))
				mu.Unlock()
				return
			}
			if !bytes.Equal(body, e2eBigBody) {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("request %d: body mismatch (%d bytes)", idx, len(body)))
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("%d/%d concurrent requests failed: %v", len(errs), concurrent, errs[:minInt(len(errs), 5)])
	}

	// The tunnel stream counter must converge once every response is consumed.
	waitFor(t, 2*time.Second, "tunnel active streams to drain", func() bool {
		return srv.app.TunnelServer().ActiveStreams() == 0
	})

	// Graceful shutdown: Run returns nil within 15s and the proxy ports are
	// released.
	shutdownStart := time.Now()
	srv.cancel()
	if err := srv.waitRun(t, 15*time.Second); err != nil {
		t.Fatalf("server Run returned %v after cancellation, want nil", err)
	}
	t.Logf("graceful shutdown returned after %v", time.Since(shutdownStart))

	if conn, err := net.DialTimeout("tcp", httpAddr, 2*time.Second); err == nil {
		_ = conn.Close()
		t.Fatalf("HTTP proxy entry %s still accepts connections after shutdown", httpAddr)
	}
	if conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second); err == nil {
		_ = conn.Close()
		t.Fatalf("SOCKS5 proxy entry %s still accepts connections after shutdown", socksAddr)
	}

	// A fresh proxy request cannot be served any more (connection refused).
	if _, body, err := e2eTryGET(client, origin.plain.URL+"/hello"); err == nil {
		t.Fatalf("proxy request after shutdown unexpectedly succeeded: %q", truncateForLog(body))
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
