package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// connectTunnelAuth issues an authenticated CONNECT request.
func connectTunnelAuth(t *testing.T, proxyAddr, target, username, password string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn := dialTCP(t, proxyAddr)
	br := bufio.NewReader(conn)
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		target, target, basicAuth(username, password))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp := readHTTPResponse(t, br, http.MethodConnect)
	return conn, br, resp
}

// basicAuth encodes HTTP Basic credentials.
func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// TestFailClosed verifies that an empty candidate set never falls back to the
// whole fleet and is reported as HTTP 503 / SOCKS5 host unreachable.
func TestFailClosed(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, opts Options) (int, byte)
	}{
		{
			name: "http-connect",
			run: func(t *testing.T, opts Options) (int, byte) {
				proxyAddr, _ := startHTTPProxy(t, opts)
				_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
				return resp.StatusCode, 0
			},
		},
		{
			name: "http-absolute",
			run: func(t *testing.T, opts Options) (int, byte) {
				proxyAddr, _ := startHTTPProxy(t, opts)
				client := httpClientViaProxy(t, "http://"+proxyAddr)
				resp, err := client.Get("http://127.0.0.1:1/")
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				defer resp.Body.Close()
				return resp.StatusCode, 0
			},
		},
		{
			name: "socks5",
			run: func(t *testing.T, opts Options) (int, byte) {
				proxyAddr, _ := startSOCKS5Proxy(t, opts)
				_, _, rep := dialSOCKS5Connect(t, proxyAddr, "127.0.0.1", 1, false, "", "")
				return 0, rep
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidates := newFakeCandidates() // empty: fail closed
			selector := &fakeSelector{}
			dialer := &fakeDialer{}
			opts := baseOptions()
			opts.Candidates = candidates
			opts.Selector = selector
			opts.Dialer = dialer
			status, rep := tc.run(t, opts)
			if status != 0 && status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", status)
			}
			if rep != 0 && rep != socks5ReplyHostUnreachable {
				t.Fatalf("reply = 0x%02x, want 0x04", rep)
			}
			if selector.callCount() != 0 {
				t.Fatalf("selector called %d times, must not be called on fail-closed", selector.callCount())
			}
			if dialer.callCount() != 0 {
				t.Fatalf("dialer called %d times, must not be called on fail-closed", dialer.callCount())
			}
		})
	}
}

// TestCandidateResolverError verifies resolver failures fail closed as well.
func TestCandidateResolverError(t *testing.T) {
	candidates := newFakeCandidates()
	candidates.setError(errors.New("registry unavailable"))
	opts := baseOptions()
	opts.Candidates = candidates
	proxyAddr, _ := startHTTPProxy(t, opts)
	_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// TestOpenErrorMappingHTTP verifies the attachment chapter 7 status mapping.
func TestOpenErrorMappingHTTP(t *testing.T) {
	cases := []struct {
		code protocol.OpenErrorCode
		want int
	}{
		{protocol.CodeDNS, http.StatusBadGateway},
		{protocol.CodeConnRefused, http.StatusBadGateway},
		{protocol.CodeTimeout, http.StatusGatewayTimeout},
		{protocol.CodePolicy, http.StatusForbidden},
		{protocol.CodeOverloaded, http.StatusServiceUnavailable},
		{protocol.CodeProtoUnsupported, http.StatusMethodNotAllowed},
		{protocol.CodeInternal, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			dialer := &fakeDialer{}
			dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
				return nil, protocol.NewError(tc.code, "injected")
			})
			opts := baseOptions()
			opts.Dialer = dialer
			proxyAddr, _ := startHTTPProxy(t, opts)
			_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// TestOpenErrorMappingSOCKS5 verifies the SOCKS5 REP mapping.
func TestOpenErrorMappingSOCKS5(t *testing.T) {
	cases := []struct {
		code protocol.OpenErrorCode
		want byte
	}{
		{protocol.CodeDNS, socks5ReplyHostUnreachable},
		{protocol.CodeConnRefused, socks5ReplyConnRefused},
		{protocol.CodeTimeout, socks5ReplyTTLExpired},
		{protocol.CodePolicy, socks5ReplyNotAllowed},
		{protocol.CodeOverloaded, socks5ReplyGeneralFailure},
		{protocol.CodeProtoUnsupported, socks5ReplyCmdNotSupported},
		{protocol.CodeInternal, socks5ReplyGeneralFailure},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			dialer := &fakeDialer{}
			dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
				return nil, protocol.NewError(tc.code, "injected")
			})
			opts := baseOptions()
			opts.Dialer = dialer
			proxyAddr, _ := startSOCKS5Proxy(t, opts)
			_, _, rep := dialSOCKS5Connect(t, proxyAddr, "127.0.0.1", 1, false, "", "")
			if rep != tc.want {
				t.Fatalf("reply = 0x%02x, want 0x%02x", rep, tc.want)
			}
		})
	}
}

// TestLocalOpenTimeout verifies the server side stream build timeout mapping.
func TestLocalOpenTimeout(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		box := newSettingsBox()
		box.set(func(s *model.Settings) { s.Timeouts.Open = model.D(50 * time.Millisecond) })
		dialer := &fakeDialer{}
		dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		opts := baseOptions()
		opts.Settings = box.get
		opts.Dialer = dialer
		proxyAddr, _ := startHTTPProxy(t, opts)
		_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
		if resp.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("status = %d, want 504", resp.StatusCode)
		}
	})
	t.Run("socks5", func(t *testing.T) {
		box := newSettingsBox()
		box.set(func(s *model.Settings) { s.Timeouts.Open = model.D(50 * time.Millisecond) })
		dialer := &fakeDialer{}
		dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		opts := baseOptions()
		opts.Settings = box.get
		opts.Dialer = dialer
		proxyAddr, _ := startSOCKS5Proxy(t, opts)
		_, _, rep := dialSOCKS5Connect(t, proxyAddr, "127.0.0.1", 1, false, "", "")
		if rep != socks5ReplyTTLExpired {
			t.Fatalf("reply = 0x%02x, want 0x06", rep)
		}
	})
}

// TestTransparentRetry verifies a node side failure before the commit point is
// retried on the next node.
func TestTransparentRetry(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	testMetrics := newTestMetrics()
	selector := &fakeSelector{}
	var calls atomic.Int32
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		if calls.Add(1) == 1 {
			return nil, protocol.NewError(protocol.CodeConnRefused, "first node refused")
		}
		return dialTarget(ctx, req.Host, int(req.Port))
	})
	opts := baseOptions()
	opts.Dialer = dialer
	opts.Selector = selector
	opts.Metrics = testMetrics
	opts.Candidates = newFakeCandidates(mustNode("node-1"), mustNode("node-2"))
	proxyAddr, _ := startHTTPProxy(t, opts)
	conn, br, resp := connectTunnel(t, proxyAddr, tcpTarget(host, port))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200 after retry", resp.StatusCode)
	}
	if dialer.callCount() != 2 {
		t.Fatalf("dial attempts = %d, want 2", dialer.callCount())
	}
	if _, err := conn.Write([]byte("retry-ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len("retry-ok"))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	var sawFailure bool
	for _, result := range selector.resultCalls() {
		if result.err != nil {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatalf("RecordResult did not receive the failed attempt")
	}
	if got := metricValue(t, testMetrics.Registry, "proxy_retries_total", map[string]string{"node": "node-1"}); got != 1 {
		t.Fatalf("ProxyRetriesTotal = %v, want 1", got)
	}
}

// TestNoRetryAfterCommit verifies no retry happens once the tunnel is open.
func TestNoRetryAfterCommit(t *testing.T) {
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		client, peer := memPipePair()
		_ = peer.Close()
		return client, nil
	})
	opts := baseOptions()
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)
	_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	if dialer.callCount() != 1 {
		t.Fatalf("dial attempts = %d, a committed CONNECT must never retry", dialer.callCount())
	}
}

// TestRetryDisabled verifies MaxAttempts=1 disables transparent retry.
func TestRetryDisabled(t *testing.T) {
	box := newSettingsBox()
	box.set(func(s *model.Settings) {
		s.Scheduler.Retry.Enabled = true
		s.Scheduler.Retry.MaxAttempts = 1
	})
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		return nil, protocol.NewError(protocol.CodeConnRefused, "refused")
	})
	opts := baseOptions()
	opts.Settings = box.get
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)
	_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if dialer.callCount() != 1 {
		t.Fatalf("dial attempts = %d, want 1", dialer.callCount())
	}
}

// TestPolicyErrorNotRetried verifies terminal policy errors are not retried.
func TestPolicyErrorNotRetried(t *testing.T) {
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		return nil, protocol.NewError(protocol.CodePolicy, "denied by node")
	})
	opts := baseOptions()
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)
	_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if dialer.callCount() != 1 {
		t.Fatalf("dial attempts = %d, policy errors must not retry", dialer.callCount())
	}
}

// TestGlobalConcurrencyLimit verifies the global entry limit returns 503.
func TestGlobalConcurrencyLimit(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	opts := baseOptions()
	opts.MaxConcurrent = 1
	proxyAddr, _ := startHTTPProxy(t, opts)
	first, _, resp := connectTunnel(t, proxyAddr, tcpTarget(host, port))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first CONNECT = %d", resp.StatusCode)
	}
	_, _, second := connectTunnel(t, proxyAddr, tcpTarget(host, port))
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second CONNECT = %d, want 503", second.StatusCode)
	}
	_ = first.Close()
}

// TestPanicRecovery verifies a panicking dependency never crashes the process.
func TestPanicRecovery(t *testing.T) {
	t.Run("selector", func(t *testing.T) {
		selector := &fakeSelector{}
		selector.setPanic(true)
		opts := baseOptions()
		opts.Selector = selector
		proxyAddr, _ := startHTTPProxy(t, opts)
		client := httpClientViaProxy(t, "http://"+proxyAddr)
		resp, err := client.Get("http://127.0.0.1:1/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 after selector panic", resp.StatusCode)
		}
		selector.setPanic(false)
		resp2, err := client.Get("http://127.0.0.1:1/")
		if err != nil {
			t.Fatalf("second GET: %v", err)
		}
		resp2.Body.Close()
	})
	t.Run("acl", func(t *testing.T) {
		acl := &fakeACL{}
		acl.setPanic(true)
		opts := baseOptions()
		opts.ACL = acl
		proxyAddr, _ := startHTTPProxy(t, opts)
		conn := dialTCP(t, proxyAddr)
		if _, err := io.WriteString(conn, "GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
			t.Fatalf("expected the panicking handler to close the connection")
		}
		acl.setPanic(false)
		client := httpClientViaProxy(t, "http://"+proxyAddr)
		resp, err := client.Get("http://127.0.0.1:1/")
		if err != nil {
			t.Fatalf("GET after panic: %v", err)
		}
		resp.Body.Close()
	})
}

// TestMetricsInstrumentation verifies counters and the active connection gauge.
func TestMetricsInstrumentation(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	testMetrics := newTestMetrics()
	opts := baseOptions()
	opts.Metrics = testMetrics
	proxyAddr, _ := startHTTPProxy(t, opts)
	conn, _, resp := connectTunnel(t, proxyAddr, tcpTarget(host, port))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if metricValue(t, testMetrics.Registry, "proxy_active_connections", nil) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("active connections gauge did not return to zero")
		}
		time.Sleep(10 * time.Millisecond)
	}
	requests := metricValue(t, testMetrics.Registry, "proxy_requests_total", map[string]string{
		"protocol": "connect", "node": "node-1", "credential": "anonymous", "result": "ok",
	})
	if requests != 1 {
		t.Fatalf("connect requests = %v, want 1", requests)
	}
}

// TestHTTPAuthRequiredMissing verifies 407 for missing credentials.
func TestHTTPAuthRequiredMissing(t *testing.T) {
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = model.AuthRequired
	opts.Authenticator = auth
	proxyAddr, _ := startHTTPProxy(t, opts)
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	resp, err := client.Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q", got)
	}
}

// TestHTTPAuthWrongPassword verifies 407 for invalid credentials.
func TestHTTPAuthWrongPassword(t *testing.T) {
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = model.AuthRequired
	opts.Authenticator = auth
	proxyAddr, _ := startHTTPProxy(t, opts)
	client := httpClientViaProxy(t, "http://alice:wrong@"+proxyAddr)
	resp, err := client.Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

// TestHTTPAuthOptionalAnonymous verifies optional mode allows anonymous use.
func TestHTTPAuthOptionalAnonymous(t *testing.T) {
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "optional-ok")
	})
	host, port := serverTarget(t, upstream)
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = model.AuthOptional
	opts.Authenticator = auth
	proxyAddr, _ := startHTTPProxy(t, opts)
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", host, port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "optional-ok" {
		t.Fatalf("status = %d body = %q", resp.StatusCode, body)
	}
}

// TestHTTPCredentialRejected verifies credential level authorization rules.
func TestHTTPCredentialRejected(t *testing.T) {
	expiredAt := time.Now().Add(-time.Minute)
	cases := []struct {
		name     string
		mutate   func(*model.Credential)
		protocol string
		want     int
	}{
		{"disabled", func(c *model.Credential) { c.Enabled = false }, model.ProtoHTTP, http.StatusProxyAuthRequired},
		{"expired", func(c *model.Credential) { c.ExpiresAt = &expiredAt }, model.ProtoHTTP, http.StatusProxyAuthRequired},
		{"protocol-not-allowed", func(c *model.Credential) { c.AllowedProtocols = []string{"http"} }, model.ProtoConnect, http.StatusForbidden},
		{"source-cidr", func(c *model.Credential) { c.SourceCIDRs = []string{"10.0.0.0/8"} }, model.ProtoHTTP, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := testCredential("cred-1", "alice")
			tc.mutate(cred)
			auth := newFakeAuthenticator().add("alice", "s3cret", cred)
			opts := baseOptions()
			opts.AuthMode = model.AuthRequired
			opts.Authenticator = auth
			proxyAddr, _ := startHTTPProxy(t, opts)
			var status int
			if tc.protocol == model.ProtoConnect {
				_, _, resp := connectTunnelAuth(t, proxyAddr, "127.0.0.1:1", "alice", "s3cret")
				status = resp.StatusCode
			} else {
				client := httpClientViaProxy(t, "http://alice:s3cret@"+proxyAddr)
				resp, err := client.Get("http://127.0.0.1:1/")
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				defer resp.Body.Close()
				status = resp.StatusCode
			}
			if status != tc.want {
				t.Fatalf("status = %d, want %d", status, tc.want)
			}
		})
	}
}

// TestPerCredentialConcurrencyLimit verifies the per credential in-flight cap.
func TestPerCredentialConcurrencyLimit(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	cred := testCredential("cred-1", "alice")
	cred.MaxConcurrent = 1
	auth := newFakeAuthenticator().add("alice", "s3cret", cred)
	opts := baseOptions()
	opts.AuthMode = model.AuthRequired
	opts.Authenticator = auth
	proxyAddr, _ := startHTTPProxy(t, opts)
	first, _, resp := connectTunnelAuth(t, proxyAddr, tcpTarget(host, port), "alice", "s3cret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first CONNECT = %d", resp.StatusCode)
	}
	_, _, second := connectTunnelAuth(t, proxyAddr, tcpTarget(host, port), "alice", "s3cret")
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second CONNECT = %d, want 503", second.StatusCode)
	}
	_ = first.Close()
}

// TestACLDenied verifies ACL denials map to 403 and are audited.
func TestACLDenied(t *testing.T) {
	var audited atomic.Int32
	acl := &fakeACL{}
	acl.setCheck(func(t model.RequestTarget) error {
		return errors.New("blocked by policy")
	})
	opts := baseOptions()
	opts.ACL = acl
	opts.Audit = func(event string, detail map[string]string) {
		if event == "proxy.acl_denied" {
			audited.Add(1)
		}
	}
	proxyAddr, _ := startHTTPProxy(t, opts)
	_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if audited.Load() != 1 {
		t.Fatalf("acl denial audit events = %d, want 1", audited.Load())
	}
}

// TestAuthAudit verifies auth failures are audited without the password.
func TestAuthAudit(t *testing.T) {
	type auditEvent struct {
		name   string
		detail map[string]string
	}
	var events atomic.Int32
	var lastDetail atomic.Value
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = model.AuthRequired
	opts.Authenticator = auth
	opts.Audit = func(event string, detail map[string]string) {
		events.Add(1)
		lastDetail.Store(fmt.Sprint(detail))
	}
	proxyAddr, _ := startHTTPProxy(t, opts)
	client := httpClientViaProxy(t, "http://alice:wrong@"+proxyAddr)
	resp, err := client.Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if events.Load() == 0 {
		t.Fatalf("auth failure was not audited")
	}
	if strings.Contains(lastDetail.Load().(string), "wrong") {
		t.Fatalf("audit detail leaked the password: %v", lastDetail.Load())
	}
}
