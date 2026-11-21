// Package integration contains process-internal end-to-end tests: a real
// server, real transports (QUIC / WebSocket) and real node agents wired through
// the app package. No external network is required.
package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"proxygw/internal/app"
	"proxygw/internal/config"
	"proxygw/internal/logx"
	"proxygw/internal/model"
)

const testToken = "np_integration0123456789abcdef0123456789"

// freePort returns a localhost TCP port that was free a moment ago. QUIC uses
// UDP on the same port; on a quiet test machine the chance of a collision is
// negligible and any collision surfaces as a fast failure.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

type testServer struct {
	app    *app.Server
	cfg    *config.ServerConfig
	port   int
	pin    string
	cancel context.CancelFunc
	done   chan error
}

// startServer starts a fully wired gateway server on loopback.
func startServer(t *testing.T, mutate func(*config.ServerConfig)) *testServer {
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
		t.Fatalf("test server config invalid: %v", err)
	}
	srv, err := app.NewServer(app.ServerOptions{Config: cfg, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("app.NewServer: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("srv.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	ts := &testServer{app: srv, cfg: cfg, port: port, pin: srv.CertStatus().Pin, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Log("server shutdown timed out")
		}
	})
	return ts
}

type testClient struct {
	client   *app.Client
	cfg      *config.ClientConfig
	cancel   context.CancelFunc
	finished chan struct{}
	runErr   error
}

// startClient starts a node agent against the given server. The error from
// Agent.Run is available in tc.runErr after tc.finished is closed.
func startClient(t *testing.T, ts *testServer, pin string, mutate func(*config.ClientConfig)) *testClient {
	t.Helper()
	cfg := config.DefaultClientConfig()
	cfg.ServerURL = fmt.Sprintf("https://127.0.0.1:%d", ts.port)
	cfg.Token = testToken
	cfg.StateDir = t.TempDir()
	cfg.TLS.Mode = "pin"
	cfg.TLS.Pins = nil
	cfg.TLS.Pin = pin
	cfg.Log = logx.Config{Level: "error", Format: "json"}
	cfg.Transport = model.TransportAuto
	cfg.Planes = 2
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test client config invalid: %v", err)
	}
	client, err := app.NewClient(app.ClientOptions{Config: cfg, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("app.NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tc := &testClient{client: client, cfg: cfg, cancel: cancel, finished: make(chan struct{})}
	go func() {
		tc.runErr = client.Run(ctx)
		close(tc.finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-tc.finished:
		case <-time.After(20 * time.Second):
			t.Log("client shutdown timed out")
		}
		_ = client.Close()
	})
	return tc
}

func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitNodeOnline waits until the registry reports one online node and returns
// its snapshot.
func waitNodeOnline(t *testing.T, ts *testServer) model.Node {
	t.Helper()
	waitFor(t, 20*time.Second, "node online", func() bool { return ts.app.Registry().OnlineCount() >= 1 })
	nodes := ts.app.Registry().List()
	if len(nodes) == 0 {
		t.Fatal("registry returned no nodes")
	}
	return nodes[0]
}

func TestQUICPrimaryRegistration(t *testing.T) {
	ts := startServer(t, nil)
	tc := startClient(t, ts, ts.pin, nil)
	node := waitNodeOnline(t, ts)
	if node.Transport != string(model.TransportQUIC) && node.Transport != "quic" {
		t.Fatalf("expected QUIC primary transport, got %q", node.Transport)
	}
	waitFor(t, 10*time.Second, "two planes", func() bool {
		n, ok := ts.app.Registry().Get(node.ID)
		return ok && n.Planes >= 2
	})
	if st := tc.client.Status(); st.Transport != "quic" {
		t.Fatalf("agent status transport = %q", st.Transport)
	}
}

func TestWSFallbackWhenOnlyWebSocketEnabled(t *testing.T) {
	ts := startServer(t, func(c *config.ServerConfig) {
		c.Tunnel.Transport = model.TransportWS
	})
	tc := startClient(t, ts, ts.pin, nil)
	node := waitNodeOnline(t, ts)
	if node.Transport != "ws" {
		t.Fatalf("expected ws transport, got %q", node.Transport)
	}
	waitFor(t, 10*time.Second, "agent ws mode", func() bool {
		return tc.client.Status().Transport == "ws"
	})
	if tc.client.Status().LastFallbackReason == "" {
		t.Fatalf("expected a fallback reason, status = %+v", tc.client.Status())
	}
}

func TestQUICUDPBlackholedFallsBackToWS(t *testing.T) {
	// Server only listens on TCP/wss; a dummy UDP socket bound to the same port
	// silently drops QUIC packets, simulating a firewall dropping UDP/443.
	ts := startServer(t, func(c *config.ServerConfig) {
		c.Tunnel.Transport = model.TransportWS
	})
	udpAddr := fmt.Sprintf("127.0.0.1:%d", ts.port)
	udpConn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		t.Skipf("cannot bind dummy UDP socket on %s: %v", udpAddr, err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := udpConn.ReadFrom(buf); err != nil {
				return
			}
			// Drop everything: no QUIC response, so the client must fall back.
		}
	}()
	start := time.Now()
	tc := startClient(t, ts, ts.pin, nil)
	waitNodeOnline(t, ts)
	elapsed := time.Since(start)
	if elapsed > 30*time.Second {
		t.Fatalf("fallback took too long: %v", elapsed)
	}
	waitFor(t, 10*time.Second, "agent fell back", func() bool {
		st := tc.client.Status()
		return st.Transport == "ws" && st.LastFallbackReason != ""
	})
}

func TestPinMismatchIsFatal(t *testing.T) {
	ts := startServer(t, nil)
	// A syntactically valid but wrong SPKI pin: 32 bytes of zeros (the server
	// generated a random key, so this cannot match).
	wrongPin := "sha256/" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	tc := startClient(t, ts, wrongPin, nil)
	select {
	case <-tc.finished:
	case <-time.After(20 * time.Second):
		t.Fatal("pin mismatch did not fail hard within 20s")
	}
	if tc.runErr == nil {
		t.Fatal("expected fatal error on pin mismatch")
	}
	if ts.app.Registry().OnlineCount() != 0 {
		t.Fatalf("node must not register with a wrong pin")
	}
}
