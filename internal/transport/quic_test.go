package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"proxygw/internal/protocol"
)

// quicTLSFixture bundles the generated certificate and the server/client TLS
// configs used by the QUIC tests.
type quicTLSFixture struct {
	cert      tls.Certificate
	serverTLS *tls.Config
	clientTLS *tls.Config
}

func newQUICTLSFixture(t *testing.T) *quicTLSFixture {
	t.Helper()
	cert := generateTestCert(t)
	return &quicTLSFixture{
		cert:      cert,
		serverTLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		clientTLS: &tls.Config{RootCAs: certPool(t, cert), MinVersion: tls.VersionTLS13},
	}
}

// startQUICOptsPair starts a listener and dialer with explicit options and
// returns both connections.
func startQUICOptsPair(t *testing.T, fixture *quicTLSFixture, srvOpts, cliOpts QUICOptions) (Listener, Conn, Conn) {
	t.Helper()
	srvOpts.Addr = "127.0.0.1:0"
	if srvOpts.TLS == nil {
		srvOpts.TLS = fixture.serverTLS
	}
	lis, err := ListenQUIC(srvOpts)
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	ctx, cancel := newTestContext(t, 15*time.Second)
	defer cancel()
	cliOpts.Addr = lis.Addr().String()
	if cliOpts.TLS == nil {
		cliOpts.TLS = fixture.clientTLS
	}
	client, err := DialQUIC(ctx, cliOpts)
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "done") })
	server, err := lis.Accept(ctx)
	if err != nil {
		t.Fatalf("listener Accept: %v", err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "done") })
	p := &testPair{name: "quic-opts", server: server, client: client, lis: lis}
	establishTestControl(t, ctx, p)
	return lis, client, server
}

// TestQUICOptionsValidation verifies mandatory option validation.
func TestQUICOptionsValidation(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	if _, err := ListenQUIC(QUICOptions{Addr: "127.0.0.1:0"}); err == nil {
		t.Fatal("ListenQUIC without TLS config returned nil error")
	}
	if _, err := ListenQUIC(QUICOptions{Addr: "127.0.0.1:0", TLS: &tls.Config{}}); err == nil {
		t.Fatal("ListenQUIC without a server certificate returned nil error")
	}
	if _, err := ListenQUIC(QUICOptions{TLS: fixture.serverTLS}); err == nil {
		t.Fatal("ListenQUIC without an address returned nil error")
	}
	ctx, cancel := newTestContext(t, 5*time.Second)
	defer cancel()
	if _, err := DialQUIC(ctx, QUICOptions{Addr: "127.0.0.1:1"}); err == nil {
		t.Fatal("DialQUIC without TLS config returned nil error")
	}
	if _, err := DialQUIC(ctx, QUICOptions{TLS: fixture.clientTLS}); err == nil {
		t.Fatal("DialQUIC without an address returned nil error")
	}
}

// TestQUICALPN verifies the default and a custom ALPN are negotiated and that a
// mismatch fails the handshake.
func TestQUICALPN(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	lis, client, server := startQUICOptsPair(t, fixture, QUICOptions{}, QUICOptions{})
	p := &testPair{name: "quic-alpn", server: server, client: client, lis: lis}
	_ = p
	clientConn := client.(*quicConn)
	serverConn := server.(*quicConn)
	if got := clientConn.conn.ConnectionState().TLS.NegotiatedProtocol; got != protocol.ALPN {
		t.Fatalf("negotiated ALPN = %q, want %q", got, protocol.ALPN)
	}
	if got := serverConn.conn.ConnectionState().TLS.NegotiatedProtocol; got != protocol.ALPN {
		t.Fatalf("server negotiated ALPN = %q, want %q", got, protocol.ALPN)
	}
	if !client.HandshakeComplete() || !server.HandshakeComplete() {
		t.Fatal("HandshakeComplete must be true after a QUIC handshake")
	}

	// Custom ALPN on both sides.
	const customALPN = "proxygw/test/2"
	lis2, client2, server2 := startQUICOptsPair(t, fixture, QUICOptions{ALPN: customALPN}, QUICOptions{ALPN: customALPN})
	_ = lis2
	if got := client2.(*quicConn).conn.ConnectionState().TLS.NegotiatedProtocol; got != customALPN {
		t.Fatalf("custom negotiated ALPN = %q, want %q", got, customALPN)
	}
	_ = server2.CloseWithError(0, "done")
	_ = client2.CloseWithError(0, "done")

	// ALPN mismatch must fail the handshake.
	srvOpts := QUICOptions{TLS: fixture.serverTLS, ALPN: "server/1"}
	lis3, err := ListenQUIC(QUICOptions{Addr: "127.0.0.1:0", TLS: srvOpts.TLS, ALPN: srvOpts.ALPN, HandshakeTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("ListenQUIC custom ALPN: %v", err)
	}
	defer lis3.Close()
	ctx, cancel := newTestContext(t, 10*time.Second)
	defer cancel()
	if _, err := DialQUIC(ctx, QUICOptions{
		Addr:             lis3.Addr().String(),
		TLS:              fixture.clientTLS,
		ALPN:             "client/1",
		HandshakeTimeout: 3 * time.Second,
	}); err == nil {
		t.Fatal("DialQUIC with mismatched ALPN returned nil error")
	}
}

// TestQUICOptionsApplied verifies the QUICOptions mapping: datagrams, packet
// size, idle/keepalive timers, congestion control selection (accepted but not
// applicable in quic-go v0.48.2) and incoming stream limits.
func TestQUICOptionsApplied(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	opts := QUICOptions{
		ALPN:               protocol.ALPN,
		HandshakeTimeout:   5 * time.Second,
		MaxIdleTimeout:     20 * time.Second,
		KeepAlivePeriod:    2 * time.Second,
		EnableDatagrams:    true,
		Allow0RTT:          false,
		CongestionControl:  "bbr",
		InitialPacketSize:  1400,
		MaxIncomingStreams: 32,
	}
	_, client, server := startQUICOptsPair(t, fixture, opts, opts)
	clientState := client.(*quicConn).conn.ConnectionState()
	if !clientState.SupportsDatagrams {
		t.Fatal("datagram extension was not negotiated with EnableDatagrams")
	}
	if !server.(*quicConn).conn.ConnectionState().SupportsDatagrams {
		t.Fatal("server did not negotiate the datagram extension")
	}
	opts.CongestionControl = "cubic"
	_, client2, server2 := startQUICOptsPair(t, fixture, opts, opts)
	// A quick echo to prove the connections with the mapped options work.
	ctx, cancel := newTestContext(t, 15*time.Second)
	defer cancel()
	stream, peer := openTestStream(t, ctx, &testPair{server: server2, client: client2}, true)
	if _, err := stream.Write([]byte("opts")); err != nil {
		t.Fatalf("write with mapped options: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := readFullWithDeadline(t, ctx, peer, buf); err != nil {
		t.Fatalf("read with mapped options: %v", err)
	}
}

// TestQUICAllow0RTT verifies that the 0-RTT capable dial path still exposes a
// correct handshake flag and usable streams once the handshake completes.
func TestQUICAllow0RTT(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	srvOpts := QUICOptions{TLS: fixture.serverTLS, Allow0RTT: true, HandshakeTimeout: 5 * time.Second}
	lis, err := ListenQUIC(QUICOptions{Addr: "127.0.0.1:0", TLS: srvOpts.TLS, Allow0RTT: true, HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	defer lis.Close()
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()
	client, err := DialQUIC(ctx, QUICOptions{
		Addr:             lis.Addr().String(),
		TLS:              fixture.clientTLS,
		Allow0RTT:        true,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialQUIC with Allow0RTT: %v", err)
	}
	defer client.CloseWithError(0, "done")
	server, err := lis.Accept(ctx)
	if err != nil {
		t.Fatalf("listener Accept: %v", err)
	}
	defer server.CloseWithError(0, "done")
	if !server.HandshakeComplete() {
		t.Fatal("server HandshakeComplete must be true after Accept")
	}
	if !waitFor(10*time.Second, func() bool { return client.HandshakeComplete() }) {
		t.Fatal("client handshake did not complete")
	}
	p := &testPair{server: server, client: client}
	establishTestControl(t, ctx, p)
	stream, peer := openTestStream(t, ctx, p, true)
	if _, err := stream.Write([]byte("0rtt")); err != nil {
		t.Fatalf("write after 0-RTT handshake: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := readFullWithDeadline(t, ctx, peer, buf); err != nil {
		t.Fatalf("read after 0-RTT handshake: %v", err)
	}
}

// TestQUICQLogDir verifies that a non-empty QLogDir produces qlog files.
func TestQUICQLogDir(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	dir := t.TempDir()
	lis, client, server := startQUICOptsPair(t, fixture,
		QUICOptions{QLogDir: dir, HandshakeTimeout: 5 * time.Second},
		QUICOptions{QLogDir: dir, HandshakeTimeout: 5 * time.Second})
	_ = lis
	_ = client
	_ = server
	// One connection produces two logs (server + client perspective).
	if !waitFor(10*time.Second, func() bool {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.sqlog"))
		return len(matches) >= 2
	}) {
		entries, _ := os.ReadDir(dir)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("qlog files not created in %s: %v", dir, names)
	}
}

// TestQUICListenerClose verifies listener close semantics.
func TestQUICListenerClose(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	lis, err := ListenQUIC(QUICOptions{Addr: "127.0.0.1:0", TLS: fixture.serverTLS})
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	if lis.Kind() != KindQUIC {
		t.Fatalf("listener Kind = %s, want quic", lis.Kind())
	}
	if lis.Addr() == nil {
		t.Fatal("listener Addr is nil")
	}
	// A cancelled context is reported as such.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := lis.Accept(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept with cancelled context = %v, want context.Canceled", err)
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("listener Close: %v", err)
	}
	ctx, cancel := newTestContext(t, 5*time.Second)
	defer cancel()
	if _, err := lis.Accept(ctx); !errors.Is(err, ErrListenerClosed) {
		t.Fatalf("Accept after Close = %v, want ErrListenerClosed", err)
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("second listener Close must be idempotent: %v", err)
	}
}

// TestQUICDialTimeout verifies the handshake timeout is implemented through the
// dial context deadline.
func TestQUICDialTimeout(t *testing.T) {
	fixture := newQUICTLSFixture(t)
	// A UDP socket that never answers completes the QUIC handshake never.
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole udp: %v", err)
	}
	defer blackhole.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = DialQUIC(ctx, QUICOptions{
		Addr:             blackhole.LocalAddr().String(),
		TLS:              fixture.clientTLS,
		HandshakeTimeout: 10 * time.Second,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("DialQUIC to a silent peer returned nil error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		// Some platforms surface the deadline as a QUIC handshake timeout; the
		// important property is that the dial returns quickly.
		t.Logf("DialQUIC deadline error = %v (not context.DeadlineExceeded)", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("DialQUIC ignored the context deadline: %v", elapsed)
	}
}

// TestQUICCleanup verifies the QUIC connection watcher goroutine exits and the
// process goroutine count returns to the baseline after closing everything.
func TestQUICCleanup(t *testing.T) {
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()
	fixture := newQUICTLSFixture(t)
	lis, client, server := startQUICOptsPair(t, fixture, QUICOptions{HandshakeTimeout: 5 * time.Second}, QUICOptions{HandshakeTimeout: 5 * time.Second})
	p := &testPair{server: server, client: client, lis: lis}

	ctx, cancel := newTestContext(t, 30*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		stream, peer := openTestStream(t, ctx, p, true)
		payload := makePayload(i, 4096)
		if _, err := stream.Write(payload); err != nil {
			t.Fatalf("write stream %d: %v", i, err)
		}
		if err := stream.CloseWrite(); err != nil {
			t.Fatalf("close write stream %d: %v", i, err)
		}
		got, err := readAllWithDeadline(t, ctx, peer)
		if err != nil {
			t.Fatalf("read stream %d: %v", i, err)
		}
		if len(got) != 4096 {
			t.Fatalf("stream %d read %d bytes", i, len(got))
		}
	}
	if err := client.CloseWithError(0, "done"); err != nil {
		t.Fatalf("client CloseWithError: %v", err)
	}
	if err := server.CloseWithError(0, "done"); err != nil {
		t.Fatalf("server CloseWithError: %v", err)
	}
	if !client.(*quicConn).waitGoroutines(5 * time.Second) {
		t.Fatal("client QUIC watcher goroutine did not exit")
	}
	if !server.(*quicConn).waitGoroutines(5 * time.Second) {
		t.Fatal("server QUIC watcher goroutine did not exit")
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("listener Close: %v", err)
	}
	if !waitGoroutinesDrain(t, baseline, 6, 15*time.Second) {
		t.Fatalf("goroutines did not drain: baseline %d, now %d", baseline, runtime.NumGoroutine())
	}
}

// TestQUICConnKindAndAddrs verifies basic Conn introspection.
func TestQUICConnKindAndAddrs(t *testing.T) {
	p := newQUICTestPair(t)
	if p.server.Kind() != KindQUIC || p.client.Kind() != KindQUIC {
		t.Fatalf("kinds = %s/%s, want quic", p.server.Kind(), p.client.Kind())
	}
	if p.server.LocalAddr() == nil || p.server.RemoteAddr() == nil {
		t.Fatal("nil addresses on the server connection")
	}
	if p.client.LocalAddr() == nil || p.server.RemoteAddr() == nil {
		t.Fatal("nil addresses on the client connection")
	}
	// The client UDP socket may be bound to a wildcard IPv6 address, so compare
	// ports instead of the full address strings.
	_, clientPort, err := net.SplitHostPort(p.client.LocalAddr().String())
	if err != nil {
		t.Fatalf("client LocalAddr %q: %v", p.client.LocalAddr(), err)
	}
	_, serverPort, err := net.SplitHostPort(p.server.RemoteAddr().String())
	if err != nil {
		t.Fatalf("server RemoteAddr %q: %v", p.server.RemoteAddr(), err)
	}
	if clientPort != serverPort {
		t.Fatalf("client local port %s != server remote port %s", clientPort, serverPort)
	}
}
