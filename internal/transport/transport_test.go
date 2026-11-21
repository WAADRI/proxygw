package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"proxygw/internal/protocol"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// testPair is one connected transport pair: a listener side Conn and a dialer
// side Conn.
type testPair struct {
	name   string
	server Conn
	client Conn

	lis       Listener
	httpSrv   *httptest.Server
	closeOnce sync.Once
}

// close tears the pair down exactly once.
func (p *testPair) close() {
	p.closeOnce.Do(func() {
		if p.client != nil {
			_ = p.client.CloseWithError(0, "test done")
		}
		if p.server != nil {
			_ = p.server.CloseWithError(0, "test done")
		}
		if p.lis != nil {
			_ = p.lis.Close()
		}
		if p.httpSrv != nil {
			p.httpSrv.Close()
		}
	})
}

// newQUICTestPair creates an in-process QUIC listener + dialer pair over
// 127.0.0.1:0 with a freshly generated self signed certificate.
func newQUICTestPair(t *testing.T) *testPair {
	t.Helper()
	cert := generateTestCert(t)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{RootCAs: certPool(t, cert), MinVersion: tls.VersionTLS13}
	srvOpts := QUICOptions{
		Addr:             "127.0.0.1:0",
		TLS:              serverTLS,
		HandshakeTimeout: 5 * time.Second,
		KeepAlivePeriod:  time.Second,
	}
	lis, err := ListenQUIC(srvOpts)
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cliOpts := QUICOptions{
		Addr:             lis.Addr().String(),
		TLS:              clientTLS,
		HandshakeTimeout: 5 * time.Second,
		KeepAlivePeriod:  time.Second,
	}
	client, err := DialQUIC(ctx, cliOpts)
	if err != nil {
		_ = lis.Close()
		t.Fatalf("DialQUIC: %v", err)
	}
	server, err := lis.Accept(ctx)
	if err != nil {
		_ = client.CloseWithError(0, "cleanup")
		_ = lis.Close()
		t.Fatalf("QUIC listener Accept: %v", err)
	}
	p := &testPair{name: "quic", server: server, client: client, lis: lis}
	establishTestControl(t, ctx, p)
	t.Cleanup(p.close)
	return p
}

// newWSTestPair creates an httptest HTTP server around a WSListener and dials
// it over ws:// (the tunnel protocol is identical for ws:// and wss://).
func newWSTestPair(t *testing.T) *testPair {
	t.Helper()
	lis := NewWSListener(WSOptions{HandshakeTimeout: 5 * time.Second})
	httpSrv := httptest.NewServer(lis.Handler())
	_, port, err := net.SplitHostPort(httpSrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("httptest listener address: %v", err)
	}
	wsURL := url.URL{Scheme: "ws", Host: net.JoinHostPort("127.0.0.1", port), Path: defaultWSPath}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := DialWS(ctx, WSOptions{URL: wsURL.String(), HandshakeTimeout: 5 * time.Second})
	if err != nil {
		httpSrv.Close()
		_ = lis.Close()
		t.Fatalf("DialWS: %v", err)
	}
	server, err := lis.Accept(ctx)
	if err != nil {
		_ = client.CloseWithError(0, "cleanup")
		httpSrv.Close()
		_ = lis.Close()
		t.Fatalf("WS listener Accept: %v", err)
	}
	p := &testPair{name: "ws", server: server, client: client, lis: lis, httpSrv: httpSrv}
	establishTestControl(t, ctx, p)
	t.Cleanup(p.close)
	return p
}

// establishTestControl performs the control stream handshake the tunnel layer
// does right after dialing: the dialer opens the control stream and writes the
// first control frame, the listener accepts it. This mirrors HELLO and makes
// the pair independent of which side opens the first data stream (on QUIC the
// control stream must be the first bidi stream).
func establishTestControl(t *testing.T, ctx context.Context, p *testPair) {
	t.Helper()
	clientCtrl, err := p.client.Control(ctx)
	if err != nil {
		p.close()
		t.Fatalf("client Control during setup: %v", err)
	}
	if err := clientCtrl.Send(ctx, protocol.FrameHello, []byte(`{"ver":1}`)); err != nil {
		p.close()
		t.Fatalf("client control Send during setup: %v", err)
	}
	serverCtrl, err := p.server.Control(ctx)
	if err != nil {
		p.close()
		t.Fatalf("server Control during setup: %v", err)
	}
	typ, payload, err := serverCtrl.Recv(ctx)
	if err != nil {
		p.close()
		t.Fatalf("server control Recv during setup: %v", err)
	}
	if typ != protocol.FrameHello || string(payload) != `{"ver":1}` {
		p.close()
		t.Fatalf("server control setup frame = (%s, %q)", typ, payload)
	}
}

// generateTestCert builds a self signed ECDSA P-256 server certificate.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "proxygw-transport-test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// certPool returns a root pool containing cert.
func certPool(t *testing.T, cert tls.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		cert.Leaf = leaf
	}
	pool.AddCert(cert.Leaf)
	return pool
}

// newTestContext returns a context bounded by the test deadline.
func newTestContext(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), timeout)
}

// testOpenMeta builds a valid OPEN header payload.
func testOpenMeta(t *testing.T) []byte {
	t.Helper()
	var trace [protocol.TraceIDLen]byte
	copy(trace[:], []byte("0123456789abcdef"))
	req := protocol.TargetToOpen("example.com", 443, trace, false)
	meta, err := req.Encode()
	if err != nil {
		t.Fatalf("encode OPEN header: %v", err)
	}
	return meta
}

// makePayload builds a deterministic payload for stream seed and size bytes.
func makePayload(seed, size int) []byte {
	buf := make([]byte, size)
	hdr := fmt.Sprintf("stream-%d:", seed)
	copy(buf, hdr)
	for i := len(hdr); i < size; i++ {
		buf[i] = byte((seed*131 + i*17 + 7) % 251)
	}
	return buf
}

// readAllWithDeadline reads until EOF, bounding the read with ctx.
func readAllWithDeadline(t *testing.T, ctx context.Context, s Stream) ([]byte, error) {
	t.Helper()
	if dl, ok := ctx.Deadline(); ok {
		if err := s.SetReadDeadline(dl); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(s)
}

// waitFor polls cond until it returns true or the timeout expires.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitGoroutinesDrain waits until the goroutine count has dropped to at most
// baseline+slack.
func waitGoroutinesDrain(t *testing.T, baseline, slack int, timeout time.Duration) bool {
	t.Helper()
	ok := waitFor(timeout, func() bool {
		return runtime.NumGoroutine() <= baseline+slack
	})
	return ok
}

// sha256Sum returns the SHA-256 digest of b.
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// ---------------------------------------------------------------------------
// Shared conformance suite: the same scenarios must pass for QUIC and WS.
// ---------------------------------------------------------------------------

type pairFactory func(*testing.T) *testPair

func runTransportSuite(t *testing.T, newPair pairFactory) {
	t.Run("OpenMetadata", func(t *testing.T) { testOpenMetadata(t, newPair) })
	t.Run("EchoData", func(t *testing.T) { testEchoData(t, newPair) })
	t.Run("HalfClose", func(t *testing.T) { testHalfClose(t, newPair) })
	t.Run("BidirectionalFin", func(t *testing.T) { testBidirectionalFin(t, newPair) })
	t.Run("Reset", func(t *testing.T) { testReset(t, newPair) })
	t.Run("LargeTransfer", func(t *testing.T) { testLargeTransfer(t, newPair) })
	t.Run("ConcurrentStreams", func(t *testing.T) { testConcurrentStreams(t, newPair) })
	t.Run("ControlFrames", func(t *testing.T) { testControlFrames(t, newPair) })
	t.Run("ControlPriorityUnderLoad", func(t *testing.T) { testControlPriorityUnderLoad(t, newPair) })
	t.Run("StreamDeadlines", func(t *testing.T) { testStreamDeadlines(t, newPair) })
	t.Run("ConnectionClose", func(t *testing.T) { testConnectionClose(t, newPair) })
}

// TestTransportConformanceQUIC runs the shared transport conformance suite on
// the QUIC path.
func TestTransportConformanceQUIC(t *testing.T) {
	runTransportSuite(t, newQUICTestPair)
}

// TestTransportConformanceWS runs the shared transport conformance suite on the
// WebSocket path.
func TestTransportConformanceWS(t *testing.T) {
	runTransportSuite(t, newWSTestPair)
}

// testOpenMetadata exercises the OPEN / OPEN_OK / OPEN_ERR framing on both
// paths and verifies DATA flows in both directions afterwards.
func testOpenMetadata(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	meta := testOpenMeta(t)
	stream, err := p.server.OpenStream(ctx)
	if err != nil {
		t.Fatalf("server OpenStream: %v", err)
	}
	if err := stream.WriteOpen(meta); err != nil {
		t.Fatalf("WriteOpen: %v", err)
	}
	peer, err := p.client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("client AcceptStream: %v", err)
	}
	gotMeta, err := peer.ReadOpen(ctx)
	if err != nil {
		t.Fatalf("ReadOpen: %v", err)
	}
	if !bytes.Equal(gotMeta, meta) {
		t.Fatalf("OPEN metadata mismatch: got %x want %x", gotMeta, meta)
	}
	result := protocol.EncodeOpenResult(0, "ok")
	if err := peer.WriteOpenResult(result); err != nil {
		t.Fatalf("WriteOpenResult: %v", err)
	}
	gotResult, err := stream.ReadOpenResult(ctx)
	if err != nil {
		t.Fatalf("ReadOpenResult: %v", err)
	}
	if !bytes.Equal(gotResult, result) {
		t.Fatalf("OPEN result mismatch: got %x want %x", gotResult, result)
	}
	if code, msg, err := protocol.DecodeOpenResult(gotResult); err != nil || code != 0 || msg != "ok" {
		t.Fatalf("DecodeOpenResult = (%d, %q, %v)", code, msg, err)
	}

	// The stream must be usable for data in both directions after the OPEN
	// handshake.
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("client read %q", buf)
	}
	if _, err := peer.Write([]byte("pong")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("server read %q", buf)
	}

	// OPEN_ERR propagation.
	stream2, err := p.server.OpenStream(ctx)
	if err != nil {
		t.Fatalf("server OpenStream 2: %v", err)
	}
	if err := stream2.WriteOpen(meta); err != nil {
		t.Fatalf("WriteOpen 2: %v", err)
	}
	peer2, err := p.client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("client AcceptStream 2: %v", err)
	}
	if _, err := peer2.ReadOpen(ctx); err != nil {
		t.Fatalf("ReadOpen 2: %v", err)
	}
	errResult := protocol.EncodeOpenResult(2, "connection refused")
	if err := peer2.WriteOpenResult(errResult); err != nil {
		t.Fatalf("WriteOpenResult 2: %v", err)
	}
	gotErrResult, err := stream2.ReadOpenResult(ctx)
	if err != nil {
		t.Fatalf("ReadOpenResult 2: %v", err)
	}
	if code, msg, err := protocol.DecodeOpenResult(gotErrResult); err != nil || code != 2 || msg != "connection refused" {
		t.Fatalf("DecodeOpenResult 2 = (%d, %q, %v)", code, msg, err)
	}
}

// testEchoData verifies bidirectional payload transfer including a 64 KiB frame
// boundary chunk.
func testEchoData(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)

	payload := makePayload(1, 1024)
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("server write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client payload mismatch")
	}

	// Exactly one maximum sized frame on the WS path (64 KiB).
	maxPayload := makePayload(2, protocol.MaxFramePayload)
	if _, err := peer.Write(maxPayload); err != nil {
		t.Fatalf("client write 64KiB: %v", err)
	}
	gotMax := make([]byte, len(maxPayload))
	if _, err := io.ReadFull(stream, gotMax); err != nil {
		t.Fatalf("server read 64KiB: %v", err)
	}
	if !bytes.Equal(gotMax, maxPayload) {
		t.Fatal("server 64KiB payload mismatch")
	}

	// Zero length write must be a no-op, data after it must still flow.
	if n, err := stream.Write(nil); n != 0 || err != nil {
		t.Fatalf("zero length write = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := stream.Write([]byte("after-zero")); err != nil {
		t.Fatalf("server write after zero: %v", err)
	}
	after := make([]byte, len("after-zero"))
	if _, err := io.ReadFull(peer, after); err != nil {
		t.Fatalf("client read after zero: %v", err)
	}
	if string(after) != "after-zero" {
		t.Fatalf("client read after zero = %q", after)
	}
}

// openTestStream opens a stream from the server side, sends OPEN metadata and
// accepts it on the client side.
func openTestStream(t *testing.T, ctx context.Context, p *testPair, withMeta bool) (Stream, Stream) {
	t.Helper()
	stream, err := p.server.OpenStream(ctx)
	if err != nil {
		t.Fatalf("server OpenStream: %v", err)
	}
	if withMeta {
		if err := stream.WriteOpen(testOpenMeta(t)); err != nil {
			t.Fatalf("WriteOpen: %v", err)
		}
	}
	peer, err := p.client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("client AcceptStream: %v", err)
	}
	if withMeta {
		if _, err := peer.ReadOpen(ctx); err != nil {
			t.Fatalf("ReadOpen: %v", err)
		}
	}
	return stream, peer
}

// testHalfClose verifies FIN semantics in both directions.
func testHalfClose(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	payload := makePayload(3, 8192)
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("server CloseWrite: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("server second CloseWrite must be idempotent: %v", err)
	}
	got, err := readAllWithDeadline(t, ctx, peer)
	if err != nil {
		t.Fatalf("client read to EOF: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client payload mismatch after FIN")
	}
	// The client must still be able to write after the remote FIN.
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatalf("client write after remote FIN: %v", err)
	}
	gotResp := make([]byte, len("response"))
	if _, err := io.ReadFull(stream, gotResp); err != nil {
		t.Fatalf("server read after local FIN: %v", err)
	}
	if string(gotResp) != "response" {
		t.Fatalf("server read after local FIN = %q", gotResp)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatalf("server read final EOF: %v", err)
	}
}

// testBidirectionalFin closes both directions of a stream concurrently and
// verifies exactly-once cleanup without panics.
func testBidirectionalFin(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := stream.CloseWrite(); err != nil {
			t.Errorf("server CloseWrite: %v", err)
		}
		if err := stream.CloseWrite(); err != nil {
			t.Errorf("server second CloseWrite: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := peer.CloseWrite(); err != nil {
			t.Errorf("client CloseWrite: %v", err)
		}
		if err := peer.CloseWrite(); err != nil {
			t.Errorf("client second CloseWrite: %v", err)
		}
	}()
	wg.Wait()
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatalf("server read after double FIN: %v", err)
	}
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatalf("client read after double FIN: %v", err)
	}
	// The connection must survive and remain usable.
	stream2, peer2 := openTestStream(t, ctx, p, true)
	if _, err := stream2.Write([]byte("alive")); err != nil {
		t.Fatalf("write after double FIN: %v", err)
	}
	buf := make([]byte, len("alive"))
	if _, err := readFullWithDeadline(t, ctx, peer2, buf); err != nil {
		t.Fatalf("read after double FIN: %v", err)
	}
	if string(buf) != "alive" {
		t.Fatalf("read after double FIN = %q", buf)
	}
}

// testReset verifies RST is reported as an error and not as EOF.
func testReset(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	if err := stream.Reset(7); err != nil {
		t.Fatalf("server Reset: %v", err)
	}
	buf := make([]byte, 16)
	_, err := peer.Read(buf)
	if err == nil {
		t.Fatal("client Read after reset returned nil error")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("client Read after reset returned EOF: %v", err)
	}
	if !errors.Is(err, ErrStreamReset) {
		t.Fatalf("client Read after reset = %v, want ErrStreamReset", err)
	}
	var rerr *StreamResetError
	if errors.As(err, &rerr) {
		if rerr.Code != 7 || !rerr.Remote {
			t.Fatalf("reset error = %+v, want code 7 remote", rerr)
		}
	} else {
		t.Fatalf("client Read error %v is not *StreamResetError", err)
	}
	// Writing on the reset stream must also fail.
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Fatal("client Write after reset returned nil error")
	}
}

// testLargeTransfer moves 2 MiB over one stream with a slow consumer, which
// forces the 256 KiB per stream window to be replenished by WINDOW frames on
// the WS path (and exercises QUIC flow control on the QUIC path).
func testLargeTransfer(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 60*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	const total = 2 * 1024 * 1024
	payload := makePayload(4, total)
	wantSum := sha256Sum(payload)

	writeErr := make(chan error, 1)
	go func() {
		if _, err := stream.Write(payload); err != nil {
			writeErr <- fmt.Errorf("writer: %w", err)
			return
		}
		writeErr <- stream.CloseWrite()
	}()

	got := make([]byte, 0, total)
	buf := make([]byte, 4096)
	read := 0
	for {
		if dl, ok := ctx.Deadline(); ok {
			_ = peer.SetReadDeadline(dl)
		}
		n, err := peer.Read(buf)
		read += n
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reader after %d bytes: %v", read, err)
		}
		// Slow consumer: force window replenishment and partial writes.
		if read%131072 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
		if read > total {
			t.Fatal("reader received more bytes than sent")
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writer: %v", err)
	}
	if read != total {
		t.Fatalf("read %d bytes, want %d", read, total)
	}
	if gotSum := sha256Sum(got); gotSum != wantSum {
		t.Fatalf("payload checksum mismatch: %x != %x", gotSum, wantSum)
	}
}

// testConcurrentStreams runs 20 server initiated and 5 client initiated
// streams concurrently and verifies data isolation between streams.
func testConcurrentStreams(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 60*time.Second)
	defer cancel()

	const (
		serverStreams = 20
		clientStreams = 5
		payloadSize   = 32 * 1024
	)
	meta := testOpenMeta(t)
	var (
		wg     sync.WaitGroup
		errCh  = make(chan error, serverStreams+clientStreams)
		failed = func(format string, args ...any) { errCh <- fmt.Errorf(format, args...) }
	)

	// Server initiated streams: server opens and writes, client accepts and
	// verifies.
	wg.Add(serverStreams)
	for i := 0; i < serverStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			payload := makePayload(100+idx, payloadSize)
			stream, err := p.server.OpenStream(ctx)
			if err != nil {
				failed("server open stream %d: %w", idx, err)
				return
			}
			if err := stream.WriteOpen(meta); err != nil {
				failed("server write open %d: %v", idx, err)
				return
			}
			if _, err := stream.Write(payload); err != nil {
				failed("server write %d: %v", idx, err)
				return
			}
			if err := stream.CloseWrite(); err != nil {
				failed("server close write %d: %v", idx, err)
				return
			}
			// The client echoes the payload back over the same stream.
			echo := make([]byte, payloadSize)
			if _, err := readFullWithDeadline(t, ctx, stream, echo); err != nil {
				failed("server read echo %d: %v", idx, err)
				return
			}
			if !bytes.Equal(echo, payload) {
				failed("server echo mismatch %d", idx)
			}
		}(i)
	}
	for i := 0; i < serverStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peer, err := p.client.AcceptStream(ctx)
			if err != nil {
				failed("client accept %d: %w", idx, err)
				return
			}
			if _, err := peer.ReadOpen(ctx); err != nil {
				failed("client read open %d: %v", idx, err)
				return
			}
			data, err := readAllWithDeadline(t, ctx, peer)
			if err != nil {
				failed("client read %d: %v", idx, err)
				return
			}
			// The payload header encodes its stream seed; verify the payload is
			// exactly one of the expected ones (no cross stream interleaving).
			seed := -1
			if _, err := fmt.Sscanf(string(data), "stream-%d:", &seed); err != nil || seed < 100 || seed >= 100+serverStreams {
				failed("client stream payload header invalid for accept %d: %q", idx, string(data[:min(len(data), 16)]))
				return
			}
			if !bytes.Equal(data, makePayload(seed, payloadSize)) {
				failed("client payload corrupted on stream seed %d", seed)
				return
			}
			if _, err := peer.Write(data); err != nil {
				failed("client echo write %d: %v", idx, err)
				return
			}
			if err := peer.CloseWrite(); err != nil {
				failed("client echo close %d: %v", idx, err)
			}
		}(i)
	}

	// Client initiated streams: client opens and writes, server accepts and
	// verifies.
	for i := 0; i < clientStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := makePayload(200+idx, payloadSize)
			stream, err := p.client.OpenStream(ctx)
			if err != nil {
				failed("client open stream %d: %w", idx, err)
				return
			}
			if err := stream.WriteOpen(meta); err != nil {
				failed("client write open %d: %v", idx, err)
				return
			}
			if _, err := stream.Write(payload); err != nil {
				failed("client write %d: %v", idx, err)
				return
			}
			if err := stream.CloseWrite(); err != nil {
				failed("client close write %d: %v", idx, err)
				return
			}
			echo := make([]byte, payloadSize)
			if _, err := readFullWithDeadline(t, ctx, stream, echo); err != nil {
				failed("client read echo %d: %v", idx, err)
				return
			}
			if !bytes.Equal(echo, payload) {
				failed("client echo mismatch %d", idx)
			}
		}(i)
	}
	for i := 0; i < clientStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peer, err := p.server.AcceptStream(ctx)
			if err != nil {
				failed("server accept %d: %w", idx, err)
				return
			}
			if _, err := peer.ReadOpen(ctx); err != nil {
				failed("server read open %d: %v", idx, err)
				return
			}
			data, err := readAllWithDeadline(t, ctx, peer)
			if err != nil {
				failed("server read %d: %v", idx, err)
				return
			}
			seed := -1
			if _, err := fmt.Sscanf(string(data), "stream-%d:", &seed); err != nil || seed < 200 || seed >= 200+clientStreams {
				failed("server stream payload header invalid for accept %d", idx)
				return
			}
			if !bytes.Equal(data, makePayload(seed, payloadSize)) {
				failed("server payload corrupted on stream seed %d", seed)
				return
			}
			if _, err := peer.Write(data); err != nil {
				failed("server echo write %d: %v", idx, err)
				return
			}
			if err := peer.CloseWrite(); err != nil {
				failed("server echo close %d: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent streams: %v", err)
	}
	if t.Failed() {
		return
	}
	// The connection must still be usable after all streams were released.
	stream, peer := openTestStream(t, ctx, p, true)
	if _, err := stream.Write([]byte("still-alive")); err != nil {
		t.Fatalf("post concurrency write: %v", err)
	}
	buf := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("post concurrency read: %v", err)
	}
	if string(buf) != "still-alive" {
		t.Fatalf("post concurrency read = %q", buf)
	}
}

// testControlFrames verifies bidirectional control frame delivery, ordering and
// idempotent concurrent Control() acquisition.
func testControlFrames(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	serverCtrl, err := p.server.Control(ctx)
	if err != nil {
		t.Fatalf("server Control: %v", err)
	}
	clientCtrl, err := p.client.Control(ctx)
	if err != nil {
		t.Fatalf("client Control: %v", err)
	}
	// Control must be idempotent: a second call returns a working handle.
	serverCtrl2, err := p.server.Control(ctx)
	if err != nil {
		t.Fatalf("server Control second call: %v", err)
	}

	// Concurrent Control() acquisition from many goroutines.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.client.Control(ctx); err != nil {
				t.Errorf("concurrent client Control: %v", err)
			}
		}()
	}
	wg.Wait()

	// Both directions, several frame types.
	frames := []struct {
		typ     protocol.FrameType
		payload []byte
	}{
		{protocol.FramePing, []byte("ping")},
		{protocol.FrameStats, []byte(`{"inflight":3}`)},
		{protocol.FramePong, []byte("pong")},
	}
	for _, f := range frames {
		if err := serverCtrl.Send(ctx, f.typ, f.payload); err != nil {
			t.Fatalf("server control Send %s: %v", f.typ, err)
		}
		typ, payload, err := clientCtrl.Recv(ctx)
		if err != nil {
			t.Fatalf("client control Recv %s: %v", f.typ, err)
		}
		if typ != f.typ || !bytes.Equal(payload, f.payload) {
			t.Fatalf("client control Recv = (%s, %q), want (%s, %q)", typ, payload, f.typ, f.payload)
		}
	}
	for i := 0; i < 10; i++ {
		payload := []byte(fmt.Sprintf("seq-%d", i))
		if err := serverCtrl2.Send(ctx, protocol.FramePing, payload); err != nil {
			t.Fatalf("server control ordered Send %d: %v", i, err)
		}
	}
	for i := 0; i < 10; i++ {
		typ, payload, err := clientCtrl.Recv(ctx)
		if err != nil {
			t.Fatalf("client control ordered Recv %d: %v", i, err)
		}
		want := fmt.Sprintf("seq-%d", i)
		if typ != protocol.FramePing || string(payload) != want {
			t.Fatalf("client control ordered Recv %d = (%s, %q), want (PING, %q)", i, typ, payload, want)
		}
	}

	// Reverse direction.
	if err := clientCtrl.Send(ctx, protocol.FrameStats, []byte(`{"bytes_in":1}`)); err != nil {
		t.Fatalf("client control Send: %v", err)
	}
	typ, payload, err := serverCtrl.Recv(ctx)
	if err != nil {
		t.Fatalf("server control Recv: %v", err)
	}
	if typ != protocol.FrameStats || string(payload) != `{"bytes_in":1}` {
		t.Fatalf("server control Recv = (%s, %q)", typ, payload)
	}
}

// testControlPriorityUnderLoad verifies that a control frame is delivered
// promptly while a data stream is flooding the connection.
func testControlPriorityUnderLoad(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 30*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	// Fill the pipe: write a large payload while the receiver does not consume
	// immediately.
	const total = 4 * 1024 * 1024
	writeDone := make(chan error, 1)
	go func() {
		_, err := stream.Write(makePayload(9, total))
		writeDone <- err
	}()
	time.Sleep(50 * time.Millisecond)

	serverCtrl, err := p.server.Control(ctx)
	if err != nil {
		t.Fatalf("server Control: %v", err)
	}
	clientCtrl, err := p.client.Control(ctx)
	if err != nil {
		t.Fatalf("client Control: %v", err)
	}
	start := time.Now()
	if err := serverCtrl.Send(ctx, protocol.FramePing, []byte("urgent")); err != nil {
		t.Fatalf("control Send under load: %v", err)
	}
	recvCtx, recvCancel := context.WithTimeout(ctx, 3*time.Second)
	defer recvCancel()
	typ, payload, err := clientCtrl.Recv(recvCtx)
	if err != nil {
		_ = p.client.CloseWithError(0, "cleanup")
		t.Fatalf("control Recv under load: %v", err)
	}
	if typ != protocol.FramePing || string(payload) != "urgent" {
		t.Fatalf("control Recv under load = (%s, %q)", typ, payload)
	}
	if latency := time.Since(start); latency > 2*time.Second {
		t.Fatalf("control frame took %v under data load", latency)
	}
	// Drain the stream so the writer goroutine finishes before cleanup.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		_, _ = io.Copy(io.Discard, peer)
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("data write under control load: %v", err)
		}
	case <-time.After(20 * time.Second):
		_ = p.client.CloseWithError(0, "timeout cleanup")
		t.Fatal("data writer did not finish")
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite after flood: %v", err)
	}
	select {
	case <-drainDone:
	case <-time.After(20 * time.Second):
		t.Fatal("drain did not finish")
	}
}

// testStreamDeadlines verifies read and write deadlines on a blocked stream.
func testStreamDeadlines(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 30*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)

	// Read deadline with no data available.
	if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 8)
	_, err := peer.Read(buf)
	if err == nil {
		t.Fatal("Read with expired deadline returned nil error")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read deadline error = %v, want os.ErrDeadlineExceeded", err)
	}
	// Clearing the deadline must make the stream usable again.
	if err := peer.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
	if _, err := stream.Write([]byte("after-deadline")); err != nil {
		t.Fatalf("write after read deadline: %v", err)
	}
	got := make([]byte, len("after-deadline"))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("read after cleared deadline: %v", err)
	}
	if string(got) != "after-deadline" {
		t.Fatalf("read after cleared deadline = %q", got)
	}

	// Write deadline when the peer stops consuming: the stream window runs out
	// and Write has to block until the deadline expires.
	blockStream, blockPeer := openTestStream(t, ctx, p, true)
	_ = blockPeer // never read from it
	if err := blockStream.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	big := makePayload(11, 2*1024*1024)
	start := time.Now()
	_, werr := blockStream.Write(big)
	if werr == nil {
		t.Fatal("Write with exhausted window and expired deadline returned nil error")
	}
	if !errors.Is(werr, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline error = %v, want os.ErrDeadlineExceeded", werr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("write deadline took %v", elapsed)
	}
	if err := blockStream.Reset(1); err != nil {
		t.Fatalf("Reset after write deadline: %v", err)
	}
}

// testConnectionClose verifies that closing a connection fails every in-flight
// stream operation and all accept/open calls, and that CloseWithError is
// idempotent.
func testConnectionClose(t *testing.T, newPair pairFactory) {
	p := newPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	if _, err := stream.Write([]byte("in-flight")); err != nil {
		t.Fatalf("write before close: %v", err)
	}
	buf := make([]byte, len("in-flight"))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("read before close: %v", err)
	}
	serverCtrl, err := p.server.Control(ctx)
	if err != nil {
		t.Fatalf("server Control: %v", err)
	}
	clientCtrl, err := p.client.Control(ctx)
	if err != nil {
		t.Fatalf("client Control: %v", err)
	}

	if err := p.server.CloseWithError(1, "shutdown"); err != nil {
		t.Fatalf("server CloseWithError: %v", err)
	}
	if err := p.server.CloseWithError(1, "shutdown again"); err != nil {
		t.Fatalf("server second CloseWithError must be idempotent: %v", err)
	}

	// Local operations fail immediately.
	if _, err := p.server.OpenStream(ctx); err == nil {
		t.Fatal("OpenStream after close returned nil error")
	}
	if _, err := p.server.AcceptStream(ctx); err == nil {
		t.Fatal("AcceptStream after close returned nil error")
	}
	if _, err := stream.Read(buf); err == nil {
		t.Fatal("Read after close returned nil error")
	}
	if _, err := stream.Write([]byte("x")); err == nil {
		t.Fatal("Write after close returned nil error")
	}
	if err := serverCtrl.Send(ctx, protocol.FramePing, nil); err == nil {
		t.Fatal("control Send after close returned nil error")
	}

	// The peer observes the close with a bounded timeout.
	closeCtx, closeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer closeCancel()
	if _, err := p.client.AcceptStream(closeCtx); err == nil {
		t.Fatal("client AcceptStream after peer close returned nil error")
	}
	if _, err := peer.Read(buf); err == nil {
		t.Fatal("client Read after peer close returned nil error")
	}
	if _, _, err := clientCtrl.Recv(closeCtx); err == nil {
		t.Fatal("client control Recv after peer close returned nil error")
	}
}
