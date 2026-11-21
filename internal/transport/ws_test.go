package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"proxygw/internal/protocol"
)

// wsTestURL builds the tunnel websocket URL for an httptest server.
func wsTestURL(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	u := url.URL{Scheme: "ws", Host: srv.Listener.Addr().String(), Path: path}
	return u.String()
}

// dialRawWS dials a raw gorilla websocket connection (no tunnel framing).
func dialRawWS(t *testing.T, rawURL string) *websocket.Conn {
	t.Helper()
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	c, resp, err := d.Dial(rawURL, nil)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("raw websocket dial %s: %v", rawURL, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// injectWSFrame queues an arbitrary protocol frame on the wsConn writer. Used
// to exercise frames the public Stream API never emits (zero length DATA, old
// epoch frames) and malformed peers.
func injectWSFrame(c Conn, typ protocol.FrameType, streamID uint32, payload []byte) error {
	wc, ok := c.(*wsConn)
	if !ok {
		return fmt.Errorf("not a wsConn")
	}
	buf, err := protocol.AppendFrame(nil, typ, streamID, payload)
	if err != nil {
		return err
	}
	return wc.enqueue(wc.dataCh, wsWriteRequest{buf: buf}, context.Background())
}

// TestWSFrameBoundaries covers WebSocket frame edge cases: a zero length DATA
// frame is accepted and ignored, a 64 KiB DATA frame is accepted, and a frame
// above the limit tears the connection down as a protocol error.
func TestWSFrameBoundaries(t *testing.T) {
	t.Run("ZeroLengthData", func(t *testing.T) {
		p := newWSTestPair(t)
		ctx, cancel := newTestContext(t, 20*time.Second)
		defer cancel()

		stream, peer := openTestStream(t, ctx, p, true)
		wsStreamSide, ok := stream.(*wsStream)
		if !ok {
			t.Fatalf("server stream is %T", stream)
		}
		// A zero length DATA frame must be accepted (no bytes delivered).
		if err := injectWSFrame(p.server, protocol.FrameData, wsStreamSide.ID(), nil); err != nil {
			t.Fatalf("inject zero length DATA: %v", err)
		}
		if _, err := stream.Write([]byte("payload")); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		if err := stream.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		got, err := readAllWithDeadline(t, ctx, peer)
		if err != nil {
			t.Fatalf("read after zero length DATA: %v", err)
		}
		if string(got) != "payload" {
			t.Fatalf("read %q, want payload", got)
		}
	})

	t.Run("MaxFrameData", func(t *testing.T) {
		p := newWSTestPair(t)
		ctx, cancel := newTestContext(t, 20*time.Second)
		defer cancel()

		stream, peer := openTestStream(t, ctx, p, true)
		payload := makePayload(21, protocol.MaxFramePayload)
		if _, err := stream.Write(payload); err != nil {
			t.Fatalf("write max frame payload: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := readFullWithDeadline(t, ctx, peer, got); err != nil {
			t.Fatalf("read max frame payload: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatal("max frame payload mismatch")
		}
	})

	t.Run("OversizedFrameRejected", func(t *testing.T) {
		lis := NewWSListener(WSOptions{})
		srv := httptest.NewServer(lis.Handler())
		defer srv.Close()
		defer lis.Close()
		raw := dialRawWS(t, wsTestURL(t, srv, defaultWSPath))
		ctx, cancel := newTestContext(t, 20*time.Second)
		defer cancel()
		conn, err := lis.Accept(ctx)
		if err != nil {
			t.Fatalf("listener Accept: %v", err)
		}
		wc := conn.(*wsConn)

		// Build a DATA frame that declares 65 KiB of payload (over the 64 KiB
		// limit) and send it as one websocket message.
		const oversize = 65 * 1024
		msg := make([]byte, protocol.FrameHeaderLen+oversize)
		msg[0] = byte(protocol.FrameData)
		binary.BigEndian.PutUint32(msg[1:5], protocol.MakeStreamID(0, 2))
		binary.BigEndian.PutUint32(msg[5:9], oversize)
		if err := raw.WriteMessage(websocket.BinaryMessage, msg); err != nil {
			t.Fatalf("raw write oversized frame: %v", err)
		}
		// The server side must close the connection because the frame is over
		// the limit.
		if !wc.waitGoroutines(5 * time.Second) {
			t.Fatal("server wsConn goroutines did not exit after oversized frame")
		}
		select {
		case <-wc.done:
		default:
			t.Fatal("server wsConn is not closed after oversized frame")
		}
		if !errors.Is(wc.lastErr(), ErrProtocol) {
			t.Fatalf("server conn close reason = %v, want ErrProtocol", wc.lastErr())
		}
		// The raw peer must observe the connection going away.
		_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := raw.ReadMessage(); err == nil {
			t.Fatal("raw peer read succeeded after oversized frame")
		}
	})
}

// readFullWithDeadline reads len(buf) bytes with the context deadline applied.
func readFullWithDeadline(t *testing.T, ctx context.Context, r Stream, buf []byte) (int, error) {
	t.Helper()
	if dl, ok := ctx.Deadline(); ok {
		if err := r.SetReadDeadline(dl); err != nil {
			return 0, err
		}
	}
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if total >= len(buf) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestWSPathRouting verifies the listener only upgrades the configured path and
// publishes its address.
func TestWSPathRouting(t *testing.T) {
	lis := NewWSListener(WSOptions{Path: "/custom-tunnel"})
	srv := httptest.NewServer(lis.Handler())
	defer srv.Close()
	defer lis.Close()
	lis.SetAddr(srv.Listener.Addr())
	if got, want := lis.Addr().String(), srv.Listener.Addr().String(); got != want {
		t.Fatalf("listener Addr = %q, want %q", got, want)
	}
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	// Wrong path must not upgrade (HTTP 404 is reported through the dialer).
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	_, resp, err := d.Dial(wsTestURL(t, srv, "/wrong"), nil)
	if err == nil {
		t.Fatal("dial to the wrong path unexpectedly upgraded")
	}
	if resp != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("wrong path status = %d, want 404", resp.StatusCode)
		}
	}

	// Correct path must upgrade and be accepted.
	client, err := DialWS(ctx, WSOptions{URL: wsTestURL(t, srv, "/custom-tunnel")})
	if err != nil {
		t.Fatalf("DialWS correct path: %v", err)
	}
	defer client.CloseWithError(0, "done")
	server, err := lis.Accept(ctx)
	if err != nil {
		t.Fatalf("listener Accept: %v", err)
	}
	defer server.CloseWithError(0, "done")
	if server.Kind() != KindWS || client.Kind() != KindWS {
		t.Fatalf("kinds = %s/%s, want ws", server.Kind(), client.Kind())
	}
	if !client.HandshakeComplete() || !server.HandshakeComplete() {
		t.Fatal("HandshakeComplete must be true after the WS upgrade")
	}
}

// TestWSListenerClose verifies that closing the listener fails Accept and
// closes connections that were queued but never accepted.
func TestWSListenerClose(t *testing.T) {
	lis := NewWSListener(WSOptions{})
	srv := httptest.NewServer(lis.Handler())
	defer srv.Close()
	raw := dialRawWS(t, wsTestURL(t, srv, defaultWSPath))

	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()
	// Wait for the upgrade to be queued.
	deadline := time.Now().Add(5 * time.Second)
	for {
		lis.mu.Lock()
		n := len(lis.conns)
		lis.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := lis.Close(); err != nil {
		t.Fatalf("listener Close: %v", err)
	}
	if _, err := lis.Accept(ctx); !errors.Is(err, ErrListenerClosed) {
		t.Fatalf("Accept after Close = %v, want ErrListenerClosed", err)
	}
	// The queued connection must have been closed.
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := raw.ReadMessage(); err == nil {
		t.Fatal("queued connection is still readable after listener Close")
	}
	// Upgrades after Close are rejected with 503.
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	_, resp, err := d.Dial(wsTestURL(t, srv, defaultWSPath), nil)
	if err == nil {
		t.Fatal("dial after listener Close unexpectedly upgraded")
	}
	if resp != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("dial after Close status = %d, want 503", resp.StatusCode)
		}
	}
	// Accept with a cancelled context returns the context error when the
	// listener is alive.
	lis2 := NewWSListener(WSOptions{})
	srv2 := httptest.NewServer(lis2.Handler())
	defer srv2.Close()
	defer lis2.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := lis2.Accept(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept with cancelled context = %v, want context.Canceled", err)
	}
}

// TestWSLateEpochFrames verifies that stale epoch frames are dropped (and
// counted) without disturbing live streams, and that too many stale frames
// close the connection with a protocol error.
func TestWSLateEpochFrames(t *testing.T) {
	p := newWSTestPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	serverWC := p.server.(*wsConn)
	clientWC := p.client.(*wsConn)
	serverWC.SetEpoch(5)
	clientWC.SetEpoch(5)

	// A stream created after SetEpoch uses epoch 5 and must be accepted.
	stream, peer := openTestStream(t, ctx, p, true)
	if _, ok := stream.(*wsStream); !ok {
		t.Fatalf("stream is %T", stream)
	}

	// One late frame from the previous epoch must be ignored.
	oldID := protocol.MakeStreamID(0, 2)
	if err := injectWSFrame(p.server, protocol.FrameData, oldID, []byte("stale")); err != nil {
		t.Fatalf("inject stale frame: %v", err)
	}
	if _, err := stream.Write([]byte("fresh")); err != nil {
		t.Fatalf("write fresh data: %v", err)
	}
	got := make([]byte, len("fresh"))
	if _, err := readFullWithDeadline(t, ctx, peer, got); err != nil {
		t.Fatalf("read fresh data: %v", err)
	}
	if string(got) != "fresh" {
		t.Fatalf("read %q, want fresh", got)
	}
	if n := clientWC.late.Load(); n != 1 {
		t.Fatalf("late frame counter = %d, want 1", n)
	}

	// Flooding stale frames must close the connection with ErrProtocol.
	for i := 0; i < wsMaxLateFrames+5; i++ {
		if err := injectWSFrame(p.server, protocol.FrameData, oldID, []byte("x")); err != nil {
			break
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for clientWC.doneErr() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if clientWC.doneErr() == nil {
		t.Fatal("client connection was not closed after late frame flood")
	}
	if !errors.Is(clientWC.lastErr(), ErrProtocol) {
		t.Fatalf("client close reason = %v, want ErrProtocol", clientWC.lastErr())
	}
}

// TestWSUnknownStreamFrameDrop verifies that frames for unknown streams are
// dropped and counted instead of failing the connection immediately.
func TestWSUnknownStreamFrameDrop(t *testing.T) {
	p := newWSTestPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	// Unknown stream id owned by the server (even), current epoch 0.
	unknownID := protocol.MakeStreamID(0, 2)
	for i := 0; i < 5; i++ {
		if err := injectWSFrame(p.server, protocol.FrameData, unknownID, []byte("ghost")); err != nil {
			t.Fatalf("inject unknown stream frame: %v", err)
		}
		if err := injectWSFrame(p.server, protocol.FrameWindow, unknownID, protocol.EncodeWindow(1024)); err != nil {
			t.Fatalf("inject unknown stream window: %v", err)
		}
	}
	// The connection must still work.
	stream, peer := openTestStream(t, ctx, p, true)
	if _, err := stream.Write([]byte("alive")); err != nil {
		t.Fatalf("write after unknown stream frames: %v", err)
	}
	buf := make([]byte, len("alive"))
	if _, err := readFullWithDeadline(t, ctx, peer, buf); err != nil {
		t.Fatalf("read after unknown stream frames: %v", err)
	}
	if string(buf) != "alive" {
		t.Fatalf("read %q", buf)
	}
	if n := p.client.(*wsConn).late.Load(); n != 10 {
		t.Fatalf("late frame counter = %d, want 10", n)
	}
}

// TestWSControlClose verifies that closing the control channel only closes that
// channel and does not tear the connection down.
func TestWSControlClose(t *testing.T) {
	p := newWSTestPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	ctrl, err := p.client.Control(ctx)
	if err != nil {
		t.Fatalf("client Control: %v", err)
	}
	if err := ctrl.Close(); err != nil {
		t.Fatalf("control Close: %v", err)
	}
	if err := ctrl.Close(); err != nil {
		t.Fatalf("control second Close: %v", err)
	}
	recvCtx, recvCancel := context.WithTimeout(ctx, 2*time.Second)
	defer recvCancel()
	if _, _, err := ctrl.Recv(recvCtx); !errors.Is(err, ErrControlClosed) {
		t.Fatalf("Recv after control Close = %v, want ErrControlClosed", err)
	}
	if err := ctrl.Send(ctx, protocol.FramePing, nil); err == nil {
		t.Fatal("Send after control Close returned nil error")
	}
	// The data path still works.
	stream, peer := openTestStream(t, ctx, p, true)
	if _, err := stream.Write([]byte("ok")); err != nil {
		t.Fatalf("write after control Close: %v", err)
	}
	buf := make([]byte, len("ok"))
	if _, err := readFullWithDeadline(t, ctx, peer, buf); err != nil {
		t.Fatalf("read after control Close: %v", err)
	}
}

// TestWSDialURLValidation verifies URL validation and connection error paths.
func TestWSDialURLValidation(t *testing.T) {
	ctx, cancel := newTestContext(t, 10*time.Second)
	defer cancel()
	cases := []string{
		"http://127.0.0.1:1/tunnel",
		"tcp://127.0.0.1:1",
		"ws://",
		"::not a url",
	}
	for _, rawURL := range cases {
		if _, err := DialWS(ctx, WSOptions{URL: rawURL}); err == nil {
			t.Fatalf("DialWS(%q) returned nil error", rawURL)
		}
	}
	// A syntactically valid ws URL to a closed port must fail fast with a dial
	// error rather than hang.
	if _, err := DialWS(ctx, WSOptions{URL: "ws://127.0.0.1:1/tunnel", HandshakeTimeout: time.Second}); err == nil {
		t.Fatal("DialWS to closed port returned nil error")
	}
}

// TestWSOpenAPI misuse guards.
func TestWSOpenAPI(t *testing.T) {
	p := newWSTestPair(t)
	ctx, cancel := newTestContext(t, 20*time.Second)
	defer cancel()

	stream, peer := openTestStream(t, ctx, p, true)
	// A locally opened stream has no peer OPEN metadata.
	if _, err := stream.ReadOpen(ctx); !errors.Is(err, ErrOpenUnavailable) {
		t.Fatalf("ReadOpen on local stream = %v, want ErrOpenUnavailable", err)
	}
	if err := stream.WriteOpenResult(protocol.EncodeOpenResult(0, "ok")); err == nil {
		t.Fatal("WriteOpenResult on the opener side returned nil error")
	}
	// The receiver side cannot write OPEN metadata for the same stream.
	if err := peer.WriteOpen(testOpenMeta(t)); err == nil {
		t.Fatal("WriteOpen on the receiver side returned nil error")
	}
	if _, err := peer.ReadOpenResult(ctx); !errors.Is(err, ErrOpenUnavailable) {
		t.Fatalf("ReadOpenResult on receiver side = %v, want ErrOpenUnavailable", err)
	}
}

// TestWSCleanup verifies that closing the connection and listener releases all
// transport goroutines.
func TestWSCleanup(t *testing.T) {
	time.Sleep(20 * time.Millisecond) // let previous tests settle
	baseline := runtime.NumGoroutine()

	lis := NewWSListener(WSOptions{})
	srv := httptest.NewServer(lis.Handler())
	lis.SetAddr(srv.Listener.Addr())
	ctx, cancel := newTestContext(t, 30*time.Second)
	defer cancel()
	client, err := DialWS(ctx, WSOptions{URL: wsTestURL(t, srv, defaultWSPath)})
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	server, err := lis.Accept(ctx)
	if err != nil {
		t.Fatalf("listener Accept: %v", err)
	}
	clientCtrl, _ := client.Control(ctx)
	if err := clientCtrl.Send(ctx, protocol.FrameHello, []byte("{}")); err != nil {
		t.Fatalf("control Send: %v", err)
	}
	serverCtrl, _ := server.Control(ctx)
	if _, _, err := serverCtrl.Recv(ctx); err != nil {
		t.Fatalf("control Recv: %v", err)
	}

	// A handful of streams and unread data so buffers and windows are active.
	const streams = 10
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, err := server.OpenStream(ctx)
			if err != nil {
				return
			}
			if err := s.WriteOpen(testOpenMeta(t)); err != nil {
				return
			}
			_, _ = s.Write(makePayload(idx, 8*1024))
		}(i)
	}
	for i := 0; i < streams; i++ {
		peer, err := client.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("client AcceptStream: %v", err)
		}
		if _, err := peer.ReadOpen(ctx); err != nil {
			t.Fatalf("ReadOpen: %v", err)
		}
	}
	wg.Wait()

	if err := client.CloseWithError(0, "done"); err != nil {
		t.Fatalf("client CloseWithError: %v", err)
	}
	if err := server.CloseWithError(0, "done"); err != nil {
		t.Fatalf("server CloseWithError: %v", err)
	}
	if !client.(*wsConn).waitGoroutines(5 * time.Second) {
		t.Fatal("client wsConn reader/writer goroutines did not exit")
	}
	if !server.(*wsConn).waitGoroutines(5 * time.Second) {
		t.Fatal("server wsConn reader/writer goroutines did not exit")
	}
	_ = lis.Close()
	srv.Close()
	if !waitFor(5*time.Second, func() bool {
		lis.mu.Lock()
		n := len(lis.conns)
		lis.mu.Unlock()
		return n == 0
	}) {
		t.Fatal("listener still tracks connections after close")
	}
	if !waitGoroutinesDrain(t, baseline, 4, 10*time.Second) {
		t.Fatalf("goroutines did not drain: baseline %d, now %d", baseline, runtime.NumGoroutine())
	}
}
