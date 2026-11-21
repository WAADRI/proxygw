package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/nodesauth"
	"proxygw/internal/protocol"
	"proxygw/internal/registry"
	"proxygw/internal/transport"
)

var (
	errFakeClosed     = errors.New("fake: connection closed")
	errFakeReset      = errors.New("fake: stream reset")
	errFakeWriteClose = errors.New("fake: write side closed")
)

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// ---------------------------------------------------------------------------
// fake listener
// ---------------------------------------------------------------------------

type acceptResult struct {
	conn transport.Conn
	err  error
}

type fakeListener struct {
	kind      transport.Kind
	results   chan acceptResult
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeListener(kind transport.Kind) *fakeListener {
	return &fakeListener{
		kind:    kind,
		results: make(chan acceptResult, 64),
		closed:  make(chan struct{}),
	}
}

func (l *fakeListener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case r := <-l.results:
		return r.conn, r.err
	case <-l.closed:
		return nil, transport.ErrConnClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr            { return fakeAddr("fake-listener") }
func (l *fakeListener) Kind() transport.Kind      { return l.kind }
func (l *fakeListener) pushConn(c transport.Conn) { l.results <- acceptResult{conn: c} }
func (l *fakeListener) pushErr(err error)         { l.results <- acceptResult{err: err} }

// ---------------------------------------------------------------------------
// fake control stream
// ---------------------------------------------------------------------------

type fakeFrame struct {
	typ     protocol.FrameType
	payload []byte
}

// fakeControlStream models the server side of a control stream: Send writes to
// out (observed by the test), Recv reads frames injected through in.
type fakeControlStream struct {
	in        chan fakeFrame
	out       chan fakeFrame
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{
		in:     make(chan fakeFrame, 256),
		out:    make(chan fakeFrame, 256),
		closed: make(chan struct{}),
	}
}

func (c *fakeControlStream) Send(ctx context.Context, typ protocol.FrameType, payload []byte) error {
	select {
	case <-c.closed:
		return errFakeClosed
	default:
	}
	select {
	case c.out <- fakeFrame{typ: typ, payload: append([]byte(nil), payload...)}:
		return nil
	case <-c.closed:
		return errFakeClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *fakeControlStream) Recv(ctx context.Context) (protocol.FrameType, []byte, error) {
	select {
	case f := <-c.in:
		return f.typ, f.payload, nil
	case <-c.closed:
		return 0, nil, errFakeClosed
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

func (c *fakeControlStream) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// inject queues a frame as if the node sent it.
func (c *fakeControlStream) inject(typ protocol.FrameType, payload []byte) bool {
	select {
	case c.in <- fakeFrame{typ: typ, payload: append([]byte(nil), payload...)}:
		return true
	case <-c.closed:
		return false
	}
}

// readServerFrame waits for one frame sent by the server. Buffered frames are
// preferred over the closed marker so a rejection ACK followed by an immediate
// close is still observable.
func readServerFrame(t *testing.T, ctrl *fakeControlStream, timeout time.Duration) (protocol.FrameType, []byte) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		select {
		case f := <-ctrl.out:
			return f.typ, f.payload
		default:
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			t.Fatalf("timeout waiting for a frame from the tunnel server")
		}
		select {
		case f := <-ctrl.out:
			return f.typ, f.payload
		case <-ctrl.closed:
			select {
			case f := <-ctrl.out:
				return f.typ, f.payload
			default:
				t.Fatalf("control stream closed before the expected frame")
			}
		case <-time.After(remain):
			t.Fatalf("timeout waiting for a frame from the tunnel server")
		}
	}
}

func readHelloAck(t *testing.T, ctrl *fakeControlStream, timeout time.Duration) protocol.HelloAck {
	t.Helper()
	typ, payload := readServerFrame(t, ctrl, timeout)
	if typ != protocol.FrameHelloAck {
		t.Fatalf("expected HELLO_ACK, got %s", typ)
	}
	var ack protocol.HelloAck
	if err := protocol.Unmarshal(payload, &ack); err != nil {
		t.Fatalf("decode HELLO_ACK: %v", err)
	}
	return ack
}

// ---------------------------------------------------------------------------
// fake stream
// ---------------------------------------------------------------------------

// fakeStream is the server side of one transport stream.
type fakeStream struct {
	mu          sync.Mutex
	readBuf     bytes.Buffer
	written     bytes.Buffer
	readClosed  bool
	writeClosed bool
	reset       bool
	readErr     error
	writeErr    error
	openMeta    []byte
	resetCode   uint64

	notify    chan struct{}
	closedCh  chan struct{}
	closeOnce sync.Once

	openResult chan []byte
}

func newFakeStream() *fakeStream {
	return &fakeStream{
		notify:     make(chan struct{}, 1),
		closedCh:   make(chan struct{}),
		openResult: make(chan []byte, 4),
	}
}

func (s *fakeStream) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *fakeStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if s.reset {
			err := s.readErr
			s.mu.Unlock()
			return 0, err
		}
		if s.readBuf.Len() > 0 {
			n, _ := s.readBuf.Read(p)
			s.mu.Unlock()
			return n, nil
		}
		readClosed := s.readClosed
		s.mu.Unlock()
		if readClosed {
			return 0, io.EOF
		}
		select {
		case <-s.notify:
		case <-s.closedCh:
		}
	}
}

func (s *fakeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reset {
		return 0, s.readErr
	}
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	if s.writeClosed {
		return 0, errFakeWriteClose
	}
	n, _ := s.written.Write(p)
	s.signal()
	return n, nil
}

func (s *fakeStream) WriteOpen(meta []byte) error {
	s.mu.Lock()
	s.openMeta = append([]byte(nil), meta...)
	s.mu.Unlock()
	s.signal()
	return nil
}

func (s *fakeStream) ReadOpen(ctx context.Context) ([]byte, error) {
	return nil, errors.New("fake: server never reads OPEN")
}

func (s *fakeStream) WriteOpenResult(result []byte) error { return nil }

func (s *fakeStream) ReadOpenResult(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.openResult:
		return b, nil
	case <-s.closedCh:
		return nil, errFakeReset
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakeStream) CloseWrite() error {
	s.mu.Lock()
	s.writeClosed = true
	s.mu.Unlock()
	s.signal()
	return nil
}

func (s *fakeStream) CloseRead() error {
	s.mu.Lock()
	s.readClosed = true
	s.mu.Unlock()
	s.signal()
	return nil
}

func (s *fakeStream) Reset(code uint64) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.reset = true
		s.resetCode = code
		if s.readErr == nil {
			s.readErr = errFakeReset
		}
		if s.writeErr == nil {
			s.writeErr = errFakeReset
		}
		s.mu.Unlock()
		close(s.closedCh)
		s.signal()
	})
	return nil
}

func (s *fakeStream) SetDeadline(t time.Time) error      { return nil }
func (s *fakeStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *fakeStream) SetWriteDeadline(t time.Time) error { return nil }

// test helpers

func (s *fakeStream) pushData(b []byte) {
	s.mu.Lock()
	s.readBuf.Write(b)
	s.mu.Unlock()
	s.signal()
}

func (s *fakeStream) sendEOF() {
	s.mu.Lock()
	s.readClosed = true
	s.mu.Unlock()
	s.signal()
}

func (s *fakeStream) provideOpenResult(code byte, message string) {
	select {
	case s.openResult <- protocol.EncodeOpenResult(code, message):
	default:
	}
}

func (s *fakeStream) waitOpenMeta(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		if len(s.openMeta) > 0 {
			meta := append([]byte(nil), s.openMeta...)
			s.mu.Unlock()
			return meta, nil
		}
		reset := s.reset
		s.mu.Unlock()
		if reset {
			return nil, errFakeReset
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, errors.New("timeout waiting for OPEN metadata")
		}
		select {
		case <-s.notify:
		case <-s.closedCh:
		case <-time.After(remain):
		}
	}
}

func (s *fakeStream) waitWritten(n int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		if s.written.Len() >= n {
			out := make([]byte, n)
			_, _ = io.ReadFull(&s.written, out)
			s.mu.Unlock()
			return out, nil
		}
		s.mu.Unlock()
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, fmt.Errorf("timeout waiting for %d written bytes", n)
		}
		select {
		case <-s.notify:
		case <-s.closedCh:
		case <-time.After(remain):
		}
	}
}

func (s *fakeStream) waitWriteClosed(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		closed := s.writeClosed
		reset := s.reset
		s.mu.Unlock()
		if closed || reset {
			return nil
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return errors.New("timeout waiting for CloseWrite")
		}
		select {
		case <-s.notify:
		case <-time.After(remain):
		}
	}
}

func (s *fakeStream) wasReset() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reset
}

// ---------------------------------------------------------------------------
// fake conn
// ---------------------------------------------------------------------------

// fakeConn is one server side transport connection. The test controls the
// control stream, the streams the server opens and the connection lifetime.
type fakeConn struct {
	kind transport.Kind
	ctrl *fakeControlStream

	opened chan *fakeStream

	closeCh     chan struct{}
	closeOnce   sync.Once
	closeCode   atomic.Uint64
	closeReason atomic.Value
	epoch       atomic.Uint32
	handshake   atomic.Bool

	controlFn func(context.Context) (transport.ControlStream, error)
	onOpen    func(*fakeStream)
	openErr   atomic.Value
}

func newFakeConn(kind transport.Kind) *fakeConn {
	c := &fakeConn{
		kind:    kind,
		ctrl:    newFakeControlStream(),
		opened:  make(chan *fakeStream, 64),
		closeCh: make(chan struct{}),
	}
	c.handshake.Store(true)
	return c
}

func (c *fakeConn) Kind() transport.Kind { return c.kind }

func (c *fakeConn) OpenStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-c.closeCh:
		return nil, transport.ErrConnClosed
	default:
	}
	if v, ok := c.openErr.Load().(error); ok && v != nil {
		return nil, v
	}
	fs := newFakeStream()
	select {
	case c.opened <- fs:
	case <-c.closeCh:
		return nil, transport.ErrConnClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.onOpen != nil {
		c.onOpen(fs)
	}
	return fs, nil
}

func (c *fakeConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-c.closeCh:
		return nil, transport.ErrConnClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) Control(ctx context.Context) (transport.ControlStream, error) {
	if c.controlFn != nil {
		return c.controlFn(ctx)
	}
	select {
	case <-c.closeCh:
		return nil, transport.ErrConnClosed
	default:
		return c.ctrl, nil
	}
}

func (c *fakeConn) CloseWithError(code uint64, reason string) error {
	c.closeOnce.Do(func() {
		c.closeCode.Store(code)
		c.closeReason.Store(reason)
		close(c.closeCh)
		_ = c.ctrl.Close()
	})
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr     { return fakeAddr("127.0.0.1:1") }
func (c *fakeConn) RemoteAddr() net.Addr    { return fakeAddr("192.0.2.10:40000") }
func (c *fakeConn) HandshakeComplete() bool { return c.handshake.Load() }
func (c *fakeConn) SetEpoch(epoch uint32)   { c.epoch.Store(epoch) }

func (c *fakeConn) waitClosed(timeout time.Duration) error {
	select {
	case <-c.closeCh:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout waiting for the connection to close")
	}
}

func (c *fakeConn) nextOpened(t *testing.T, timeout time.Duration) *fakeStream {
	t.Helper()
	select {
	case fs := <-c.opened:
		return fs
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for the server to open a stream")
		return nil
	}
}

// ---------------------------------------------------------------------------
// control stream tap
// ---------------------------------------------------------------------------

// ctrlTap consumes every frame the tunnel server sends on a control stream. It
// optionally echoes PING with PONG, and forwards all frames to a channel so
// tests can assert on KICK and PING.
type ctrlTap struct {
	ctrl     *fakeControlStream
	frames   chan fakeFrame
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	echo     atomic.Bool
}

func newCtrlTap(t *testing.T, ctrl *fakeControlStream, echoPings bool) *ctrlTap {
	t.Helper()
	tap := &ctrlTap{
		ctrl:   ctrl,
		frames: make(chan fakeFrame, 256),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	tap.echo.Store(echoPings)
	go tap.loop()
	t.Cleanup(tap.close)
	return tap
}

func (tap *ctrlTap) loop() {
	defer close(tap.done)
	handle := func(f fakeFrame) {
		if tap.echo.Load() && f.typ == protocol.FramePing {
			tap.ctrl.inject(protocol.FramePong, f.payload)
		}
		select {
		case tap.frames <- f:
		default:
		}
	}
	for {
		select {
		case f := <-tap.ctrl.out:
			handle(f)
		case <-tap.ctrl.closed:
			for {
				select {
				case f := <-tap.ctrl.out:
					handle(f)
				default:
					return
				}
			}
		case <-tap.stop:
			return
		}
	}
}

// setEcho enables or disables automatic PONG replies.
func (tap *ctrlTap) setEcho(v bool) { tap.echo.Store(v) }

func (tap *ctrlTap) close() {
	tap.stopOnce.Do(func() { close(tap.stop) })
	<-tap.done
}

// next returns the next frame or fails the test on timeout.
func (tap *ctrlTap) next(t *testing.T, timeout time.Duration) fakeFrame {
	t.Helper()
	select {
	case f := <-tap.frames:
		return f
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for a control frame")
		return fakeFrame{}
	}
}

// nextOfType skips frames until typ arrives.
func (tap *ctrlTap) nextOfType(t *testing.T, typ protocol.FrameType, timeout time.Duration) fakeFrame {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			t.Fatalf("timeout waiting for a %s frame", typ)
		}
		select {
		case f := <-tap.frames:
			if f.typ == typ {
				return f
			}
		case <-time.After(remain):
			t.Fatalf("timeout waiting for a %s frame", typ)
		}
	}
}

// tryNext returns a frame if one is available.
func (tap *ctrlTap) tryNext(timeout time.Duration) (fakeFrame, bool) {
	select {
	case f := <-tap.frames:
		return f, true
	case <-time.After(timeout):
		return fakeFrame{}, false
	}
}

// ---------------------------------------------------------------------------
// test environment
// ---------------------------------------------------------------------------

type settingsBox struct {
	mu sync.Mutex
	st model.Settings
}

func (b *settingsBox) get() model.Settings {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st
}

func (b *settingsBox) set(st model.Settings) {
	b.mu.Lock()
	b.st = st
	b.mu.Unlock()
}

type testEnvOptions struct {
	times     *Timeouts
	auth      config.NodesAuthConfig
	settings  *model.Settings
	noAuth    bool
	noMetrics bool
	kind      transport.Kind
}

type testEnv struct {
	t        *testing.T
	srv      *Server
	reg      *registry.Registry
	auth     *nodesauth.Authenticator
	metrics  *metrics.Metrics
	box      *settingsBox
	listener *fakeListener
	token    string
	serveCtx context.Context

	serveCancel   context.CancelFunc
	serveFinished chan struct{}
	serveErr      error

	mu     sync.Mutex
	conns  []*fakeConn
	taps   []*ctrlTap
	closed sync.Once
}

func newTestEnv(t *testing.T, opts testEnvOptions) *testEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	var m *metrics.Metrics
	if !opts.noMetrics {
		m = metrics.New()
	}
	reg, err := registry.New(logger, m, "")
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	var auth *nodesauth.Authenticator
	if !opts.noAuth {
		cfg := opts.auth
		if len(cfg.Tokens) == 0 {
			cfg.Tokens = []config.StaticNodeToken{{NodeID: nodesauth.NodeIDWildcard, Token: "test-token"}}
		}
		auth, err = nodesauth.New(cfg, "", logger)
		if err != nil {
			t.Fatalf("nodesauth.New: %v", err)
		}
	}
	st := model.DefaultSettings()
	if opts.settings != nil {
		st = *opts.settings
	}
	box := &settingsBox{st: st}
	kind := opts.kind
	if kind == "" {
		kind = transport.KindQUIC
	}
	ln := newFakeListener(kind)
	serverOpts := ServerOptions{
		Logger:        logger,
		Registry:      reg,
		Auth:          auth,
		Settings:      box.get,
		Metrics:       m,
		MaxFrameBytes: protocol.MaxFramePayload,
	}
	if kind == transport.KindQUIC {
		serverOpts.QUICListener = ln
	} else {
		serverOpts.WSListener = ln
	}
	if opts.times != nil {
		tt := *opts.times
		serverOpts.Timeouts = &tt
	}
	srv, err := NewServer(serverOpts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serveCtx, serveCancel := context.WithCancel(context.Background())
	env := &testEnv{
		t:             t,
		srv:           srv,
		reg:           reg,
		auth:          auth,
		metrics:       m,
		box:           box,
		listener:      ln,
		token:         "test-token",
		serveCtx:      serveCtx,
		serveCancel:   serveCancel,
		serveFinished: make(chan struct{}),
	}
	go func() {
		env.serveErr = srv.Serve(serveCtx)
		close(env.serveFinished)
	}()

	t.Cleanup(env.shutdown)
	return env
}

// waitServe waits for Serve to return and returns its error.
func (e *testEnv) waitServe(timeout time.Duration) error {
	e.t.Helper()
	select {
	case <-e.serveFinished:
		return e.serveErr
	case <-time.After(timeout):
		e.t.Fatalf("Serve did not return within %s", timeout)
		return nil
	}
}

func (e *testEnv) shutdown() {
	e.closed.Do(func() {
		e.mu.Lock()
		taps := append([]*ctrlTap(nil), e.taps...)
		conns := append([]*fakeConn(nil), e.conns...)
		e.mu.Unlock()
		for _, tap := range taps {
			tap.close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.srv.Close(ctx)
		e.serveCancel()
		for _, c := range conns {
			_ = c.CloseWithError(0, "test cleanup")
		}
		select {
		case <-e.serveFinished:
			if e.serveErr != nil {
				e.t.Errorf("Serve returned error: %v", e.serveErr)
			}
		case <-time.After(5 * time.Second):
			e.t.Errorf("Serve did not return after Close")
		}
		select {
		case <-e.srv.shutdownDone:
		case <-time.After(5 * time.Second):
			e.t.Errorf("shutdown did not finish")
		}
		if got := e.srv.ActiveStreams(); got != 0 {
			e.t.Errorf("active streams after shutdown = %d, want 0", got)
		}
		e.srv.mu.Lock()
		live, streams := len(e.srv.live), len(e.srv.streams)
		e.srv.mu.Unlock()
		if live != 0 {
			e.t.Errorf("live sessions after shutdown = %d, want 0", live)
		}
		if streams != 0 {
			e.t.Errorf("registered streams after shutdown = %d, want 0", streams)
		}
	})
}

// pushConn hands a fake connection to the accept loop.
func (e *testEnv) pushConn(c *fakeConn) {
	e.mu.Lock()
	e.conns = append(e.conns, c)
	e.mu.Unlock()
	e.listener.pushConn(c)
}

// registerNode performs a successful HELLO handshake and returns the connection,
// a control tap that echoes PINGs and the HELLO_ACK.
func (e *testEnv) registerNode(nodeID string, plane int, mutate ...func(*protocol.Hello)) (*fakeConn, *ctrlTap, protocol.HelloAck) {
	e.t.Helper()
	c := newFakeConn(e.listener.kind)
	e.pushConn(c)
	e.hello(c, nodeID, plane, e.token, mutate...)
	ack := readHelloAck(e.t, c.ctrl, 3*time.Second)
	if !ack.OK {
		e.t.Fatalf("registration for %s:%d failed: %s", nodeID, plane, ack.Error)
	}
	if ack.Epoch == 0 {
		e.t.Fatalf("registration for %s:%d returned epoch 0", nodeID, plane)
	}
	if ack.Transport != string(c.kind) {
		e.t.Errorf("HELLO_ACK transport = %q, want %q", ack.Transport, c.kind)
	}
	waitFor(e.t, 3*time.Second, "node online", func() bool {
		n, ok := e.reg.Get(nodeID)
		return ok && n.Online
	})
	e.waitReady(nodeID)
	tap := newCtrlTap(e.t, c.ctrl, true)
	e.trackTap(tap)
	return c, tap, ack
}

// waitReady blocks until the node has at least one session in the ready state.
func (e *testEnv) waitReady(nodeID string) {
	e.t.Helper()
	waitFor(e.t, 3*time.Second, "session ready for "+nodeID, func() bool {
		state, _, ok := e.srv.SessionState(nodeID)
		return ok && state == "ready"
	})
}

// registerNodeIn registers a node and returns the raw conn plus the ACK, without
// creating a ping-echoing tap.
func (e *testEnv) registerNodeIn(nodeID string, plane int) (*fakeConn, protocol.HelloAck) {
	e.t.Helper()
	c := newFakeConn(e.listener.kind)
	e.pushConn(c)
	e.hello(c, nodeID, plane, e.token)
	ack := readHelloAck(e.t, c.ctrl, 3*time.Second)
	if !ack.OK {
		e.t.Fatalf("registration for %s:%d failed: %s", nodeID, plane, ack.Error)
	}
	return c, ack
}

func (e *testEnv) trackTap(tap *ctrlTap) {
	e.mu.Lock()
	e.taps = append(e.taps, tap)
	e.mu.Unlock()
}

// trackTapFor registers a tap on a conn that was not created via registerNode.
func (e *testEnv) trackTapFor(c *fakeConn, echo bool) *ctrlTap {
	tap := newCtrlTap(e.t, c.ctrl, echo)
	e.trackTap(tap)
	return tap
}

// hello queues a HELLO frame on conn's control stream.
func (e *testEnv) hello(c *fakeConn, nodeID string, plane int, token string, mutate ...func(*protocol.Hello)) {
	h := protocol.Hello{
		Ver:        protocol.Version1,
		Token:      token,
		ClientID:   nodeID,
		PlaneIndex: plane,
		Transport:  string(c.kind),
		Version:    "test-1.0",
		EgressV4:   "203.0.113.7",
		Alias:      nodeID + "-alias",
	}
	for _, fn := range mutate {
		fn(&h)
	}
	payload, err := protocol.Marshal(h)
	if err != nil {
		e.t.Fatalf("marshal HELLO: %v", err)
	}
	if !c.ctrl.inject(protocol.FrameHello, payload) {
		e.t.Fatalf("control stream already closed")
	}
}

// pushHelloOnly sends a HELLO without waiting for the answer.
func (e *testEnv) pushHelloConn(nodeID string, plane int, token string, mutate ...func(*protocol.Hello)) *fakeConn {
	c := newFakeConn(e.listener.kind)
	e.pushConn(c)
	e.hello(c, nodeID, plane, token, mutate...)
	return c
}

func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// autoOpenOK makes the fake conn answer every server OPEN with OK, optionally
// launching a handler for the stream.
func autoOpenOK(c *fakeConn, handler func(*fakeStream)) {
	c.onOpen = func(fs *fakeStream) {
		go func() {
			if _, err := fs.waitOpenMeta(2 * time.Second); err != nil {
				return
			}
			fs.provideOpenResult(byte(protocol.CodeOK), "")
			if handler != nil {
				handler(fs)
			}
		}()
	}
}

// openStreamOn starts DialStream for a specific connection: it returns the
// server stream and the fake transport stream after answering OPEN with OK.
func openStreamOn(t *testing.T, srv *Server, conn *fakeConn, nodeID string, req protocol.OpenRequest, timeout time.Duration) (*Stream, *fakeStream) {
	t.Helper()
	type result struct {
		st  *Stream
		err error
	}
	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	go func() {
		st, err := srv.DialStream(ctx, nodeID, req)
		ch <- result{st: st, err: err}
	}()
	fs := conn.nextOpened(t, timeout)
	if _, err := fs.waitOpenMeta(timeout); err != nil {
		t.Fatalf("wait OPEN meta: %v", err)
	}
	fs.provideOpenResult(byte(protocol.CodeOK), "")
	var res result
	select {
	case res = <-ch:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for DialStream")
	}
	if res.err != nil {
		t.Fatalf("DialStream: %v", res.err)
	}
	return res.st, fs
}

// dialStreamErr runs one DialStream attempt against a specific connection and
// returns its error. The fake stream is expected to be opened; resultCode is
// sent back as the OPEN result.
func dialStreamErr(t *testing.T, srv *Server, conn *fakeConn, nodeID string, req protocol.OpenRequest, resultCode byte, message string, timeout time.Duration) error {
	t.Helper()
	type result struct{ err error }
	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	go func() {
		_, err := srv.DialStream(ctx, nodeID, req)
		ch <- result{err: err}
	}()
	fs := conn.nextOpened(t, timeout)
	if _, err := fs.waitOpenMeta(timeout); err != nil {
		t.Fatalf("wait OPEN meta: %v", err)
	}
	fs.provideOpenResult(resultCode, message)
	select {
	case res := <-ch:
		return res.err
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for DialStream error")
		return nil
	}
}

func (e *testEnv) newOpenRequest(host string) protocol.OpenRequest {
	var trace [protocol.TraceIDLen]byte
	trace[0] = 0x42
	return protocol.TargetToOpen(host, 443, trace, false)
}

func traceID(b byte) [protocol.TraceIDLen]byte {
	var tr [protocol.TraceIDLen]byte
	for i := range tr {
		tr[i] = b
	}
	return tr
}
