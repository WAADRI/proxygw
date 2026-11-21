package nodeagent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

// ---------------------------------------------------------------------------
// fake transport implementation
// ---------------------------------------------------------------------------

type fakeFrame struct {
	typ     protocol.FrameType
	payload []byte
}

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// fakeControlStream implements transport.ControlStream. Frames written by the
// node are exposed on events; frames pushed by the test are returned by Recv.
type fakeControlStream struct {
	mu      sync.Mutex
	sent    []fakeFrame
	events  chan fakeFrame
	recvCh  chan fakeFrame
	closed  chan struct{}
	closeCN sync.Once
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{
		events: make(chan fakeFrame, 512),
		recvCh: make(chan fakeFrame, 512),
		closed: make(chan struct{}),
	}
}

func (c *fakeControlStream) Send(ctx context.Context, typ protocol.FrameType, payload []byte) error {
	select {
	case <-c.closed:
		return transport.ErrConnClosed
	default:
	}
	f := fakeFrame{typ: typ, payload: append([]byte(nil), payload...)}
	select {
	case c.events <- f:
		c.mu.Lock()
		c.sent = append(c.sent, f)
		c.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return transport.ErrConnClosed
	}
}

func (c *fakeControlStream) Recv(ctx context.Context) (protocol.FrameType, []byte, error) {
	select {
	case f := <-c.recvCh:
		return f.typ, f.payload, nil
	case <-c.closed:
		return 0, nil, transport.ErrConnClosed
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

func (c *fakeControlStream) Close() error {
	c.closeCN.Do(func() { close(c.closed) })
	return nil
}

// pushSim delivers a frame from the fake server to the node.
func (c *fakeControlStream) pushSim(typ protocol.FrameType, payload []byte) {
	f := fakeFrame{typ: typ, payload: payload}
	select {
	case c.recvCh <- f:
	case <-c.closed:
	default:
		panic("fakeControlStream: recv buffer full")
	}
}

type fakeConn struct {
	kind      transport.Kind
	ctrl      *fakeControlStream
	acceptCh  chan transport.Stream
	closeCh   chan struct{}
	closeCN   sync.Once
	handshake atomic.Bool
	closeCode atomic.Uint64
}

func newFakeConn(kind transport.Kind) *fakeConn {
	return &fakeConn{
		kind:     kind,
		ctrl:     newFakeControlStream(),
		acceptCh: make(chan transport.Stream, 16),
		closeCh:  make(chan struct{}),
	}
}

func (c *fakeConn) Kind() transport.Kind { return c.kind }

func (c *fakeConn) OpenStream(ctx context.Context) (transport.Stream, error) {
	return nil, errors.New("fake: OpenStream not supported on node side")
}

func (c *fakeConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case st := <-c.acceptCh:
		return st, nil
	case <-c.closeCh:
		return nil, transport.ErrConnClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) Control(ctx context.Context) (transport.ControlStream, error) {
	select {
	case <-c.closeCh:
		return nil, transport.ErrConnClosed
	default:
	}
	return c.ctrl, nil
}

func (c *fakeConn) CloseWithError(code uint64, reason string) error {
	c.closeCode.Store(code)
	c.closeCN.Do(func() {
		close(c.closeCh)
		_ = c.ctrl.Close()
	})
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr  { return fakeAddr("127.0.0.1:443") }
func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr("127.0.0.1:443") }

func (c *fakeConn) HandshakeComplete() bool { return c.handshake.Load() }

// pushStream hands a new server initiated stream to the node.
func (c *fakeConn) pushStream(st transport.Stream) {
	select {
	case c.acceptCh <- st:
	case <-c.closeCh:
	}
}

// fakeStream implements transport.Stream for the node side. Data written by the
// fake server to inW is read by the node; data written by the node to outW is
// read by the test from outR.
type fakeStream struct {
	openMeta     []byte
	readOpenErr  error
	readOpenWait chan struct{}

	inR *io.PipeReader
	inW *io.PipeWriter

	outR *io.PipeReader
	outW *io.PipeWriter

	resultCh     chan []byte
	resetCh      chan uint64
	closeWriteCh chan struct{}
	closeReadCh  chan struct{}
	closedCh     chan struct{}

	closeWriteCN sync.Once
	closeReadCN  sync.Once
	closedCN     sync.Once

	writeDeadline atomic.Value // time.Time
	writeErr      error
	writeMu       sync.Mutex
}

func newFakeStream(openMeta []byte) *fakeStream {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	return &fakeStream{
		openMeta:     openMeta,
		inR:          inR,
		inW:          inW,
		outR:         outR,
		outW:         outW,
		resultCh:     make(chan []byte, 8),
		resetCh:      make(chan uint64, 8),
		closeWriteCh: make(chan struct{}),
		closeReadCh:  make(chan struct{}),
		closedCh:     make(chan struct{}),
	}
}

func (s *fakeStream) Read(p []byte) (int, error) { return s.inR.Read(p) }

func (s *fakeStream) Write(p []byte) (int, error) {
	if dl, ok := s.writeDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	s.writeMu.Lock()
	err := s.writeErr
	s.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return s.outW.Write(p)
}

func (s *fakeStream) WriteOpen(meta []byte) error {
	return errors.New("fake: node must not WriteOpen")
}

func (s *fakeStream) ReadOpen(ctx context.Context) ([]byte, error) {
	if s.readOpenWait != nil {
		select {
		case <-s.readOpenWait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.readOpenErr != nil {
		return nil, s.readOpenErr
	}
	return append([]byte(nil), s.openMeta...), nil
}

func (s *fakeStream) WriteOpenResult(result []byte) error {
	select {
	case s.resultCh <- append([]byte(nil), result...):
	default:
	}
	return nil
}

func (s *fakeStream) ReadOpenResult(ctx context.Context) ([]byte, error) {
	return nil, errors.New("fake: ReadOpenResult not used on node side")
}

func (s *fakeStream) CloseWrite() error {
	s.closeWriteCN.Do(func() {
		close(s.closeWriteCh)
		_ = s.outW.Close()
	})
	return nil
}

func (s *fakeStream) CloseRead() error {
	s.closeReadCN.Do(func() {
		close(s.closeReadCh)
		_ = s.inR.CloseWithError(io.ErrClosedPipe)
	})
	return nil
}

func (s *fakeStream) Reset(code uint64) error {
	select {
	case s.resetCh <- code:
	default:
	}
	s.closedCN.Do(func() { close(s.closedCh) })
	_ = s.inR.CloseWithError(io.ErrClosedPipe)
	_ = s.outR.CloseWithError(io.ErrClosedPipe)
	_ = s.inW.CloseWithError(io.ErrClosedPipe)
	return nil
}

func (s *fakeStream) SetDeadline(t time.Time) error      { s.writeDeadline.Store(t); return nil }
func (s *fakeStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *fakeStream) SetWriteDeadline(t time.Time) error { s.writeDeadline.Store(t); return nil }

func (s *fakeStream) waitResult(t *testing.T, timeout time.Duration) (byte, string) {
	t.Helper()
	select {
	case raw := <-s.resultCh:
		code, msg, err := protocol.DecodeOpenResult(raw)
		if err != nil {
			t.Fatalf("DecodeOpenResult: %v", err)
		}
		return code, msg
	case <-time.After(timeout):
		t.Fatalf("等待 OPEN 结果超时")
		return 0, ""
	}
}

// ---------------------------------------------------------------------------
// fake server: dial functions + per connection control driver
// ---------------------------------------------------------------------------

type fakeServer struct {
	t *testing.T

	mu        sync.Mutex
	conns     []*fakeConn
	dialLog   []dialRecord
	helloAck  protocol.HelloAck
	helloOK   bool
	onReady   func(c *fakeConn, h protocol.Hello)
	onHello   func(c *fakeConn, h protocol.Hello)
	ackMutate func(a *protocol.HelloAck)
	quicFn    func(ctx context.Context) (transport.Conn, error)
	wsFn      func(ctx context.Context) (transport.Conn, error)

	helloCh chan protocol.Hello
	pongCh  chan []byte
	statsCh chan protocol.Stats
	probeCh chan protocol.ProbeResult

	closed chan struct{}
}

type dialRecord struct {
	kind transport.Kind
	at   time.Time
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	s := &fakeServer{
		t:        t,
		helloOK:  true,
		helloAck: protocol.HelloAck{Ver: protocol.Version1, OK: true, Epoch: 7, Transport: "quic"},
		helloCh:  make(chan protocol.Hello, 32),
		pongCh:   make(chan []byte, 32),
		statsCh:  make(chan protocol.Stats, 64),
		probeCh:  make(chan protocol.ProbeResult, 32),
		closed:   make(chan struct{}),
	}
	t.Cleanup(s.stop)
	return s
}

func (s *fakeServer) stop() {
	close(s.closed)
	s.mu.Lock()
	conns := append([]*fakeConn(nil), s.conns...)
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(0, "test done")
	}
}

func (s *fakeServer) setHelloOK(ok bool, errText string, epoch uint32) {
	s.mu.Lock()
	s.helloOK = ok
	s.helloAck.OK = ok
	s.helloAck.Error = errText
	if epoch != 0 {
		s.helloAck.Epoch = epoch
	}
	s.mu.Unlock()
}

func (s *fakeServer) setHeartbeatMS(ms int64) {
	s.mu.Lock()
	s.helloAck.Settings.HeartbeatMS = ms
	s.mu.Unlock()
}

func (s *fakeServer) QUICDial(ctx context.Context) (transport.Conn, error) {
	s.noteDial(transport.KindQUIC)
	s.mu.Lock()
	fn := s.quicFn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return s.newConn(transport.KindQUIC), nil
}

func (s *fakeServer) WSDial(ctx context.Context) (transport.Conn, error) {
	s.noteDial(transport.KindWS)
	s.mu.Lock()
	fn := s.wsFn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return s.newConn(transport.KindWS), nil
}

func (s *fakeServer) noteDial(kind transport.Kind) {
	s.mu.Lock()
	s.dialLog = append(s.dialLog, dialRecord{kind: kind, at: time.Now()})
	s.mu.Unlock()
}

func (s *fakeServer) dials() []dialRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dialRecord(nil), s.dialLog...)
}

func (s *fakeServer) newConn(kind transport.Kind) *fakeConn {
	c := newFakeConn(kind)
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
	go s.drive(c)
	return c
}

func (s *fakeServer) connsSnapshot() []*fakeConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*fakeConn(nil), s.conns...)
}

// lastAliveConn returns the most recent connection that the node has not closed.
func (s *fakeServer) lastAliveConn() *fakeConn {
	conns := s.connsSnapshot()
	for i := len(conns) - 1; i >= 0; i-- {
		select {
		case <-conns[i].closeCh:
			continue
		default:
			return conns[i]
		}
	}
	return nil
}

// drive answers HELLO and republishes node frames on the server channels.
func (s *fakeServer) drive(c *fakeConn) {
	for {
		select {
		case <-c.closeCh:
			return
		case <-s.closed:
			return
		case f := <-c.ctrl.events:
			switch f.typ {
			case protocol.FrameHello:
				var h protocol.Hello
				if err := protocol.Unmarshal(f.payload, &h); err != nil {
					s.t.Errorf("解析节点 HELLO 失败: %v", err)
					return
				}
				select {
				case s.helloCh <- h:
				default:
				}
				s.mu.Lock()
				ack := s.helloAck
				ok := s.helloOK
				onReady := s.onReady
				onHello := s.onHello
				ackMutate := s.ackMutate
				s.mu.Unlock()
				if onHello != nil {
					onHello(c, h)
				}
				ack.Ver = protocol.Version1
				ack.OK = ok
				if ackMutate != nil {
					ackMutate(&ack)
				}
				payload, err := protocol.Marshal(ack)
				if err != nil {
					s.t.Errorf("编码 HELLO_ACK 失败: %v", err)
					return
				}
				c.ctrl.pushSim(protocol.FrameHelloAck, payload)
				if ok && onReady != nil {
					go onReady(c, h)
				}
			case protocol.FramePong:
				select {
				case s.pongCh <- f.payload:
				default:
				}
			case protocol.FrameStats:
				var st protocol.Stats
				if err := protocol.Unmarshal(f.payload, &st); err == nil {
					select {
					case s.statsCh <- st:
					default:
					}
				}
			case protocol.FrameProbeRes:
				var pr protocol.ProbeResult
				if err := protocol.Unmarshal(f.payload, &pr); err == nil {
					select {
					case s.probeCh <- pr:
					default:
					}
				}
			}
		}
	}
}

// push sends a control frame to the most recent live connection.
func (s *fakeServer) push(typ protocol.FrameType, payload []byte) {
	c := s.lastAliveConn()
	if c == nil {
		s.t.Errorf("没有存活连接，无法下发帧 %s", typ)
		return
	}
	c.ctrl.pushSim(typ, payload)
}

func (s *fakeServer) pushJSON(typ protocol.FrameType, v any) {
	payload, err := protocol.Marshal(v)
	if err != nil {
		s.t.Fatalf("编码控制帧 %s 失败: %v", typ, err)
	}
	s.push(typ, payload)
}

// waitHello waits for the next HELLO.
func (s *fakeServer) waitHello(t *testing.T, timeout time.Duration) protocol.Hello {
	t.Helper()
	select {
	case h := <-s.helloCh:
		return h
	case <-time.After(timeout):
		t.Fatalf("等待 HELLO 超时")
		return protocol.Hello{}
	}
}

func (s *fakeServer) waitPong(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	select {
	case p := <-s.pongCh:
		return p
	case <-time.After(timeout):
		t.Fatalf("等待 PONG 超时")
		return nil
	}
}

func (s *fakeServer) waitStats(t *testing.T, timeout time.Duration) protocol.Stats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		select {
		case st := <-s.statsCh:
			return st
		case <-time.After(time.Until(deadline)):
			t.Fatalf("等待 STATS 超时")
			return protocol.Stats{}
		}
	}
}

func (s *fakeServer) waitProbeResult(t *testing.T, timeout time.Duration) protocol.ProbeResult {
	t.Helper()
	select {
	case pr := <-s.probeCh:
		return pr
	case <-time.After(timeout):
		t.Fatalf("等待 PROBE_RESULT 超时")
		return protocol.ProbeResult{}
	}
}

// ---------------------------------------------------------------------------
// agent test helpers
// ---------------------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testConfig() *config.ClientConfig {
	cfg := config.DefaultClientConfig()
	cfg.ServerURL = "https://127.0.0.1:443"
	cfg.Token = "test-token"
	cfg.ClientID = "test-node"
	cfg.Planes = 1
	cfg.Transport = model.TransportAuto
	cfg.QUICFallback = model.D(time.Second)
	cfg.Egress.ManualV4 = "203.0.113.9"
	cfg.Egress.ManualV6 = "2001:db8::9"
	return cfg
}

// fastHooks returns short but non flaky test timings. Individual tests override
// the entries they care about.
func fastHooks() *TestHooks {
	return &TestHooks{
		FallbackTimeout:     40 * time.Millisecond,
		HandshakeTimeout:    200 * time.Millisecond,
		HelloTimeout:        300 * time.Millisecond,
		HeartbeatInterval:   30 * time.Second,
		HeartbeatMissLimit:  3,
		DrainTimeout:        50 * time.Millisecond,
		WriteBlock:          500 * time.Millisecond,
		OpenDialTimeout:     300 * time.Millisecond,
		StatsInterval:       40 * time.Millisecond,
		ReProbeInterval:     10 * time.Second,
		BackoffBase:         60 * time.Millisecond,
		BackoffMax:          240 * time.Millisecond,
		ReconnectBase:       20 * time.Millisecond,
		QuicConfirmInterval: 20 * time.Millisecond,
		QuicRevertWindow:    10 * time.Second,
		ProbeTick:           10 * time.Millisecond,
		ReplacedWindow:      5 * time.Second,
		ReplacedLimit:       3,
		ReplacedCooldown:    200 * time.Millisecond,
		KickRetryDelay:      20 * time.Millisecond,
		EgressRefresh:       200 * time.Millisecond,
		EgressTimeout:       50 * time.Millisecond,
	}
}

type agentHarness struct {
	agent  *Agent
	cancel context.CancelFunc
	errCh  chan error
	doneCh chan struct{}
}

func startAgent(t *testing.T, srv *fakeServer, mutate func(*Options, *config.ClientConfig)) *agentHarness {
	t.Helper()
	cfg := testConfig()
	opts := Options{
		Config:    cfg,
		ClientID:  cfg.ClientID,
		Logger:    discardLogger(),
		Version:   "test-1.0",
		QUICDial:  srv.QUICDial,
		WSDial:    srv.WSDial,
		TestHooks: fastHooks(),
	}
	if mutate != nil {
		mutate(&opts, cfg)
	}
	a, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &agentHarness{agent: a, cancel: cancel, errCh: make(chan error, 1), doneCh: make(chan struct{})}
	go func() {
		err := a.Run(ctx)
		h.errCh <- err
		close(h.doneCh)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.doneCh:
		case <-time.After(5 * time.Second):
			t.Errorf("Run 未在超时内退出")
		}
		if err := a.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return h
}

func (h *agentHarness) waitErr(t *testing.T, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-h.errCh:
		return err
	case <-time.After(timeout):
		t.Fatalf("等待 Run 返回超时")
		return nil
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待条件超时: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// startEchoServer starts a TCP echo server and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		wg.Wait()
	})
	return ln.Addr().String()
}

// splitHostPort is a test convenience.
func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	var port int
	for _, r := range portStr {
		port = port*10 + int(r-'0')
	}
	return host, port
}

// openStreamFor builds a server initiated fake stream whose OPEN header points
// at host:port.
func openStreamFor(t *testing.T, host string, port int) *fakeStream {
	t.Helper()
	req := protocol.TargetToOpen(host, port, [protocol.TraceIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}, false)
	meta, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode OPEN: %v", err)
	}
	return newFakeStream(meta)
}
