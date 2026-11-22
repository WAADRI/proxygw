// Package tunnel implements the server side of the node tunnel: it accepts
// transport connections (QUIC and WebSocket planes), authenticates the HELLO
// registration, aggregates planes into registry nodes, dispatches OPEN requests
// and relays stream data.
//
// The session and stream lifecycles follow the state-machine design exactly:
// chapter 2 session FSM (implemented with internal/fsm), chapter 3 stream FSM,
// chapter 6 timeout table and chapter 7 error mapping. The circuit breaker
// counters live in internal/sched; this package only exposes the raw counters
// through metrics and the registry.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"proxygw/internal/clock"
	"proxygw/internal/fsm"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/nodesauth"
	"proxygw/internal/protocol"
	"proxygw/internal/registry"
	"proxygw/internal/transport"
	"proxygw/internal/version"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Fixed timeouts from the protocol design (state-machine chapter 6).
const (
	// DefaultHandshakeTimeout covers control stream acquisition and HELLO.
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultHelloTimeout is the time a connected peer has to send HELLO.
	DefaultHelloTimeout = 5 * time.Second
	// DefaultHeartbeatInterval is the keepalive PING interval.
	DefaultHeartbeatInterval = 15 * time.Second
	// DefaultHeartbeatLost is when a session with unanswered PINGs is removed.
	DefaultHeartbeatLost = 45 * time.Second
	// DefaultDrainTimeout is the graceful drain budget on KICK/shutdown.
	DefaultDrainTimeout = 10 * time.Second
	// DefaultTakeoverWindow is the debounce window for same-slot takeovers.
	DefaultTakeoverWindow = 60 * time.Second
	// DefaultTakeoverCooldown is the slot cooldown after too many takeovers.
	DefaultTakeoverCooldown = 10 * time.Minute
	// DefaultTakeoverLimit is the number of takeovers allowed inside the window.
	DefaultTakeoverLimit = 3
	// DefaultProbeTimeout is the default budget for PROBE and PING RTT.
	DefaultProbeTimeout = 10 * time.Second
	// DefaultPingTimeout is the default budget of PingNode.
	DefaultPingTimeout = 5 * time.Second
	// DefaultStreamCleanup is the fallback stream cleanup budget.
	DefaultStreamCleanup = 5 * time.Second
)

// ErrSessionClosed reports that the session carrying a stream went away.
var ErrSessionClosed = errors.New("tunnel: session closed")

// maxLiveSessions bounds concurrent tunnel sessions across all nodes. Without a
// bound an unauthenticated peer could keep half-open handshaking sessions open
// and exhaust goroutines/memory. Registered nodes are capped separately by the
// registry.
const maxLiveSessions = 4096

// ErrServerClosed reports that the tunnel server is shutting down.
var ErrServerClosed = errors.New("tunnel: server closed")

// ErrHeartbeatLost reports a session whose PINGs were not answered in time.
var ErrHeartbeatLost = errors.New("tunnel: heartbeat lost")

// Timeouts overrides the fixed timeout table. Zero values keep the defaults from
// the attachment. It exists so tests can compress the clock; production code
// must leave ServerOptions.Timeouts nil.
type Timeouts struct {
	Handshake        time.Duration
	Hello            time.Duration
	Heartbeat        time.Duration
	HeartbeatLost    time.Duration
	Drain            time.Duration
	TakeoverWindow   time.Duration
	TakeoverCooldown time.Duration
	TakeoverLimit    int
	Probe            time.Duration
	Ping             time.Duration
	Open             time.Duration // 0 = dynamic Settings().Timeouts.Open
	StreamCleanup    time.Duration
}

func defaultTimeouts() Timeouts {
	return Timeouts{
		Handshake:        DefaultHandshakeTimeout,
		Hello:            DefaultHelloTimeout,
		Heartbeat:        DefaultHeartbeatInterval,
		HeartbeatLost:    DefaultHeartbeatLost,
		Drain:            DefaultDrainTimeout,
		TakeoverWindow:   DefaultTakeoverWindow,
		TakeoverCooldown: DefaultTakeoverCooldown,
		TakeoverLimit:    DefaultTakeoverLimit,
		Probe:            DefaultProbeTimeout,
		Ping:             DefaultPingTimeout,
		StreamCleanup:    DefaultStreamCleanup,
	}
}

// withDefaults fills zero fields with the specification defaults.
func (t Timeouts) withDefaults() Timeouts {
	d := defaultTimeouts()
	if t.Handshake <= 0 {
		t.Handshake = d.Handshake
	}
	if t.Hello <= 0 {
		t.Hello = d.Hello
	}
	if t.Heartbeat <= 0 {
		t.Heartbeat = d.Heartbeat
	}
	if t.HeartbeatLost <= 0 {
		t.HeartbeatLost = d.HeartbeatLost
	}
	if t.Drain <= 0 {
		t.Drain = d.Drain
	}
	if t.TakeoverWindow <= 0 {
		t.TakeoverWindow = d.TakeoverWindow
	}
	if t.TakeoverCooldown <= 0 {
		t.TakeoverCooldown = d.TakeoverCooldown
	}
	if t.TakeoverLimit <= 0 {
		t.TakeoverLimit = d.TakeoverLimit
	}
	if t.Probe <= 0 {
		t.Probe = d.Probe
	}
	if t.Ping <= 0 {
		t.Ping = d.Ping
	}
	if t.StreamCleanup <= 0 {
		t.StreamCleanup = d.StreamCleanup
	}
	return t
}

// drainTimeout resolves the effective drain budget. The test override wins, then
// the hot-reloadable runtime settings, then the specification default.
func (t Timeouts) drainTimeout() time.Duration {
	if t.Drain > 0 && t.Drain != DefaultDrainTimeout {
		return t.Drain
	}
	return t.Drain
}

// openTimeout resolves the effective OPEN budget.
func (t Timeouts) openTimeout(st model.Settings) time.Duration {
	if t.Open > 0 {
		return t.Open
	}
	if d := st.Timeouts.Open.Std(); d > 0 {
		return d
	}
	return 10 * time.Second
}

// ServerOptions configures the tunnel server. Listeners and Registry are
// required; everything else has a safe default.
type ServerOptions struct {
	Logger       *slog.Logger
	QUICListener transport.Listener
	WSListener   transport.Listener
	Registry     *registry.Registry
	Auth         *nodesauth.Authenticator
	// Settings returns the hot-reloadable runtime settings. nil means
	// model.DefaultSettings().
	Settings func() model.Settings
	Metrics  *metrics.Metrics
	PinNext  string
	ALPN     string
	// MaxFrameBytes bounds a single control frame payload.
	MaxFrameBytes int
	Version       string
	// Timeouts is a test-only override of the fixed timeout table.
	Timeouts *Timeouts
}

type sessionKey struct {
	nodeID     string
	planeIndex int
}

func (k sessionKey) String() string { return k.nodeID + ":" + strconv.Itoa(k.planeIndex) }

// Server accepts node tunnel connections.
type Server struct {
	opts         ServerOptions
	logger       *slog.Logger
	times        Timeouts
	reg          *registry.Registry
	auth         *nodesauth.Authenticator
	settings     func() model.Settings
	metrics      *metrics.Metrics
	alpn         string
	version      string
	pinNext      atomic.Value // string; hot-updatable via SetPinNext
	audit        atomic.Value // func(string, map[string]string), optional
	maxFrame     int
	acceptCtx    context.Context
	acceptCancel context.CancelFunc

	closedCh     chan struct{}
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	serveOnce    sync.Once
	wg           sync.WaitGroup

	mu           sync.Mutex
	closing      bool
	sessions     map[sessionKey]*session // current owner per (node, plane)
	live         map[*session]struct{}   // every live session, including handshaking/draining
	takeovers    map[string][]time.Time
	cooldown     map[string]time.Time
	nodeErrs     map[string]string
	stateMu      sync.Mutex
	stateCounts  map[string]map[fsm.SessionState]int
	streamMu     sync.Mutex
	streams      map[uint64]*Stream
	nodeStreams  map[string]int
	activeStream atomic.Int64
	streamSeq    atomic.Uint64
	rr           atomic.Uint64
}

// NewServer validates opts and builds a server. At least one listener and a
// registry are required.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Registry == nil {
		return nil, errors.New("tunnel: ServerOptions.Registry is required")
	}
	if opts.QUICListener == nil && opts.WSListener == nil {
		return nil, errors.New("tunnel: at least one listener is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	settings := opts.Settings
	if settings == nil {
		settings = model.DefaultSettings
	}
	times := defaultTimeouts()
	if opts.Timeouts != nil {
		times = opts.Timeouts.withDefaults()
	}
	maxFrame := opts.MaxFrameBytes
	if maxFrame <= 0 {
		maxFrame = protocol.MaxFramePayload
	}
	if maxFrame > protocol.MaxFramePayload {
		maxFrame = protocol.MaxFramePayload
	}
	alpn := opts.ALPN
	if alpn == "" {
		alpn = protocol.ALPN
	}
	ver := opts.Version
	if ver == "" {
		ver = version.Version
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		opts:     opts,
		logger:   logger,
		times:    times,
		reg:      opts.Registry,
		auth:     opts.Auth,
		settings: settings,
		metrics:  opts.Metrics,
		alpn:     alpn,
		version:  ver,
		// pinNext is set below through SetPinNext so the panel can rotate it.
		maxFrame:     maxFrame,
		acceptCtx:    ctx,
		acceptCancel: cancel,
		closedCh:     make(chan struct{}),
		shutdownDone: make(chan struct{}),
		sessions:     make(map[sessionKey]*session),
		live:         make(map[*session]struct{}),
		takeovers:    make(map[string][]time.Time),
		cooldown:     make(map[string]time.Time),
		nodeErrs:     make(map[string]string),
		stateCounts:  make(map[string]map[fsm.SessionState]int),
		streams:      make(map[uint64]*Stream),
		nodeStreams:  make(map[string]int),
	}
	if opts.Auth == nil {
		logger.Warn("tunnel auth disabled: every node registration will be accepted")
	}
	s.pinNext.Store(strings.TrimSpace(opts.PinNext))
	logger.Info("tunnel server initialised",
		"alpn", alpn, "max_frame_bytes", maxFrame, "version", ver,
		"heartbeat", times.Heartbeat, "drain", times.Drain)
	return s, nil
}

// Serve starts the accept loops and blocks until ctx is cancelled or the server
// is closed. It always returns nil after a graceful shutdown.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.serveOnce.Do(func() {
		if ln := s.opts.QUICListener; ln != nil {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(ln)
			}()
		}
		if ln := s.opts.WSListener; ln != nil {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(ln)
			}()
		}
	})
	select {
	case <-ctx.Done():
	case <-s.closedCh:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.hardShutdownTimeout())
	defer cancel()
	_ = s.Close(shutdownCtx)
	return nil
}

func (s *Server) hardShutdownTimeout() time.Duration {
	d := s.drainTimeout() + 5*time.Second
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

func (s *Server) drainTimeout() time.Duration {
	if s.times.Drain > 0 && s.times.Drain != DefaultDrainTimeout {
		return s.times.Drain
	}
	if d := s.settings().Timeouts.Drain.Std(); d > 0 {
		return d
	}
	if s.times.Drain > 0 {
		return s.times.Drain
	}
	return DefaultDrainTimeout
}

func (s *Server) acceptLoop(ln transport.Listener) {
	kind := string(ln.Kind())
	s.logger.Info("tunnel accept loop started", "transport", kind)
	for {
		conn, err := ln.Accept(s.acceptCtx)
		if err != nil {
			if s.isClosing() || s.acceptCtx.Err() != nil || errors.Is(err, transport.ErrConnClosed) {
				return
			}
			s.logger.Warn("tunnel accept failed", "transport", kind, "error", err)
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-s.acceptCtx.Done():
				timer.Stop()
				return
			case <-s.closedCh:
				timer.Stop()
				return
			}
			continue
		}
		if conn == nil {
			continue
		}
		if s.isClosing() {
			_ = conn.CloseWithError(0, "server shutting down")
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

// Close stops accepting connections, kicks every session with a shutdown KICK,
// waits up to the drain budget for in-flight streams and then closes the
// transports. It is idempotent.
func (s *Server) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.shutdownOnce.Do(func() { s.shutdown(ctx) })
	return nil
}

func (s *Server) shutdown(ctx context.Context) {
	s.mu.Lock()
	if !s.closing {
		s.closing = true
	}
	live := make([]*session, 0, len(s.live))
	for sess := range s.live {
		live = append(live, sess)
	}
	s.sessions = make(map[sessionKey]*session)
	s.mu.Unlock()
	close(s.closedCh)
	s.acceptCancel()
	// NOTE: the listeners are intentionally NOT closed here. Closing a QUIC
	// listener tears down every established connection (quic-go) and closing the
	// WS listener closes the accepted websockets, which would destroy in-flight
	// streams before the drain window. Cancelling acceptCtx only stops accepting
	// new connections; established sessions keep draining.
	s.logger.Info("tunnel shutting down", "sessions", len(live), "active_streams", s.activeStream.Load())

	// KICK(shutdown): stop accepting new OPENs but let in-flight streams finish.
	for _, sess := range live {
		sess.beginDrain(protocol.KickShutdown, "server is shutting down")
	}
	// Wait for the in-flight streams to drain, bounded by the drain budget and
	// the caller context.
	deadline := time.NewTimer(s.drainTimeout())
	drainPoll := time.NewTicker(10 * time.Millisecond)
	defer func() {
		deadline.Stop()
		drainPoll.Stop()
	}()
wait:
	for {
		if s.activeStream.Load() <= 0 {
			break
		}
		select {
		case <-ctx.Done():
			break wait
		case <-deadline.C:
			break wait
		case <-drainPoll.C:
		}
	}
	// Force-close whatever is left, then wait for the goroutines to settle.
	for _, sess := range live {
		sess.shut(ErrServerClosed)
	}
	// Drain window elapsed: now close the listeners (this also tears down any
	// connection that somehow survived the session shutdown).
	for _, ln := range []transport.Listener{s.opts.QUICListener, s.opts.WSListener} {
		if ln == nil {
			continue
		}
		if err := ln.Close(); err != nil {
			s.logger.Warn("tunnel listener close failed", "transport", string(ln.Kind()), "error", err)
		}
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.logger.Warn("tunnel shutdown timed out waiting for goroutines")
	case <-time.After(2 * time.Second):
		s.logger.Warn("tunnel shutdown timed out waiting for goroutines")
	}
	for _, n := range s.reg.List() {
		s.reg.SetNodeOnline(n.ID, false)
	}
	s.logger.Info("tunnel server stopped")
	close(s.shutdownDone)
}

// WaitShutdown blocks until the internal shutdown sequence finished.
func (s *Server) WaitShutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) isClosing() bool {
	select {
	case <-s.closedCh:
		return true
	default:
		return false
	}
}

func (s *Server) handleConn(conn transport.Conn) {
	// A panic in one session goroutine must never take down the whole server.
	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Error("tunnel session panic recovered", "panic", fmt.Sprint(rec), "transport", string(conn.Kind()))
			_ = conn.CloseWithError(1, "internal panic")
		}
	}()
	sess := s.newSession(conn)
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "server shutting down")
		return
	}
	if len(s.live) >= maxLiveSessions {
		s.mu.Unlock()
		s.logger.Warn("tunnel connection limit reached, rejecting new session", "limit", maxLiveSessions, "transport", string(conn.Kind()))
		_ = conn.CloseWithError(1, "too many sessions")
		return
	}
	s.live[sess] = struct{}{}
	s.mu.Unlock()
	s.logger.Debug("tunnel connection accepted",
		"session_id", sess.id, "node_id", "", "transport", string(conn.Kind()), "remote", addrString(conn.RemoteAddr()))
	// The node must never initiate data streams: the control stream is opened by
	// the node, every data stream is server initiated. Consume and reject peer
	// initiated streams so an abusive node cannot fill the accept queue, and
	// record a security log describing the phase in which it happened.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.rejectPeerStreams(sess)
	}()
	defer func() {
		sess.teardown()
		s.mu.Lock()
		delete(s.live, sess)
		s.mu.Unlock()
	}()
	if err := sess.handshake(); err != nil {
		s.logger.Warn("tunnel session handshake failed",
			"session_id", sess.id, "node_id", sess.node(), "transport", string(conn.Kind()), "error", err)
		s.setNodeError(sess.node(), err.Error())
		if sess.epoch.Load() > 0 {
			s.countReconnect(sess.node(), "handshake_failed")
		} else {
			// Never label metrics with a node id that was not authenticated.
			s.countReconnectLabel("unauthenticated", "handshake_failed")
		}
		return
	}
	s.startHeartbeat(sess)
	sess.readyLoop()
}

func (s *Server) newSession(conn transport.Conn) *session {
	sess := &session{
		srv:       s,
		conn:      conn,
		transport: string(conn.Kind()),
		createdAt: time.Now(),
		pings:     make(map[uint64]*pingEntry),
		probes:    make(map[string]chan *protocol.ProbeResult),
		streams:   make(map[uint64]*Stream),
		closedCh:  make(chan struct{}),
		draining:  atomic.Bool{},
		clock:     clock.NewDetector(32, 30*time.Second),
	}
	sess.id = sess.transport + "-" + randomHex(8)
	sess.ctx, sess.cancel = context.WithCancel(context.Background())
	sess.fsm = fsm.NewSessionFSM(fsm.SessionHandshaking, sess.onStateChange)
	return sess
}

// nodeLiveCount counts live sessions whose state still accepts new streams.
func (s *Server) nodeLiveCount(nodeID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for sess := range s.live {
		if sess.node() != nodeID {
			continue
		}
		st := sess.state()
		if st.CanHoldNewStreams() {
			n++
		}
	}
	return n
}

func (s *Server) settingsSnapshot() model.Settings {
	st := s.settings()
	if st.Limits.MaxStreamsPerNode <= 0 {
		st.Limits.MaxStreamsPerNode = 1000
	}
	if st.Timeouts.Open <= 0 {
		st.Timeouts.Open = model.D(10 * time.Second)
	}
	if st.Timeouts.Drain <= 0 {
		st.Timeouts.Drain = model.D(10 * time.Second)
	}
	return st
}

// maxNodeErrors bounds the node error map so unauthenticated peers cannot grow
// it without limit by probing random (format-valid) client ids.
const maxNodeErrors = 1024

// setNodeError records the last node level error for the panel.
func (s *Server) setNodeError(nodeID, msg string) {
	if nodeID == "" {
		return
	}
	s.mu.Lock()
	if msg == "" {
		delete(s.nodeErrs, nodeID)
	} else {
		if _, exists := s.nodeErrs[nodeID]; !exists && len(s.nodeErrs) >= maxNodeErrors {
			s.mu.Unlock()
			return
		}
		s.nodeErrs[nodeID] = msg
	}
	s.mu.Unlock()
}

func (s *Server) nodeLabel(nodeID string) string {
	if s.metrics == nil {
		return nodeID
	}
	return s.metrics.NodeLabel(nodeID)
}

func (s *Server) countReconnect(nodeID, reason string) {
	if s.metrics == nil || nodeID == "" {
		return
	}
	s.metrics.TunnelReconnects.WithLabelValues(s.nodeLabel(nodeID), reason).Inc()
}

// countReconnectLabel increments the reconnect counter with an explicit label
// value. It is used for unauthenticated failures so attacker supplied node ids
// never become metric labels.
func (s *Server) countReconnectLabel(label, reason string) {
	if s.metrics == nil {
		return
	}
	if label == "" {
		label = "none"
	}
	s.metrics.TunnelReconnects.WithLabelValues(label, reason).Inc()
}

func (s *Server) countTakeover(nodeID, result string) {
	if s.metrics == nil || nodeID == "" {
		return
	}
	s.metrics.SessionTakeovers.WithLabelValues(s.nodeLabel(nodeID), result).Inc()
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// noteSessionState updates the per-node session state counters and metrics.
func (s *Server) noteSessionState(nodeID string, from, to fsm.SessionState) {
	if nodeID == "" {
		return
	}
	label := s.nodeLabel(nodeID)
	s.stateMu.Lock()
	counts := s.stateCounts[nodeID]
	if counts == nil {
		counts = make(map[fsm.SessionState]int)
		s.stateCounts[nodeID] = counts
	}
	fromCount := 0
	if from != "" {
		if counts[from] > 0 {
			counts[from]--
		}
		fromCount = counts[from]
	}
	counts[to]++
	toCount := counts[to]
	ready := counts[fsm.SessionReady] + counts[fsm.SessionDegraded]
	s.stateMu.Unlock()
	if s.metrics == nil {
		return
	}
	if from != "" {
		s.metrics.TunnelSessionState.WithLabelValues(label, string(from)).Set(float64(fromCount))
	}
	s.metrics.TunnelSessionState.WithLabelValues(label, string(to)).Set(float64(toCount))
	s.metrics.TunnelPlanes.WithLabelValues(label).Set(float64(ready))
}

// recordSessionRemoved subtracts the final state of a session from the gauges.
func (s *Server) recordSessionRemoved(nodeID string, st fsm.SessionState) {
	if nodeID == "" {
		return
	}
	label := s.nodeLabel(nodeID)
	s.stateMu.Lock()
	counts := s.stateCounts[nodeID]
	if counts == nil {
		counts = make(map[fsm.SessionState]int)
		s.stateCounts[nodeID] = counts
	}
	if counts[st] > 0 {
		counts[st]--
	}
	remaining := counts[st]
	ready := counts[fsm.SessionReady] + counts[fsm.SessionDegraded]
	empty := true
	for _, c := range counts {
		if c > 0 {
			empty = false
			break
		}
	}
	if empty {
		delete(s.stateCounts, nodeID)
	}
	s.stateMu.Unlock()
	if s.metrics == nil {
		return
	}
	s.metrics.TunnelSessionState.WithLabelValues(label, string(st)).Set(float64(remaining))
	s.metrics.TunnelPlanes.WithLabelValues(label).Set(float64(ready))
}

// SetAudit installs the optional audit hook. It may be called after NewServer so
// the application can share one audit store between the tunnel, proxy and panel.
func (s *Server) SetAudit(fn func(action string, detail map[string]string)) {
	if fn == nil {
		s.audit.Store((func(string, map[string]string))(nil))
		return
	}
	s.audit.Store(fn)
}

// auditEvent publishes one security relevant tunnel event (auth failures,
// protocol violations, takeover throttling) to the audit trail.
func (s *Server) auditEvent(action string, detail map[string]string) {
	fn, _ := s.audit.Load().(func(string, map[string]string))
	if fn == nil {
		return
	}
	if detail == nil {
		detail = map[string]string{}
	}
	fn(action, detail)
}
