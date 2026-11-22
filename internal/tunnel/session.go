package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/clock"
	"proxygw/internal/fsm"
	"proxygw/internal/protocol"
	"proxygw/internal/registry"
	"proxygw/internal/transport"
)

// Session close reasons used in structured logs.
const (
	reasonReplaced  = "session_replaced"
	reasonDrain     = "drain"
	reasonShutdown  = "shutdown"
	reasonHeartbeat = "heartbeat_lost"
	reasonTransport = "transport_error"
	reasonProtocol  = "protocol_error"
	reasonAuth      = "authentication_failed"
)

// ErrDrainComplete marks a session that closed after finishing its drain.
var ErrDrainComplete = errors.New("tunnel: session drained")

// pingEntry tracks one outstanding PING. Heartbeat PINGs feed liveness checks,
// explicit PingNode PINGs carry a result channel.
type pingEntry struct {
	sentAt    time.Time
	heartbeat bool
	rttCh     chan time.Duration
}

// session is one transport connection, i.e. one plane of a node.
type session struct {
	srv       *Server
	conn      transport.Conn
	ctrlMu    sync.RWMutex
	ctrl      transport.ControlStream
	transport string

	id        string
	nodeID    atomic.Value // string
	plane     atomic.Int64
	epoch     atomic.Uint32
	fsm       *fsm.SessionFSM
	ctx       context.Context
	cancel    context.CancelFunc
	createdAt time.Time
	readyAt   time.Time

	replaced       atomic.Bool
	draining       atomic.Bool
	compressAgreed atomic.Bool
	// clock tracks the node clock offset (local - remote) sampled from HELLO
	// and STATS timestamps. It is observation only; the server never adjusts
	// its own clock.
	clock        *clock.Detector
	teardownOnce sync.Once
	shutOnce     sync.Once
	drainOnce    sync.Once
	sendMu       sync.Mutex
	streamsMu    sync.Mutex
	streams      map[uint64]*Stream

	mu       sync.Mutex
	pings    map[uint64]*pingEntry
	probes   map[string]chan *protocol.ProbeResult
	lastPong time.Time
	closeErr error

	closedCh chan struct{}
}

func (sess *session) node() string {
	v, _ := sess.nodeID.Load().(string)
	return v
}

func (sess *session) planeIndex() int { return int(sess.plane.Load()) }

func (sess *session) setNode(nodeID string, plane int) {
	sess.nodeID.Store(nodeID)
	sess.plane.Store(int64(plane))
}

func (sess *session) key() sessionKey {
	return sessionKey{nodeID: sess.node(), planeIndex: sess.planeIndex()}
}

func (sess *session) state() fsm.SessionState { return sess.fsm.State() }

func (sess *session) closed() bool {
	select {
	case <-sess.closedCh:
		return true
	default:
		return false
	}
}

func (sess *session) isDraining() bool { return sess.draining.Load() }

func (sess *session) logger() *slog.Logger {
	return sess.srv.logger.With(
		"session_id", sess.id,
		"node_id", sess.node(),
		"plane_index", sess.planeIndex(),
		"epoch", sess.epoch.Load(),
		"transport", sess.transport,
	)
}

func (sess *session) closeError() error {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closeErr == nil {
		return ErrSessionClosed
	}
	return sess.closeErr
}

// onStateChange runs inside the fsm lock: it must only do bookkeeping and must
// not call back into the fsm.
func (sess *session) onStateChange(from, to fsm.SessionState, event fsm.SessionEvent) {
	duration := time.Since(sess.createdAt)
	fields := []any{
		"event", "session_state",
		"transition", string(event),
		"session_id", sess.id,
		"node_id", sess.node(),
		"plane_index", sess.planeIndex(),
		"epoch", sess.epoch.Load(),
		"from", string(from),
		"to", string(to),
		"duration_ms", duration.Milliseconds(),
	}
	level := slog.LevelInfo
	if to == fsm.SessionClosed {
		level = slog.LevelWarn
	}
	sess.srv.logger.Log(context.Background(), level, "session state transition", fields...)
	// Session state metrics are only tracked for registered sessions. This keeps
	// the label cardinality bounded: unauthenticated peers must not be able to
	// create metric series with arbitrary node ids.
	if sess.epoch.Load() > 0 {
		sess.srv.noteSessionState(sess.node(), from, to)
	}
}

// setControl publishes the control stream acquired during handshake. It is
// synchronized because shutdown/drain paths may send a KICK while a connection
// is still handshaking (and therefore before this assignment happens).
func (sess *session) setControl(ctrl transport.ControlStream) {
	sess.ctrlMu.Lock()
	sess.ctrl = ctrl
	sess.ctrlMu.Unlock()
}

// control returns the control stream, if the handshake has acquired it yet.
func (sess *session) control() transport.ControlStream {
	sess.ctrlMu.RLock()
	defer sess.ctrlMu.RUnlock()
	return sess.ctrl
}

// sendFrame serializes writes on the control stream. The transport is expected
// to serialize writes as well; the mutex additionally protects fake transports
// and keeps PONG/PING ordering sane.
func (sess *session) sendFrame(typ protocol.FrameType, payload []byte) error {
	ctrl := sess.control()
	if ctrl == nil {
		return errors.New("tunnel: no control stream")
	}
	timeout := sess.srv.times.Ping
	if timeout <= 0 {
		timeout = DefaultPingTimeout
	}
	ctx, cancel := context.WithTimeout(sess.ctx, timeout)
	defer cancel()
	sess.sendMu.Lock()
	defer sess.sendMu.Unlock()
	return ctrl.Send(ctx, typ, payload)
}

func (sess *session) sendJSON(typ protocol.FrameType, v any) error {
	payload, err := protocol.Marshal(v)
	if err != nil {
		return err
	}
	return sess.sendFrame(typ, payload)
}

func (sess *session) sendHelloAck(ack protocol.HelloAck) error {
	return sess.sendJSON(protocol.FrameHelloAck, ack)
}

// rejectHello answers a failed registration with an explicit reason and returns
// an error carrying the same text.
func (sess *session) rejectHello(msg string) error {
	ack := protocol.HelloAck{
		Ver:        protocol.Version1,
		OK:         false,
		Error:      msg,
		Transport:  string(sess.conn.Kind()),
		ServerTime: protocol.NowMillis(),
	}
	if err := sess.sendHelloAck(ack); err != nil {
		sess.srv.logger.Warn("failed to send HELLO_ACK rejection",
			"session_id", sess.id, "transport", string(sess.conn.Kind()), "error", err)
	} else {
		// Give the peer a moment to read the rejection before the transport is
		// torn down. Otherwise a node with a bad token/version sees only a
		// closed connection and keeps retrying instead of failing fast with the
		// documented fatal error (auth failure / unsupported version).
		grace := time.NewTimer(helloRejectGrace)
		select {
		case <-grace.C:
		case <-sess.ctx.Done():
		case <-sess.closedCh:
		}
		grace.Stop()
	}
	return errors.New(msg)
}

// handshake performs transport control stream acquisition, HELLO validation,
// authentication and registration.
func (sess *session) handshake() error {
	s := sess.srv
	handshakeCtx, cancel := context.WithTimeout(sess.ctx, s.times.Handshake)
	ctrl, err := sess.conn.Control(handshakeCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("control stream: %w", err)
	}
	sess.setControl(ctrl)

	helloCtx, hcancel := context.WithTimeout(sess.ctx, s.times.Hello)
	typ, payload, err := ctrl.Recv(helloCtx)
	hcancel()
	if err != nil {
		return fmt.Errorf("HELLO timeout: %w", err)
	}
	if typ != protocol.FrameHello {
		// Registration-before-data rule: nothing but HELLO is allowed here.
		s.logger.Warn("security: control frame before registration",
			"session_id", sess.id, "frame", typ.String(), "transport", sess.transport,
			"remote", addrString(sess.conn.RemoteAddr()))
		return fmt.Errorf("unexpected %s frame before HELLO", typ)
	}
	if len(payload) > s.maxFrame {
		return fmt.Errorf("HELLO frame too large: %d > %d", len(payload), s.maxFrame)
	}
	var hello protocol.Hello
	if err := protocol.Unmarshal(payload, &hello); err != nil {
		return fmt.Errorf("decode HELLO: %w", err)
	}
	nodeID := strings.TrimSpace(hello.ClientID)
	sess.setNode(nodeID, hello.PlaneIndex)
	// Keep the session id unique (transport + random suffix); node_id and
	// plane_index are separate log fields, so two connections can never share
	// an id in logs or metrics.
	// Clock offset observation (HELLO timestamp is unix milliseconds).
	sess.clock.Sample(hello.TS, time.Now())
	if hello.Ver != protocol.Version1 {
		msg := fmt.Sprintf("unsupported protocol version %d (server speaks %d)", hello.Ver, protocol.Version1)
		s.logger.Warn("security: incompatible protocol version",
			"session_id", sess.id, "transport", sess.transport, "client", hello.Ver)
		s.auditEvent("node.version_mismatch", map[string]string{
			"node_id": nodeID, "transport": sess.transport, "client_version": fmt.Sprint(hello.Ver),
		})
		return sess.rejectHello(msg)
	}
	if !validClientID(nodeID) {
		s.logger.Warn("security: invalid client_id",
			"session_id", sess.id, "transport", sess.transport, "len", len(nodeID))
		return sess.rejectHello("invalid client_id")
	}
	if hello.PlaneIndex < 0 || hello.PlaneIndex > 31 {
		return sess.rejectHello(fmt.Sprintf("invalid plane_index %d", hello.PlaneIndex))
	}
	if s.auth != nil {
		if err := s.auth.AuthenticateWithMTLS(nodeID, hello.Token, s.auth.MTLSEnabled()); err != nil {
			s.logger.Warn("security: node authentication failed",
				"session_id", sess.id, "node_id", nodeID, "transport", sess.transport,
				"remote", addrString(sess.conn.RemoteAddr()), "error", err)
			s.countReconnectLabel("unauthenticated", reasonAuth)
			s.auditEvent("node.auth_failed", map[string]string{
				"node_id":   nodeID,
				"transport": sess.transport,
				"remote":    addrString(sess.conn.RemoteAddr()),
				"reason":    "authentication failed",
			})
			return sess.rejectHello("authentication failed")
		}
	}
	// Compression must be negotiated before the registry snapshot is built, so
	// node.Compression is correct the moment the plane attaches.
	agreed := s.compressionAgreed(&hello)
	sess.compressAgreed.Store(agreed)
	epoch, err := sess.register(&hello)
	if err != nil {
		return err
	}
	sess.epoch.Store(epoch)
	if setter, ok := sess.conn.(transport.EpochSetter); ok {
		setter.SetEpoch(epoch)
	}
	ack := protocol.HelloAck{
		Ver:        protocol.Version1,
		OK:         true,
		Epoch:      epoch,
		Transport:  string(sess.conn.Kind()),
		Settings:   sess.helloSettings(agreed),
		PinNext:    s.currentPinNext(),
		ServerTime: protocol.NowMillis(),
	}
	if err := sess.sendHelloAck(ack); err != nil {
		return fmt.Errorf("send HELLO_ACK: %w", err)
	}
	if _, err := sess.fsm.Fire(fsm.SessEvHelloOK); err != nil {
		return fmt.Errorf("session fsm: %w", err)
	}
	sess.readyAt = time.Now()
	s.setNodeError(nodeID, "")
	reason := "connect"
	if epoch > 1 {
		reason = "reconnect"
	}
	s.countReconnect(nodeID, reason)
	sess.logger().Info("session ready",
		"event", "session_ready", "duration_ms", time.Since(sess.createdAt).Milliseconds())
	// Send the first PING immediately: the liveness check then has a baseline
	// and a healthy node is never flagged as degraded by tick alignment.
	if err := sess.sendHeartbeatPing(); err != nil {
		return fmt.Errorf("send initial PING: %w", err)
	}
	return nil
}

// register claims the (nodeID, planeIndex) slot, applying takeover debounce and
// attaching the plane to the registry. On rejection it has already sent
// HELLO_ACK(ok=false) with a clear error text.
func (sess *session) register(hello *protocol.Hello) (uint32, error) {
	s := sess.srv
	nodeID := sess.node()
	key := sess.key()
	now := time.Now()

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return 0, ErrServerClosed
	}
	if until, ok := s.cooldown[nodeID]; ok {
		if now.Before(until) {
			s.mu.Unlock()
			msg := fmt.Sprintf("takeover cooldown: slot %s is cooling down until %s", key.String(), until.UTC().Format(time.RFC3339))
			s.logger.Warn("security: takeover cooldown rejection",
				"session_id", sess.id, "node_id", nodeID, "plane_index", key.planeIndex,
				"cooldown_until", until, "remote", addrString(sess.conn.RemoteAddr()))
			s.countTakeover(nodeID, "cooldown_rejected")
			s.countReconnect(nodeID, "takeover_cooldown")
			s.setNodeError(nodeID, msg)
			_ = sess.rejectHello(msg)
			return 0, errors.New(msg)
		}
		delete(s.cooldown, nodeID)
	}
	old := s.sessions[key]
	takeover := false
	if old != nil && old != sess {
		hist := pruneHistory(s.takeovers[nodeID], now.Add(-s.times.TakeoverWindow))
		if old.canTakeoverFrom() {
			if len(hist) >= s.times.TakeoverLimit {
				delete(s.takeovers, nodeID)
				s.cooldown[nodeID] = now.Add(s.times.TakeoverCooldown)
				s.mu.Unlock()
				msg := fmt.Sprintf("takeover cooldown: node %q plane %d was taken over too often within %s, retry after %s",
					nodeID, key.planeIndex, s.times.TakeoverWindow, s.times.TakeoverCooldown)
				s.logger.Warn("security: takeover flapping detected",
					"session_id", sess.id, "node_id", nodeID, "plane_index", key.planeIndex,
					"takeovers", len(hist), "window", s.times.TakeoverWindow,
					"cooldown", s.times.TakeoverCooldown, "remote", addrString(sess.conn.RemoteAddr()))
				s.countTakeover(nodeID, "cooldown_rejected")
				s.countReconnect(nodeID, "takeover_cooldown")
				s.setNodeError(nodeID, msg)
				_ = sess.rejectHello(msg)
				return 0, errors.New(msg)
			}
			hist = append(hist, now)
			s.takeovers[nodeID] = hist
			takeover = true
		}
		delete(s.sessions, key)
		old.replaced.Store(true)
	}
	s.sessions[key] = sess
	s.mu.Unlock()

	_, epoch, err := s.reg.AttachPlane(registry.PlaneMeta{
		NodeID:       nodeID,
		PlaneIndex:   key.planeIndex,
		Alias:        hello.Alias,
		Tags:         append([]string(nil), hello.Tags...),
		Region:       hello.Region,
		ISPLabel:     hello.ISPLabel,
		Weight:       hello.Weight,
		Version:      hello.Version,
		Transport:    sess.transport,
		EgressV4:     hello.EgressV4,
		EgressV6:     hello.EgressV6,
		Capabilities: append([]string(nil), hello.Capabilities...),
		Compression:  sess.compressAgreed.Load(),
	})
	if err != nil {
		s.mu.Lock()
		if s.sessions[key] == sess {
			delete(s.sessions, key)
		}
		s.mu.Unlock()
		return 0, fmt.Errorf("register plane: %w", err)
	}
	if takeover {
		s.countTakeover(nodeID, "replaced")
		sess.logger().Info("session takeover",
			"event", "session_takeover", "takeovers_in_window", len(s.takeovers[nodeID]),
			"window", s.times.TakeoverWindow)
		old.beginDrain(protocol.KickReplaced, "session replaced by a newer connection")
	} else if old != nil {
		// Stale non-ready session for the same slot; close it without counting a
		// takeover because no streams can have been opened on it.
		old.shut(fmt.Errorf("tunnel: replaced by newer connection for slot %s", key.String()))
	}
	return epoch, nil
}

// validClientID enforces the documented client_id format: 1..128 bytes from a
// safe ASCII subset. It is a format check, not an authentication check.
func validClientID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == ':':
		default:
			return false
		}
	}
	return true
}

func pruneHistory(hist []time.Time, cutoff time.Time) []time.Time {
	out := hist[:0]
	for _, t := range hist {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// canTakeoverFrom reports whether replacing old loses live streams and must be
// counted against the takeover debounce budget.
func (sess *session) canTakeoverFrom() bool {
	st := sess.state()
	return st == fsm.SessionReady || st == fsm.SessionDegraded
}

// helloSettings builds the session specific HELLO_ACK policy: compression is
// only advertised when both sides agreed on it.
func (sess *session) helloSettings(compressionAgreed bool) protocol.HelloSettings {
	st := sess.srv.helloSettings()
	st.Compression = compressionAgreed
	return st
}

// helloSettings builds the runtime policy returned in HELLO_ACK.
func (s *Server) helloSettings() protocol.HelloSettings {
	st := s.settingsSnapshot()
	return protocol.HelloSettings{
		MaxStreams:    st.Limits.MaxStreamsPerNode,
		MaxFrameBytes: s.maxFrame,
		Compression:   st.Compression,
		HeartbeatMS:   s.times.Heartbeat.Milliseconds(),
	}
}

// compressionAgreed reports whether zstd compression was negotiated for this
// node: the server setting, the node opt-in and the zstd capability must all
// be present. Without this intersection the server would mark streams as
// compressed towards a node that cannot decode them.
func (s *Server) compressionAgreed(hello *protocol.Hello) bool {
	if hello == nil {
		return false
	}
	if !s.settingsSnapshot().Compression {
		return false
	}
	if !hello.Compression {
		return false
	}
	for _, cap := range hello.Capabilities {
		if cap == protocol.CapZstd {
			return true
		}
	}
	return false
}

// readyLoop reads and dispatches control frames until the session dies.
func (sess *session) readyLoop() {
	s := sess.srv
	ctrl := sess.control()
	if ctrl == nil {
		return
	}
	for {
		typ, payload, err := ctrl.Recv(sess.ctx)
		if err != nil {
			if sess.isDraining() || s.isClosing() {
				return
			}
			sess.shut(fmt.Errorf("control stream read: %w", err))
			return
		}
		if len(payload) > s.maxFrame {
			sess.protocolError(fmt.Errorf("control frame %s payload %d exceeds limit %d", typ, len(payload), s.maxFrame))
			return
		}
		if err := sess.handleControlFrame(typ, payload); err != nil {
			sess.protocolError(err)
			return
		}
		if sess.closed() {
			return
		}
	}
}

func (sess *session) protocolError(err error) {
	sess.srv.logger.Warn("security: tunnel protocol error",
		"session_id", sess.id, "node_id", sess.node(), "epoch", sess.epoch.Load(), "error", err)
	sess.srv.countReconnect(sess.node(), reasonProtocol)
	sess.shut(err)
}

func (sess *session) handleControlFrame(typ protocol.FrameType, payload []byte) error {
	switch typ {
	case protocol.FrameStats:
		var st protocol.Stats
		if err := protocol.Unmarshal(payload, &st); err != nil {
			return fmt.Errorf("decode STATS: %w", err)
		}
		sess.clock.Sample(st.TS, time.Now())
		sess.srv.reg.UpdateStats(sess.node(), st)
		return nil
	case protocol.FramePong:
		sess.handlePong(payload)
		return nil
	case protocol.FramePing:
		// Nodes may probe the server as well; echo the payload unchanged.
		return sess.sendFrame(protocol.FramePong, append([]byte(nil), payload...))
	case protocol.FrameProbeRes:
		var res protocol.ProbeResult
		if err := protocol.Unmarshal(payload, &res); err != nil {
			return fmt.Errorf("decode PROBE_RESULT: %w", err)
		}
		sess.deliverProbe(&res)
		return nil
	default:
		return fmt.Errorf("unexpected %s frame on control stream", typ)
	}
}

// sendHeartbeatPing sends one PING with an 8 byte nonce and records it.
func (sess *session) sendHeartbeatPing() error {
	nonce := randNonce()
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, nonce)
	sess.mu.Lock()
	sess.pings[nonce] = &pingEntry{sentAt: time.Now(), heartbeat: true}
	sess.mu.Unlock()
	if err := sess.sendFrame(protocol.FramePing, payload); err != nil {
		sess.removePing(nonce)
		return err
	}
	return nil
}

func (sess *session) removePing(nonce uint64) {
	sess.mu.Lock()
	delete(sess.pings, nonce)
	sess.mu.Unlock()
}

func (sess *session) handlePong(payload []byte) {
	now := time.Now()
	var matched *pingEntry
	sess.mu.Lock()
	if len(payload) >= 8 {
		nonce := binary.BigEndian.Uint64(payload[:8])
		if p, ok := sess.pings[nonce]; ok {
			delete(sess.pings, nonce)
			matched = p
		}
	}
	if matched == nil && len(sess.pings) > 0 {
		// Tolerate peers that do not echo the nonce: clear the oldest pending PING.
		var oldestNonce uint64
		var oldest *pingEntry
		for nonce, p := range sess.pings {
			if oldest == nil || p.sentAt.Before(oldest.sentAt) {
				oldest = p
				oldestNonce = nonce
			}
		}
		if oldest != nil {
			delete(sess.pings, oldestNonce)
			matched = oldest
		}
	}
	sess.lastPong = now
	sess.mu.Unlock()
	if matched != nil && matched.rttCh != nil {
		select {
		case matched.rttCh <- now.Sub(matched.sentAt):
		default:
		}
	}
	if sess.state() == fsm.SessionDegraded {
		if _, err := sess.fsm.Fire(fsm.SessEvHeartbeatOK); err == nil {
			sess.logger().Info("session recovered", "event", "heartbeat_ok")
		}
	}
}

// startHeartbeat launches the per-session keepalive loop.
func (s *Server) startHeartbeat(sess *session) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		sess.heartbeatLoop()
	}()
}

func (sess *session) heartbeatLoop() {
	interval := sess.srv.times.Heartbeat
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-sess.closedCh:
			return
		case <-sess.ctx.Done():
			return
		case <-ticker.C:
			if sess.isDraining() {
				return
			}
			if err := sess.sendHeartbeatPing(); err != nil {
				sess.shut(fmt.Errorf("heartbeat PING: %w", err))
				return
			}
			sess.evaluateHeartbeat()
			if sess.closed() {
				return
			}
		}
	}
}

// evaluateHeartbeat turns unanswered PINGs into the degraded and closed session
// transitions required by chapter 2 of the attachment.
func (sess *session) evaluateHeartbeat() {
	s := sess.srv
	now := time.Now()
	sess.mu.Lock()
	var oldest time.Time
	for _, p := range sess.pings {
		if !p.heartbeat {
			continue
		}
		if oldest.IsZero() || p.sentAt.Before(oldest) {
			oldest = p.sentAt
		}
	}
	sess.mu.Unlock()
	if oldest.IsZero() {
		return
	}
	age := now.Sub(oldest)
	if age >= s.times.HeartbeatLost {
		sess.logger().Warn("session heartbeat lost",
			"event", "heartbeat_lost", "age", age.String())
		s.countReconnect(sess.node(), reasonHeartbeat)
		sess.shut(fmt.Errorf("%w after %s", ErrHeartbeatLost, age))
		return
	}
	if age >= s.times.Heartbeat {
		if sess.state() == fsm.SessionReady {
			if _, err := sess.fsm.Fire(fsm.SessEvHeartbeatMiss); err == nil {
				sess.logger().Warn("session degraded",
					"event", "heartbeat_miss", "age", age.String())
				s.countReconnect(sess.node(), "heartbeat_miss")
			}
		}
		return
	}
	if sess.state() == fsm.SessionDegraded {
		if _, err := sess.fsm.Fire(fsm.SessEvHeartbeatOK); err == nil {
			sess.logger().Info("session recovered", "event", "heartbeat_ok", "age", age.String())
		}
	}
}

// beginDrain sends KICK and lets in-flight streams finish before closing the
// transport. It is executed at most once per session.
func (sess *session) beginDrain(reason, message string) {
	sess.drainOnce.Do(func() {
		s := sess.srv
		sess.draining.Store(true)
		st := sess.state()
		if st == fsm.SessionReady || st == fsm.SessionDegraded {
			_, _ = sess.fsm.Fire(fsm.SessEvKick)
		}
		sess.logger().Info("session draining",
			"event", "session_drain", "reason", reason, "message", message)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			kick := protocol.Kick{Reason: reason, Message: message}
			if err := sess.sendJSON(protocol.FrameKick, kick); err != nil {
				if !sess.closed() {
					// A node that cannot receive KICK would keep opening streams
					// against a session we already stopped scheduling, so close the
					// transport instead of waiting for the drain budget.
					s.logger.Warn("failed to send KICK, closing session",
						"session_id", sess.id, "node_id", sess.node(), "reason", reason, "error", err)
					sess.shut(fmt.Errorf("tunnel: send KICK(%s): %w", reason, err))
				}
				return
			}
			// Give the peer a moment to consume the KICK control frame before the
			// transport is closed. Without this grace period a kick with no active
			// streams closes the session immediately after queueing KICK, and the
			// node can observe only "session drained"/connection error, entering
			// the generic 1-minute reconnect backoff instead of the intended 1s
			// KICK retry.
			if sess.activeStreamCount() == 0 {
				grace := time.NewTimer(kickDeliveryGrace)
				select {
				case <-grace.C:
				case <-sess.closedCh:
				case <-sess.ctx.Done():
				}
				grace.Stop()
			}
			drain := s.drainTimeout()
			timer := time.NewTimer(drain)
			poll := time.NewTicker(5 * time.Millisecond)
			defer func() {
				timer.Stop()
				poll.Stop()
			}()
			deadlineHit := false
		wait:
			for {
				if sess.activeStreamCount() == 0 {
					break
				}
				select {
				case <-sess.closedCh:
					return
				case <-sess.ctx.Done():
					return
				case <-timer.C:
					deadlineHit = true
					break wait
				case <-poll.C:
				}
			}
			if deadlineHit && sess.activeStreamCount() > 0 {
				s.logger.Warn("session drain timeout",
					"session_id", sess.id, "node_id", sess.node(), "reason", reason,
					"active_streams", sess.activeStreamCount(), "drain", drain)
			}
			sess.shut(ErrDrainComplete)
		}()
	})
}

// shut releases the transport exactly once. A graceful close uses transport
// error code 0.
func (sess *session) shut(reason error) {
	sess.shutOnce.Do(func() {
		sess.mu.Lock()
		sess.closeErr = reason
		sess.mu.Unlock()
		code := uint64(0)
		reasonText := "closed"
		if reason != nil {
			reasonText = reason.Error()
			if !isGracefulClose(reason) {
				code = 1
			}
		}
		sess.cancel()
		if ctrl := sess.control(); ctrl != nil {
			_ = ctrl.Close()
		}
		_ = sess.conn.CloseWithError(code, reasonText)
		close(sess.closedCh)
	})
}

func isGracefulClose(err error) bool {
	return err == nil ||
		errors.Is(err, ErrDrainComplete) ||
		errors.Is(err, ErrServerClosed) ||
		errors.Is(err, ErrSessionClosed)
}

// teardown fails the session streams, detaches the plane from the registry and
// releases bookkeeping. It runs once per session.
func (sess *session) teardown() {
	sess.teardownOnce.Do(func() {
		s := sess.srv
		sess.shut(ErrSessionClosed)
		closeErr := sess.closeError()

		// Fail every stream that is still registered for this session. The
		// snapshot is taken first so Stream.fail can take the session lock.
		sess.streamsMu.Lock()
		failing := make([]*Stream, 0, len(sess.streams))
		for _, st := range sess.streams {
			failing = append(failing, st)
		}
		sess.streamsMu.Unlock()
		for _, st := range failing {
			st.fail(closeErr)
		}

		// Drive the session FSM to closed so metrics and logs stay consistent.
		st := sess.state()
		if st != fsm.SessionClosed {
			if st == fsm.SessionDraining {
				_, _ = sess.fsm.Fire(fsm.SessEvDrainDone)
			} else {
				_, _ = sess.fsm.Fire(fsm.SessEvTransportErr)
			}
		}
		nodeID := sess.node()
		plane := sess.planeIndex()
		s.recordSessionRemoved(nodeID, sess.state())

		replaced := sess.replaced.Load()
		var detach bool
		if nodeID != "" {
			key := sessionKey{nodeID: nodeID, planeIndex: plane}
			s.mu.Lock()
			if s.sessions[key] == sess {
				delete(s.sessions, key)
				detach = true
			} else if s.sessions[key] == nil {
				detach = true
			}
			s.mu.Unlock()
		}
		if nodeID != "" && detach && !replaced {
			s.reg.DetachPlane(nodeID, plane)
			s.setNodeError(nodeID, closeErr.Error())
		}
		reason := "closed"
		if closeErr != nil {
			reason = closeErr.Error()
		}
		if nodeID != "" {
			sess.logger().Info("session closed",
				"event", "session_closed", "reason", reason,
				"duration_ms", time.Since(sess.createdAt).Milliseconds())
		} else {
			s.logger.Debug("unregistered connection closed",
				"session_id", sess.id, "transport", sess.transport, "reason", reason)
		}
	})
}

func (sess *session) addStream(st *Stream) {
	sess.streamsMu.Lock()
	sess.streams[st.id] = st
	sess.streamsMu.Unlock()
}

func (sess *session) removeStream(st *Stream) {
	sess.streamsMu.Lock()
	delete(sess.streams, st.id)
	sess.streamsMu.Unlock()
}

func (sess *session) activeStreamCount() int {
	sess.streamsMu.Lock()
	defer sess.streamsMu.Unlock()
	return len(sess.streams)
}

func (sess *session) deliverProbe(res *protocol.ProbeResult) {
	sess.mu.Lock()
	var ch chan *protocol.ProbeResult
	if res.ID != "" {
		ch = sess.probes[res.ID]
		delete(sess.probes, res.ID)
	} else if len(sess.probes) == 1 {
		for id, c := range sess.probes {
			ch = c
			delete(sess.probes, id)
		}
	}
	sess.mu.Unlock()
	if ch == nil {
		sess.logger().Debug("unsolicited PROBE_RESULT dropped", "probe_id", res.ID)
		return
	}
	select {
	case ch <- res:
	default:
	}
}

func randNonce() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint64(b[:])
	}
	// crypto/rand failing is practically impossible; still never return a
	// constant nonce, otherwise PONG matching would alias.
	return uint64(time.Now().UnixNano())
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))[:n*2]
	}
	return hex.EncodeToString(b)
}

// kickDeliveryGrace is how long a draining session with no in-flight streams
// waits after queueing KICK so the peer can read it before the transport is
// closed (otherwise a manual kick is observed as a connection error and the
// node enters the generic reconnect backoff instead of the KICK retry path).
const kickDeliveryGrace = 300 * time.Millisecond

// helloRejectGrace lets the rejected peer consume HELLO_ACK(ok=false) before
// the transport closes, so the rejection reason reaches the node instead of
// being masked by a connection reset.
const helloRejectGrace = 250 * time.Millisecond
