package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/fsm"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

// session is one registered transport connection (one plane). It owns the
// control stream, the heartbeat watcher, the periodic STATS reporter and the
// stream table of every proxied connection that rides on this connection.
type session struct {
	a          *Agent
	plane      int
	conn       transport.Conn
	kind       transport.Kind
	ctrl       transport.ControlStream
	fsm        *fsm.SessionFSM
	log        *slog.Logger
	ack        protocol.HelloAck
	heartbeat  time.Duration
	maxStreams int

	ctx    context.Context
	cancel context.CancelFunc

	sendMu sync.Mutex

	streamsMu     sync.Mutex
	streams       map[uint64]*streamEntry
	nextStreamID  atomic.Uint64
	activeStreams atomic.Int64

	kickCh    chan protocol.Kick
	ctrlErrCh chan error
	redialCh  chan string
	abortCh   chan string

	drainOnce     sync.Once
	drainStarted  atomic.Bool
	shutdownOnce  sync.Once
	statsStopOnce sync.Once
	acceptOnce    sync.Once
	statsStop     chan struct{}
	statsWake     chan struct{}

	loopWG   sync.WaitGroup
	handlers atomic.Int64
}

// newSession builds the per connection state. It performs no I/O.
func newSession(a *Agent, p *plane, conn transport.Conn, kind transport.Kind, machine *fsm.SessionFSM) *session {
	ctx, cancel := context.WithCancel(context.Background())
	return &session{
		a:          a,
		plane:      p.index,
		conn:       conn,
		kind:       kind,
		fsm:        machine,
		log:        p.log.With("transport", string(kind)),
		heartbeat:  a.timings.heartbeatInterval,
		maxStreams: maxStreamsDefault,
		ctx:        ctx,
		cancel:     cancel,
		streams:    make(map[uint64]*streamEntry),
		kickCh:     make(chan protocol.Kick, 1),
		ctrlErrCh:  make(chan error, 1),
		redialCh:   p.redialCh,
		abortCh:    make(chan string, 1),
		statsStop:  make(chan struct{}),
		statsWake:  make(chan struct{}, 1),
	}
}

// hello performs the HELLO/HELLO_ACK registration exchange (5s budget). The
// data stream acceptor is already running during the handshake so that a
// server sending data streams before registration is rejected and logged
// (security invariant chapter 2.3).
func (s *session) hello(ctx context.Context) error {
	s.startAcceptLoop()
	cctx, cancel := context.WithTimeout(ctx, s.a.timings.helloTimeout)
	defer cancel()

	ctrl, err := s.conn.Control(cctx)
	if err != nil {
		return fmt.Errorf("获取控制流失败: %w", err)
	}
	if ctrl == nil {
		return errors.New("控制流为空")
	}
	s.ctrl = ctrl

	v4, v6 := s.a.egress()
	msg := protocol.Hello{
		Ver:          protocol.Version1,
		Token:        s.a.cfg.EffectiveToken(),
		ClientID:     s.a.clientID,
		Alias:        s.a.cfg.Alias,
		Tags:         s.a.cfg.NormalizedTags(),
		Region:       s.a.cfg.Region,
		ISPLabel:     s.a.cfg.ISPLabel,
		Weight:       s.a.cfg.Weight,
		Transport:    string(s.kind),
		Planes:       len(s.a.planes),
		PlaneIndex:   s.plane,
		EgressV4:     v4,
		EgressV6:     v6,
		Version:      s.a.version,
		Capabilities: []string{protocol.CapZstd, protocol.CapDNS, protocol.CapProbe},
		Compression:  s.a.cfg.Compression,
		TS:           protocol.NowMillis(),
	}
	payload, err := protocol.Marshal(msg)
	if err != nil {
		return fmt.Errorf("编码 HELLO 失败: %w", err)
	}
	if err := s.sendControlCtx(cctx, protocol.FrameHello, payload); err != nil {
		return fmt.Errorf("发送 HELLO 失败: %w", err)
	}
	typ, raw, err := s.ctrl.Recv(cctx)
	if err != nil {
		if isTimeoutErr(err) {
			return fmt.Errorf("等待 HELLO_ACK 超时（%s）: %w", s.a.timings.helloTimeout, err)
		}
		return fmt.Errorf("等待 HELLO_ACK 失败: %w", err)
	}
	if typ != protocol.FrameHelloAck {
		return fmt.Errorf("期望 HELLO_ACK，收到 %s", typ)
	}
	var ack protocol.HelloAck
	if err := protocol.Unmarshal(raw, &ack); err != nil {
		return fmt.Errorf("解析 HELLO_ACK 失败: %w", err)
	}
	if ack.Ver != protocol.Version1 {
		return &FatalError{Reason: fmt.Sprintf("协议版本不兼容：服务端 ver=%d，本端 ver=%d", ack.Ver, protocol.Version1)}
	}
	if !ack.OK {
		// Takeover cooldown is a retryable server-side rate limit (attachment
		// 2.2): the agent must back off instead of exiting fatally.
		if containsFold(asciiLower(ack.Error), "cooldown") {
			return &cooldownError{
				Reason: ack.Error,
				Delay:  s.a.timings.replacedCooldown,
			}
		}
		return &FatalError{Reason: fmt.Sprintf("服务端拒绝注册：%s", ack.Error)}
	}
	if setter, ok := s.conn.(transport.EpochSetter); ok {
		setter.SetEpoch(ack.Epoch)
	} else if setter, ok := s.ctrl.(transport.EpochSetter); ok {
		setter.SetEpoch(ack.Epoch)
	}
	s.ack = ack
	if ms := ack.Settings.HeartbeatMS; ms > 0 {
		s.heartbeat = time.Duration(ms) * time.Millisecond
	}
	if n := ack.Settings.MaxStreams; n > 0 {
		s.maxStreams = n
	}
	s.fire(fsm.SessEvHelloOK)
	s.log.Info("HELLO 注册成功",
		"event", "conn.hello_ok",
		"epoch", ack.Epoch,
		"server_transport", ack.Transport,
		"heartbeat_ms", s.heartbeat.Milliseconds(),
		"max_streams", s.maxStreams)
	if ack.PinNext != "" {
		s.log.Info("服务端下发下一枚证书 pin，可用它完成轮换窗口", "event", "conn.pin_next")
	}
	return nil
}

// serve runs the session until it is kicked, fails or the agent shuts down.
// The returned sessionEnd tells the plane loop what to do next.
func (s *session) serve(ctx context.Context) (end sessionEnd) {
	defer s.teardown()
	s.startLoops()
	select {
	case <-ctx.Done():
		s.log.Info("本地停机，开始排空会话", "event", "session.drain", "reason", "context_canceled")
		s.drainAndClose(s.a.timings.drainTimeout, "agent_shutdown")
		return sessionEnd{kind: s.kind, graceful: true}
	case <-s.a.forceCh:
		s.abort("agent_close")
		return sessionEnd{kind: s.kind, err: errSessionClosed, graceful: true}
	case <-s.a.stopCh:
		s.drainAndClose(s.a.timings.drainTimeout, "kick_shutdown")
		return sessionEnd{kind: s.kind, graceful: true}
	case reason := <-s.abortCh:
		return sessionEnd{kind: s.kind, err: fmt.Errorf("%w: %s", errSessionClosed, reason)}
	case err := <-s.ctrlErrCh:
		s.abort("transport_error")
		return sessionEnd{kind: s.kind, err: err}
	case kick := <-s.kickCh:
		if kick.Reason == protocol.KickShutdown {
			s.log.Info("收到服务端停机 KICK，排空在途流后退出",
				"event", "kick.shutdown", "message", kick.Message)
			s.a.requestStop()
			s.drainAndClose(s.a.timings.drainTimeout, "kick_shutdown")
			return sessionEnd{kind: s.kind, graceful: true, kickReason: kick.Reason}
		}
		s.log.Warn("收到服务端 KICK，停止接新流并排空在途流",
			"event", "kick.received", "reason", kick.Reason, "message", kick.Message)
		s.drainAndClose(s.a.timings.drainTimeout, "kick_"+kick.Reason)
		return sessionEnd{kind: s.kind, kicked: true, kickReason: kick.Reason,
			err: fmt.Errorf("服务端 KICK: %s", kick.Reason)}
	case reason := <-s.redialCh:
		s.log.Info("传输切换，主动重建会话", "event", "session.redial", "reason", reason)
		s.drainAndClose(s.a.timings.probeDrainTimeout, "transport_probe")
		return sessionEnd{kind: s.kind, probe: true, kickReason: reason}
	}
}

// startAcceptLoop launches the data stream acceptor exactly once. It starts
// before HELLO so pre-registration streams can be rejected; the FSM state guard
// decides whether a stream may be proxied.
func (s *session) startAcceptLoop() {
	s.acceptOnce.Do(func() {
		s.loopWG.Add(1)
		go func() {
			defer s.loopWG.Done()
			s.acceptLoop()
		}()
	})
}

// startLoops launches the control reader and the STATS reporter.
func (s *session) startLoops() {
	s.loopWG.Add(2)
	go func() {
		defer s.loopWG.Done()
		s.controlLoop()
	}()
	go func() {
		defer s.loopWG.Done()
		s.statsLoop()
	}()
}

// controlLoop reads connection level frames, answers PING with PONG, triggers
// STATS reports, executes probes and surfaces KICK events. The heartbeat is
// detected by the absence of any control frame: 1 missed interval marks the
// session degraded, 3 (45s by default) close the connection and reconnect.
func (s *session) controlLoop() {
	misses := 0
	lastFrame := time.Now()
	for {
		if s.ctx.Err() != nil {
			return
		}
		interval := s.heartbeat
		if interval <= 0 {
			interval = HeartbeatInterval
		}
		// Use a receive deadline slightly longer than the server PING interval:
		// with a deadline equal to the interval any positive jitter makes a
		// healthy session flap into degraded every few PINGs. 1.25x keeps the
		// documented 45s loss detection (3 misses) while removing the zero
		// margin; the degraded/lost decision below is wall clock based, not
		// "number of timeouts".
		recvTimeout := interval + interval/4
		rctx, cancel := context.WithTimeout(s.ctx, recvTimeout)
		typ, payload, err := s.ctrl.Recv(rctx)
		cancel()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			if isTimeoutErr(err) {
				misses++
				silentFor := time.Since(lastFrame)
				if s.fsm.State() != fsm.SessionDegraded && silentFor >= 2*interval {
					s.fire(fsm.SessEvHeartbeatMiss)
					s.log.Warn("服务端心跳迟到，会话降级",
						"event", "heartbeat.miss",
						"misses", misses,
						"silent_ms", silentFor.Milliseconds())
				}
				if silentFor >= time.Duration(s.a.timings.heartbeatMissLimit)*interval {
					s.fire(fsm.SessEvHeartbeatLost)
					s.log.Warn("心跳连续丢失，判定链路失活，主动断开重连",
						"event", "heartbeat.lost",
						"misses", misses,
						"silent_ms", silentFor.Milliseconds())
					s.reportError(fmt.Errorf("心跳连续 %d 次丢失（静默 %s）: %w",
						misses, silentFor.Round(time.Millisecond), err))
					return
				}
				continue
			}
			s.reportError(fmt.Errorf("读取控制流失败: %w", err))
			return
		}
		lastFrame = time.Now()
		misses = 0
		if s.fsm.State() == fsm.SessionDegraded {
			s.fire(fsm.SessEvHeartbeatOK)
			s.log.Info("心跳恢复，会话回到 ready", "event", "heartbeat.recovered")
		}
		s.dispatch(typ, payload)
	}
}

// dispatch applies one control frame.
func (s *session) dispatch(typ protocol.FrameType, payload []byte) {
	switch typ {
	case protocol.FramePing:
		// Echo the payload unchanged; only the server originates heartbeats.
		if err := s.sendControl(protocol.FramePong, payload); err != nil {
			s.log.Debug("回复 PONG 失败", "event", "heartbeat.pong_fail", "error", err)
		}
	case protocol.FramePong:
		// The node never sends PING; a stray PONG is harmless.
	case protocol.FrameStatsReq:
		s.sendStats()
	case protocol.FrameKick:
		var kick protocol.Kick
		if err := protocol.Unmarshal(payload, &kick); err != nil {
			s.log.Warn("解析 KICK 失败", "event", "kick.invalid", "error", err)
			return
		}
		select {
		case s.kickCh <- kick:
		default:
			// A drain is already in progress.
		}
	case protocol.FrameProbe:
		var probe protocol.Probe
		if err := protocol.Unmarshal(payload, &probe); err != nil {
			s.log.Warn("解析 PROBE 失败", "event", "probe.invalid", "error", err)
			return
		}
		s.startProbe(probe)
	case protocol.FrameStats:
		// Direction is node -> server only.
	case protocol.FrameHello, protocol.FrameHelloAck:
		s.log.Debug("注册完成后收到重复注册帧，已忽略", "event", "control.duplicate_hello")
	default:
		s.log.Debug("忽略未知控制帧", "event", "control.unknown", "frame", typ.String(), "length", len(payload))
	}
}

// statsLoop reports STATS every StatsInterval and immediately on STATS_REQ or
// when the egress addresses changed.
func (s *session) statsLoop() {
	interval := s.a.timings.statsInterval
	if interval <= 0 {
		interval = StatsInterval
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.statsStop:
			return
		case <-s.statsWake:
			s.sendStats()
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(interval)
		case <-timer.C:
			s.sendStats()
			timer.Reset(interval)
		}
	}
}

// sendStats marshals and sends one STATS frame.
func (s *session) sendStats() {
	v4, v6 := s.a.egress()
	stats := protocol.Stats{
		Inflight:      s.a.inflight.Load(),
		ActiveStreams: s.a.activeStreams.Load(),
		BytesIn:       s.a.bytesIn.Load(),
		BytesOut:      s.a.bytesOut.Load(),
		LatencyMS:     s.a.latencyMS(),
		Transport:     string(s.kind),
		Version:       s.a.version,
		EgressV4:      v4,
		EgressV6:      v6,
		TS:            protocol.NowMillis(),
	}
	payload, err := protocol.Marshal(stats)
	if err != nil {
		s.log.Warn("编码 STATS 失败", "event", "stats.encode_fail", "error", err)
		return
	}
	if err := s.sendControl(protocol.FrameStats, payload); err != nil {
		s.log.Debug("上报 STATS 失败", "event", "stats.send_fail", "error", err)
	}
}

// requestStats asks the stats loop to report immediately.
func (s *session) requestStats() {
	select {
	case s.statsWake <- struct{}{}:
	default:
	}
}

func (s *session) stopStats() {
	s.statsStopOnce.Do(func() { close(s.statsStop) })
}

// sendControl serializes one control frame write with a bounded context.
func (s *session) sendControl(typ protocol.FrameType, payload []byte) error {
	ctx, cancel := context.WithTimeout(s.ctx, controlWriteTimeout)
	defer cancel()
	return s.sendControlCtx(ctx, typ, payload)
}

// sendControlCtx serializes one control frame write with the caller context.
// transport.ControlStream writes must be serialized: PONG from the reader
// goroutine, STATS from the stats goroutine, PROBE_RESULT from the probe
// goroutines all take this lock.
func (s *session) sendControlCtx(ctx context.Context, typ protocol.FrameType, payload []byte) error {
	if s.ctrl == nil {
		return errors.New("nodeagent: 控制流未建立")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.ctrl.Send(ctx, typ, payload)
}

// beginDrain moves the session to draining: no new data streams are accepted,
// existing streams may finish.
func (s *session) beginDrain(reason string) {
	s.drainOnce.Do(func() {
		s.drainStarted.Store(true)
		s.fire(fsm.SessEvKick)
		s.log.Info("会话进入 draining，拒绝新数据流",
			"event", "session.draining",
			"reason", reason,
			"active_streams", s.activeStreams.Load())
	})
}

// drainAndClose waits up to timeout for in-flight streams, then closes the
// transport connection gracefully.
func (s *session) drainAndClose(timeout time.Duration, reason string) {
	s.beginDrain(reason)
	if timeout > 0 {
		deadline := time.Now().Add(timeout)
		poll := drainPollInterval(timeout)
		for s.activeStreams.Load() > 0 && time.Now().Before(deadline) {
			if !sleepCtx(s.ctx, poll) {
				break
			}
		}
	}
	if remaining := s.activeStreams.Load(); remaining > 0 {
		s.log.Warn("排空超时，强制关闭剩余数据流",
			"event", "session.drain_timeout",
			"reason", reason,
			"remaining", remaining)
	}
	s.shutdown(closeCodeGraceful, reason)
}

func drainPollInterval(timeout time.Duration) time.Duration {
	poll := planeDrainPoll
	if timeout > 0 && timeout/4 < poll {
		poll = timeout / 4
	}
	if poll < time.Millisecond {
		poll = time.Millisecond
	}
	return poll
}

// abort tears the session down immediately (agent close, fatal error, transport
// failure). It is safe to call multiple times and from any goroutine.
func (s *session) abort(reason string) {
	select {
	case s.abortCh <- reason:
	default:
	}
	s.shutdown(closeCodeError, reason)
}

// shutdown releases every resource exactly once: stream contexts are cancelled,
// targets closed, the control stream and the transport connection closed.
func (s *session) shutdown(code uint64, reason string) {
	s.shutdownOnce.Do(func() {
		s.fire(fsm.SessEvTransportErr)
		s.fire(fsm.SessEvDrainDone)
		s.cancel()
		s.abortStreams()
		if s.ctrl != nil {
			_ = s.ctrl.Close()
		}
		if s.conn != nil {
			_ = s.conn.CloseWithError(code, reason)
		}
		s.log.Info("会话传输连接已关闭",
			"event", "session.transport_closed",
			"reason", reason,
			"code", code)
	})
}

// teardown waits for the session goroutines before the plane moves on.
func (s *session) teardown() {
	s.shutdown(closeCodeError, "session_teardown")
	s.stopStats()
	if !waitGroupTimeout(&s.loopWG, time.Second) {
		s.log.Warn("会话循环未在超时内退出", "event", "session.loop_leak")
	}
	if !waitUntil(2*time.Second, func() bool { return s.handlers.Load() == 0 }) {
		s.log.Warn("数据流处理未在超时内退出", "event", "session.stream_leak",
			"handlers", s.handlers.Load())
	}
}

func (s *session) fire(ev fsm.SessionEvent) {
	if s.fsm == nil {
		return
	}
	if _, err := s.fsm.Fire(ev); err != nil {
		s.log.Debug("会话状态迁移被拒绝",
			"event", "session.state_rejected",
			"event_name", string(ev),
			"error", err)
	}
}

// reportError surfaces a fatal transport condition to the serve loop.
func (s *session) reportError(err error) {
	if err == nil {
		return
	}
	select {
	case s.ctrlErrCh <- err:
	default:
	}
}

// abortStreams cancels every in-flight stream and closes its target connection.
func (s *session) abortStreams() {
	s.streamsMu.Lock()
	list := make([]*streamEntry, 0, len(s.streams))
	for _, e := range s.streams {
		list = append(list, e)
	}
	s.streamsMu.Unlock()
	for _, e := range list {
		e.abort()
	}
}

// addStream registers a stream in the table, enforcing the per session limit.
func (s *session) addStream(e *streamEntry) bool {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if s.drainStarted.Load() {
		return false
	}
	if len(s.streams) >= s.maxStreams {
		return false
	}
	s.streams[e.id] = e
	s.activeStreams.Add(1)
	s.a.activeStreams.Add(1)
	return true
}

func (s *session) removeStream(id uint64) {
	s.streamsMu.Lock()
	if _, ok := s.streams[id]; ok {
		delete(s.streams, id)
		s.activeStreams.Add(-1)
		s.a.activeStreams.Add(-1)
	}
	s.streamsMu.Unlock()
}
