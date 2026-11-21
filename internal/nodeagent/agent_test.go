package nodeagent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("缺少 Config 时 New 应报错")
	}
	cfg := testConfig()
	cfg.Planes = 0
	if _, err := New(Options{Config: cfg, ClientID: "n1", QUICDial: func(context.Context) (transport.Conn, error) { return nil, nil }}); err == nil {
		t.Fatal("planes=0 时 New 应报错")
	}
	cfg = testConfig()
	if _, err := New(Options{Config: cfg, ClientID: "n1"}); err == nil {
		t.Fatal("auto 模式两个 dial 均为 nil 时 New 应报错")
	}
	cfg = testConfig()
	cfg.Transport = model.TransportQUIC
	if _, err := New(Options{Config: cfg, ClientID: "n1", WSDial: func(context.Context) (transport.Conn, error) { return nil, nil }}); err == nil {
		t.Fatal("transport=quic 但只有 WSDial 时 New 应报错")
	}
}

func TestAutoFallbackToWS(t *testing.T) {
	srv := newFakeServer(t)
	srv.quicFn = func(ctx context.Context) (transport.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.FallbackTimeout = 30 * time.Millisecond
		cfg.Transport = model.TransportAuto
	})
	waitFor(t, 3*time.Second, "回退到 wss 并注册成功", func() bool {
		st := h.agent.Status()
		return st.Connected && st.Transport == "ws"
	})
	st := h.agent.Status()
	if st.LastFallbackReason == "" {
		t.Fatalf("回退后 Status.LastFallbackReason 不应为空: %+v", st)
	}
	if st.Planes != 1 {
		t.Fatalf("ready planes = %d, want 1", st.Planes)
	}
	if st.ConnectedSince.IsZero() {
		t.Fatal("ConnectedSince 应被设置")
	}
	if st.Version != "test-1.0" {
		t.Fatalf("Status.Version = %q", st.Version)
	}
	if st.EgressV4 != "203.0.113.9" || st.EgressV6 != "2001:db8::9" {
		t.Fatalf("Status egress = %q/%q", st.EgressV4, st.EgressV6)
	}

	hello := srv.waitHello(t, 2*time.Second)
	if hello.Ver != protocol.Version1 {
		t.Errorf("HELLO ver = %d", hello.Ver)
	}
	if hello.Transport != "ws" {
		t.Errorf("HELLO transport = %q, want ws", hello.Transport)
	}
	if hello.ClientID != "test-node" || hello.Token != "test-token" {
		t.Errorf("HELLO 身份字段错误: client_id=%q", hello.ClientID)
	}
	if hello.Planes != 1 || hello.PlaneIndex != 0 {
		t.Errorf("HELLO planes=%d plane_index=%d", hello.Planes, hello.PlaneIndex)
	}
	if hello.Version != "test-1.0" {
		t.Errorf("HELLO version = %q", hello.Version)
	}
	caps := map[string]bool{}
	for _, c := range hello.Capabilities {
		caps[c] = true
	}
	for _, want := range []string{protocol.CapZstd, protocol.CapDNS, protocol.CapProbe} {
		if !caps[want] {
			t.Errorf("HELLO 缺少能力 %q", want)
		}
	}
	if !hello.Compression {
		t.Error("默认配置开启压缩，HELLO compression 应为 true")
	}
	if hello.TS <= 0 {
		t.Error("HELLO ts 应大于 0")
	}
	if hello.EgressV4 != "203.0.113.9" {
		t.Errorf("HELLO egress_v4 = %q", hello.EgressV4)
	}
}

func TestQUICPreferred(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		cfg.Transport = model.TransportAuto
	})
	waitFor(t, 3*time.Second, "QUIC 注册成功", func() bool {
		st := h.agent.Status()
		return st.Connected && st.Transport == "quic"
	})
	if st := h.agent.Status(); st.LastFallbackReason != "" {
		t.Fatalf("QUIC 正常时不应记录回退原因: %q", st.LastFallbackReason)
	}
}

// TestReProbeQUICAndRevert covers the background QUIC re-probe with hysteresis
// and the revert rule when the fresh QUIC session fails within the window.
func TestReProbeQUICAndRevert(t *testing.T) {
	srv := newFakeServer(t)
	var quicCalls atomic.Int32
	srv.quicFn = func(ctx context.Context) (transport.Conn, error) {
		if quicCalls.Add(1) == 1 {
			// First attempt is blackholed: force the wss fallback.
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return srv.newConn(transport.KindQUIC), nil
	}
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.FallbackTimeout = 25 * time.Millisecond
		o.TestHooks.ReProbeInterval = 300 * time.Millisecond
		o.TestHooks.QuicConfirmInterval = 20 * time.Millisecond
		o.TestHooks.ProbeTick = 10 * time.Millisecond
		o.TestHooks.BackoffBase = 20 * time.Millisecond
		o.TestHooks.BackoffMax = 80 * time.Millisecond
		cfg.Transport = model.TransportAuto
	})
	waitFor(t, 3*time.Second, "先回退到 wss", func() bool {
		st := h.agent.Status()
		return st.Connected && st.Transport == "ws"
	})
	waitFor(t, 5*time.Second, "重探 QUIC 后切回", func() bool {
		return h.agent.Status().Transport == "quic"
	})

	// Force the freshly switched QUIC session to fail: the agent must revert to
	// wss and reset the backoff instead of flapping.
	c := srv.lastAliveConn()
	if c == nil {
		t.Fatal("没有存活的 QUIC 连接")
	}
	_ = c.CloseWithError(1, "simulated failure")
	waitFor(t, 3*time.Second, "QUIC 短时间失败后回到 wss", func() bool {
		st := h.agent.Status()
		return st.Connected && st.Transport == "ws"
	})
	if st := h.agent.Status(); st.LastFallbackReason == "" {
		t.Fatal("回退后 LastFallbackReason 应被记录")
	}
}

// TestQUICReprobeFailureKeepsWS verifies that a failing background QUIC probe
// leaves the working wss session untouched (no flapping).
func TestQUICReprobeFailureKeepsWS(t *testing.T) {
	srv := newFakeServer(t)
	var quicCalls atomic.Int32
	srv.quicFn = func(ctx context.Context) (transport.Conn, error) {
		if quicCalls.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, errors.New("udp/443 still blocked")
	}
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.FallbackTimeout = 20 * time.Millisecond
		o.TestHooks.ReProbeInterval = 60 * time.Millisecond
		o.TestHooks.ProbeTick = 10 * time.Millisecond
		cfg.Transport = model.TransportAuto
	})
	waitFor(t, 3*time.Second, "回退到 wss", func() bool {
		st := h.agent.Status()
		return st.Connected && st.Transport == "ws"
	})
	waitFor(t, 3*time.Second, "后台重探被执行", func() bool {
		return quicCalls.Load() >= 3
	})
	if st := h.agent.Status(); st.Transport != "ws" || !st.Connected {
		t.Fatalf("QUIC 重探失败后应保持 wss，实际 %+v", st)
	}
	if st := h.agent.Status(); st.LastFallbackReason == "" {
		t.Fatal("QUIC 重探失败应记录回退原因")
	}
}

func TestBothTransportsFailBackoff(t *testing.T) {
	srv := newFakeServer(t)
	srv.quicFn = func(ctx context.Context) (transport.Conn, error) {
		return nil, errors.New("quic unreachable")
	}
	srv.wsFn = func(ctx context.Context) (transport.Conn, error) {
		return nil, errors.New("wss unreachable")
	}
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.BackoffBase = 40 * time.Millisecond
		o.TestHooks.BackoffMax = 160 * time.Millisecond
		cfg.Transport = model.TransportAuto
	})
	time.Sleep(500 * time.Millisecond)
	dials := srv.dials()
	if len(dials) < 4 {
		t.Fatalf("退避重连次数过少: %d", len(dials))
	}
	if len(dials) > 30 {
		t.Fatalf("退避重连过于频繁（可能未生效）: %d", len(dials))
	}
	if st := h.agent.Status(); st.Connected {
		t.Fatalf("两种传输都失败时不应显示已连接: %+v", st)
	}
	select {
	case err := <-h.errCh:
		t.Fatalf("非致命错误不应让 Run 退出: %v", err)
	default:
	}
	if st := h.agent.Status(); st.LastError == "" {
		t.Error("LastError 应记录最近一次错误")
	}
}

func TestHelloRejectedIsFatal(t *testing.T) {
	srv := newFakeServer(t)
	srv.setHelloOK(false, "authentication failed", 0)
	h := startAgent(t, srv, nil)
	err := h.waitErr(t, 3*time.Second)
	var fe *FatalError
	if !errors.As(err, &fe) {
		t.Fatalf("HELLO_ACK ok=false 应返回 FatalError，得到 %v", err)
	}
	if !IsFatal(err) {
		t.Fatal("IsFatal(FatalError) 应为 true")
	}
	time.Sleep(150 * time.Millisecond)
	if got := len(srv.dials()); got != 1 {
		t.Fatalf("致命错误后不允许重连，实际拨号次数 %d", got)
	}
}

func TestPinMismatchInjectedClassifierFatal(t *testing.T) {
	srv := newFakeServer(t)
	pinErr := errors.New("tls: pin mismatch: expected sha256/AAA got sha256/BBB")
	srv.quicFn = func(ctx context.Context) (transport.Conn, error) { return nil, pinErr }
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		cfg.Transport = model.TransportAuto
		o.IsFatal = func(err error) bool {
			return errors.Is(err, pinErr) || IsFatal(err)
		}
	})
	err := h.waitErr(t, 3*time.Second)
	var fe *FatalError
	if !errors.As(err, &fe) {
		t.Fatalf("pin mismatch 应返回 FatalError，得到 %v", err)
	}
	if !errors.Is(err, pinErr) {
		t.Fatalf("FatalError 应保留原因链，得到 %v", err)
	}
	// Fatal QUIC errors must not degrade into a wss fallback.
	for _, d := range srv.dials() {
		if d.kind == transport.KindWS {
			t.Fatal("致命错误后不应回退 wss")
		}
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(srv.dials()); got != 1 {
		t.Fatalf("致命错误后不允许重连，实际拨号次数 %d", got)
	}
}

func TestPingPong(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitFor(t, 3*time.Second, "连接就绪", func() bool { return h.agent.Status().Connected })
	payload := []byte("heartbeat-payload")
	srv.push(protocol.FramePing, payload)
	pong := srv.waitPong(t, 2*time.Second)
	if string(pong) != string(payload) {
		t.Fatalf("PONG payload = %q, want %q", pong, payload)
	}
}

func TestStatsOnRequestAndPeriodic(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.StatsInterval = 30 * time.Millisecond
	})
	st := srv.waitStats(t, 2*time.Second)
	if st.Transport == "" {
		t.Fatalf("STATS transport 为空: %+v", st)
	}
	if st.Version != "test-1.0" {
		t.Errorf("STATS version = %q", st.Version)
	}
	if st.EgressV4 != "203.0.113.9" {
		t.Errorf("STATS egress_v4 = %q", st.EgressV4)
	}
	if st.TS <= 0 {
		t.Error("STATS ts 应大于 0")
	}
	// STATS_REQ must trigger an immediate report as well.
	srv.push(protocol.FrameStatsReq, nil)
	select {
	case got := <-srv.statsCh:
		if got.Transport == "" {
			t.Fatalf("STATS_REQ 触发的 STATS 不完整: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("STATS_REQ 未触发 STATS")
	}
	_ = h
}

func TestHelloAckVersionMismatchFatal(t *testing.T) {
	srv := newFakeServer(t)
	srv.ackMutate = func(a *protocol.HelloAck) { a.Ver = 9 }
	h := startAgent(t, srv, nil)
	err := h.waitErr(t, 3*time.Second)
	var fe *FatalError
	if !errors.As(err, &fe) {
		t.Fatalf("协议版本不兼容应返回 FatalError，得到 %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(srv.dials()); got != 1 {
		t.Fatalf("版本不兼容后不允许重连，拨号次数 %d", got)
	}
}

func TestKickRevokedReconnects(t *testing.T) {
	srv := newFakeServer(t)
	var kicked atomic.Bool
	srv.onReady = func(c *fakeConn, h protocol.Hello) {
		if !kicked.CompareAndSwap(false, true) {
			return
		}
		time.Sleep(3 * time.Millisecond)
		payload, _ := protocol.Marshal(protocol.Kick{Reason: protocol.KickRevoked})
		select {
		case c.ctrl.recvCh <- fakeFrame{typ: protocol.FrameKick, payload: payload}:
		case <-c.closeCh:
		}
	}
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.KickRetryDelay = 15 * time.Millisecond
	})
	waitFor(t, 3*time.Second, "revoked KICK 后重连", func() bool {
		return len(srv.dials()) >= 2 && h.agent.Status().Connected
	})
	select {
	case err := <-h.errCh:
		t.Fatalf("revoked KICK 不应让 Run 退出: %v", err)
	default:
	}
}

func TestKickShutdownReturnsNil(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitFor(t, 3*time.Second, "连接就绪", func() bool { return h.agent.Status().Connected })
	start := time.Now()
	srv.pushJSON(protocol.FrameKick, protocol.Kick{Reason: protocol.KickShutdown})
	err := h.waitErr(t, 2*time.Second)
	if err != nil {
		t.Fatalf("shutdown KICK 后 Run 应返回 nil，得到 %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shutdown KICK 优雅退出耗时过长: %s", elapsed)
	}
}

func TestKickReplacedCooldown(t *testing.T) {
	srv := newFakeServer(t)
	srv.onReady = func(c *fakeConn, h protocol.Hello) {
		time.Sleep(3 * time.Millisecond)
		payload, _ := protocol.Marshal(protocol.Kick{Reason: protocol.KickReplaced})
		select {
		case c.ctrl.recvCh <- fakeFrame{typ: protocol.FrameKick, payload: payload}:
		case <-c.closeCh:
		}
	}
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.KickRetryDelay = 10 * time.Millisecond
		o.TestHooks.ReplacedCooldown = 200 * time.Millisecond
		o.TestHooks.ReplacedWindow = 5 * time.Second
		o.TestHooks.ReplacedLimit = 3
	})
	_ = h
	waitFor(t, 5*time.Second, "至少重连 4 次", func() bool {
		return len(srv.dials()) >= 4
	})
	dials := srv.dials()
	firstGap := dials[2].at.Sub(dials[1].at)
	cooldownGap := dials[3].at.Sub(dials[2].at)
	if firstGap > 150*time.Millisecond {
		t.Fatalf("普通 replaced 重连过慢: %s", firstGap)
	}
	if cooldownGap < 150*time.Millisecond {
		t.Fatalf("60s 内第 3 次 replaced 未进入冷却退避: 间隔 %s", cooldownGap)
	}
}

func TestMultiPlaneIsolation(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		cfg.Planes = 2
	})
	waitFor(t, 3*time.Second, "两个平面就绪", func() bool {
		return h.agent.Status().Planes == 2
	})
	conns := srv.connsSnapshot()
	if len(conns) < 2 {
		t.Fatalf("应有 2 条连接，实际 %d", len(conns))
	}
	closed := conns[0]
	survivor := conns[1]
	_ = closed.CloseWithError(1, "simulate plane failure")
	select {
	case <-survivor.closeCh:
		t.Fatal("另一平面不应受单平面故障影响")
	default:
	}
	waitFor(t, 3*time.Second, "故障平面重连并恢复 2 个 ready 平面", func() bool {
		st := h.agent.Status()
		return st.Planes == 2 && len(srv.dials()) >= 3
	})
	select {
	case <-survivor.closeCh:
		t.Fatal("恢复过程中另一平面被关闭")
	default:
	}
}

func TestHeartbeatLossReconnects(t *testing.T) {
	srv := newFakeServer(t)
	startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.HeartbeatInterval = 25 * time.Millisecond
		o.TestHooks.HeartbeatMissLimit = 3
		o.TestHooks.BackoffBase = 20 * time.Millisecond
		o.TestHooks.BackoffMax = 80 * time.Millisecond
	})
	waitFor(t, 3*time.Second, "心跳丢失后主动重连", func() bool {
		return len(srv.dials()) >= 2
	})
}

func TestHeartbeatKeepsSessionAlive(t *testing.T) {
	srv := newFakeServer(t)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	srv.onReady = func(c *fakeConn, h protocol.Hello) {
		go func() {
			ticker := time.NewTicker(8 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					select {
					case c.ctrl.recvCh <- fakeFrame{typ: protocol.FramePing, payload: []byte("hb")}:
					case <-c.closeCh:
						return
					case <-stop:
						return
					}
				case <-c.closeCh:
					return
				case <-stop:
					return
				}
			}
		}()
	}
	startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.HeartbeatInterval = 20 * time.Millisecond
		o.TestHooks.HeartbeatMissLimit = 3
	})
	time.Sleep(300 * time.Millisecond)
	if got := len(srv.dials()); got != 1 {
		t.Fatalf("持续收到 PING 时不应重连，拨号次数 %d", got)
	}
}

func TestEgressCallbackReported(t *testing.T) {
	srv := newFakeServer(t)
	var v4 atomic.Value
	v4.Store("198.51.100.7")
	startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		// Manual override would win over detection; clear it for this test.
		cfg.Egress.ManualV4 = ""
		cfg.Egress.ManualV6 = ""
		o.Egress = func(ctx context.Context) (string, string) {
			return v4.Load().(string), "2001:db8::7"
		}
		o.TestHooks.EgressRefresh = 20 * time.Millisecond
		o.TestHooks.StatsInterval = time.Hour // only egress changes trigger STATS
	})
	hello := srv.waitHello(t, 2*time.Second)
	if hello.EgressV4 != "198.51.100.7" || hello.EgressV6 != "2001:db8::7" {
		t.Fatalf("HELLO egress = %q/%q", hello.EgressV4, hello.EgressV6)
	}
	v4.Store("198.51.100.99")
	deadline := time.After(3 * time.Second)
	for {
		select {
		case st := <-srv.statsCh:
			if st.EgressV4 == "198.51.100.99" {
				return
			}
		case <-deadline:
			t.Fatal("出口 IP 变化后未触发 STATS 上报")
		}
	}
}

func TestPreRegistrationStreamRejected(t *testing.T) {
	srv := newFakeServer(t)
	st := openStreamFor(t, "127.0.0.1", 80)
	srv.onHello = func(c *fakeConn, h protocol.Hello) {
		// Push a data stream before HELLO_ACK: a protocol violation the node
		// must reject. Delaying the ACK keeps the node in handshaking while the
		// stream is accepted, making the check deterministic.
		c.pushStream(st)
		time.Sleep(25 * time.Millisecond)
	}
	h := startAgent(t, srv, nil)
	waitFor(t, 3*time.Second, "注册成功", func() bool { return h.agent.Status().Connected })
	select {
	case code := <-st.resetCh:
		if code == 0 {
			t.Fatalf("注册前数据流应以非 0 码复位")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("注册前收到的数据流未被拒绝（未 Reset）")
	}
}

func TestCtxCancelGraceful(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitFor(t, 3*time.Second, "连接就绪", func() bool { return h.agent.Status().Connected })
	h.cancel()
	if err := h.waitErr(t, 3*time.Second); err != nil {
		t.Fatalf("ctx 取消后 Run 应返回 nil，得到 %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitFor(t, 3*time.Second, "连接就绪", func() bool { return h.agent.Status().Connected })
	if err := h.agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.agent.Close(); err != nil {
		t.Fatalf("第二次 Close 应幂等: %v", err)
	}
	if err := h.waitErr(t, 3*time.Second); err != nil {
		t.Fatalf("Close 后 Run 应返回 nil，得到 %v", err)
	}
}
