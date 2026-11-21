package tunnel

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"proxygw/internal/protocol"
	"proxygw/internal/registry"
	"proxygw/internal/transport"
)

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// metricValue gathers the value of one labelled metric from the prometheus
// registry. It returns the sum of all matching series, or 0 when absent.
func (e *testEnv) metricValue(name string, labels map[string]string) float64 {
	e.t.Helper()
	if e.metrics == nil {
		return 0
	}
	families, err := e.metrics.Registry.Gather()
	if err != nil {
		e.t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			ok := true
			for k, want := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == want {
						found = true
						break
					}
				}
				if !found {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			switch {
			case m.GetGauge() != nil:
				total += m.GetGauge().GetValue()
			case m.GetCounter() != nil:
				total += m.GetCounter().GetValue()
			case m.GetHistogram() != nil:
				total += float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return total
}

func TestServerRegistration(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, ack := env.registerNode("node-a", 0)

	if !ack.OK || ack.Ver != protocol.Version1 {
		t.Fatalf("bad HELLO_ACK: %+v", ack)
	}
	if ack.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1", ack.Epoch)
	}
	if ack.Transport != string(transport.KindQUIC) {
		t.Fatalf("transport = %q", ack.Transport)
	}
	if ack.Settings.HeartbeatMS != DefaultHeartbeatInterval.Milliseconds() {
		t.Fatalf("heartbeat_ms = %d, want %d", ack.Settings.HeartbeatMS, DefaultHeartbeatInterval.Milliseconds())
	}
	if ack.Settings.MaxStreams != 1000 {
		t.Fatalf("max_streams = %d, want 1000", ack.Settings.MaxStreams)
	}
	if ack.Settings.MaxFrameBytes != protocol.MaxFramePayload {
		t.Fatalf("max_frame_bytes = %d, want %d", ack.Settings.MaxFrameBytes, protocol.MaxFramePayload)
	}
	if ack.ServerTime <= 0 {
		t.Fatalf("server_time not set: %d", ack.ServerTime)
	}
	if got := conn.epoch.Load(); got != 1 {
		t.Fatalf("EpochSetter epoch = %d, want 1", got)
	}

	node, ok := env.reg.Get("node-a")
	if !ok {
		t.Fatal("node not registered")
	}
	if !node.Online || node.Planes != 1 || !node.Enabled {
		t.Fatalf("unexpected node: %+v", node)
	}
	if node.Transport != string(transport.KindQUIC) {
		t.Fatalf("node transport = %q", node.Transport)
	}
	if node.EgressIP.V4 != "203.0.113.7" {
		t.Fatalf("egress = %+v", node.EgressIP)
	}
	if node.Alias != "node-a-alias" || node.Version != "test-1.0" || node.Weight != 1 {
		t.Fatalf("metadata not applied: %+v", node)
	}
	if node.BreakerState != "closed" {
		t.Fatalf("breaker state = %q", node.BreakerState)
	}
	if env.reg.OnlineCount() != 1 || env.reg.UniqueEgressCount() != 1 {
		t.Fatalf("registry counters online=%d unique=%d", env.reg.OnlineCount(), env.reg.UniqueEgressCount())
	}
	if got := env.srv.NodePlaneCount("node-a"); got != 1 {
		t.Fatalf("NodePlaneCount = %d, want 1", got)
	}
	if state, tr, ok := env.srv.SessionState("node-a"); !ok || state != "ready" || tr != string(transport.KindQUIC) {
		t.Fatalf("SessionState = %q %q %v", state, tr, ok)
	}
	if errStr := env.srv.NodeLastError("node-a"); errStr != "" {
		t.Fatalf("NodeLastError = %q, want empty", errStr)
	}
	if _, _, ok := env.srv.SessionState("missing"); ok {
		t.Fatal("SessionState for unknown node must report !ok")
	}
	if v := env.metricValue("tunnel_session_state", map[string]string{"node": "node-a", "state": "ready"}); v != 1 {
		t.Fatalf("tunnel_session_state{ready} = %v, want 1", v)
	}
	if v := env.metricValue("tunnel_planes", map[string]string{"node": "node-a"}); v != 1 {
		t.Fatalf("tunnel_planes = %v, want 1", v)
	}
	if v := env.metricValue("nodes_online", nil); v != 1 {
		t.Fatalf("nodes_online = %v, want 1", v)
	}
}

func TestWSRegistration(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{kind: transport.KindWS})
	_, _, ack := env.registerNode("ws-node", 1)
	if !ack.OK || ack.Transport != string(transport.KindWS) || ack.Epoch != 1 {
		t.Fatalf("unexpected ack: %+v", ack)
	}
	node, ok := env.reg.Get("ws-node")
	if !ok || !node.Online || node.Transport != string(transport.KindWS) {
		t.Fatalf("node = %+v ok=%v", node, ok)
	}
}

func TestRegistrationRejections(t *testing.T) {
	cases := []struct {
		name      string
		nodeID    string
		token     string
		mutate    func(*protocol.Hello)
		wantError string
	}{
		{
			name: "version mismatch", nodeID: "node-ver", token: "test-token",
			mutate:    func(h *protocol.Hello) { h.Ver = 2 },
			wantError: "version",
		},
		{
			name: "invalid client id", nodeID: "bad id!", token: "test-token",
			wantError: "client_id",
		},
		{
			name: "bad token", nodeID: "node-auth", token: "wrong-token",
			wantError: "authentication",
		},
		{
			name: "missing token", nodeID: "node-auth2", token: "",
			wantError: "authentication",
		},
		{
			name: "invalid plane index", nodeID: "node-plane", token: "test-token",
			mutate:    func(h *protocol.Hello) { h.PlaneIndex = 99 },
			wantError: "plane_index",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, testEnvOptions{})
			var mutate []func(*protocol.Hello)
			if tc.mutate != nil {
				mutate = append(mutate, tc.mutate)
			}
			conn := env.pushHelloConn(tc.nodeID, 0, tc.token, mutate...)
			ack := readHelloAck(t, conn.ctrl, 3*time.Second)
			if ack.OK {
				t.Fatalf("registration unexpectedly succeeded: %+v", ack)
			}
			if ack.Ver != protocol.Version1 {
				t.Fatalf("rejection ack version = %d", ack.Ver)
			}
			if !strings.Contains(ack.Error, tc.wantError) {
				t.Fatalf("rejection error = %q, want it to contain %q", ack.Error, tc.wantError)
			}
			if err := conn.waitClosed(3 * time.Second); err != nil {
				t.Fatalf("connection not closed: %v", err)
			}
			if env.reg.Count() != 0 {
				t.Fatalf("registry has %d nodes after rejected registration", env.reg.Count())
			}
			if got := env.srv.NodeLastError(tc.nodeID); got == "" {
				t.Fatalf("NodeLastError for %q is empty", tc.nodeID)
			}
		})
	}
}

func TestHelloTimeout(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Hello: 20 * time.Millisecond}})
	conn := newFakeConn(transport.KindQUIC)
	env.pushConn(conn)
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("connection not closed after HELLO timeout: %v", err)
	}
	if env.reg.Count() != 0 {
		t.Fatalf("registry has nodes after HELLO timeout")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Handshake: 20 * time.Millisecond}})
	conn := newFakeConn(transport.KindQUIC)
	conn.controlFn = func(ctx context.Context) (transport.ControlStream, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	env.pushConn(conn)
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("connection not closed after handshake timeout: %v", err)
	}
	if env.reg.Count() != 0 {
		t.Fatalf("registry has nodes after handshake timeout")
	}
}

func TestFrameBeforeHello(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn := newFakeConn(transport.KindQUIC)
	env.pushConn(conn)
	// A STATS frame is valid on a control stream only after registration.
	if !conn.ctrl.inject(protocol.FrameStats, []byte("{}")) {
		t.Fatal("inject failed")
	}
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("connection not closed after pre-HELLO control frame: %v", err)
	}
	if env.reg.Count() != 0 {
		t.Fatalf("registry has nodes after pre-HELLO frame")
	}
}

func TestTakeover(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	first, tap, ack := env.registerNode("node-take", 0)
	if ack.Epoch != 1 {
		t.Fatalf("first epoch = %d", ack.Epoch)
	}
	waitFor(t, 3*time.Second, "plane count 1", func() bool { return env.srv.NodePlaneCount("node-take") == 1 })

	second := env.pushHelloConn("node-take", 0, env.token)
	ack2 := readHelloAck(t, second.ctrl, 3*time.Second)
	if !ack2.OK {
		t.Fatalf("takeover registration failed: %s", ack2.Error)
	}
	if ack2.Epoch != 2 {
		t.Fatalf("takeover epoch = %d, want 2", ack2.Epoch)
	}
	env.trackTapFor(second, true)
	env.waitReady("node-take")

	// The old session receives KICK(replaced) and is closed.
	kickFrame := tap.nextOfType(t, protocol.FrameKick, 3*time.Second)
	var kick protocol.Kick
	if err := protocol.Unmarshal(kickFrame.payload, &kick); err != nil {
		t.Fatalf("decode KICK: %v", err)
	}
	if kick.Reason != protocol.KickReplaced {
		t.Fatalf("KICK reason = %q, want %q", kick.Reason, protocol.KickReplaced)
	}
	if err := first.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("old connection not closed: %v", err)
	}
	if got := second.epoch.Load(); got != 2 {
		t.Fatalf("new epoch setter = %d, want 2", got)
	}
	if got := env.reg.Epoch("node-take"); got != 2 {
		t.Fatalf("registry epoch = %d, want 2", got)
	}
	if got := env.srv.NodePlaneCount("node-take"); got != 1 {
		t.Fatalf("plane count = %d, want 1", got)
	}
	if v := env.metricValue("session_takeovers_total", map[string]string{"node": "node-take", "result": "replaced"}); v != 1 {
		t.Fatalf("session_takeovers_total{replaced} = %v, want 1", v)
	}
}

func TestTakeoverCooldown(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conns := make([]*fakeConn, 0, 5)
	first, _, ack := env.registerNode("node-flap", 0)
	if ack.Epoch != 1 {
		t.Fatalf("first epoch = %d", ack.Epoch)
	}
	conns = append(conns, first)
	// Three successful takeovers are allowed inside the 60s window.
	for i := 0; i < 3; i++ {
		c := env.pushHelloConn("node-flap", 0, env.token)
		a := readHelloAck(t, c.ctrl, 3*time.Second)
		if !a.OK {
			t.Fatalf("takeover %d rejected: %s", i+1, a.Error)
		}
		env.trackTapFor(c, true)
		env.waitReady("node-flap")
		conns = append(conns, c)
	}
	if got := env.reg.Epoch("node-flap"); got != 4 {
		t.Fatalf("epoch after takeovers = %d, want 4", got)
	}
	// The fourth takeover in the window triggers the cooldown.
	flap := env.pushHelloConn("node-flap", 0, env.token)
	ack2 := readHelloAck(t, flap.ctrl, 3*time.Second)
	if ack2.OK {
		t.Fatalf("4th takeover unexpectedly accepted: %+v", ack2)
	}
	if !strings.Contains(ack2.Error, "cooldown") {
		t.Fatalf("rejection error = %q, want it to contain cooldown", ack2.Error)
	}
	if err := flap.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("rejected connection not closed: %v", err)
	}
	if got := env.reg.Epoch("node-flap"); got != 4 {
		t.Fatalf("epoch after rejected takeover = %d, want 4", got)
	}
	if got := env.srv.NodePlaneCount("node-flap"); got != 1 {
		t.Fatalf("plane count = %d, want 1", got)
	}
	if v := env.metricValue("session_takeovers_total", map[string]string{"node": "node-flap", "result": "cooldown_rejected"}); v != 1 {
		t.Fatalf("session_takeovers_total{cooldown_rejected} = %v, want 1", v)
	}
	// The cooldown rejection is recorded for the panel.
	if got := env.srv.NodeLastError("node-flap"); !strings.Contains(got, "cooldown") {
		t.Fatalf("NodeLastError = %q, want cooldown text", got)
	}
	// While the slot is cooling down every further attempt is rejected too.
	again := env.pushHelloConn("node-flap", 0, env.token)
	ack3 := readHelloAck(t, again.ctrl, 3*time.Second)
	if ack3.OK || !strings.Contains(ack3.Error, "cooldown") {
		t.Fatalf("attempt during cooldown: ok=%v error=%q", ack3.OK, ack3.Error)
	}
	if err := again.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("cooldown rejected connection not closed: %v", err)
	}
	if got := env.reg.Epoch("node-flap"); got != 4 {
		t.Fatalf("epoch changed during cooldown: %d", got)
	}
}

func TestUnauthenticatedFailureLabelsAreBounded(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	// A rejected peer must not leak its claimed node id into metric labels.
	c := env.pushHelloConn("attacker-controlled-node", 0, "bad-token")
	ack := readHelloAck(t, c.ctrl, 3*time.Second)
	if ack.OK {
		t.Fatal("bad token accepted")
	}
	if v := env.metricValue("tunnel_reconnects_total", map[string]string{"node": "unauthenticated", "reason": "authentication_failed"}); v < 1 {
		t.Fatalf("tunnel_reconnects_total{unauthenticated} = %v, want >= 1", v)
	}
	if v := env.metricValue("tunnel_reconnects_total", map[string]string{"node": "attacker-controlled-node"}); v != 0 {
		t.Fatalf("attacker supplied node id leaked into metric labels: %v", v)
	}
	if v := env.metricValue("tunnel_session_state", map[string]string{"node": "attacker-controlled-node"}); v != 0 {
		t.Fatalf("attacker supplied node id leaked into session state metrics: %v", v)
	}
}

func TestHeartbeatDegradedAndRecovered(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{
		Heartbeat:     50 * time.Millisecond,
		HeartbeatLost: 2 * time.Second,
	}})
	conn, tap, _ := env.registerNode("node-hb", 0)
	tap.setEcho(false)
	waitFor(t, 3*time.Second, "session degraded", func() bool {
		state, _, ok := env.srv.SessionState("node-hb")
		return ok && state == "degraded"
	})
	tap.setEcho(true)
	// Answer every PING already queued so the oldest outstanding PING clears.
	deadline := time.Now().Add(3 * time.Second)
	for {
		state, _, _ := env.srv.SessionState("node-hb")
		if state == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session did not recover, state=%q", state)
		}
		if f, ok := tap.tryNext(10 * time.Millisecond); ok && f.typ == protocol.FramePing {
			conn.ctrl.inject(protocol.FramePong, f.payload)
		}
	}
	if err := conn.waitClosed(100 * time.Millisecond); err == nil {
		t.Fatal("session closed while it should stay ready")
	}
}

func TestHeartbeatLost(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{
		Heartbeat:     20 * time.Millisecond,
		HeartbeatLost: 60 * time.Millisecond,
	}})
	conn, tap, _ := env.registerNode("node-lost", 0)
	tap.setEcho(false)
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("session not closed after heartbeat loss: %v", err)
	}
	waitFor(t, 3*time.Second, "node offline", func() bool {
		n, ok := env.reg.Get("node-lost")
		return !ok || !n.Online
	})
	if got := env.srv.NodePlaneCount("node-lost"); got != 0 {
		t.Fatalf("plane count = %d, want 0", got)
	}
	if _, _, ok := env.srv.SessionState("node-lost"); ok {
		t.Fatal("SessionState after heartbeat loss should be !ok")
	}
	waitFor(t, 3*time.Second, "node error recorded", func() bool {
		return strings.Contains(env.srv.NodeLastError("node-lost"), "heartbeat")
	})
	if v := env.metricValue("tunnel_reconnects_total", map[string]string{"node": "node-lost", "reason": "heartbeat_lost"}); v < 1 {
		t.Fatalf("tunnel_reconnects_total{heartbeat_lost} = %v, want >=1", v)
	}
}

func TestStatsUpdate(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-stats", 0)
	stats := protocol.Stats{Inflight: 7, ActiveStreams: 7, BytesIn: 1234, BytesOut: 5678, LatencyMS: 42, EgressV4: "203.0.113.7"}
	payload, err := protocol.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.ctrl.inject(protocol.FrameStats, payload) {
		t.Fatal("inject STATS failed")
	}
	waitFor(t, 3*time.Second, "stats applied", func() bool {
		n, ok := env.reg.Get("node-stats")
		return ok && n.Inflight == 7 && n.BytesIn == 1234 && n.BytesOut == 5678 && n.LatencyEWMA == 42
	})
}

func TestProtocolViolationClosesSession(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-proto", 0)
	// A data plane frame on the control stream is a protocol error.
	if !conn.ctrl.inject(protocol.FrameData, []byte("payload")) {
		t.Fatal("inject failed")
	}
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("session not closed after protocol violation: %v", err)
	}
	waitFor(t, 3*time.Second, "node offline", func() bool {
		n, ok := env.reg.Get("node-proto")
		return !ok || !n.Online
	})
}

func TestNoAuthAndNilMetrics(t *testing.T) {
	// No authenticator and no metrics collector: the tunnel must still work and
	// must never dereference the optional collaborators.
	env := newTestEnv(t, testEnvOptions{noAuth: true, noMetrics: true})
	conn, _, ack := env.registerNode("open-node", 0)
	if !ack.OK {
		t.Fatalf("registration without auth failed: %s", ack.Error)
	}
	st, _ := openStreamOn(t, env.srv, conn, "open-node", env.newOpenRequest("open.example"), 3*time.Second)
	if _, err := st.Write([]byte("data")); err != nil {
		t.Fatalf("write without metrics: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close without metrics: %v", err)
	}
	waitFor(t, 3*time.Second, "stream drained", func() bool { return env.srv.ActiveStreams() == 0 })
	// Ping/Probe helpers need real handshakes but not metrics either.
	if _, err := env.srv.PingNode(context.Background(), "open-node"); err != nil {
		t.Fatalf("PingNode without metrics: %v", err)
	}
}

func TestNewServerValidation(t *testing.T) {
	reg, err := registry.New(nil, nil, "")
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	defer reg.Close()
	if _, err := NewServer(ServerOptions{Registry: reg}); err == nil {
		t.Fatal("NewServer without a listener must fail")
	}
	ln := newFakeListener(transport.KindQUIC)
	if _, err := NewServer(ServerOptions{QUICListener: ln}); err == nil {
		t.Fatal("NewServer without a registry must fail")
	}
	srv, err := NewServer(ServerOptions{Registry: reg, QUICListener: ln})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.maxFrame != protocol.MaxFramePayload {
		t.Fatalf("default max frame = %d", srv.maxFrame)
	}
	if srv.times.Heartbeat != DefaultHeartbeatInterval {
		t.Fatalf("default heartbeat = %s", srv.times.Heartbeat)
	}
	// Close without Serve must release resources and be idempotent.
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("Close without Serve: %v", err)
	}
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("second Close without Serve: %v", err)
	}
}

func TestNodeErrorClearedOnReconnect(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	bad := env.pushHelloConn("node-recover", 0, "wrong")
	ack := readHelloAck(t, bad.ctrl, 3*time.Second)
	if ack.OK {
		t.Fatal("bad token accepted")
	}
	waitFor(t, 3*time.Second, "node error recorded", func() bool {
		return env.srv.NodeLastError("node-recover") != ""
	})
	env.registerNode("node-recover", 1)
	if got := env.srv.NodeLastError("node-recover"); got != "" {
		t.Fatalf("NodeLastError = %q, want empty after successful reconnect", got)
	}
}
