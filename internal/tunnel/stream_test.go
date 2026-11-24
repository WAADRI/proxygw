package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

func TestDialStreamSuccess(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-dial", 0)
	req := env.newOpenRequest("example.com")
	st, fs := openStreamOn(t, env.srv, conn, "node-dial", req, 3*time.Second)

	if st.NodeID() != "node-dial" || st.PlaneIndex() != 0 || st.Epoch() != 1 {
		t.Fatalf("stream identity: node=%q plane=%d epoch=%d", st.NodeID(), st.PlaneIndex(), st.Epoch())
	}
	meta, err := fs.waitOpenMeta(time.Second)
	if err != nil {
		t.Fatalf("open meta: %v", err)
	}
	decoded, err := protocol.DecodeOpen(meta)
	if err != nil {
		t.Fatalf("decode OPEN meta: %v", err)
	}
	if decoded.Host != "example.com" || decoded.Port != 443 {
		t.Fatalf("OPEN target = %s, want example.com:443", decoded.Target())
	}
	if decoded.TraceID != req.TraceID {
		t.Fatalf("trace id not preserved")
	}

	// Node -> server data.
	fs.pushData([]byte("response"))
	buf := make([]byte, len("response"))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read from node: %v", err)
	}
	if string(buf) != "response" {
		t.Fatalf("read = %q", buf)
	}
	// Server -> node data.
	if _, err := st.Write([]byte("request")); err != nil {
		t.Fatalf("write to node: %v", err)
	}
	written, err := fs.waitWritten(len("request"), 2*time.Second)
	if err != nil {
		t.Fatalf("node did not receive data: %v", err)
	}
	if string(written) != "request" {
		t.Fatalf("written = %q", written)
	}

	// Half close: CloseWrite keeps the read side usable.
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := fs.waitWriteClosed(2 * time.Second); err != nil {
		t.Fatalf("node did not observe FIN: %v", err)
	}
	fs.pushData([]byte("tail"))
	tail := make([]byte, len("tail"))
	if _, err := io.ReadFull(st, tail); err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if string(tail) != "tail" {
		t.Fatalf("tail = %q", tail)
	}

	// Remote FIN surfaces as a clean EOF, not as a session failure.
	fs.sendEOF()
	if _, err := st.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after remote FIN = %v, want io.EOF", err)
	}
	if got := st.BytesIn(); got != uint64(len("response")+len("tail")) {
		t.Fatalf("BytesIn = %d", got)
	}
	if got := st.BytesOut(); got != uint64(len("request")) {
		t.Fatalf("BytesOut = %d", got)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	waitFor(t, 3*time.Second, "streams drained", func() bool { return env.srv.ActiveStreams() == 0 })
	env.srv.streamMu.Lock()
	registered := len(env.srv.streams)
	env.srv.streamMu.Unlock()
	if registered != 0 {
		t.Fatalf("stream table still has %d entries", registered)
	}
	if v := env.metricValue("tunnel_open_seconds", map[string]string{"node": "node-dial", "transport": "quic"}); v < 1 {
		t.Fatalf("tunnel_open_seconds sample count = %v, want >= 1", v)
	}
	if v := env.metricValue("tunnel_bytes_total", map[string]string{"direction": "in", "node": "node-dial"}); v < float64(len("response")+len("tail")) {
		t.Fatalf("tunnel_bytes_total{in} = %v", v)
	}
	if v := env.metricValue("tunnel_bytes_total", map[string]string{"direction": "out", "node": "node-dial"}); v < float64(len("request")) {
		t.Fatalf("tunnel_bytes_total{out} = %v", v)
	}
}

// TestHalfCloseRemoteFINKeepsWrites verifies that a remote FIN only closes the
// remote write direction and the local write side keeps working.
func TestHalfCloseRemoteFINKeepsWrites(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-half", 0)
	st, fs := openStreamOn(t, env.srv, conn, "node-half", env.newOpenRequest("half.example"), 3*time.Second)
	fs.sendEOF()
	if _, err := st.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after remote FIN = %v, want io.EOF", err)
	}
	if _, err := st.Write([]byte("still-writable")); err != nil {
		t.Fatalf("write after remote FIN: %v", err)
	}
	got, err := fs.waitWritten(len("still-writable"), 2*time.Second)
	if err != nil {
		t.Fatalf("node did not receive data written after remote FIN: %v", err)
	}
	if string(got) != "still-writable" {
		t.Fatalf("written = %q", got)
	}
	_ = st.Close()
	waitFor(t, 3*time.Second, "stream drained", func() bool { return env.srv.ActiveStreams() == 0 })
}

func TestDialStreamOpenTimeout(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Open: 40 * time.Millisecond}})
	conn, _, _ := env.registerNode("node-open-to", 0)

	type result struct{ err error }
	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_, err := env.srv.DialStream(ctx, "node-open-to", env.newOpenRequest("slow.example"))
		ch <- result{err: err}
	}()
	fs := conn.nextOpened(t, 3*time.Second)
	// Deliberately never answer the OPEN.
	select {
	case res := <-ch:
		pe := protocol.AsError(res.err)
		if pe == nil {
			t.Fatalf("expected *protocol.Error, got %v", res.err)
		}
		if pe.Code != protocol.CodeTimeout {
			t.Fatalf("open timeout code = %s, want %s", pe.Code, protocol.CodeTimeout)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialStream did not return after the OPEN timeout")
	}
	waitFor(t, 2*time.Second, "stream reset after open timeout", func() bool { return fs.wasReset() })
	waitFor(t, 2*time.Second, "reservation released", func() bool { return env.srv.ActiveStreams() == 0 })
	if v := env.metricValue("tunnel_open_errors_total", map[string]string{"node": "node-open-to", "code": "connection_timeout"}); v < 1 {
		t.Fatalf("tunnel_open_errors_total{connection_timeout} = %v, want >= 1", v)
	}
}

func TestDialStreamOpenErrorMapping(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-err", 0)

	cases := []struct {
		code protocol.OpenErrorCode
		name string
	}{
		{protocol.CodeDNS, "dns_failure"},
		{protocol.CodeConnRefused, "connection_refused"},
		{protocol.CodeTimeout, "connection_timeout"},
		{protocol.CodePolicy, "policy_rejected"},
		{protocol.CodeOverloaded, "overloaded"},
		{protocol.CodeProtoUnsupported, "protocol_unsupported"},
		{protocol.CodeInternal, "internal_error"},
	}
	for _, tc := range cases {
		err := dialStreamErr(t, env.srv, conn, "node-err", env.newOpenRequest("target.example"), byte(tc.code), "node text "+tc.name, 3*time.Second)
		pe := protocol.AsError(err)
		if pe == nil {
			t.Fatalf("%s: expected *protocol.Error, got %v", tc.name, err)
		}
		if pe.Code != tc.code {
			t.Fatalf("%s: code = %s, want %s", tc.name, pe.Code, tc.code)
		}
		if !strings.Contains(pe.Message, "node text "+tc.name) {
			t.Fatalf("%s: message = %q must contain the node text", tc.name, pe.Message)
		}
	}
	// An unknown error code is folded into the internal error code.
	err := dialStreamErr(t, env.srv, conn, "node-err", env.newOpenRequest("target.example"), 99, "weird", 3*time.Second)
	if pe := protocol.AsError(err); pe == nil || pe.Code != protocol.CodeInternal {
		t.Fatalf("unknown OPEN code mapped to %v, want internal", err)
	}
	// HTTP/SOCKS5 mappings derive from the code and must match chapter 7.
	if got := protocol.CodeTimeout.HTTPStatus(); got != 504 {
		t.Fatalf("CodeTimeout HTTP status = %d", got)
	}
	waitFor(t, 2*time.Second, "streams drained", func() bool { return env.srv.ActiveStreams() == 0 })
	if v := env.metricValue("tunnel_open_errors_total", map[string]string{"node": "node-err", "code": "connection_refused"}); v < 1 {
		t.Fatalf("tunnel_open_errors_total{connection_refused} = %v, want >= 1", v)
	}
}

func TestDialStreamOverloaded(t *testing.T) {
	settings := model.DefaultSettings()
	settings.Limits.MaxStreamsPerNode = 2
	env := newTestEnv(t, testEnvOptions{settings: &settings})
	conn, _, ack := env.registerNode("node-limit", 0)
	if ack.Settings.MaxStreams != 2 {
		t.Fatalf("HELLO_ACK max_streams = %d, want the runtime setting 2", ack.Settings.MaxStreams)
	}
	st1, _ := openStreamOn(t, env.srv, conn, "node-limit", env.newOpenRequest("a.example"), 3*time.Second)
	st2, _ := openStreamOn(t, env.srv, conn, "node-limit", env.newOpenRequest("b.example"), 3*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := env.srv.DialStream(ctx, "node-limit", env.newOpenRequest("c.example"))
	pe := protocol.AsError(err)
	if pe == nil || pe.Code != protocol.CodeOverloaded {
		t.Fatalf("third stream error = %v, want overloaded", err)
	}
	// No transport stream may be opened for an overloaded request.
	select {
	case fs := <-conn.opened:
		t.Fatalf("server opened a transport stream despite the limit: %v", fs)
	default:
	}
	_ = st1.Close()
	_ = st2.Close()
	waitFor(t, 3*time.Second, "streams drained", func() bool { return env.srv.ActiveStreams() == 0 })
}

func TestDialStreamNodeUnavailable(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-unavail", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := env.srv.DialStream(ctx, "ghost", env.newOpenRequest("x.example")); protocol.AsError(err) == nil {
		t.Fatalf("unknown node error = %v, want overloaded error", err)
	}
	if err := env.reg.SetEnabled("node-unavail", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, err := env.srv.DialStream(ctx, "node-unavail", env.newOpenRequest("x.example")); protocol.AsError(err).Code != protocol.CodeOverloaded {
		t.Fatalf("disabled node error = %v, want overloaded", err)
	}
	if err := env.reg.SetEnabled("node-unavail", true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	env.reg.DetachPlane("node-unavail", 0)
	if _, err := env.srv.DialStream(ctx, "node-unavail", env.newOpenRequest("x.example")); protocol.AsError(err).Code != protocol.CodeOverloaded {
		t.Fatalf("offline node error = %v, want overloaded", err)
	}
	_ = conn
}

func TestSessionCloseFailsStreams(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, _, _ := env.registerNode("node-drop", 0)
	st, _ := openStreamOn(t, env.srv, conn, "node-drop", env.newOpenRequest("drop.example"), 3*time.Second)

	readErr := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 4))
		readErr <- err
	}()
	// Abrupt transport loss: the session must fail its streams with an error, not
	// with a clean EOF.
	_ = conn.CloseWithError(1, "network gone")
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("blocked read returned nil after session loss")
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("session loss surfaced as io.EOF, want an error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked read was not released after session loss")
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("write after session loss succeeded")
	}
	waitFor(t, 3*time.Second, "stream drained", func() bool { return env.srv.ActiveStreams() == 0 })
	waitFor(t, 3*time.Second, "node offline", func() bool {
		n, ok := env.reg.Get("node-drop")
		return !ok || !n.Online
	})
	waitFor(t, 3*time.Second, "session torn down", func() bool {
		return len(env.srv.liveSessionsFor("node-drop")) == 0
	})
	if got := env.srv.NodePlaneCount("node-drop"); got != 0 {
		t.Fatalf("plane count = %d, want 0", got)
	}
	if _, _, ok := env.srv.SessionState("node-drop"); ok {
		t.Fatal("SessionState should be !ok after disconnect")
	}
}

func TestKickNode(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Drain: 2 * time.Second}})
	conn, tap, _ := env.registerNode("node-kick", 0)
	st, fs := openStreamOn(t, env.srv, conn, "node-kick", env.newOpenRequest("kick.example"), 3*time.Second)

	if err := env.srv.KickNode("node-kick", protocol.KickRevoked, "token revoked by test"); err != nil {
		t.Fatalf("KickNode: %v", err)
	}
	kickFrame := tap.nextOfType(t, protocol.FrameKick, 3*time.Second)
	var kick protocol.Kick
	if err := protocol.Unmarshal(kickFrame.payload, &kick); err != nil {
		t.Fatalf("decode KICK: %v", err)
	}
	if kick.Reason != protocol.KickRevoked {
		t.Fatalf("KICK reason = %q", kick.Reason)
	}
	// New streams are rejected immediately, in-flight streams keep working.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := env.srv.DialStream(ctx, "node-kick", env.newOpenRequest("new.example")); err == nil {
		t.Fatal("DialStream succeeded on a kicking node")
	}
	fs.pushData([]byte("late data"))
	late := make([]byte, len("late data"))
	if _, err := io.ReadFull(st, late); err != nil {
		t.Fatalf("in-flight stream broken by kick: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("stream close: %v", err)
	}
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("kicked session not closed after its streams drained: %v", err)
	}
	waitFor(t, 3*time.Second, "session torn down", func() bool {
		return len(env.srv.liveSessionsFor("node-kick")) == 0
	})
	waitFor(t, 3*time.Second, "node offline", func() bool {
		n, ok := env.reg.Get("node-kick")
		return !ok || !n.Online
	})
	if err := env.srv.KickNode("node-kick", protocol.KickShutdown, ""); err == nil {
		t.Fatal("KickNode on a disconnected node must fail")
	}
}

func TestResetNodeTakeover(t *testing.T) {
	now := time.Now()
	srv := &Server{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		cooldown:  map[string]time.Time{"node-reset": now.Add(10 * time.Minute)},
		takeovers: map[string][]time.Time{"node-reset": {now}},
	}

	srv.ResetNodeTakeover("node-reset")

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if _, ok := srv.cooldown["node-reset"]; ok {
		t.Fatal("cooldown was not cleared")
	}
	if _, ok := srv.takeovers["node-reset"]; ok {
		t.Fatal("takeover history was not cleared")
	}
}

func TestDrainNode(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Drain: 2 * time.Second}})
	conn, tap, _ := env.registerNode("node-drain", 0)
	st, _ := openStreamOn(t, env.srv, conn, "node-drain", env.newOpenRequest("drain.example"), 3*time.Second)
	if err := env.srv.DrainNode("node-drain"); err != nil {
		t.Fatalf("DrainNode: %v", err)
	}
	kickFrame := tap.nextOfType(t, protocol.FrameKick, 3*time.Second)
	var kick protocol.Kick
	if err := protocol.Unmarshal(kickFrame.payload, &kick); err != nil {
		t.Fatalf("decode KICK: %v", err)
	}
	if kick.Reason != reasonDrain {
		t.Fatalf("KICK reason = %q, want %q", kick.Reason, reasonDrain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := env.srv.DialStream(ctx, "node-drain", env.newOpenRequest("new.example")); err == nil {
		t.Fatal("DialStream succeeded on a draining node")
	}
	_ = st.Close()
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("drained session not closed: %v", err)
	}
	waitFor(t, 3*time.Second, "session torn down", func() bool {
		return len(env.srv.liveSessionsFor("node-drain")) == 0
	})
	if err := env.srv.DrainNode("node-drain"); err == nil {
		t.Fatal("DrainNode on a disconnected node must fail")
	}
}

func TestGracefulCloseDrains(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Drain: 150 * time.Millisecond}})
	conn, tap, _ := env.registerNode("node-shutdown", 0)
	st, fs := openStreamOn(t, env.srv, conn, "node-shutdown", env.newOpenRequest("shutdown.example"), 3*time.Second)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- env.srv.Close(context.Background())
	}()
	kickFrame := tap.nextOfType(t, protocol.FrameKick, 3*time.Second)
	var kick protocol.Kick
	if err := protocol.Unmarshal(kickFrame.payload, &kick); err != nil {
		t.Fatalf("decode KICK: %v", err)
	}
	if kick.Reason != protocol.KickShutdown {
		t.Fatalf("KICK reason = %q, want shutdown", kick.Reason)
	}
	// In-flight streams may finish during the drain window.
	fs.pushData([]byte("draining"))
	buf := make([]byte, len("draining"))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("in-flight stream failed during graceful drain: %v", err)
	}
	_ = st.Close()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return within the drain window")
	}
	if err := env.srv.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := env.waitServe(3 * time.Second); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	waitFor(t, 3*time.Second, "all streams closed", func() bool { return env.srv.ActiveStreams() == 0 })
	if err := env.reg.SetEnabled("node-shutdown", true); err != nil {
		// registry is not closed by the tunnel; must still work.
		t.Fatalf("registry unusable after tunnel close: %v", err)
	}
	// New streams are rejected after shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := env.srv.DialStream(ctx, "node-shutdown", env.newOpenRequest("late.example")); err == nil {
		t.Fatal("DialStream succeeded after server shutdown")
	}
}

func TestConcurrentDialStreams(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	const nodes = 3
	const planes = 2
	type nodePlanes struct {
		conns  []*fakeConn
		counts []*atomic.Int64
	}
	byNode := make([]nodePlanes, nodes)
	for n := 0; n < nodes; n++ {
		nodeID := "node-" + string(rune('a'+n))
		np := nodePlanes{}
		for p := 0; p < planes; p++ {
			conn, _, _ := env.registerNode(nodeID, p)
			count := &atomic.Int64{}
			conn.onOpen = func(fs *fakeStream) {
				count.Add(1)
				go func() {
					if _, err := fs.waitOpenMeta(2 * time.Second); err != nil {
						return
					}
					fs.provideOpenResult(byte(protocol.CodeOK), "")
					go func() {
						// Echo one chunk so callers can exercise the data path.
						fs.pushData([]byte("ok"))
					}()
				}()
			}
			np.conns = append(np.conns, conn)
			np.counts = append(np.counts, count)
		}
		byNode[n] = np
	}

	const workers = 50
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			nodeID := "node-" + string(rune('a'+i%nodes))
			req := protocol.TargetToOpen("target.example", 443, traceID(byte(i+1)), false)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st, err := env.srv.DialStream(ctx, nodeID, req)
			if err != nil {
				failures.Add(1)
				t.Errorf("DialStream %d: %v", i, err)
				return
			}
			if _, err := st.Write([]byte("payload")); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
			if err := st.Close(); err != nil {
				t.Errorf("close %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if got := failures.Load(); got != 0 {
		t.Fatalf("%d/%d DialStream calls failed", got, workers)
	}
	waitFor(t, 3*time.Second, "streams drained", func() bool { return env.srv.ActiveStreams() == 0 })
	var total int64
	for _, np := range byNode {
		for _, c := range np.counts {
			total += c.Load()
		}
	}
	if total != workers {
		t.Fatalf("transport streams opened = %d, want %d", total, workers)
	}
	env.srv.streamMu.Lock()
	left := len(env.srv.streams)
	env.srv.streamMu.Unlock()
	if left != 0 {
		t.Fatalf("stream table has %d entries after all streams closed", left)
	}
}

func TestTraceAffinity(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	var counts [2]*atomic.Int64
	var conns [2]*fakeConn
	for p := 0; p < 2; p++ {
		conn, _, _ := env.registerNode("node-affinity", p)
		counts[p] = &atomic.Int64{}
		idx := p
		conn.onOpen = func(fs *fakeStream) {
			counts[idx].Add(1)
			go func() {
				if _, err := fs.waitOpenMeta(2 * time.Second); err != nil {
					return
				}
				fs.provideOpenResult(byte(protocol.CodeOK), "")
			}()
		}
		conns[p] = conn
	}
	trace := traceID(0x5a)
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		st, err := env.srv.DialStream(ctx, "node-affinity", protocol.TargetToOpen("sticky.example", 443, trace, false))
		cancel()
		if err != nil {
			t.Fatalf("DialStream %d: %v", i, err)
		}
		_ = st.Close()
	}
	// All requests carrying the same trace id must land on the same plane.
	a, b := counts[0].Load(), counts[1].Load()
	if a+b != 10 {
		t.Fatalf("opened streams = %d, want 10", a+b)
	}
	if a != 10 && b != 10 {
		t.Fatalf("trace affinity broken: opened on plane0=%d plane1=%d", a, b)
	}
	_ = conns
}

func TestPingNode(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	_, tap, _ := env.registerNode("node-ping", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rtt, err := env.srv.PingNode(ctx, "node-ping")
	if err != nil {
		t.Fatalf("PingNode: %v", err)
	}
	if rtt < 0 {
		t.Fatalf("RTT = %v, want > 0", rtt)
	}
	// The tunnel echoes PING frames that the node initiates.
	payload := []byte("87654321")
	env.conns[0].ctrl.inject(protocol.FramePing, payload)
	pong := tap.nextOfType(t, protocol.FramePong, 3*time.Second)
	if string(pong.payload) != string(payload) {
		t.Fatalf("PONG payload = %q, want echo %q", pong.payload, payload)
	}
	if _, err := env.srv.PingNode(ctx, "node-missing"); err == nil {
		t.Fatal("PingNode on a disconnected node must fail")
	}
}

func TestProbeNode(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn, tap, _ := env.registerNode("node-probe", 0)
	type result struct {
		res *protocol.ProbeResult
		err error
	}
	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		res, err := env.srv.ProbeNode(ctx, "node-probe", protocol.ProbeTCPing, "example.com:443", []byte("ping"))
		ch <- result{res: res, err: err}
	}()
	frame := tap.nextOfType(t, protocol.FrameProbe, 3*time.Second)
	var probe protocol.Probe
	if err := protocol.Unmarshal(frame.payload, &probe); err != nil {
		t.Fatalf("decode PROBE: %v", err)
	}
	if probe.Kind != protocol.ProbeTCPing || probe.Target != "example.com:443" || string(probe.Payload) != "ping" {
		t.Fatalf("unexpected PROBE: %+v", probe)
	}
	if probe.ID == "" {
		t.Fatal("PROBE id must be set for correlation")
	}
	reply, err := protocol.Marshal(protocol.ProbeResult{ID: probe.ID, OK: true, LatencyMS: 12.5, Detail: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if !conn.ctrl.inject(protocol.FrameProbeRes, reply) {
		t.Fatal("inject PROBE_RESULT failed")
	}
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("ProbeNode: %v", res.err)
		}
		if res.res == nil || !res.res.OK || res.res.LatencyMS != 12.5 || res.res.ID != probe.ID {
			t.Fatalf("unexpected PROBE_RESULT: %+v", res.res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ProbeNode did not return")
	}
	if _, err := env.srv.ProbeNode(ctx, "node-missing", protocol.ProbePing, "x", nil); err == nil {
		t.Fatal("ProbeNode on a disconnected node must fail")
	}
}
