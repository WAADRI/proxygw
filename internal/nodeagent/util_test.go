package nodeagent

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

func TestBackoffDuration(t *testing.T) {
	base := time.Minute
	max := 10 * time.Minute
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		if got := backoffDuration(i+1, base, max); got != w {
			t.Fatalf("backoffDuration(%d) = %s, want %s", i+1, got, w)
		}
	}
}

func TestOpenErrorCodeMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want protocol.OpenErrorCode
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "example.invalid"}, protocol.CodeDNS},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, protocol.CodeConnRefused},
		{"refused-text", errors.New("dial tcp 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it"), protocol.CodeConnRefused},
		{"timeout", context.DeadlineExceeded, protocol.CodeTimeout},
		{"other", errors.New("unexpected internal failure"), protocol.CodeInternal},
		{"nil", nil, protocol.CodeOK},
	}
	for _, tc := range cases {
		if got := openErrorCode(tc.err); got != tc.want {
			t.Fatalf("%s: openErrorCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestIsFatalHeuristic(t *testing.T) {
	if IsFatal(nil) {
		t.Fatal("nil 不应视为致命")
	}
	if IsFatal(errors.New("connection reset by peer")) {
		t.Fatal("普通网络错误不应视为致命")
	}
	for _, msg := range []string{
		"tls: pin mismatch expected x got y",
		"x509: certificate signed by unknown authority",
		"authentication failed",
		"unsupported version 9",
	} {
		if !IsFatal(errors.New(msg)) {
			t.Fatalf("致命文本未识别: %q", msg)
		}
	}
	fe := &FatalError{Reason: "服务端拒绝注册", Err: errors.New("bad token")}
	if !IsFatal(fe) {
		t.Fatal("FatalError 必须视为致命")
	}
	if !errors.Is(fe, fe.Err) {
		t.Fatal("FatalError 应可 Unwrap")
	}
	if fe.Error() == "" {
		t.Fatal("FatalError.Error 不应为空")
	}
}

func TestRetryGateSequence(t *testing.T) {
	gate := retryGate{wake: make(chan struct{})}
	ctx := context.Background()
	start := time.Now()
	gate.fail(30*time.Millisecond, 120*time.Millisecond)
	// A concurrent failure inside the same window must not escalate.
	gate.fail(30*time.Millisecond, 120*time.Millisecond)
	if n := gate.failuresCount(); n != 1 {
		t.Fatalf("同一窗口内重复 fail 不应叠加，failures=%d", n)
	}
	if err := gate.wait(ctx); err != nil {
		t.Fatalf("gate.wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("退避等待过短: %s", elapsed)
	}
	// Next window escalates to 60ms.
	gate.fail(30*time.Millisecond, 120*time.Millisecond)
	if n := gate.failuresCount(); n != 2 {
		t.Fatalf("第二个窗口应升级退避，failures=%d", n)
	}
	// A success resets the sequence and wakes waiters.
	gate.success()
	if n := gate.failuresCount(); n != 0 {
		t.Fatalf("success 后 failures=%d", n)
	}
	gate.fail(30*time.Millisecond, 120*time.Millisecond)
	if n := gate.failuresCount(); n != 1 {
		t.Fatalf("重置后 failures=%d", n)
	}
}

func TestTimingDefaults(t *testing.T) {
	cfg := testConfig()
	tr := resolveTimings(cfg, model.DefaultSettings(), nil)
	if tr.fallbackTimeout != time.Second {
		t.Fatalf("fallbackTimeout = %s, want 1s (from config)", tr.fallbackTimeout)
	}
	if tr.helloTimeout != HelloTimeout || tr.handshakeTimeout != HandshakeTimeout {
		t.Fatalf("默认超时未对齐附件常量: %+v", tr)
	}
	if tr.heartbeatInterval != HeartbeatInterval || tr.heartbeatMissLimit != HeartbeatMissLimit {
		t.Fatal("心跳默认值与附件不一致")
	}
	if tr.drainTimeout != DrainTimeout || tr.openDialTimeout != OpenDialTimeout {
		t.Fatal("排空/拨号超时与附件不一致")
	}
	if tr.reProbeInterval != ReProbeInterval || tr.backoffBase != BackoffBase || tr.backoffMax != BackoffMax {
		t.Fatal("重探/退避默认值与附件不一致")
	}
	// The fallback budget is clamped to the documented 1s-5s window.
	cfg.QUICFallback = 0
	if got := resolveTimings(cfg, model.DefaultSettings(), nil).fallbackTimeout; got != FallbackTimeout {
		t.Fatalf("未配置 quic_fallback 时应使用 %s，实际 %s", FallbackTimeout, got)
	}
}

func TestTimingScaleHook(t *testing.T) {
	cfg := testConfig()
	hooks := &TestHooks{Scale: 0.5}
	tr := resolveTimings(cfg, model.DefaultSettings(), hooks)
	if want := HandshakeTimeout / 2; tr.handshakeTimeout != want {
		t.Fatalf("Scale 未生效: handshakeTimeout=%s want %s", tr.handshakeTimeout, want)
	}
	if want := HelloTimeout / 2; tr.helloTimeout != want {
		t.Fatalf("Scale 未生效: helloTimeout=%s want %s", tr.helloTimeout, want)
	}
}

func TestShutdownWithActiveStreamDrains(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.DrainTimeout = 60 * time.Millisecond
	})
	waitConnected(t, h)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		time.Sleep(2 * time.Second)
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())
	st := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	waitFor(t, 2*time.Second, "活跃流计数为 1", func() bool { return h.agent.Status().Streams == 1 })

	start := time.Now()
	h.cancel()
	if err := h.waitErr(t, 3*time.Second); err != nil {
		t.Fatalf("ctx 取消后 Run 应返回 nil，得到 %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("排空耗时过长: %s", elapsed)
	}
}

func TestNoGoroutineLeakAfterClose(t *testing.T) {
	base := runtime.NumGoroutine()
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)

	echoAddr := startEchoServer(t)
	host, port := splitHostPort(t, echoAddr)
	st := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	go func() {
		_, _ = st.inW.Write([]byte("data"))
		_ = st.inW.Close()
	}()
	_, _ = io.Copy(io.Discard, st.outR)

	h.cancel()
	if err := h.waitErr(t, 3*time.Second); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := h.agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		now := runtime.NumGoroutine()
		if now <= base+8 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("关闭后 goroutine 未回落: base=%d now=%d", base, now)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
