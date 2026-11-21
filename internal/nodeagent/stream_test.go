package nodeagent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

// pushStreamOnLiveConn hands a server initiated stream to the current session.
func pushStreamOnLiveConn(t *testing.T, srv *fakeServer, st transport.Stream) {
	t.Helper()
	c := srv.lastAliveConn()
	if c == nil {
		t.Fatal("没有存活连接，无法下发数据流")
	}
	c.pushStream(st)
}

func waitConnected(t *testing.T, h *agentHarness) {
	t.Helper()
	waitFor(t, 3*time.Second, "连接就绪", func() bool { return h.agent.Status().Connected })
}

// echoOnce writes payload through the tunnel and verifies the target echoes it
// back. Reading happens while writing because the fake pipes are synchronous.
func echoOnce(t *testing.T, st *fakeStream, payload []byte) {
	t.Helper()
	go func() {
		_, _ = st.inW.Write(payload)
	}()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(st.outR, buf); err != nil {
		t.Fatalf("读取回显数据失败: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("回显数据 = %q, want %q", buf, payload)
	}
}

// TestDrainAllowsInflightStream checks the "draining is not an immediate
// disconnect" invariant: after KICK(shutdown) the in-flight stream keeps
// working during DrainTimeout while new streams are rejected.
func TestDrainAllowsInflightStream(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.DrainTimeout = 400 * time.Millisecond
	})
	waitConnected(t, h)
	echoAddr := startEchoServer(t)
	host, port := splitHostPort(t, echoAddr)

	st := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	echoOnce(t, st, []byte("before-kick"))

	srv.pushJSON(protocol.FrameKick, protocol.Kick{Reason: protocol.KickShutdown})
	time.Sleep(40 * time.Millisecond) // let the drain start
	echoOnce(t, st, []byte("during-drain"))

	// New streams must be refused while draining.
	st2 := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st2)
	select {
	case <-st2.resetCh:
	case <-time.After(2 * time.Second):
		t.Fatal("排空期新数据流未被拒绝")
	}
	if err := h.waitErr(t, 3*time.Second); err != nil {
		t.Fatalf("shutdown KICK 后 Run 应返回 nil，得到 %v", err)
	}
}

func TestDataStreamEcho(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)
	echoAddr := startEchoServer(t)
	host, port := splitHostPort(t, echoAddr)

	st := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st)
	code, msg := st.waitResult(t, 3*time.Second)
	if code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s), want 0", code, msg)
	}

	payload := []byte("hello-through-tunnel")
	go func() {
		_, _ = st.inW.Write(payload)
		_ = st.inW.Close()
	}()
	got, err := io.ReadAll(st.outR)
	if err != nil {
		t.Fatalf("读取下行数据失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("回显数据 = %q, want %q", got, payload)
	}
	waitFor(t, 2*time.Second, "数据流完成后流表归零", func() bool {
		return h.agent.Status().Streams == 0
	})

	// STATS must account for the relayed bytes.
	srv.push(protocol.FrameStatsReq, nil)
	deadline := time.After(3 * time.Second)
	for {
		select {
		case st := <-srv.statsCh:
			if st.BytesIn >= uint64(len(payload)) && st.BytesOut >= uint64(len(payload)) && st.ActiveStreams == 0 {
				return
			}
		case <-deadline:
			t.Fatal("STATS 未正确统计流量/活跃流")
		}
	}
}

// TestHalfCloseKeepsReading verifies the half-close rule: after the server FINs
// its side, the node still delivers data that the target sends afterwards.
func TestHalfCloseKeepsReading(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(conn)
		received <- string(data)
		// Write the tail after the node half-closed its write direction.
		_, _ = conn.Write([]byte("tail-data"))
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())

	st := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	// Server sends its request body then FINs (half close).
	go func() {
		_, _ = st.inW.Write([]byte("ping"))
		_ = st.inW.Close()
	}()
	got, err := io.ReadAll(st.outR)
	if err != nil {
		t.Fatalf("读取尾部数据失败: %v", err)
	}
	if string(got) != "tail-data" {
		t.Fatalf("半关闭后尾部数据 = %q, want tail-data", got)
	}
	select {
	case body := <-received:
		if body != "ping" {
			t.Fatalf("目标收到 = %q, want ping", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("目标未收到上行数据")
	}
}

func TestTargetDialRefusedCode2(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.DialTarget = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
	})
	waitConnected(t, h)
	st := openStreamFor(t, "192.0.2.10", 8080)
	pushStreamOnLiveConn(t, srv, st)
	code, msg := st.waitResult(t, 3*time.Second)
	if code != byte(protocol.CodeConnRefused) {
		t.Fatalf("拒绝连接的 OPEN 错误码 = %d (%s), want %d", code, msg, protocol.CodeConnRefused)
	}
}

func TestTargetDialTimeoutCode3(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.OpenDialTimeout = 40 * time.Millisecond
		o.TestHooks.DialTarget = func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	waitConnected(t, h)
	st := openStreamFor(t, "192.0.2.20", 81)
	pushStreamOnLiveConn(t, srv, st)
	code, msg := st.waitResult(t, 3*time.Second)
	if code != byte(protocol.CodeTimeout) {
		t.Fatalf("超时拨号的 OPEN 错误码 = %d (%s), want %d", code, msg, protocol.CodeTimeout)
	}
}

func TestInvalidOpenResets(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)
	st := newFakeStream([]byte{0x09, 0x01, 0x02})
	pushStreamOnLiveConn(t, srv, st)
	select {
	case code := <-st.resetCh:
		if code == 0 {
			t.Fatal("非法 OPEN 头应以非 0 错误码复位")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("非法 OPEN 头未被复位")
	}
}

// TestSessionLostCancelsStream verifies that a transport failure cancels every
// in-flight stream and closes the target connection (no goroutine/fd leak).
func TestSessionLostCancelsStream(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	targetClosed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		buf := make([]byte, 16)
		_, _ = conn.Read(buf)
		close(targetClosed)
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())
	st := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	select {
	case conn := <-accepted:
		_ = conn
	case <-time.After(2 * time.Second):
		t.Fatal("目标未接受连接")
	}
	waitFor(t, 2*time.Second, "活跃流计数为 1", func() bool { return h.agent.Status().Streams == 1 })

	// Simulate the transport connection dying.
	srv.lastAliveConn().CloseWithError(1, "simulated transport failure")
	select {
	case <-targetClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("会话断开后目标连接未被关闭")
	}
	waitFor(t, 3*time.Second, "会话断开后流表归零", func() bool {
		return h.agent.Status().Streams == 0
	})
}

func TestOverloadedStreamRejected(t *testing.T) {
	srv := newFakeServer(t)
	srv.mu.Lock()
	srv.helloAck.Settings.MaxStreams = 1
	srv.mu.Unlock()
	h := startAgent(t, srv, nil)
	waitConnected(t, h)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targetConn := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		targetConn <- conn
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())

	st1 := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st1)
	if code, msg := st1.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("第一条流 OPEN 结果 = %d (%s)", code, msg)
	}
	select {
	case c := <-targetConn:
		t.Cleanup(func() { _ = c.Close() })
	case <-time.After(2 * time.Second):
		t.Fatal("第一条流未建立目标连接")
	}
	waitFor(t, 2*time.Second, "活跃流计数为 1", func() bool { return h.agent.Status().Streams == 1 })

	st2 := openStreamFor(t, host, port)
	pushStreamOnLiveConn(t, srv, st2)
	code, msg := st2.waitResult(t, 3*time.Second)
	if code != byte(protocol.CodeOverloaded) {
		t.Fatalf("流表满时第二条流应返回 overloaded(%d)，实际 %d (%s)", protocol.CodeOverloaded, code, msg)
	}
	_ = errors.Is
}

// TestWriteErrorResetsStream verifies a failed stream write resets the stream
// instead of blocking the relay forever.
func TestWriteErrorResetsStream(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, func(o *Options, cfg *config.ClientConfig) {
		o.TestHooks.WriteBlock = 40 * time.Millisecond
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
		// Send data so the node has to write it back to the tunnel stream.
		_, _ = conn.Write([]byte("response-bytes"))
		time.Sleep(400 * time.Millisecond)
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())
	st := openStreamFor(t, host, port)
	st.writeMu.Lock()
	st.writeErr = errors.New("peer stopped consuming")
	st.writeMu.Unlock()
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	select {
	case code := <-st.resetCh:
		if code == 0 {
			t.Fatal("写失败应以非 0 错误码复位")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("写入失败后未复位数据流")
	}
}
