package nodeagent

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"proxygw/internal/compress"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

// zstdMagic is the little endian magic number of a zstd frame.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// openStreamCompressedFor builds a server initiated fake stream whose OPEN header
// points at host:port and, when compressed is true, carries
// protocol.FlagCompressed.
func openStreamCompressedFor(t *testing.T, host string, port int, compressed bool) *fakeStream {
	t.Helper()
	req := protocol.TargetToOpen(host, port, [protocol.TraceIDLen]byte{9, 8, 7, 6, 5, 4, 3, 2}, compressed)
	meta, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode OPEN: %v", err)
	}
	return newFakeStream(meta)
}

// zstdWireEncode encodes payload as one zstd stream, as the server side of a
// compressed tunnel stream would.
func zstdWireEncode(t *testing.T, payload []byte) []byte {
	t.Helper()
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	var buf bytes.Buffer
	if err := enc.Reset(&buf); err != nil {
		t.Fatalf("encoder Reset: %v", err)
	}
	if _, err := enc.Write(payload); err != nil {
		t.Fatalf("encoder Write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("encoder Close: %v", err)
	}
	return buf.Bytes()
}

// zstdWireDecode decodes the zstd bytes the node wrote towards the server.
func zstdWireDecode(t *testing.T, wire []byte) []byte {
	t.Helper()
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Reset(bytes.NewReader(wire)); err != nil {
		t.Fatalf("decoder Reset: %v", err)
	}
	out, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("decode tunnel output: %v", err)
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("decoder Close: %v", err)
	}
	return out
}

// TestDataStreamCompressed verifies the full compressed roundtrip on a fake
// transport: the payload arriving from the server is zstd, the node decodes it
// before the target, and the target reply is encoded again before it goes back
// to the server.
func TestDataStreamCompressed(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)
	echoAddr := startEchoServer(t)
	host, port := splitHostPort(t, echoAddr)

	st := openStreamCompressedFor(t, host, port, true)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s), want 0", code, msg)
	}

	payload := bytes.Repeat([]byte("compressed-tunnel-payload-"), 8<<10) // ~208 KiB
	go func() {
		_, _ = st.inW.Write(zstdWireEncode(t, payload))
		_ = st.inW.Close()
	}()
	wire, err := io.ReadAll(st.outR)
	if err != nil {
		t.Fatalf("读取下行压缩数据失败: %v", err)
	}
	if !bytes.HasPrefix(wire, zstdMagic) {
		t.Fatalf("下行数据不是 zstd 帧，开头字节 = %x", wire[:min(8, len(wire))])
	}
	if got := zstdWireDecode(t, wire); !bytes.Equal(got, payload) {
		t.Fatalf("压缩往返数据不一致: got %d bytes, want %d", len(got), len(payload))
	}
	waitFor(t, 2*time.Second, "压缩数据流完成后流表归零", func() bool {
		return h.agent.Status().Streams == 0
	})
}

// TestUncompressedOpenIsNotWrapped is the negative control: without
// protocol.FlagCompressed the node must relay raw bytes untouched.
func TestUncompressedOpenIsNotWrapped(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)
	echoAddr := startEchoServer(t)
	host, port := splitHostPort(t, echoAddr)

	st := openStreamCompressedFor(t, host, port, false)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s), want 0", code, msg)
	}
	payload := []byte("plaintext-through-tunnel")
	go func() {
		_, _ = st.inW.Write(payload)
		_ = st.inW.Close()
	}()
	wire, err := io.ReadAll(st.outR)
	if err != nil {
		t.Fatalf("读取下行数据失败: %v", err)
	}
	if bytes.HasPrefix(wire, zstdMagic) {
		t.Fatalf("未压缩 OPEN 的下行数据被错误地压缩了: %x", wire[:min(8, len(wire))])
	}
	if !bytes.Equal(wire, payload) {
		t.Fatalf("未压缩回显 = %q, want %q", wire, payload)
	}
}

// TestCompressedHalfCloseKeepsReading verifies FIN semantics through the
// compressed stream: after the server half-closes, the node still delivers the
// target's tail data, encoded with the final zstd frame flushed by CloseWrite.
func TestCompressedHalfCloseKeepsReading(t *testing.T) {
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
		_, _ = conn.Write([]byte("compressed-tail-data"))
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())

	st := openStreamCompressedFor(t, host, port, true)
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s)", code, msg)
	}
	go func() {
		_, _ = st.inW.Write(zstdWireEncode(t, []byte("compressed-ping")))
		_ = st.inW.Close()
	}()
	wire, err := io.ReadAll(st.outR)
	if err != nil {
		t.Fatalf("读取尾部压缩数据失败: %v", err)
	}
	if got := string(zstdWireDecode(t, wire)); got != "compressed-tail-data" {
		t.Fatalf("半关闭后尾部数据 = %q, want compressed-tail-data", got)
	}
	select {
	case body := <-received:
		if body != "compressed-ping" {
			t.Fatalf("目标收到 = %q, want compressed-ping", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("目标未收到上行压缩数据")
	}
}

// TestCompressedWriteErrorResetsStream verifies a flush failure on the
// compressed path fails the stream (RST) instead of silently truncating data.
func TestCompressedWriteErrorResetsStream(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
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
		_, _ = conn.Write([]byte("response-that-cannot-be-sent"))
		time.Sleep(150 * time.Millisecond)
		_ = conn.Close()
	}()
	host, port := splitHostPort(t, ln.Addr().String())
	st := openStreamCompressedFor(t, host, port, true)
	st.writeMu.Lock()
	st.writeErr = errors.New("peer stopped consuming")
	st.writeMu.Unlock()
	pushStreamOnLiveConn(t, srv, st)
	if code, msg := st.waitResult(t, 3*time.Second); code != 0 {
		t.Fatalf("OPEN 结果 = %d (%s), want 0", code, msg)
	}
	select {
	case code := <-st.resetCh:
		if code == 0 {
			t.Fatal("压缩写失败应以非 0 错误码复位")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("压缩写失败后未复位数据流")
	}
}

// ensure the fake stream really implements the transport contract used above.
var _ transport.Stream = (*fakeStream)(nil)
