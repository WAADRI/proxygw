package compress_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"proxygw/internal/compress"
)

// TestWrapReadWriteRoundTrip pushes a payload through two wrapped ends of the
// same stream and checks the raw bytes were actually compressed on the wire.
func TestWrapReadWriteRoundTrip(t *testing.T) {
	a, b := netPipe(t)
	defer a.Close()
	defer b.Close()

	ca, err := compress.WrapReadWrite(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	cb, err := compress.WrapReadWrite(b, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}

	payload := randomBytes(t, 256<<10)
	type readResult struct {
		data []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 32<<10)
		for {
			n, rerr := cb.Read(buf)
			if n > 0 {
				got.Write(buf[:n])
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					readCh <- readResult{data: got.Bytes()}
				} else {
					readCh <- readResult{data: got.Bytes(), err: rerr}
				}
				return
			}
		}
	}()

	for off := 0; off < len(payload); off += 32 << 10 {
		end := off + 32<<10
		if end > len(payload) {
			end = len(payload)
		}
		if _, werr := ca.Write(payload[off:end]); werr != nil {
			t.Fatalf("write at %d: %v", off, werr)
		}
	}
	if err := ca.Close(); err != nil {
		t.Fatalf("Close writer side: %v", err)
	}

	select {
	case res := <-readCh:
		if res.err != nil {
			t.Fatalf("peer read: %v", res.err)
		}
		if !bytes.Equal(res.data, payload) {
			t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(res.data), len(payload))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the wrapped stream roundtrip")
	}

	if err := cb.Close(); err != nil {
		t.Fatalf("Close reader side: %v", err)
	}
}

// TestWrapReadWriteHalfClose keeps TCP FIN semantics: CloseWrite ends the zstd
// write direction (peer sees io.EOF) while the read direction stays usable.
// It uses real TCP connections because the peer can only see io.EOF once the
// underlying transport half-closes (net.Pipe has no CloseWrite); that is
// exactly what transport.Stream provides on both QUIC and WS.
func TestWrapReadWriteHalfClose(t *testing.T) {
	a, b := tcpPipe(t)
	defer a.Close()
	defer b.Close()

	ca, err := compress.WrapReadWrite(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	cb, err := compress.WrapReadWrite(b, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	closeWriter, ok := ca.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("wrapped stream does not forward CloseWrite")
	}
	peerCloseWriter, ok := cb.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("wrapped peer does not forward CloseWrite")
	}

	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response := textPayload(8 << 10)

	type readResult struct {
		data []byte
		err  error
	}
	reqCh := make(chan readResult, 1)
	go func() {
		var got []byte
		buf := make([]byte, 4096)
		for {
			n, rerr := cb.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if rerr != nil {
				reqCh <- readResult{data: got, err: rerr}
				return
			}
		}
	}()

	if _, err := ca.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	select {
	case res := <-reqCh:
		if !errors.Is(res.err, io.EOF) {
			t.Fatalf("peer read error = %v, want io.EOF", res.err)
		}
		if !bytes.Equal(res.data, request) {
			t.Fatalf("request mismatch: got %q", res.data)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the half-closed request")
	}
	if _, err := ca.Write([]byte("late")); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Write after CloseWrite = %v, want ErrClosed", err)
	}

	// The read direction must still carry the response.
	writeCh := make(chan error, 1)
	go func() {
		for off := 0; off < len(response); off += 4096 {
			end := off + 4096
			if end > len(response) {
				end = len(response)
			}
			if _, werr := cb.Write(response[off:end]); werr != nil {
				writeCh <- werr
				return
			}
		}
		writeCh <- peerCloseWriter.CloseWrite()
	}()
	gotResp := make([]byte, len(response))
	if _, err := io.ReadFull(ca, gotResp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if err := <-writeCh; err != nil {
		t.Fatalf("peer reply: %v", err)
	}
	if !bytes.Equal(gotResp, response) {
		t.Fatalf("response mismatch: got %d bytes, want %d", len(gotResp), len(response))
	}
	if err := ca.Close(); err != nil {
		t.Fatalf("Close a: %v", err)
	}
	if err := cb.Close(); err != nil {
		t.Fatalf("Close b: %v", err)
	}
}

// tcpPipe returns both ends of a loopback TCP connection with deadlines set, so
// the test exercises real CloseWrite/FIN semantics.
func tcpPipe(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, aerr := ln.Accept()
		ch <- acceptResult{conn: c, err: aerr}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	res := <-ch
	if res.err != nil {
		_ = client.Close()
		t.Fatalf("accept: %v", res.err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for _, c := range []net.Conn{client, res.conn} {
		if derr := c.SetDeadline(deadline); derr != nil {
			t.Fatalf("set deadline: %v", derr)
		}
	}
	return client.(*net.TCPConn), res.conn.(*net.TCPConn)
}

// trackingRW records what the wrapper does to the underlying stream.
type trackingRW struct {
	mu        sync.Mutex
	closed    int
	written   int64
	wire      bytes.Buffer
	resetCode uint64
}

func (t *trackingRW) Read(p []byte) (int, error) { return 0, io.EOF }

func (t *trackingRW) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.written += int64(len(p))
	t.wire.Write(p)
	return len(p), nil
}

func (t *trackingRW) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed++
	return nil
}

func (t *trackingRW) Reset(code uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resetCode = code
	return nil
}

func (t *trackingRW) snapshot() (closes int, written int64, wire []byte, resetCode uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed, t.written, append([]byte(nil), t.wire.Bytes()...), t.resetCode
}

// TestWrapReadWriteCloseIdempotent checks Close closes the underlying stream
// exactly once, releases the codecs and reports later IO as ErrClosed.
func TestWrapReadWriteCloseIdempotent(t *testing.T) {
	rw := &trackingRW{}
	c, err := compress.WrapReadWrite(rw, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := c.Write([]byte("hello tunnel")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v, want io.EOF", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	closes, written, wire, _ := rw.snapshot()
	if closes != 1 {
		t.Fatalf("underlying Close called %d times, want 1", closes)
	}
	if written == 0 || len(wire) == 0 {
		t.Fatal("compressed payload never reached the underlying stream")
	}
	// The wire format must really be zstd (magic number 0xFD2FB528).
	if len(wire) < 4 || binary.LittleEndian.Uint32(wire[:4]) != 0xFD2FB528 {
		t.Fatalf("wire data is not a zstd frame: %x", wire[:min(8, len(wire))])
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}
	if closes, _, _, _ := rw.snapshot(); closes != 1 {
		t.Fatalf("underlying Close called %d times after second Close, want 1", closes)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Read after Close = %v, want ErrClosed", err)
	}
	// Reset is forwarded to the transport stream.
	if rr, ok := c.(interface{ Reset(uint64) error }); ok {
		if err := rr.Reset(7); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		if _, _, _, code := rw.snapshot(); code != 7 {
			t.Fatalf("Reset code = %d, want 7", code)
		}
	} else {
		t.Fatal("wrapped stream does not forward Reset")
	}
}

// TestWrapReadWriteDeadlineForwarding checks the relay can still apply
// timeouts through the compression wrapper.
func TestWrapReadWriteDeadlineForwarding(t *testing.T) {
	a, b := netPipe(t)
	defer a.Close()
	defer b.Close()
	c, err := compress.WrapReadWrite(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	deadlineSetter, ok := c.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		t.Fatal("wrapped stream does not forward SetReadDeadline")
	}
	if err := deadlineSetter.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read should fail after the forwarded read deadline")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("read deadline took %v to trigger", elapsed)
	}
	_ = c.Close()
}

// TestWrapReadWriteNilUnderlying rejects a nil stream.
func TestWrapReadWriteNilUnderlying(t *testing.T) {
	if _, err := compress.WrapReadWrite(nil, compress.DefaultLevel); err == nil {
		t.Fatal("WrapReadWrite(nil) returned no error")
	}
}

// TestWrapReadWriteEmptyStream covers a wrapped stream closed before any payload
// was written: the peer sees EOF and no error.
func TestWrapReadWriteEmptyStream(t *testing.T) {
	a, b := netPipe(t)
	defer a.Close()
	defer b.Close()
	ca, err := compress.WrapReadWrite(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	cb, err := compress.WrapReadWrite(b, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		n, rerr := cb.Read(buf)
		if n != 0 {
			errCh <- errors.New("unexpected payload on an empty stream")
			return
		}
		errCh <- rerr
	}()
	if err := ca.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}
	select {
	case rerr := <-errCh:
		if !errors.Is(rerr, io.EOF) {
			t.Fatalf("peer read = %v, want io.EOF", rerr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for EOF on an empty wrapped stream")
	}
	_ = cb.Close()
}
