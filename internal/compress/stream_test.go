package compress_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"proxygw/internal/compress"
)

// relayStream is the exact capability set the tunnel relay layers (server proxy
// relay and node agent relay) need from a compressed stream. Stream must satisfy
// it directly, without interface probing.
type relayStream interface {
	io.ReadWriteCloser
	CloseWrite() error
	CloseRead() error
	Reset(code uint64) error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// TestStreamCapabilities verifies WrapStream returns the concrete Stream adapter
// that carries half-close, reset and deadline forwarding on its method set.
func TestStreamCapabilities(t *testing.T) {
	a, b := netPipe(t)
	defer a.Close()
	defer b.Close()

	s, err := compress.WrapStream(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("WrapStream: %v", err)
	}
	var pipe relayStream = s
	if pipe == nil {
		t.Fatal("Stream does not satisfy the relay capability set")
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestStreamNilUnderlying rejects a nil stream.
func TestStreamNilUnderlying(t *testing.T) {
	if _, err := compress.WrapStream(nil, compress.DefaultLevel); err == nil {
		t.Fatal("WrapStream(nil) returned no error")
	}
}

// TestStreamRoundTrip4MB pushes a 4 MiB payload through two wrapped ends and
// checks byte fidelity. The payload is incompressible on purpose: this guards the
// tunnel framing, not the compression ratio.
func TestStreamRoundTrip4MB(t *testing.T) {
	a, b := netPipe(t)
	defer a.Close()
	defer b.Close()

	ca, err := compress.WrapStream(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	cb, err := compress.WrapStream(b, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}

	payload := randomBytes(t, 4<<20)
	type readResult struct {
		data []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		got := make([]byte, 0, len(payload))
		buf := make([]byte, 32<<10)
		for {
			n, rerr := cb.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if rerr != nil {
				readCh <- readResult{data: got, err: rerr}
				return
			}
		}
	}()

	const chunk = 32 << 10
	for off := 0; off < len(payload); off += chunk {
		end := off + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if _, werr := ca.Write(payload[off:end]); werr != nil {
			t.Fatalf("write at %d: %v", off, werr)
		}
	}
	// net.Pipe has no half-close, so the peer only observes io.EOF once the
	// writer closes the underlying stream. Close flushes the final frame first.
	if err := ca.Close(); err != nil {
		t.Fatalf("Close writer side: %v", err)
	}

	select {
	case res := <-readCh:
		if !errors.Is(res.err, io.EOF) {
			t.Fatalf("peer read error = %v, want io.EOF", res.err)
		}
		if !bytes.Equal(res.data, payload) {
			t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(res.data), len(payload))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the 4 MiB stream roundtrip")
	}
	_ = cb.Close()
}

// TestStreamHalfCloseOverTCP keeps the TCP FIN semantics through the compressed
// Stream type: CloseWrite flushes the final zstd frame and half-closes only the
// write direction, so the peer sees io.EOF while the reverse direction still
// carries data.
func TestStreamHalfCloseOverTCP(t *testing.T) {
	a, b := tcpPipe(t)
	defer a.Close()
	defer b.Close()

	ca, err := compress.WrapStream(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	cb, err := compress.WrapStream(b, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
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
	if err := ca.CloseWrite(); err != nil {
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

	// The read direction stays usable after the local half close.
	if err := writeInChunks(cb, response, 4096); err != nil {
		t.Fatalf("peer response write: %v", err)
	}
	if err := cb.CloseWrite(); err != nil {
		t.Fatalf("peer CloseWrite: %v", err)
	}
	gotResp := make([]byte, len(response))
	if _, err := io.ReadFull(ca, gotResp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Equal(gotResp, response) {
		t.Fatalf("response mismatch: got %d bytes, want %d", len(gotResp), len(response))
	}
	_ = ca.Close()
	_ = cb.Close()
}

// writeInChunks writes data in chunk sized Write calls.
func writeInChunks(w io.Writer, data []byte, chunk int) error {
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := w.Write(data[off:end]); err != nil {
			return err
		}
	}
	return nil
}

// trackingStreamRW records what the compressed Stream adapter does to the
// underlying stream: half closes, deadlines, resets and closes.
type trackingStreamRW struct {
	mu         sync.Mutex
	wire       bytes.Buffer
	closes     int
	closeWrite int
	closeRead  int
	resetCode  uint64
	deadline   time.Time
	readDL     time.Time
	writeDL    time.Time
}

func (t *trackingStreamRW) Read(p []byte) (int, error) { return 0, io.EOF }

func (t *trackingStreamRW) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.wire.Write(p)
}

func (t *trackingStreamRW) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closes++
	return nil
}

func (t *trackingStreamRW) CloseWrite() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeWrite++
	return nil
}

func (t *trackingStreamRW) CloseRead() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeRead++
	return nil
}

func (t *trackingStreamRW) Reset(code uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resetCode = code
	return nil
}

func (t *trackingStreamRW) SetDeadline(d time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deadline = d
	return nil
}

func (t *trackingStreamRW) SetReadDeadline(d time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.readDL = d
	return nil
}

func (t *trackingStreamRW) SetWriteDeadline(d time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeDL = d
	return nil
}

func (t *trackingStreamRW) snapshot() trackingSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return trackingSnapshot{
		wire:       append([]byte(nil), t.wire.Bytes()...),
		closes:     t.closes,
		closeWrite: t.closeWrite,
		closeRead:  t.closeRead,
		resetCode:  t.resetCode,
		deadline:   t.deadline,
		readDL:     t.readDL,
		writeDL:    t.writeDL,
	}
}

// trackingSnapshot is a copy of trackingStreamRW taken for assertions.
type trackingSnapshot struct {
	wire       []byte
	closes     int
	closeWrite int
	closeRead  int
	resetCode  uint64
	deadline   time.Time
	readDL     time.Time
	writeDL    time.Time
}

// TestStreamCloseWriteFlushesAndForwards verifies CloseWrite flushes the final
// zstd frame to the wire before forwarding the half close to the transport.
func TestStreamCloseWriteFlushesAndForwards(t *testing.T) {
	rw := &trackingStreamRW{}
	s, err := compress.WrapStream(rw, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("WrapStream: %v", err)
	}
	if _, err := s.Write([]byte("tail-before-fin")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	if err := s.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := s.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := s.Reset(9); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	snap := rw.snapshot()
	if snap.closeWrite != 1 {
		t.Fatalf("underlying CloseWrite called %d times, want 1", snap.closeWrite)
	}
	wire := snap.wire
	if len(wire) < 4 {
		t.Fatalf("wire payload too short: %d bytes", len(wire))
	}
	// The flushed tail must be a decodable zstd stream carrying the payload.
	if binary.LittleEndian.Uint32(wire[:4]) != 0xFD2FB528 {
		t.Fatalf("flushed tail is not a zstd frame: %x", wire[:8])
	}
	if got := decodeAll(t, wire, 0); string(got) != "tail-before-fin" {
		t.Fatalf("decoded tail = %q, want tail-before-fin", got)
	}
	if !snap.writeDL.Equal(deadline) || !snap.readDL.Equal(deadline) || !snap.deadline.Equal(deadline) {
		t.Fatalf("deadlines not forwarded: write=%v read=%v all=%v", snap.writeDL, snap.readDL, snap.deadline)
	}
	if snap.resetCode != 9 {
		t.Fatalf("Reset code = %d, want 9", snap.resetCode)
	}

	// Close after CloseWrite must flush (already done), close the underlying
	// stream exactly once and release the codecs.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}
	snap = rw.snapshot()
	if snap.closes != 1 {
		t.Fatalf("underlying Close called %d times, want 1", snap.closes)
	}
	if _, err := s.Write([]byte("after-close")); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
}

// TestStreamCloseFlushesTail covers Close without a prior CloseWrite: the peer
// must still receive the whole payload and a clean io.EOF.
func TestStreamCloseFlushesTail(t *testing.T) {
	a, b := netPipe(t)
	defer b.Close()

	ca, err := compress.WrapStream(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	cb, err := compress.WrapStream(b, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	payload := textPayload(16 << 10)
	writeCh := make(chan error, 1)
	go func() {
		_, werr := ca.Write(payload)
		if werr == nil {
			// Give the peer a moment to start reading before the flush.
			time.Sleep(10 * time.Millisecond)
			werr = ca.Close()
		}
		writeCh <- werr
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cb, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	// The next read must report EOF after the final frame.
	if _, err := cb.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after final frame = %v, want io.EOF", err)
	}
	if err := <-writeCh; err != nil {
		t.Fatalf("writer side: %v", err)
	}
	_ = cb.Close()
}

// TestStreamDeadlineForwardingOverTCP checks the relay can still apply timeout
// deadlines through the typed Stream adapter.
func TestStreamDeadlineForwardingOverTCP(t *testing.T) {
	a, b := tcpPipe(t)
	defer a.Close()
	defer b.Close()
	s, err := compress.WrapStream(a, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("WrapStream: %v", err)
	}
	if err := s.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	if _, err := s.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read should fail after the forwarded read deadline")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("read deadline took %v to trigger", elapsed)
	}
	_ = s.Close()
}

// TestStreamCloseReadStopsReading verifies CloseRead cancels the local read
// direction while Close still releases everything exactly once.
func TestStreamCloseReadStopsReading(t *testing.T) {
	rw := &trackingStreamRW{}
	s, err := compress.WrapStream(rw, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("WrapStream: %v", err)
	}
	if err := s.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if err := s.CloseRead(); err != nil {
		t.Fatalf("second CloseRead must be idempotent, got %v", err)
	}
	if snap := rw.snapshot(); snap.closeRead != 1 {
		t.Fatalf("underlying CloseRead called %d times, want 1", snap.closeRead)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if snap := rw.snapshot(); snap.closes != 1 {
		t.Fatalf("underlying Close called %d times, want 1", snap.closes)
	}
}

// plainRW is a plain net.Conn-ish io.ReadWriteCloser without the optional tunnel
// capabilities; the Stream adapter must not panic and must report the missing
// capabilities as errors.
type plainRW struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *plainRW) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *plainRW) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *plainRW) Close() error {
	_ = p.r.Close()
	return p.w.Close()
}

// TestStreamMissingCapabilities checks that a plain io.ReadWriteCloser yields
// errors instead of panicking when the relay asks for optional capabilities.
func TestStreamMissingCapabilities(t *testing.T) {
	r, w := io.Pipe()
	pr, pw := io.Pipe()
	rw := &plainRW{r: r, w: pw}
	s, err := compress.WrapStream(rw, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("WrapStream: %v", err)
	}
	if err := s.SetReadDeadline(time.Now()); err == nil {
		t.Fatal("SetReadDeadline on a plain stream returned nil error")
	}
	if err := s.SetWriteDeadline(time.Now()); err == nil {
		t.Fatal("SetWriteDeadline on a plain stream returned nil error")
	}
	if err := s.SetDeadline(time.Now()); err == nil {
		t.Fatal("SetDeadline on a plain stream returned nil error")
	}
	if err := s.Reset(3); err == nil {
		t.Fatal("Reset on a plain stream returned nil error")
	}
	_ = w.Close()
	_ = pr.Close()
	_ = s.Close()
}

// ensure the compile time interface assertions stay meaningful even if the
// adapter grows additional methods.
var _ relayStream = (*compress.Stream)(nil)
