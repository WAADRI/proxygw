package compress_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"proxygw/internal/compress"
)

// TestEncoderDecoderRoundTrip4MB guards the 4 MiB tunnel payload case.
func TestEncoderDecoderRoundTrip4MB(t *testing.T) {
	data := randomBytes(t, 4<<20)
	compressed := encodeAll(t, compress.DefaultLevel, data, 64<<10)
	got := decodeAll(t, compressed, 64<<10)
	if !bytes.Equal(got, data) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

// TestTextCompressionRatio verifies that compressible tunnel traffic really
// shrinks: text must come out below 60% of its original size.
func TestTextCompressionRatio(t *testing.T) {
	data := textPayload(512 << 10)
	compressed := encodeAll(t, compress.MinLevel, data, 32<<10)
	ratio := float64(len(compressed)) / float64(len(data))
	if ratio >= 0.60 {
		t.Fatalf("compression ratio %.3f >= 0.60 (compressed %d, original %d)", ratio, len(compressed), len(data))
	}
	t.Logf("text compression ratio: %.3f (%d -> %d bytes)", ratio, len(data), len(compressed))
	got := decodeAll(t, compressed, 4096)
	if !bytes.Equal(got, data) {
		t.Fatalf("text roundtrip mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

// TestCompressionLevels checks every accepted level (and clamping of invalid
// levels) produces a decodable stream.
func TestCompressionLevels(t *testing.T) {
	data := textPayload(128 << 10)
	for _, level := range []int{-100, 0, 1, 2, 3, 4, 100} {
		compressed := encodeAll(t, level, data, 8192)
		got := decodeAll(t, compressed, 32<<10)
		if !bytes.Equal(got, data) {
			t.Fatalf("level %d roundtrip mismatch", level)
		}
	}
	if _, err := compress.NewEncoder(-5); err != nil {
		t.Fatalf("NewEncoder(-5) should clamp, got error: %v", err)
	}
}

// TestChunkedWrites writes the payload in 100 chunks.
func TestChunkedWrites(t *testing.T) {
	data := textPayload(64 << 10)
	var buf bytes.Buffer
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if err := enc.Reset(&buf); err != nil {
		t.Fatalf("encoder Reset: %v", err)
	}
	chunk := len(data) / 100
	if chunk == 0 {
		chunk = 1
	}
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := enc.Write(data[off:end]); err != nil {
			t.Fatalf("Write chunk at %d: %v", off, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := decodeAll(t, buf.Bytes(), 1024)
	if !bytes.Equal(got, data) {
		t.Fatalf("chunked roundtrip mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

// TestFlushPushesBufferedData verifies the explicit Flush contract.
func TestFlushPushesBufferedData(t *testing.T) {
	data := []byte("flush-me-please")
	w := &lockedBuffer{}
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if err := enc.Reset(w); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := enc.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := enc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if w.Len() == 0 {
		t.Fatal("Flush did not push buffered data to the underlying writer")
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := decodeAll(t, w.Bytes(), 16)
	if !bytes.Equal(got, data) {
		t.Fatalf("flushed roundtrip mismatch: got %q, want %q", got, data)
	}
}

// TestThresholdTriggersSynchronousFlush: a Write that fills FlushThreshold
// bytes must flush before returning, without waiting for the 50ms ticker.
func TestThresholdTriggersSynchronousFlush(t *testing.T) {
	payload := randomBytes(t, compress.FlushThreshold)
	w := &lockedBuffer{}
	enc, err := compress.NewEncoder(compress.MinLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if err := enc.Reset(w); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := enc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Read immediately after Write returns: the ticker cannot have fired yet on
	// a normal machine, so a non-empty writer proves the synchronous flush path.
	if w.Len() == 0 {
		t.Fatal("Write of FlushThreshold bytes returned without flushing")
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := decodeAll(t, w.Bytes(), 8192); !bytes.Equal(got, payload) {
		t.Fatalf("threshold roundtrip mismatch")
	}
}

// trackReadCloser is an io.ReadCloser that records Close calls.
type trackReadCloser struct {
	r      io.Reader
	closed int
	mu     sync.Mutex
}

func (c *trackReadCloser) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *trackReadCloser) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *trackReadCloser) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// TestDecoderDoesNotCloseUnderlyingReader: the tunnel stream owns the reader,
// Decoder.Close must only release its reference.
func TestDecoderDoesNotCloseUnderlyingReader(t *testing.T) {
	data := textPayload(64 << 10)
	compressed := encodeAll(t, compress.DefaultLevel, data, 4096)
	src := &trackReadCloser{r: bytes.NewReader(compressed)}
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Reset(src); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	got, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(data))
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := src.closeCount(); n != 0 {
		t.Fatalf("Decoder.Close closed the underlying reader %d time(s)", n)
	}
}

// TestEncoderCloseIdempotentAndWriteAfterClose covers the encoder lifecycle.
func TestEncoderCloseIdempotentAndWriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if err := enc.Reset(&buf); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := enc.Write([]byte("payload")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}
	if _, err := enc.Write([]byte("x")); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
	if err := enc.Flush(); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Flush after Close = %v, want ErrClosed", err)
	}
}

// TestEncoderRequiresReset: a fresh Encoder has no writer yet.
func TestEncoderRequiresReset(t *testing.T) {
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if _, err := enc.Write([]byte("x")); !errors.Is(err, compress.ErrNotInitialized) {
		t.Fatalf("Write before Reset = %v, want ErrNotInitialized", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close without Reset: %v", err)
	}
}

// TestDecoderCloseIdempotentAndReadAfterClose covers the decoder lifecycle.
func TestDecoderCloseIdempotentAndReadAfterClose(t *testing.T) {
	compressed := encodeAll(t, compress.DefaultLevel, textPayload(32<<10), 4096)
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Reset(bytes.NewReader(compressed)); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	partial := make([]byte, 8)
	if _, err := dec.Read(partial); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}
	if _, err := dec.Read(partial); !errors.Is(err, compress.ErrClosed) {
		t.Fatalf("Read after Close = %v, want ErrClosed", err)
	}
}

// TestDecoderRequiresReset: a fresh Decoder has no reader yet.
func TestDecoderRequiresReset(t *testing.T) {
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if _, err := dec.Read(make([]byte, 8)); !errors.Is(err, compress.ErrNotInitialized) {
		t.Fatalf("Read before Reset = %v, want ErrNotInitialized", err)
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("Close without Reset: %v", err)
	}
}

// TestDecoderRejectsCorruptStream makes sure a corrupt stream is an error, not
// silent data loss.
func TestDecoderRejectsCorruptStream(t *testing.T) {
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	// strings.Reader has no Bytes method, so the decoder uses the streaming path.
	if err := dec.Reset(strings.NewReader("this is definitely not a zstd frame")); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := io.ReadAll(dec); err == nil {
		t.Fatal("decoding garbage returned no error")
	}
	_ = dec.Close()
}

// errWriter fails every write.
type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

// TestEncoderPropagatesWriteErrors verifies compression failures are never
// swallowed: Write, subsequent Write and Close all report the write error.
func TestEncoderPropagatesWriteErrors(t *testing.T) {
	boom := errors.New("boom")
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if err := enc.Reset(errWriter{err: boom}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	payload := randomBytes(t, compress.FlushThreshold)
	if _, err := enc.Write(payload); err == nil || !errors.Is(err, boom) {
		t.Fatalf("Write = %v, want wrapped boom", err)
	}
	if _, err := enc.Write([]byte("more")); err == nil || !errors.Is(err, boom) {
		t.Fatalf("second Write = %v, want sticky wrapped boom", err)
	}
	if err := enc.Close(); err == nil || !errors.Is(err, boom) {
		t.Fatalf("Close = %v, want wrapped boom", err)
	}
}

// TestEncoderResetReuse reuses a closed encoder for a second stream.
func TestEncoderResetReuse(t *testing.T) {
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	first := textPayload(48 << 10)
	var b1 bytes.Buffer
	if err := enc.Reset(&b1); err != nil {
		t.Fatalf("Reset 1: %v", err)
	}
	if _, err := enc.Write(first); err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	second := randomBytes(t, 48<<10)
	var b2 bytes.Buffer
	if err := enc.Reset(&b2); err != nil {
		t.Fatalf("Reset 2: %v", err)
	}
	if _, err := enc.Write(second); err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close 2: %v", err)
	}

	if got := decodeAll(t, b1.Bytes(), 8192); !bytes.Equal(got, first) {
		t.Fatalf("first stream mismatch after reuse")
	}
	if got := decodeAll(t, b2.Bytes(), 8192); !bytes.Equal(got, second) {
		t.Fatalf("second stream mismatch after reuse")
	}
}

// TestDecoderResetReuse reuses a closed decoder for a second stream.
func TestDecoderResetReuse(t *testing.T) {
	first := textPayload(48 << 10)
	second := randomBytes(t, 48<<10)
	comp1 := encodeAll(t, compress.DefaultLevel, first, 4096)
	comp2 := encodeAll(t, compress.DefaultLevel, second, 4096)

	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	readAll := func(compressed []byte, want []byte) {
		t.Helper()
		if err := dec.Reset(bytes.NewReader(compressed)); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		got, rerr := io.ReadAll(dec)
		if rerr != nil {
			t.Fatalf("ReadAll: %v", rerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("stream mismatch: got %d bytes, want %d", len(got), len(want))
		}
		if cerr := dec.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	}
	readAll(comp1, first)
	readAll(comp2, second)
}

// TestSmallWriteVisibleWithin200ms is the latency guard: a single small packet
// must reach the peer through the background flusher well within 200 ms.
func TestSmallWriteVisibleWithin200ms(t *testing.T) {
	server, client := netPipe(t)
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if err := enc.Reset(server); err != nil {
		t.Fatalf("encoder Reset: %v", err)
	}
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Reset(client); err != nil {
		t.Fatalf("decoder Reset: %v", err)
	}
	defer func() {
		// Close the underlying pipe first so a pending final flush cannot block
		// on a reader that already stopped.
		_ = server.Close()
		_ = client.Close()
		_ = enc.Close()
		_ = dec.Close()
	}()

	payload := []byte("low-latency-probe")
	type readResult struct {
		data []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		var got []byte
		for len(got) < len(payload) {
			n, rerr := dec.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if rerr != nil {
				readCh <- readResult{got, rerr}
				return
			}
		}
		readCh <- readResult{got, nil}
	}()

	if _, err := enc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	start := time.Now()
	select {
	case res := <-readCh:
		elapsed := time.Since(start)
		if res.err != nil {
			t.Fatalf("read: %v", res.err)
		}
		if !bytes.Equal(res.data, payload) {
			t.Fatalf("payload mismatch: got %q, want %q", res.data, payload)
		}
		if elapsed > 200*time.Millisecond {
			t.Fatalf("small packet took %v to become readable, want <= 200ms", elapsed)
		}
		t.Logf("small packet readable after %v", elapsed)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the background flush")
	}
}

// TestNoGoroutineLeakAfterClose verifies the per-encoder flush goroutine is
// stopped by Close.
func TestNoGoroutineLeakAfterClose(t *testing.T) {
	payload := textPayload(16 << 10)
	compressed := encodeAll(t, compress.DefaultLevel, payload, 4096)
	base := runtime.NumGoroutine()
	for i := 0; i < 16; i++ {
		enc, err := compress.NewEncoder(compress.DefaultLevel)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		if err := enc.Reset(io.Discard); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		if _, err := enc.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		dec, err := compress.NewDecoder()
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		if err := dec.Reset(bytes.NewReader(compressed)); err != nil {
			t.Fatalf("decoder Reset: %v", err)
		}
		if err := dec.Close(); err != nil {
			t.Fatalf("decoder Close: %v", err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return runtime.NumGoroutine() <= base })
}

// TestConcurrentStreams runs independent encode/decode pipelines in parallel;
// the race detector guards encoder/decoder stream independence and pooling.
func TestConcurrentStreams(t *testing.T) {
	const streams = 8
	pool := compress.DefaultPool()
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := textPayload(256 << 10)
			for j := range data {
				data[j] ^= byte(i)
			}
			var buf bytes.Buffer
			enc, err := pool.GetEncoder(&buf, compress.DefaultLevel)
			if err != nil {
				errs <- err
				return
			}
			for off := 0; off < len(data); off += 8192 {
				end := off + 8192
				if end > len(data) {
					end = len(data)
				}
				if _, err := enc.Write(data[off:end]); err != nil {
					errs <- err
					pool.PutEncoder(enc)
					return
				}
			}
			if err := enc.Close(); err != nil {
				errs <- err
				pool.PutEncoder(enc)
				return
			}
			pool.PutEncoder(enc)

			dec, err := pool.GetDecoder(bytes.NewReader(buf.Bytes()))
			if err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(dec)
			if err != nil {
				errs <- err
				pool.PutDecoder(dec)
				return
			}
			_ = dec.Close()
			pool.PutDecoder(dec)
			if !bytes.Equal(got, data) {
				errs <- io.ErrUnexpectedEOF
				return
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent stream failed: %v", err)
		}
	}
}

// netPipe is a tiny indirection so tests do not repeat deadline setup.
func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(15 * time.Second)
	if err := a.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := b.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return a, b
}
