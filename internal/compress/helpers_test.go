package compress_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"sync"
	"testing"
	"time"

	"proxygw/internal/compress"
)

// randomBytes returns deterministic incompressible data.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	r := mrand.New(mrand.NewSource(42))
	if _, err := r.Read(b); err != nil {
		t.Fatalf("generate random data: %v", err)
	}
	return b
}

// textPayload returns n bytes of repetitive, realistic proxy traffic text.
func textPayload(n int) []byte {
	var b bytes.Buffer
	b.Grow(n)
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "2026-11-17T12:00:00Z level=info node=node-%d credential=credential-%d trace_id=%08x target=example.com:443 status=200 latency_ms=%d bytes=%d\n",
			i%7, i%13, i*2654435761, i%250, i*90)
	}
	return b.Bytes()[:n]
}

// encodeAll encodes data with a fresh Encoder, writing in chunks.
func encodeAll(t *testing.T, level int, data []byte, chunk int) []byte {
	t.Helper()
	if chunk <= 0 {
		chunk = len(data)
	}
	var buf bytes.Buffer
	enc, err := compress.NewEncoder(level)
	if err != nil {
		t.Fatalf("NewEncoder(%d): %v", level, err)
	}
	if err := enc.Reset(&buf); err != nil {
		t.Fatalf("encoder Reset: %v", err)
	}
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := enc.Write(data[off:end]); err != nil {
			t.Fatalf("encoder Write at %d: %v", off, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("encoder Close: %v", err)
	}
	return buf.Bytes()
}

// decodeAll decodes compressed with a fresh Decoder, reading in readChunk sizes.
func decodeAll(t *testing.T, compressed []byte, readChunk int) []byte {
	t.Helper()
	if readChunk <= 0 {
		readChunk = 32 << 10
	}
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Reset(bytes.NewReader(compressed)); err != nil {
		t.Fatalf("decoder Reset: %v", err)
	}
	var out bytes.Buffer
	buf := make([]byte, readChunk)
	for {
		n, rerr := dec.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("decoder Read: %v", rerr)
		}
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("decoder Close: %v", err)
	}
	return out.Bytes()
}

// lockedBuffer is an io.Writer safe against the encoder's background flusher,
// used to observe when bytes reach the underlying writer.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// waitFor polls cond until it is true or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
