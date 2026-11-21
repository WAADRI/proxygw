package compress_test

import (
	"bytes"
	"io"
	"runtime/debug"
	"testing"

	"proxygw/internal/compress"
)

// TestDefaultPoolSingleton: the process wide pool used by WrapReadWrite is a
// stable instance.
func TestDefaultPoolSingleton(t *testing.T) {
	if compress.DefaultPool() == nil {
		t.Fatal("DefaultPool() returned nil")
	}
	if compress.DefaultPool() != compress.DefaultPool() {
		t.Fatal("DefaultPool() must return the same pool instance")
	}
}

// TestPoolReusesEncoders checks both the functional reuse contract (the pooled
// encoder is reset and produces a decodable stream, also across a level change)
// and the identity contract: a Put/Get cycle on one goroutine hands the same
// encoder back. GC is paused for the identity part because sync.Pool may drop
// its items at any collection.
func TestPoolReusesEncoders(t *testing.T) {
	pool := &compress.Pool{}
	const cycles = 4
	var buffers []*bytes.Buffer
	var payloads [][]byte

	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var prev *compress.Encoder
	reused := 0
	for i := 0; i < cycles; i++ {
		buf := new(bytes.Buffer)
		enc, err := pool.GetEncoder(buf, compress.DefaultLevel)
		if err != nil {
			t.Fatalf("GetEncoder: %v", err)
		}
		if i > 0 && enc == prev {
			reused++
		}
		prev = enc
		data := textPayload(8 << 10)
		if _, err := enc.Write(data); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		pool.PutEncoder(enc)
		buffers = append(buffers, buf)
		payloads = append(payloads, data)
	}
	if !raceEnabled && reused != cycles-1 {
		t.Fatalf("pool reused the encoder %d/%d times in a tight Put/Get loop", reused, cycles-1)
	}
	for i := range buffers {
		if got := decodeAll(t, buffers[i].Bytes(), 4096); !bytes.Equal(got, payloads[i]) {
			t.Fatalf("roundtrip %d mismatch after pool reuse", i)
		}
	}

	// A level change on a pooled encoder must recreate the zstd writer and stay
	// functional.
	level := compress.MaxLevel
	var levelBuffers []*bytes.Buffer
	var levelPayloads [][]byte
	for i := 0; i < 3; i++ {
		buf := new(bytes.Buffer)
		enc, err := pool.GetEncoder(buf, level)
		if err != nil {
			t.Fatalf("GetEncoder(level %d): %v", level, err)
		}
		data := textPayload(16 << 10)
		if _, err := enc.Write(data); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		pool.PutEncoder(enc)
		levelBuffers = append(levelBuffers, buf)
		levelPayloads = append(levelPayloads, data)
		level = 1 + (level % compress.MaxLevel)
	}
	for i := range levelBuffers {
		if got := decodeAll(t, levelBuffers[i].Bytes(), 4096); !bytes.Equal(got, levelPayloads[i]) {
			t.Fatalf("roundtrip mismatch after level change %d", i)
		}
	}
}

// TestPoolReusesDecoders: a returned decoder is reused and can decode a fresh
// stream.
func TestPoolReusesDecoders(t *testing.T) {
	pool := &compress.Pool{}
	data := textPayload(16 << 10)
	compressed := encodeAll(t, compress.DefaultLevel, data, 4096)

	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var prev *compress.Decoder
	reused := 0
	const cycles = 4
	for i := 0; i < cycles; i++ {
		dec, err := pool.GetDecoder(bytes.NewReader(compressed))
		if err != nil {
			t.Fatalf("GetDecoder: %v", err)
		}
		if i > 0 && dec == prev {
			reused++
		}
		prev = dec
		got, rerr := io.ReadAll(dec)
		if rerr != nil {
			t.Fatalf("ReadAll: %v", rerr)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("roundtrip %d mismatch after decoder pool reuse", i)
		}
		if err := dec.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		pool.PutDecoder(dec)
	}
	if !raceEnabled && reused != cycles-1 {
		t.Fatalf("pool reused the decoder %d/%d times in a tight Put/Get loop", reused, cycles-1)
	}
}

// TestPoolNilAndInvalidArguments covers defensive handling of bad input.
func TestPoolNilAndInvalidArguments(t *testing.T) {
	pool := &compress.Pool{}
	if _, err := pool.GetEncoder(nil, compress.DefaultLevel); err == nil {
		t.Fatal("GetEncoder(nil) returned no error")
	}
	if _, err := pool.GetDecoder(nil); err == nil {
		t.Fatal("GetDecoder(nil) returned no error")
	}
	// Putting nil must not panic.
	pool.PutEncoder(nil)
	pool.PutDecoder(nil)
}

// TestPoolPutUnclosedEncoder documents the defensive poolPut path: an encoder
// returned without Close is detached and reusable, with the tail discarded.
func TestPoolPutUnclosedEncoder(t *testing.T) {
	pool := &compress.Pool{}
	var first bytes.Buffer
	enc, err := pool.GetEncoder(&first, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("GetEncoder: %v", err)
	}
	if _, err := enc.Write([]byte("dropped tail")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Return without Close: allowed, the unflushed tail is intentionally dropped.
	pool.PutEncoder(enc)

	var second bytes.Buffer
	again, err := pool.GetEncoder(&second, compress.DefaultLevel)
	if err != nil {
		t.Fatalf("GetEncoder again: %v", err)
	}
	data := []byte("fresh-stream")
	if _, err := again.Write(data); err != nil {
		t.Fatalf("Write fresh stream: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatalf("Close fresh stream: %v", err)
	}
	pool.PutEncoder(again)
	got := decodeAll(t, second.Bytes(), 16)
	if !bytes.Equal(got, data) {
		t.Fatalf("fresh stream after poolPut mismatch: got %q, want %q", got, data)
	}
}

// TestPoolPutUnclosedDecoder detaches a decoder returned without Close.
func TestPoolPutUnclosedDecoder(t *testing.T) {
	pool := &compress.Pool{}
	data := textPayload(8 << 10)
	compressed := encodeAll(t, compress.DefaultLevel, data, 4096)
	dec, err := pool.GetDecoder(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("GetDecoder: %v", err)
	}
	// Return without Close.
	pool.PutDecoder(dec)

	again, err := pool.GetDecoder(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("GetDecoder again: %v", err)
	}
	got, rerr := io.ReadAll(again)
	if rerr != nil {
		t.Fatalf("ReadAll: %v", rerr)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("decoder reuse after poolPut mismatch")
	}
	if err := again.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	pool.PutDecoder(again)
}
