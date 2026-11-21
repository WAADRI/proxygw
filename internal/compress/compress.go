// Package compress wraps tunnel payload streams with streaming zstd
// compression.
//
// Compression is negotiated outside this package: the tunnel OPEN header
// carries protocol.FlagCompressed, and both ends then wrap the same logical
// stream, one side with an Encoder (writer) and the other with a Decoder
// (reader). The OPEN header itself and the connection level control stream are
// never compressed, only the raw stream payload is.
//
// Latency matters more than the last few percent of compression ratio for an
// interactive proxy, so the encoder flushes eagerly: a Write that leaves at
// least FlushThreshold bytes buffered flushes immediately, and a background
// ticker flushes whatever is left every FlushInterval. A peer therefore sees
// freshly written data within roughly FlushInterval, even for a tiny packet.
//
// # Concurrency
//
// An Encoder or Decoder is not safe for concurrent use by arbitrary
// goroutines: Write/Flush/Reset/Close (resp. Read/Reset/Close) must be
// serialized by the caller and one Encoder/Decoder belongs to exactly one
// stream. The one exception is the internal flush goroutine: it takes the same
// mutex as Write/Flush/Close, so the public methods themselves must still be
// called from a single goroutine but a background Flush can never race with
// them. Different streams use different Encoders/Decoders and are fully
// independent; the pools below are safe for concurrent use.
package compress

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Compression levels accepted by NewEncoder. Levels outside this range are
// clamped into it instead of being rejected.
const (
	MinLevel     = 1
	MaxLevel     = 3
	DefaultLevel = 1
)

// Flush tuning. Payload buffered in the encoder is pushed to the wire when it
// reaches FlushThreshold, and in any case at most FlushInterval after the last
// Write, so tunnel peers observe low and bounded added latency.
const (
	FlushThreshold = 32 << 10
	FlushInterval  = 50 * time.Millisecond
)

// Errors reported by this package. All returned errors are wrapped with %w so
// callers can use errors.Is.
var (
	// ErrClosed is returned by Write, Flush and Read after Close.
	ErrClosed = errors.New("compress: closed")
	// ErrNotInitialized is returned when a fresh Encoder/Decoder is used
	// before its Reset method attached an underlying reader or writer.
	ErrNotInitialized = errors.New("compress: not initialized")

	// errNilStream guards the public constructors against nil streams.
	errNilStream = errors.New("compress: nil underlying stream")
)

// clampLevel clamps a user supplied level into [MinLevel, MaxLevel].
func clampLevel(level int) int {
	switch {
	case level < MinLevel:
		return MinLevel
	case level > MaxLevel:
		return MaxLevel
	default:
		return level
	}
}

// zstdLevel maps the package level to a klauspost/compress level. Level 1 is
// the latency oriented default; 2 and 3 trade CPU for a better ratio.
func zstdLevel(level int) zstd.EncoderLevel {
	switch clampLevel(level) {
	case 2:
		return zstd.SpeedDefault
	case 3:
		return zstd.SpeedBetterCompression
	default:
		return zstd.SpeedFastest
	}
}

// encoderOptions builds the zstd writer options. A single encoder goroutine and
// a 1 MiB window bound per-stream memory, which matters for the hundreds of
// concurrent streams a tunnel plane can carry.
func encoderOptions(level int) []zstd.EOption {
	return []zstd.EOption{
		zstd.WithEncoderLevel(zstdLevel(level)),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(1 << 20),
		zstd.WithZeroFrames(false),
	}
}

// newZstdWriter is the reusable constructor used by both NewEncoder and a level
// switch in Reset.
func newZstdWriter(level int) (*zstd.Encoder, error) {
	// A nil writer is allowed: Reset(w) attaches the real stream later. Creating
	// the encoder eagerly lets pooled encoders keep their allocation.
	return zstd.NewWriter(nil, encoderOptions(level)...)
}

// Encoder is a reusable streaming zstd encoder writing to an io.Writer.
//
// It is bound to one stream at a time and is not safe for concurrent use by
// arbitrary goroutines (see the package comment). A fresh Encoder needs a call
// to Reset before the first Write. Close flushes the final zstd frame, stops
// the background flusher and is idempotent; the Encoder can be reused
// afterwards with Reset.
type Encoder struct {
	mu       sync.Mutex
	zw       *zstd.Encoder
	level    int
	writable bool
	closed   bool
	// err is a sticky error: once a write/flush failed the stream is broken and
	// every further Write/Flush/Close reports it instead of silently dropping
	// data.
	err      error
	closeErr error
	pending  int // encoded bytes not yet flushed to the underlying writer
	loop     flushLoop
}

// NewEncoder returns an encoder using the given level (clamped to
// [MinLevel, MaxLevel]). Call Reset to attach the output writer.
func NewEncoder(level int) (*Encoder, error) {
	level = clampLevel(level)
	zw, err := newZstdWriter(level)
	if err != nil {
		return nil, fmt.Errorf("compress: new encoder (level %d): %w", level, err)
	}
	return &Encoder{zw: zw, level: level}, nil
}

// Reset attaches a new output writer and starts a fresh zstd stream. It keeps
// the current compression level and is the intended way to reuse an encoder.
// A previously open stream is abandoned unflushed: callers that care about the
// data must Flush or Close first.
func (e *Encoder) Reset(w io.Writer) error {
	return e.reset(w, -1)
}

// reset attaches w and optionally switches the compression level (level < 0
// keeps the current one).
func (e *Encoder) reset(w io.Writer, level int) error {
	if w == nil {
		return errors.New("compress: encoder reset: nil writer")
	}
	e.mu.Lock()
	if level < 0 {
		level = e.level
	}
	level = clampLevel(level)
	if level != e.level {
		// The klauspost encoder level is fixed at construction time. The old
		// encoder is dropped; a pool user must have closed it before returning
		// it, in which case its stream is already finalized.
		e.zw = nil
	}
	if e.zw == nil {
		zw, err := newZstdWriter(level)
		if err != nil {
			e.mu.Unlock()
			return fmt.Errorf("compress: encoder reset (level %d): %w", level, err)
		}
		e.zw = zw
		e.level = level
	}
	e.zw.Reset(w)
	e.writable = true
	e.closed = false
	e.err = nil
	e.closeErr = nil
	e.pending = 0
	e.mu.Unlock()
	e.loop.start(FlushInterval, e.backgroundFlush)
	return nil
}

// Write encodes p into the stream. Low latency flush policy: when at least
// FlushThreshold bytes accumulate the encoder is flushed synchronously, which
// makes Write block until the current block reaches the underlying writer. It
// returns the number of plaintext bytes accepted (always len(p) on success).
func (e *Encoder) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0, fmt.Errorf("compress: write: %w", ErrClosed)
	}
	if !e.writable {
		return 0, fmt.Errorf("compress: write: %w", ErrNotInitialized)
	}
	if e.err != nil {
		return 0, fmt.Errorf("compress: write: %w", e.err)
	}
	if len(p) == 0 {
		return 0, nil
	}
	n, err := e.zw.Write(p)
	e.pending += n
	if err != nil {
		e.err = err
		return n, fmt.Errorf("compress: write: %w", err)
	}
	if e.pending >= FlushThreshold {
		if ferr := e.zw.Flush(); ferr != nil {
			e.err = ferr
			return n, fmt.Errorf("compress: flush after %d buffered bytes: %w", e.pending, ferr)
		}
		e.pending = 0
	}
	return n, nil
}

// Flush pushes all currently buffered plaintext to the underlying writer so the
// peer can decode it immediately.
func (e *Encoder) Flush() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return fmt.Errorf("compress: flush: %w", ErrClosed)
	}
	if !e.writable {
		return fmt.Errorf("compress: flush: %w", ErrNotInitialized)
	}
	return e.flushLocked()
}

func (e *Encoder) flushLocked() error {
	if e.err != nil {
		return fmt.Errorf("compress: flush: %w", e.err)
	}
	if err := e.zw.Flush(); err != nil {
		e.err = err
		return fmt.Errorf("compress: flush: %w", err)
	}
	e.pending = 0
	return nil
}

// backgroundFlush is the 50 ms safety net that bounds how long a small Write
// can stay invisible to the peer.
func (e *Encoder) backgroundFlush() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || !e.writable || e.err != nil || e.pending == 0 {
		return
	}
	if err := e.zw.Flush(); err != nil {
		e.err = err
		return
	}
	e.pending = 0
}

// Close flushes the final block, terminates the zstd stream and stops the
// background flusher. It is idempotent: repeated calls return the same result.
// A write or flush failure is reported here as well, never swallowed.
func (e *Encoder) Close() error {
	e.loop.halt()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return e.closeErr
	}
	e.closed = true
	var first error
	if e.err != nil {
		first = e.err
	}
	if e.writable && e.zw != nil {
		if err := e.zw.Close(); err != nil && first == nil {
			first = err
		}
		// Detach the stream so a pooled encoder does not keep it (and its
		// buffers/connection) alive. Reset(w) re-attaches it on reuse.
		e.zw.Reset(io.Discard)
		e.writable = false
	}
	e.pending = 0
	if first != nil {
		e.closeErr = fmt.Errorf("compress: close encoder: %w", first)
	}
	return e.closeErr
}

// poolRelease detaches a returned encoder. It is used by Pool.PutEncoder for
// encoders that were never closed; the unflushed tail is intentionally
// discarded because a pooled encoder must not write to the old stream anymore.
func (e *Encoder) poolRelease() {
	e.loop.halt()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		if e.writable && e.zw != nil {
			_ = e.zw.Close()
			e.zw.Reset(io.Discard)
			e.writable = false
		}
	}
	e.pending = 0
}

// Decoder is a reusable streaming zstd decoder reading from an io.Reader.
//
// It is bound to one stream at a time and is not safe for concurrent use by
// arbitrary goroutines. A fresh Decoder needs a call to Reset before the first
// Read. Close releases the current reader reference and is idempotent; the
// Decoder can be reused afterwards with Reset.
type Decoder struct {
	mu          sync.Mutex
	dec         *zstd.Decoder
	rc          io.ReadCloser
	initialized bool
	closed      bool
	// poisoned marks a decoder that cannot be reset anymore (defensive: our
	// Close never calls zstd's irreversible Decoder.Close, so this should not
	// happen).
	poisoned bool
	closeErr error
}

// NewDecoder returns a decoder ready for Reset.
func NewDecoder() (*Decoder, error) {
	// A nil reader is allowed by klauspost/compress; Reset attaches the stream.
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
	)
	if err != nil {
		return nil, fmt.Errorf("compress: new decoder: %w", err)
	}
	return &Decoder{dec: dec}, nil
}

// Reset attaches a new input reader and starts decoding a fresh zstd stream. It
// is the intended way to reuse a decoder.
func (d *Decoder) Reset(r io.Reader) error {
	if r == nil {
		return errors.New("compress: decoder reset: nil reader")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.poisoned {
		return fmt.Errorf("compress: decoder reset: %w", ErrClosed)
	}
	// zstd's IOReadCloser wrapper reads without ever closing the underlying
	// reader (the tunnel stream owns its lifetime), which is exactly what a
	// relay needs. Closing that wrapper would call zstd.Decoder.Close, which is
	// irreversible and would defeat pool reuse; Close below therefore only
	// detaches the reader with Decoder.Reset(nil).
	if err := d.dec.Reset(r); err != nil {
		return fmt.Errorf("compress: decoder reset: %w", err)
	}
	d.rc = d.dec.IOReadCloser()
	d.initialized = true
	d.closed = false
	d.closeErr = nil
	return nil
}

// Read returns decompressed plaintext. It returns io.EOF unchanged when the
// peer's zstd stream ends and wraps any decode or underlying read error.
func (d *Decoder) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, fmt.Errorf("compress: read: %w", ErrClosed)
	}
	if !d.initialized {
		return 0, fmt.Errorf("compress: read: %w", ErrNotInitialized)
	}
	if len(p) == 0 {
		return 0, nil
	}
	n, err := d.rc.Read(p)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return n, io.EOF
		}
		return n, fmt.Errorf("compress: read: %w", err)
	}
	return n, nil
}

// Close releases the current reader reference. It never closes the underlying
// reader (the caller owns it) and keeps the zstd decoder reusable, so a pooled
// decoder is reset instead of destroyed. Errors that happened while reading
// were already returned by Read and are not repeated here.
func (d *Decoder) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.closeErr
	}
	d.closed = true
	d.rc = nil
	d.initialized = false
	if err := d.dec.Reset(nil); err != nil && !errors.Is(err, zstd.ErrDecoderClosed) {
		d.poisoned = true
		d.closeErr = fmt.Errorf("compress: close decoder: %w", err)
	}
	return d.closeErr
}

// poolRelease is the defensive variant for Pool.PutDecoder: a decoder that was
// returned without Close is detached so it cannot keep the old reader alive.
func (d *Decoder) poolRelease() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	d.rc = nil
	d.initialized = false
	if err := d.dec.Reset(nil); err != nil && !errors.Is(err, zstd.ErrDecoderClosed) {
		d.poisoned = true
	}
}

// flushLoop owns the background flush goroutine of one Encoder. The zero value
// is ready to use: start launches the goroutine and halt stops it, waiting for
// the goroutine to exit so Close never leaks one.
type flushLoop struct {
	mu      sync.Mutex
	stop    chan struct{}
	done    chan struct{}
	running bool
}

// start launches fn on a ticker. It is a no-op when the loop is already running.
func (l *flushLoop) start(interval time.Duration, fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	l.stop = stop
	l.done = done
	l.running = true
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				fn()
			}
		}
	}()
}

// halt stops the loop and waits for the goroutine. It is idempotent.
func (l *flushLoop) halt() {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return
	}
	stop, done := l.stop, l.done
	l.running = false
	l.mu.Unlock()
	close(stop)
	<-done
}
