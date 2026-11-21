package transport

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// WebSocket transport flow control defaults (design attachment 3.3).
//
// Every logical stream starts with a 256 KiB receive window and every
// transport connection with an 8 MiB connection level receive window. A
// receiver hands WINDOW credit back to the sender once the application has
// consumed at least WindowUpdateThreshold bytes. The same values are used for
// both directions independently.
//
// The QUIC path relies on QUIC's native flow control instead and does not use
// these constants.
const (
	DefaultStreamWindow   = 256 * 1024
	DefaultConnWindow     = 8 * 1024 * 1024
	WindowUpdateThreshold = 32 * 1024
)

// Transport level errors. Implementations wrap these with operator readable
// context using fmt.Errorf("%w") so callers can classify failures with
// errors.Is.
var (
	// ErrListenerClosed is returned by Listener.Accept after Listener.Close.
	ErrListenerClosed = errors.New("transport: listener closed")
	// ErrStreamClosed is returned when an operation uses a stream direction
	// that was already closed locally (CloseWrite/CloseRead).
	ErrStreamClosed = errors.New("transport: stream closed")
	// ErrStreamReset is the sentinel wrapped by StreamResetError. It
	// distinguishes an abnormal stream termination (RST) from a normal EOF.
	ErrStreamReset = errors.New("transport: stream reset")
	// ErrProtocol reports a peer protocol violation. The transport closes the
	// connection after returning it, so upper layers treat it as fatal for the
	// whole connection.
	ErrProtocol = errors.New("transport: protocol violation")
	// ErrControlClosed is returned by ControlStream operations after the
	// control stream (or the whole connection) was closed.
	ErrControlClosed = errors.New("transport: control stream closed")
	// ErrOpenUnavailable is returned by ReadOpen when the stream carries no
	// peer OPEN metadata (a locally opened WebSocket stream never receives an
	// OPEN frame from the peer).
	ErrOpenUnavailable = errors.New("transport: peer OPEN metadata unavailable")
	// ErrWindowStall reports that a stream's send window stayed exhausted for
	// longer than the configured stall budget, so the stream was reset.
	ErrWindowStall = errors.New("transport: window stall")
	// ErrAcceptQueueFull is returned to a freshly upgraded peer when the
	// listener accept queue is full.
	ErrAcceptQueueFull = errors.New("transport: accept queue full")
)

// StreamResetError describes an abnormally reset stream. It wraps
// ErrStreamReset so errors.Is(err, ErrStreamReset) works, and carries the
// application reset code for error mapping (attachment chapter 7).
type StreamResetError struct {
	// Code is the transport level reset code supplied by Reset.
	Code uint64
	// Remote reports whether the peer reset the stream (as opposed to a local
	// Reset call).
	Remote bool
}

// Error implements error.
func (e *StreamResetError) Error() string {
	side := "local"
	if e.Remote {
		side = "peer"
	}
	return fmt.Sprintf("transport: stream reset by %s (code %d)", side, e.Code)
}

// Unwrap exposes ErrStreamReset to errors.Is.
func (e *StreamResetError) Unwrap() error { return ErrStreamReset }

// deadlineError wraps os.ErrDeadlineExceeded so net.Error semantics survive
// while the error text says which operation timed out.
func deadlineError(op string) error {
	return fmt.Errorf("transport: %s: %w", op, os.ErrDeadlineExceeded)
}

// minDeadline returns the earlier non-zero deadline of a and b.
func minDeadline(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

// satAdd adds two non-negative credits, saturating instead of overflowing.
func satAdd(a, b int64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if b <= 0 {
		return a
	}
	if a > maxInt64-b {
		return maxInt64
	}
	return a + b
}
