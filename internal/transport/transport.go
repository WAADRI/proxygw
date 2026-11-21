// Package transport abstracts the tunnel transport. Two implementations exist:
// QUIC (primary) and WebSocket (fallback). Upper layers only depend on this
// package's interfaces.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"proxygw/internal/protocol"
)

// Kind identifies a transport implementation.
type Kind string

// Supported transports.
const (
	KindQUIC Kind = "quic"
	KindWS   Kind = "ws"
)

// ErrConnClosed is returned after the peer closed the transport connection.
var ErrConnClosed = errors.New("transport: connection closed")

// Stream is one logical bidirectional stream. It hides the difference between
// a native QUIC stream and a multiplexed WebSocket stream.
//
// The OPEN metadata and the build result travel through the transport so the
// tunnel layer can stay path independent: on QUIC WriteOpen writes a
// length-prefixed payload followed by raw stream data; on WS it emits an OPEN
// frame and data sub-frames.
type Stream interface {
	io.Reader
	io.Writer
	// WriteOpen sends the local OPEN metadata to the peer.
	WriteOpen(meta []byte) error
	// ReadOpen blocks until the peer's OPEN metadata arrives.
	ReadOpen(ctx context.Context) ([]byte, error)
	// WriteOpenResult sends the stream build result back to the opener.
	WriteOpenResult(result []byte) error
	// ReadOpenResult blocks until the peer returns the build result.
	ReadOpenResult(ctx context.Context) ([]byte, error)
	// CloseWrite half-closes the local write direction (FIN).
	CloseWrite() error
	// CloseRead cancels the local read direction.
	CloseRead() error
	// Reset terminates the stream abnormally with a transport error code.
	Reset(code uint64) error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// ControlStream is the connection level control channel carrying JSON control
// messages and connection level PING/PONG frames.
type ControlStream interface {
	Send(ctx context.Context, typ protocol.FrameType, payload []byte) error
	Recv(ctx context.Context) (protocol.FrameType, []byte, error)
	Close() error
}

// Conn is one transport connection. A node uses several connections ("planes")
// against the same server; streams are hashed across planes.
type Conn interface {
	Kind() Kind
	// OpenStream opens a locally initiated stream (server -> node for data
	// streams).
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream waits for a peer initiated stream.
	AcceptStream(ctx context.Context) (Stream, error)
	// Control returns the connection level control stream. On QUIC the client
	// opens the first bidirectional stream and the server accepts it; on WS the
	// control channel is implicit.
	Control(ctx context.Context) (ControlStream, error)
	// CloseWithError closes the connection. A graceful close should use error
	// code 0.
	CloseWithError(code uint64, reason string) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	// HandshakeComplete reports whether the underlying TLS handshake finished.
	// Data streams must not be opened before this is true (0-RTT replay rule).
	HandshakeComplete() bool
}

// Listener accepts transport connections on the server side.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
	Addr() net.Addr
	Kind() Kind
}

// Dialer dials transport connections on the node side.
type Dialer interface {
	Dial(ctx context.Context) (Conn, error)
	Close() error
	Kind() Kind
}

// EpochSetter is implemented by transports that embed the session epoch in
// stream ids (the WebSocket path). The tunnel layer calls SetEpoch right after
// a successful HELLO so that late frames from a previous session can be
// detected and dropped.
type EpochSetter interface {
	SetEpoch(epoch uint32)
}

// QUICOptions configures a QUIC transport (listener or dialer).
type QUICOptions struct {
	Addr              string
	TLS               *tls.Config
	ALPN              string
	HandshakeTimeout  time.Duration
	MaxIdleTimeout    time.Duration
	KeepAlivePeriod   time.Duration
	EnableDatagrams   bool
	Allow0RTT         bool
	CongestionControl string // cubic | bbr
	QLogDir           string
	InitialPacketSize uint16
	// MaxIncomingStreams caps concurrent peer streams (server side).
	MaxIncomingStreams int64
}

// WSOptions configures the WebSocket transport.
type WSOptions struct {
	// URL is used by the dialer, Path by the listener handler.
	URL              string
	Path             string
	TLS              *tls.Config
	Header           http.Header
	HandshakeTimeout time.Duration
	MaxFrameBytes    int
	// WriteQueueFrames bounds the per connection data frame queue; callers are
	// backpressured when it is full.
	WriteQueueFrames int
	// ReadLimit is the per-message read limit enforced by the websocket layer.
	ReadLimit int64
	// WindowStall resets a stream whose send window stays exhausted for longer
	// than this budget (attachment chapter 3.7). Zero disables the watchdog.
	WindowStall time.Duration
}
