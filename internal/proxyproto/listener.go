package proxyproto

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// Listener wraps a net.Listener so that every accepted connection consumes an
// optional PROXY protocol header before the application reads from it. This is
// the integration point for servers that run behind a CDN or layer-4 load
// balancer: wrap the plain TCP listener first and then (for example) hand the
// wrapped listener to tls.NewListener, because the PROXY header is sent in
// clear text before the TLS handshake.
//
// The wrapper is transparent: a peer that does not send a header keeps working
// unchanged (the sniffed bytes are replayed). See Conn for the exact semantics
// and for the header read timeout. Read deadlines installed by the consumer
// (for example by net/http around a TLS handshake) are preserved: the header
// parser only installs its own bound temporarily.
//
// When the wrapped listener feeds net/http (panel, wss tunnel), a ReadTimeout of
// zero is a good choice because net/http installs its own TLS handshake and
// header deadlines; pass a positive value for hand-written accept loops that do
// not set deadlines themselves.
type Listener struct {
	net.Listener
	// ReadTimeout bounds the first read that attempts to parse the header. Zero
	// disables the deadline.
	ReadTimeout time.Duration
}

// NewListener wraps ln. Both arguments are validated: ln must not be nil and
// readTimeout must not be negative.
func NewListener(ln net.Listener, readTimeout time.Duration) (*Listener, error) {
	if ln == nil {
		return nil, errors.New("proxyproto: cannot wrap a nil net.Listener")
	}
	if readTimeout < 0 {
		return nil, fmt.Errorf("proxyproto: negative header read timeout %v", readTimeout)
	}
	return &Listener{Listener: ln, ReadTimeout: readTimeout}, nil
}

// Accept implements net.Listener. The accepted connection is returned wrapped;
// parsing stays lazy so Accept never blocks on the peer.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped, err := NewConn(c, l.ReadTimeout)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return wrapped, nil
}

// Unwrap returns the underlying listener, for callers that need the concrete
// type (for example to replace the listener on a hot reload).
func (l *Listener) Unwrap() net.Listener { return l.Listener }
