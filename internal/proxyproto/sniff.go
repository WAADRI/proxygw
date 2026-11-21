package proxyproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	v1PrefixBytes    = []byte(v1Prefix)
	v2SignatureBytes = []byte(v2Signature)
)

// IsProxyHeaderPrefix reports whether b could be the beginning of a PROXY
// protocol v1 or v2 header. It is meant for callers that already have a peek
// buffer (for example a buffered listener) and need to decide whether to hand
// the connection to Parse: partial prefixes such as "P" or "\r\n" return true,
// while data that cannot become a header (for example a TLS ClientHello that
// starts with 0x16, or "GET ") returns false.
func IsProxyHeaderPrefix(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) <= len(v1PrefixBytes) {
		if bytes.HasPrefix(v1PrefixBytes, b) {
			return true
		}
	} else if bytes.HasPrefix(b, v1PrefixBytes) {
		return true
	}
	if len(b) <= len(v2SignatureBytes) {
		return bytes.HasPrefix(v2SignatureBytes, b)
	}
	return bytes.HasPrefix(b, v2SignatureBytes)
}

// Parse sniffs the first bytes of r and parses either a v1 or a v2 PROXY
// protocol header. It reads the minimal number of bytes needed to identify the
// version, and never reads past the end of the header.
//
// When the input does not start with a PROXY protocol header, Parse returns an
// error wrapping ErrNoProxyHeader; the bytes consumed while sniffing (at most
// the 12-byte signature, or the 6-byte v1 prefix) are lost. Callers that must
// preserve those bytes (transparent listeners) should use Conn instead.
func Parse(r io.Reader) (Header, error) {
	if r == nil {
		return Header{}, fmt.Errorf("proxyproto: nil reader")
	}
	h, passthrough, err := sniff(r)
	if err != nil {
		return Header{}, err
	}
	if h != nil {
		return *h, nil
	}
	return Header{}, fmt.Errorf("%w (got %s)", ErrNoProxyHeader, describePrefix(passthrough))
}

// describePrefix renders at most the first 8 sniffed bytes for error messages.
func describePrefix(b []byte) string {
	if len(b) > 8 {
		b = b[:8]
	}
	return fmt.Sprintf("%q", b)
}

// sniff inspects r just far enough to identify a PROXY protocol header. It
// returns one of:
//   - h != nil: a complete header was parsed;
//   - h == nil and err == nil: the bytes are not a PROXY header; passthrough
//     holds every byte that was consumed from r and must be delivered to the
//     application unchanged;
//   - err != nil: the input started like a header but was invalid or
//     truncated.
func sniff(r io.Reader) (h *Header, passthrough []byte, err error) {
	src := &byteSource{r: r}
	first, err := src.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	switch first {
	case 'P':
		// v1 signature is the 6-byte string "PROXY ". A mismatch means this is
		// just an application payload that happens to start with 'P'.
		for _, want := range []byte("ROXY ") {
			b, err := src.ReadByte()
			if err != nil {
				return nil, src.buf, nil
			}
			if b != want {
				return nil, src.buf, nil
			}
		}
		hdr, err := parseV1Line(src.r, src.buf)
		if err != nil {
			return nil, nil, err
		}
		return &hdr, nil, nil
	case v2Signature[0]: // '\r'
		for _, want := range []byte(v2Signature[1:]) {
			b, err := src.ReadByte()
			if err != nil {
				return nil, src.buf, nil
			}
			if b != want {
				return nil, src.buf, nil
			}
		}
		sig := append([]byte(nil), src.buf...)
		hdr, err := readV2Body(src.r, sig)
		if err != nil {
			return nil, nil, err
		}
		return &hdr, nil, nil
	default:
		return nil, src.buf, nil
	}
}

// byteSource reads a stream one byte at a time while remembering the bytes it
// consumed, so a failed sniff attempt can hand them back to the application.
// Reading byte by byte guarantees no byte beyond the header is ever consumed.
type byteSource struct {
	r   io.Reader
	buf []byte
}

func (s *byteSource) ReadByte() (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(s.r, b[:]); err != nil {
		return 0, err
	}
	s.buf = append(s.buf, b[0])
	return b[0], nil
}

// Conn wraps a net.Conn and transparently consumes a PROXY protocol header on
// first use. RemoteAddr and LocalAddr are then reported as the original client
// and server endpoints from the header; when the peer does not send a header
// (or sends LOCAL/UNSPEC) the real socket addresses are used and every byte is
// passed through unchanged.
//
// Parsing happens lazily on the first Read, RemoteAddr, LocalAddr or Header
// call so that callers can wrap the connection in the accept path without
// blocking. The optional read timeout bounds that first use: a header that is
// not complete within it makes the connection fail (the specification
// recommends a few seconds). A read deadline installed by the caller (for
// example by net/http around a TLS handshake) is respected and restored after
// parsing, so wrapping does not weaken the caller's timeout policy. On parse
// failure the error is sticky and every further Read returns it. Closing the
// connection still goes straight to the underlying net.Conn.
//
// Conn is safe for concurrent use by multiple goroutines.
type Conn struct {
	net.Conn
	readTimeout time.Duration

	mu       sync.Mutex
	parsed   bool
	header   Header
	haveHdr  bool
	prefix   []byte
	parseErr error

	dlMu             sync.Mutex
	userReadDeadline time.Time
}

// NewConn wraps c so that the first Read (or address query) consumes an
// optional PROXY protocol v1/v2 header. c must not be nil. A zero readTimeout
// disables the header read deadline; a negative one is rejected.
func NewConn(c net.Conn, readTimeout time.Duration) (*Conn, error) {
	if c == nil {
		return nil, errors.New("proxyproto: cannot wrap a nil net.Conn")
	}
	if readTimeout < 0 {
		return nil, fmt.Errorf("proxyproto: negative header read timeout %v", readTimeout)
	}
	return &Conn{Conn: c, readTimeout: readTimeout}, nil
}

// Read implements io.Reader. The first call parses (and strips) the optional
// PROXY protocol header; when there is no header the sniffed bytes are returned
// first so nothing is lost.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if !c.parsed {
		c.parseLocked()
	}
	if c.parseErr != nil {
		err := c.parseErr
		c.mu.Unlock()
		return 0, err
	}
	if n := copy(p, c.prefix); n > 0 {
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// RemoteAddr returns the original client address from the header, or the
// underlying connection address when the header carries none (LOCAL/UNSPEC, no
// header, or a parse error).
func (c *Conn) RemoteAddr() net.Addr {
	c.mu.Lock()
	if !c.parsed {
		c.parseLocked()
	}
	have, h := c.haveHdr, c.header
	c.mu.Unlock()
	if have {
		if a := h.SourceAddr(); a != nil {
			return a
		}
	}
	return c.Conn.RemoteAddr()
}

// LocalAddr returns the original destination address from the header (the
// address the client connected to, before the fronting proxy), or the
// underlying local address when the header carries none.
func (c *Conn) LocalAddr() net.Addr {
	c.mu.Lock()
	if !c.parsed {
		c.parseLocked()
	}
	have, h := c.haveHdr, c.header
	c.mu.Unlock()
	if have {
		if a := h.DestinationAddr(); a != nil {
			return a
		}
	}
	return c.Conn.LocalAddr()
}

// Header returns the parsed header (zero Header and false when the peer did not
// send one). It triggers the lazy parse like Read does and is mainly useful for
// diagnostics and tests.
func (c *Conn) Header() (Header, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.parsed {
		c.parseLocked()
	}
	return c.header, c.haveHdr
}

// Flushed reports whether the optional header has already been parsed (or the
// stream has been classified as not carrying a header). It is a diagnostics and
// test helper and never triggers parsing.
func (c *Conn) Flushed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.parsed
}

// CloseWrite forwards the TCP half-close (FIN on the write direction) when the
// underlying connection supports it. It lets a wrapped listener connection keep
// the half-close semantics the relay relies on.
func (c *Conn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("proxyproto: underlying connection does not support CloseWrite")
}

// CloseRead forwards the read half-close when the underlying connection
// supports it.
func (c *Conn) CloseRead() error {
	type closeReader interface{ CloseRead() error }
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return errors.New("proxyproto: underlying connection does not support CloseRead")
}

// SetReadDeadline implements net.Conn. It remembers the deadline so the lazy
// header parser can restore it after temporarily installing its own bound.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.userReadDeadline = t
	err := c.Conn.SetReadDeadline(t)
	c.dlMu.Unlock()
	return err
}

// SetDeadline implements net.Conn. The read half of the deadline is remembered
// for the lazy header parser.
func (c *Conn) SetDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.userReadDeadline = t
	err := c.Conn.SetDeadline(t)
	c.dlMu.Unlock()
	return err
}

// parseLocked parses the optional header. It must be called with c.mu held.
func (c *Conn) parseLocked() {
	c.parsed = true
	restoreDeadline := false
	var savedDeadline time.Time
	if c.readTimeout > 0 {
		c.dlMu.Lock()
		savedDeadline = c.userReadDeadline
		headerDeadline := time.Now().Add(c.readTimeout)
		// Never extend a shorter deadline the caller installed earlier.
		if !savedDeadline.IsZero() && savedDeadline.Before(headerDeadline) {
			headerDeadline = savedDeadline
		}
		_ = c.Conn.SetReadDeadline(headerDeadline)
		c.dlMu.Unlock()
		restoreDeadline = true
	}
	hdr, passthrough, err := sniff(c.Conn)
	if restoreDeadline {
		c.dlMu.Lock()
		// A deadline installed while parsing wins over the one we saved.
		if c.userReadDeadline.Equal(savedDeadline) {
			_ = c.Conn.SetReadDeadline(savedDeadline)
		} else {
			_ = c.Conn.SetReadDeadline(c.userReadDeadline)
		}
		c.dlMu.Unlock()
	}
	if err != nil {
		c.parseErr = err
		return
	}
	if hdr == nil {
		c.prefix = passthrough
		return
	}
	c.header = *hdr
	c.haveHdr = true
}
