package proxy

import (
	"net"
	"strings"
)

// remoteIP extracts the IP part of a peer address without the port.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// isTimeout reports whether err is an i/o timeout.
func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	var t timeout
	if ok := asInterface(err, &t); ok {
		return t.Timeout()
	}
	return false
}

// asInterface is a tiny errors.As replacement for single method interfaces; it
// walks the wrap chain.
func asInterface[T any](err error, target *T) bool {
	for err != nil {
		if v, ok := err.(T); ok {
			*target = v
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// isClosedError reports whether the error means the peer connection was closed.
func isClosedError(err error) bool {
	if err == nil {
		return true
	}
	if isTimeout(err) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection aborted") ||
		strings.Contains(msg, "connection closed") ||
		strings.Contains(msg, "eof")
}
