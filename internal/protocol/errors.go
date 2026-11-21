package protocol

import "fmt"

// OpenErrorCode is the error code carried by OPEN_ERR frames (WS) or the first
// byte of the OPEN result on QUIC streams. The mapping follows the tunnel
// state machine attachment, chapter 7.
type OpenErrorCode uint8

// Stream build error codes.
const (
	CodeOK               OpenErrorCode = 0
	CodeDNS              OpenErrorCode = 1 // DNS resolution failed
	CodeConnRefused      OpenErrorCode = 2 // connection refused
	CodeTimeout          OpenErrorCode = 3 // connection timeout
	CodePolicy           OpenErrorCode = 4 // policy/ACL/empty group
	CodeOverloaded       OpenErrorCode = 5 // node overloaded
	CodeProtoUnsupported OpenErrorCode = 6 // protocol unsupported
	CodeInternal         OpenErrorCode = 7 // node internal error
)

var codeNames = map[OpenErrorCode]string{
	CodeOK: "ok", CodeDNS: "dns_failure", CodeConnRefused: "connection_refused",
	CodeTimeout: "connection_timeout", CodePolicy: "policy_rejected",
	CodeOverloaded: "overloaded", CodeProtoUnsupported: "protocol_unsupported",
	CodeInternal: "internal_error",
}

// String implements fmt.Stringer.
func (c OpenErrorCode) String() string {
	if s, ok := codeNames[c]; ok {
		return s
	}
	return fmt.Sprintf("code_%d", uint8(c))
}

// Valid reports whether the code is defined by this protocol version.
func (c OpenErrorCode) Valid() bool {
	_, ok := codeNames[c]
	return ok
}

// HTTPStatus maps the code to the proxy entry HTTP status as mandated by the
// attachment. Group-empty (no candidates) is decided before a stream is opened
// and must use 503; see the proxy package for that local mapping.
func (c OpenErrorCode) HTTPStatus() int {
	switch c {
	case CodeDNS, CodeConnRefused:
		return 502
	case CodeTimeout:
		return 504
	case CodePolicy:
		return 403
	case CodeOverloaded:
		return 503
	case CodeProtoUnsupported:
		return 405
	case CodeInternal:
		return 502
	default:
		return 502
	}
}

// SOCKS5Reply maps the code to the RFC 1928 reply byte.
func (c OpenErrorCode) SOCKS5Reply() byte {
	switch c {
	case CodeDNS:
		return 0x04 // host unreachable
	case CodeConnRefused:
		return 0x05 // connection refused
	case CodeTimeout:
		return 0x06 // TTL expired
	case CodePolicy:
		return 0x02 // connection not allowed by ruleset
	case CodeOverloaded:
		return 0x01 // general failure
	case CodeProtoUnsupported:
		return 0x07 // command not supported
	case CodeInternal:
		return 0x01 // general failure
	default:
		return 0x01
	}
}

// Error wraps an open error code with a human readable reason.
type Error struct {
	Code    OpenErrorCode
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code.String()
	}
	return e.Code.String() + ": " + e.Message
}

// NewError builds an *Error.
func NewError(code OpenErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError extracts an *Error from err, or returns nil.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var pe *Error
	if ok := asError(err, &pe); ok {
		return pe
	}
	return nil
}

// asError is errors.As without importing errors twice at call sites.
func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
