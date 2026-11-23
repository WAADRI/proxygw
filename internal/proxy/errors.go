package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"proxygw/internal/protocol"
)

// Machine readable failure reasons. They are used in logs, metrics labels and
// audit records; the user facing text is the Chinese message on proxyError.
const (
	reasonNoCandidates          = "no_candidates"
	reasonNoCredential          = "no_credential"
	reasonBadCredential         = "bad_credential"
	reasonCredentialDisabled    = "credential_disabled"
	reasonCredentialExpired     = "credential_expired"
	reasonProtocolNotAllowed    = "protocol_not_allowed"
	reasonSourceNotAllowed      = "source_not_allowed"
	reasonACLDenied             = "acl_denied"
	reasonGlobalConcurrency     = "global_concurrency"
	reasonCredentialConcurrency = "credential_concurrency"
	reasonOpenTimeout           = "open_timeout"
	reasonInvalidTarget         = "invalid_target"
	reasonInvalidRequest        = "invalid_request"
	reasonHeaderTooLarge        = "header_too_large"
	reasonClientGone            = "client_gone"
	reasonInternal              = "internal_error"
	reasonSelectFailure         = "select_failure"
	reasonUpstreamClosed        = "upstream_closed"
	reasonShuttingDown          = "shutting_down"
	reasonAuthMalformed         = "auth_malformed"
	reasonUnsupportedTarget     = "unsupported_target"
	reasonSourceBanned          = "source_banned"
)

// proxyError carries the exact entry protocol representation of a failure: the
// HTTP status, the SOCKS5 reply byte and the reason. It is the only error type
// the handlers write to clients, which keeps the attachment chapter 7 mapping
// in one place.
type proxyError struct {
	status    int  // HTTP status code
	reply     byte // SOCKS5 REP byte
	auth      bool // emit Proxy-Authenticate on HTTP 407
	silent    bool // the client is gone or the server is closing: write nothing
	retryable bool // node side failure that may be retried on another node
	reason    string
	message   string // Chinese user facing message
	cause     error
}

// Error implements the error interface without ever exposing credentials.
func (e *proxyError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("proxy: %s: %v", e.reason, e.cause)
	}
	return "proxy: " + e.reason
}

// Unwrap exposes the cause to errors.Is / errors.As.
func (e *proxyError) Unwrap() error { return e.cause }

func newProxyError(status int, reply byte, reason, message string, cause error) *proxyError {
	return &proxyError{status: status, reply: reply, reason: reason, message: message, cause: cause}
}

// errNoCredential is returned in auth=required mode when no credentials were
// supplied at all. HTTP 407 / SOCKS5 "not allowed".
func errNoCredential() *proxyError {
	e := newProxyError(407, 0x02, reasonNoCredential, "代理需要身份认证，请提供用户名和密码", nil)
	e.auth = true
	return e
}

// errBadCredential is returned when the supplied credentials are invalid.
func errBadCredential() *proxyError {
	e := newProxyError(407, 0x02, reasonBadCredential, "代理认证失败：用户名或密码错误", nil)
	e.auth = true
	return e
}

// errCredentialDisabled is returned when a valid credential has been disabled.
func errCredentialDisabled() *proxyError {
	e := newProxyError(407, 0x02, reasonCredentialDisabled, "代理认证失败：凭据已被禁用", nil)
	e.auth = true
	return e
}

// errCredentialExpired is returned when a valid credential has expired.
func errCredentialExpired() *proxyError {
	e := newProxyError(407, 0x02, reasonCredentialExpired, "代理认证失败：凭据已过期", nil)
	e.auth = true
	return e
}

// errProtocolNotAllowed is returned when the credential is not allowed to use
// the entry protocol of the request.
func errProtocolNotAllowed(protocolName string) *proxyError {
	return newProxyError(403, 0x02, reasonProtocolNotAllowed,
		fmt.Sprintf("当前凭据不允许使用 %s 代理协议", protocolName), nil)
}

// errSourceBanned is returned when the source IP exceeded the auth failure
// threshold. It deliberately does not advertise authentication, so a scanner
// does not immediately retry with another guessed credential.
func errSourceBanned() *proxyError {
	return newProxyError(403, 0x02, reasonSourceBanned,
		"来源 IP 因代理认证失败次数过多被临时封禁，请稍后重试", nil)
}

// errSourceNotAllowed is returned when the client source address does not match
// the credential source CIDRs.
func errSourceNotAllowed() *proxyError {
	return newProxyError(403, 0x02, reasonSourceNotAllowed, "当前来源地址不在凭据允许的网段内", nil)
}

// errACLDenied is returned when the ACL engine rejects the target.
func errACLDenied(cause error) *proxyError {
	return newProxyError(403, 0x02, reasonACLDenied, "目标地址被访问控制规则拒绝", cause)
}

// errNoCandidates is the fail-closed error: the credential has no usable node.
// It must never fall back to the full node set.
func errNoCandidates(cause error) *proxyError {
	return newProxyError(503, 0x04, reasonNoCandidates, "当前没有可用的代理节点", cause)
}

// errGlobalConcurrency is returned when the global entry concurrency limit is
// reached.
func errGlobalConcurrency() *proxyError {
	e := newProxyError(503, 0x01, reasonGlobalConcurrency, "代理入口繁忙，请稍后重试", nil)
	e.retryable = true
	return e
}

// errCredentialConcurrency is returned when the per-credential concurrency
// limit is reached.
func errCredentialConcurrency() *proxyError {
	e := newProxyError(503, 0x01, reasonCredentialConcurrency, "当前凭据的并发连接数已达上限", nil)
	e.retryable = true
	return e
}

// errOpenTimeout is the local stream build timeout (server side); the node
// never answered in time.
func errOpenTimeout(cause error) *proxyError {
	e := newProxyError(504, 0x06, reasonOpenTimeout, "代理节点建流超时", cause)
	e.retryable = true
	return e
}

// errInvalidTarget is returned for malformed or disallowed request targets.
func errInvalidTarget(message string, cause error) *proxyError {
	return newProxyError(400, 0x01, reasonInvalidTarget, message, cause)
}

// errInvalidRequest is returned for malformed entry protocol messages.
func errInvalidRequest(message string, cause error) *proxyError {
	return newProxyError(400, 0x01, reasonInvalidRequest, message, cause)
}

// errHeaderTooLarge is returned when the HTTP request head exceeds the
// configured limit.
func errHeaderTooLarge() *proxyError {
	return newProxyError(400, 0x01, reasonHeaderTooLarge, "代理请求头过长", nil)
}

// errInternal reports a local (server side) processing failure.
func errInternal(cause error) *proxyError {
	e := newProxyError(502, 0x01, reasonInternal, "代理网关内部错误", cause)
	return e
}

// errClientGone is used when the client connection disappeared; nothing must be
// written back.
func errClientGone(cause error) *proxyError {
	e := newProxyError(0, 0x01, reasonClientGone, "客户端连接已断开", cause)
	e.silent = true
	return e
}

// errShuttingDown is returned when new requests arrive while the entry point is
// draining.
func errShuttingDown() *proxyError {
	e := newProxyError(503, 0x01, reasonShuttingDown, "代理网关正在停机", nil)
	e.silent = false
	return e
}

// errUpstreamClosed reports that the node closed the stream before the final
// response was received. It is retryable before the commit point.
func errUpstreamClosed(cause error) *proxyError {
	e := newProxyError(502, 0x01, reasonUpstreamClosed, "代理节点连接中断", cause)
	e.retryable = true
	return e
}

// errSelectFailure reports that the scheduler could not pick a node.
func errSelectFailure(cause error) *proxyError {
	return newProxyError(502, 0x01, reasonSelectFailure, "调度器无法选择节点", cause)
}

// mapOpenFailure maps a stream build failure to the entry protocol
// representation required by the attachment, chapter 7.
func mapOpenFailure(cause error, parent context.Context, openTimedOut bool) *proxyError {
	if parent != nil && parent.Err() != nil {
		return errClientGone(cause)
	}
	if openTimedOut || errors.Is(cause, context.DeadlineExceeded) {
		return errOpenTimeout(cause)
	}
	var pe *protocol.Error
	if errors.As(cause, &pe) {
		return mapOpenCode(pe)
	}
	// Defensive mapping for raw network errors returned by a dialer that does
	// not translate them; adapters should return *protocol.Error.
	var derr *net.DNSError
	if errors.As(cause, &derr) {
		return mapOpenCode(protocol.NewError(protocol.CodeDNS, "%v", cause))
	}
	if errors.Is(cause, syscall.ECONNREFUSED) {
		return mapOpenCode(protocol.NewError(protocol.CodeConnRefused, "%v", cause))
	}
	var nerr net.Error
	if errors.As(cause, &nerr) && nerr.Timeout() {
		return errOpenTimeout(cause)
	}
	if errors.Is(cause, context.Canceled) {
		return errClientGone(cause)
	}
	return mapOpenCode(protocol.NewError(protocol.CodeInternal, "%v", cause))
}

// mapOpenCode maps one OPEN error code, exactly as defined by the attachment.
func mapOpenCode(pe *protocol.Error) *proxyError {
	switch pe.Code {
	case protocol.CodeDNS:
		e := newProxyError(502, 0x04, "dns_failure", "无法解析目标域名", pe)
		e.retryable = true
		return e
	case protocol.CodeConnRefused:
		e := newProxyError(502, 0x05, "connection_refused", "目标拒绝连接", pe)
		e.retryable = true
		return e
	case protocol.CodeTimeout:
		e := newProxyError(504, 0x06, "connection_timeout", "连接目标超时", pe)
		e.retryable = true
		return e
	case protocol.CodePolicy:
		return newProxyError(403, 0x02, "policy_rejected", "代理节点策略拒绝该目标", pe)
	case protocol.CodeOverloaded:
		e := newProxyError(503, 0x01, "overloaded", "代理节点过载", pe)
		e.retryable = true
		return e
	case protocol.CodeProtoUnsupported:
		return newProxyError(405, 0x07, "protocol_unsupported", "代理节点不支持该协议", pe)
	default:
		e := newProxyError(502, 0x01, "internal_error", "代理节点内部错误", pe)
		e.retryable = true
		return e
	}
}

// httpStatus returns the HTTP status to write for this error.
func (e *proxyError) httpStatus() int {
	if e.status == 0 {
		return 502
	}
	return e.status
}

// statusText returns a short English status text for the HTTP status line.
func statusText(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 405:
		return "Method Not Allowed"
	case 407:
		return "Proxy Authentication Required"
	case 431:
		return "Request Header Fields Too Large"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return "Error"
	}
}
