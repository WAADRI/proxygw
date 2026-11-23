package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"proxygw/internal/model"
)

// SOCKS5 protocol constants (RFC 1928 / RFC 1929).
const (
	socks5Version        = 0x05
	socks5MethodNoAuth   = 0x00
	socks5MethodUserPass = 0x02
	socks5MethodNone     = 0xFF
	socks5AuthVersion    = 0x01

	socks5CmdConnect = 0x01
	socks5CmdBind    = 0x02
	socks5CmdUDP     = 0x03

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5ReplySucceeded        = 0x00
	socks5ReplyGeneralFailure   = 0x01
	socks5ReplyNotAllowed       = 0x02
	socks5ReplyHostUnreachable  = 0x04
	socks5ReplyConnRefused      = 0x05
	socks5ReplyTTLExpired       = 0x06
	socks5ReplyCmdNotSupported  = 0x07
	socks5ReplyAtypNotSupported = 0x08
)

// SOCKS5Proxy is the SOCKS5 entry point (RFC 1928 handshake, RFC 1929 username
// / password authentication, CONNECT command only).
type SOCKS5Proxy struct {
	p   *pipeline
	srv *entryServer
}

// NewSOCKS5Proxy validates opts and builds the SOCKS5 entry point.
func NewSOCKS5Proxy(opts Options) (*SOCKS5Proxy, error) {
	p, err := newPipeline(opts)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Proxy{p: p, srv: newEntryServer(p)}, nil
}

// Serve accepts SOCKS5 connections on ln until ctx is cancelled or Close is
// called. It returns nil after a graceful shutdown.
func (s *SOCKS5Proxy) Serve(ctx context.Context, ln net.Listener) error {
	return s.srv.serve(ctx, ln, s.handleConn)
}

// Close stops accepting connections, drains in-flight tunnels up to the
// configured drain timeout (or ctx) and force closes the remainder.
func (s *SOCKS5Proxy) Close(ctx context.Context) error {
	return s.srv.close(ctx)
}

// socksRequest is a parsed SOCKS5 CONNECT/BIND/UDP request.
type socksRequest struct {
	cmd  byte
	host string
	port int
}

// handleConn runs the SOCKS5 handshake and, on success, relays one tunnel.
func (s *SOCKS5Proxy) handleConn(ctx context.Context, conn net.Conn) {
	p := s.p
	start := time.Now()
	sourceIP := remoteIP(conn.RemoteAddr())
	br := bufio.NewReaderSize(conn, 4096)
	t := p.timeouts()

	methods, err := readSocksGreeting(conn, br, t)
	if err != nil {
		p.logger.Warn("SOCKS5 handshake failed", "event", "proxy_socks5_handshake",
			"remote", sourceIP, "error", err.Error())
		var perr *proxyError
		if !errors.As(err, &perr) || perr == nil {
			perr = newProxyError(400, socks5ReplyGeneralFailure, reasonInvalidRequest, "SOCKS5 握手失败", err)
		}
		p.finishRequest(model.ProtoSOCKS5, "", "", "", "", "", perr.reason, start, perr)
		return
	}
	if perr := p.authBanBlocked(sourceIP, model.ProtoSOCKS5); perr != nil {
		_ = writeFull(conn, []byte{socks5Version, socks5MethodNone})
		p.finishRequest(model.ProtoSOCKS5, "", "", "", "", "", perr.reason, start, perr)
		return
	}
	method, ok := s.chooseMethod(methods)
	if !ok {
		// No acceptable method: the RFC requires 0xFF and a close.
		_ = writeFull(conn, []byte{socks5Version, socks5MethodNone})
		p.auditEvent("proxy.auth_failed", map[string]string{
			"protocol": model.ProtoSOCKS5, "source_ip": sourceIP, "reason": reasonNoCredential,
		})
		p.recordAuthFailure(sourceIP, model.ProtoSOCKS5, reasonNoCredential)
		p.finishRequest(model.ProtoSOCKS5, "", "", "", "", "", reasonNoCredential, start, errNoCredential())
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(t.writeBlock))
	if err := writeFull(conn, []byte{socks5Version, method}); err != nil {
		p.finishRequest(model.ProtoSOCKS5, "", "", "", "", "", reasonClientGone, start, errClientGone(err))
		return
	}
	var cred *model.Credential
	if method == socks5MethodUserPass {
		username, password, perr := readSocksUserPass(conn, br, t)
		if perr != nil {
			writeSocksAuthStatus(conn, t.writeBlock, socks5AuthVersion, 0x01)
			p.auditEvent("proxy.auth_failed", map[string]string{
				"protocol": model.ProtoSOCKS5, "source_ip": sourceIP, "reason": reasonAuthMalformed,
			})
			p.recordAuthFailure(sourceIP, model.ProtoSOCKS5, reasonAuthMalformed)
			p.finishRequest(model.ProtoSOCKS5, "", "", "", "", "", perr.reason, start, perr)
			return
		}
		cred, perr = p.verifyCredential(username, password, model.ProtoSOCKS5, sourceIP)
		if perr != nil {
			// RFC 1929: a non-zero status byte signals authentication failure.
			writeSocksAuthStatus(conn, t.writeBlock, socks5AuthVersion, 0x02)
			p.finishRequest(model.ProtoSOCKS5, "", "", username, "", "", perr.reason, start, perr)
			return
		}
		if err := writeSocksAuthStatus(conn, t.writeBlock, socks5AuthVersion, 0x00); err != nil {
			p.finishRequest(model.ProtoSOCKS5, "", "", username, credentialID(cred), "", reasonClientGone, start, errClientGone(err))
			return
		}
	}

	sreq, perr := readSocksRequest(conn, br, t)
	if perr != nil {
		if !perr.silent {
			s.writeReply(conn, t, perr.reply)
		}
		p.finishRequest(model.ProtoSOCKS5, "", "", credentialUsername(cred), credentialID(cred), "", perr.reason, start, perr)
		return
	}
	traceID, traceHex := newTrace()
	target := model.RequestTarget{
		Protocol:   model.ProtoSOCKS5,
		Host:       sreq.host,
		Port:       sreq.port,
		SourceIP:   sourceIP,
		Credential: credentialID(cred),
		Username:   credentialUsername(cred),
		TraceID:    traceHex,
	}
	track := p.trackRequest(model.ProtoSOCKS5, target.String(), target.Credential)
	var trackErr *proxyError
	defer func() { track.finish(trackErr) }()
	if sreq.cmd != socks5CmdConnect {
		// BIND, UDP ASSOCIATE and unknown commands are not supported.
		s.writeReply(conn, t, socks5ReplyCmdNotSupported)
		perr = newProxyError(405, socks5ReplyCmdNotSupported, "command_not_supported",
			"仅支持 SOCKS5 CONNECT 命令", nil)
		trackErr = perr
		p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		return
	}
	if cred != nil {
		if perr := p.authorizeCredential(cred, sourceIP, model.ProtoSOCKS5); perr != nil {
			s.writeReply(conn, t, perr.reply)
			trackErr = perr
			p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
			return
		}
	}
	release, perr := p.acquire(cred, model.ProtoSOCKS5, traceHex, target.Username, sourceIP)
	if perr != nil {
		s.writeReply(conn, t, perr.reply)
		trackErr = perr
		p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		return
	}
	defer release()
	candidates, perr := p.resolveCandidates(cred, model.ProtoSOCKS5, traceHex, target.Username)
	if perr != nil {
		s.writeReply(conn, t, perr.reply)
		trackErr = perr
		p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		return
	}
	if perr := p.checkACL(target, traceHex, target.Username); perr != nil {
		s.writeReply(conn, t, perr.reply)
		trackErr = perr
		p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		return
	}
	out, perr := p.openStream(ctx, SelectRequest{
		CredentialID: target.Credential,
		Username:     target.Username,
		SourceIP:     sourceIP,
		Protocol:     model.ProtoSOCKS5,
		Target:       target,
	}, candidates, traceID, traceHex, p.maxAttempts(true), track)
	if perr != nil {
		s.writeReply(conn, t, perr.reply)
		trackErr = perr
		p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		return
	}
	// Commit point.
	track.serving(out.Node.ID)
	if err := writeSocksReply(conn, t.writeBlock, socks5ReplySucceeded); err != nil {
		out.Conn.Close()
		trackErr = errClientGone(err)
		p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, out.Node.ID, reasonClientGone, start, trackErr)
		return
	}
	upBytes, downBytes, rerr := relayDuplex(ctx, clientHalf(conn, br), streamHalf(out.Conn, nil), relayConfig{
		idle:        t.idle,
		writeBlock:  t.writeBlock,
		linger:      t.linger,
		upLimiter:   p.limiterUp(target.Credential, out.Node.ID),
		downLimiter: p.limiterDown(target.Credential, out.Node.ID),
	})
	p.addBytes("in", out.Node.ID, upBytes)
	p.addBytes("out", out.Node.ID, downBytes)
	track.addBytes(upBytes, downBytes)
	result := "ok"
	var failure *proxyError
	if rerr != nil && !isClosedError(rerr) && !isTimeout(rerr) {
		result = "relay_error"
		failure = errUpstreamClosed(rerr)
	}
	trackErr = failure
	p.finishRequest(model.ProtoSOCKS5, traceHex, target.String(), target.Username, target.Credential, out.Node.ID, result, start, failure)
}

// chooseMethod selects the authentication method from the client offer.
func (s *SOCKS5Proxy) chooseMethod(methods []byte) (byte, bool) {
	offered := func(want byte) bool {
		for _, method := range methods {
			if method == want {
				return true
			}
		}
		return false
	}
	switch s.p.authMode {
	case model.AuthNone:
		if offered(socks5MethodNoAuth) {
			return socks5MethodNoAuth, true
		}
		return 0, false
	case model.AuthOptional:
		if offered(socks5MethodUserPass) {
			return socks5MethodUserPass, true
		}
		if offered(socks5MethodNoAuth) {
			return socks5MethodNoAuth, true
		}
		return 0, false
	default: // model.AuthRequired
		if offered(socks5MethodUserPass) {
			return socks5MethodUserPass, true
		}
		return 0, false
	}
}

// readSocksGreeting reads the version / method offer.
func readSocksGreeting(conn net.Conn, br *bufio.Reader, t timeouts) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(t.readHeader))
	var header [2]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return nil, err
	}
	if header[0] != socks5Version {
		return nil, newProxyError(0, socks5ReplyGeneralFailure, reasonInvalidRequest,
			"SOCKS5 版本错误", errors.New("unsupported SOCKS version"))
	}
	count := int(header[1])
	if count == 0 {
		return nil, newProxyError(0, socks5ReplyGeneralFailure, reasonInvalidRequest,
			"SOCKS5 未提供认证方法", nil)
	}
	methods := make([]byte, count)
	if _, err := io.ReadFull(br, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// readSocksUserPass reads the RFC 1929 username / password sub-negotiation.
func readSocksUserPass(conn net.Conn, br *bufio.Reader, t timeouts) (username, password string, perr *proxyError) {
	_ = conn.SetReadDeadline(time.Now().Add(t.readHeader))
	var header [2]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return "", "", errClientGone(err)
	}
	if header[0] != socks5AuthVersion {
		return "", "", newProxyError(0, socks5ReplyNotAllowed, reasonAuthMalformed,
			"SOCKS5 用户名密码认证版本错误", nil)
	}
	ulen := int(header[1])
	if ulen == 0 {
		return "", "", newProxyError(0, socks5ReplyNotAllowed, reasonAuthMalformed,
			"SOCKS5 用户名为空", nil)
	}
	user := make([]byte, ulen)
	if _, err := io.ReadFull(br, user); err != nil {
		return "", "", errClientGone(err)
	}
	var plen [1]byte
	if _, err := io.ReadFull(br, plen[:]); err != nil {
		return "", "", errClientGone(err)
	}
	if plen[0] == 0 {
		return "", "", newProxyError(0, socks5ReplyNotAllowed, reasonAuthMalformed,
			"SOCKS5 密码为空", nil)
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(br, pass); err != nil {
		return "", "", errClientGone(err)
	}
	return string(user), string(pass), nil
}

// readSocksRequest reads a SOCKS5 request after authentication.
func readSocksRequest(conn net.Conn, br *bufio.Reader, t timeouts) (*socksRequest, *proxyError) {
	_ = conn.SetReadDeadline(time.Now().Add(t.readHeader))
	var header [4]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return nil, errClientGone(err)
	}
	if header[0] != socks5Version {
		return nil, newProxyError(0, socks5ReplyGeneralFailure, reasonInvalidRequest,
			"SOCKS5 请求版本错误", nil)
	}
	if header[2] != 0x00 {
		return nil, newProxyError(0, socks5ReplyGeneralFailure, reasonInvalidRequest,
			"SOCKS5 请求保留字段非零", nil)
	}
	req := &socksRequest{cmd: header[1]}
	switch header[3] {
	case socks5AtypIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(br, addr[:]); err != nil {
			return nil, errClientGone(err)
		}
		req.host = net.IP(addr[:]).String()
	case socks5AtypIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(br, addr[:]); err != nil {
			return nil, errClientGone(err)
		}
		req.host = net.IP(addr[:]).String()
	case socks5AtypDomain:
		length, err := br.ReadByte()
		if err != nil {
			return nil, errClientGone(err)
		}
		if length == 0 {
			return nil, newProxyError(0, socks5ReplyAtypNotSupported, reasonInvalidTarget,
				"SOCKS5 域名长度为 0", nil)
		}
		domain := make([]byte, int(length))
		if _, err := io.ReadFull(br, domain); err != nil {
			return nil, errClientGone(err)
		}
		req.host = string(domain)
	default:
		return nil, newProxyError(0, socks5ReplyAtypNotSupported, reasonInvalidTarget,
			"SOCKS5 地址类型不支持", nil)
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return nil, errClientGone(err)
	}
	req.port = int(binary.BigEndian.Uint16(portBytes[:]))
	if req.port == 0 {
		return nil, newProxyError(0, socks5ReplyGeneralFailure, reasonInvalidTarget,
			"SOCKS5 目标端口为 0", nil)
	}
	if perr := validateTarget(req.host, req.port); perr != nil {
		return nil, newProxyError(0, socks5ReplyGeneralFailure, perr.reason, perr.message, perr.cause)
	}
	return req, nil
}

// writeSocksAuthStatus writes the RFC 1929 sub-negotiation reply.
func writeSocksAuthStatus(conn net.Conn, writeBlock time.Duration, version, status byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(writeBlock))
	return writeFull(conn, []byte{version, status})
}

// writeSocksReply writes a SOCKS5 reply with BND.ADDR 0.0.0.0 and port 0.
func writeSocksReply(conn net.Conn, writeBlock time.Duration, reply byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(writeBlock))
	buf := []byte{socks5Version, reply, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	return writeFull(conn, buf)
}

// writeReply maps a pipeline error to a SOCKS5 reply byte.
func (s *SOCKS5Proxy) writeReply(conn net.Conn, t timeouts, reply byte) {
	if err := writeSocksReply(conn, t.writeBlock, reply); err != nil {
		return
	}
}
