package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxygw/internal/model"
)

// httpRequest is the parsed head of one HTTP proxy request. The body is read
// directly from the client connection by the dedicated body readers below.
type httpRequest struct {
	method        string
	requestURI    string
	protoMajor    int
	protoMinor    int
	header        http.Header
	host          string
	url           *url.URL
	contentLength int64 // >= 0, or -1 when chunked
	chunked       bool
	keepAlive     bool
	body          io.Reader
}

func (r *httpRequest) hasBody() bool { return r.chunked || r.contentLength > 0 }

// requestPlan is everything needed to forward one request upstream.
type requestPlan struct {
	method         string
	uri            string
	hostHeader     string
	header         http.Header
	targetHost     string
	targetPort     int
	key            string
	contentLength  int64
	chunked        bool
	hasBody        bool
	upgrade        bool
	keepAlive      bool
	expectContinue bool
}

// upstreamStream is one reusable tunnel stream towards a target.
type upstreamStream struct {
	node     *model.Node
	conn     StreamConn
	br       *bufio.Reader
	key      string
	traceHex string
}

// newUpstreamStream wraps a successfully opened stream.
func newUpstreamStream(out *openResult, key, traceHex string) *upstreamStream {
	return &upstreamStream{
		node:     out.Node,
		conn:     out.Conn,
		br:       bufio.NewReaderSize(out.Conn, 16*1024),
		key:      key,
		traceHex: traceHex,
	}
}

// close releases the upstream stream.
func (u *upstreamStream) close() {
	if u == nil || u.conn == nil {
		return
	}
	_ = u.conn.Close()
	u.conn = nil
}

// setReadDeadline applies a read deadline when the stream supports it.
func (u *upstreamStream) setReadDeadline(deadline time.Time) {
	if u == nil || u.conn == nil {
		return
	}
	if d, ok := u.conn.(readDeadliner); ok {
		_ = d.SetReadDeadline(deadline)
	}
}

// setWriteDeadline applies a write deadline when the stream supports it.
func (u *upstreamStream) setWriteDeadline(deadline time.Time) {
	if u == nil || u.conn == nil {
		return
	}
	if d, ok := u.conn.(writeDeadliner); ok {
		_ = d.SetWriteDeadline(deadline)
	}
}

// HTTPProxy is the HTTP and CONNECT entry point.
type HTTPProxy struct {
	p   *pipeline
	srv *entryServer
}

// NewHTTPProxy validates opts and builds the HTTP entry point.
func NewHTTPProxy(opts Options) (*HTTPProxy, error) {
	p, err := newPipeline(opts)
	if err != nil {
		return nil, err
	}
	return &HTTPProxy{p: p, srv: newEntryServer(p)}, nil
}

// Serve accepts proxy connections on ln until ctx is cancelled or Close is
// called. It returns nil after a graceful shutdown.
func (h *HTTPProxy) Serve(ctx context.Context, ln net.Listener) error {
	return h.srv.serve(ctx, ln, h.handleConn)
}

// Close stops accepting connections, drains in-flight requests up to the
// configured drain timeout (or ctx) and force closes the remainder.
func (h *HTTPProxy) Close(ctx context.Context) error {
	return h.srv.close(ctx)
}

// handleConn runs the HTTP proxy request loop of one client connection.
func (h *HTTPProxy) handleConn(ctx context.Context, conn net.Conn) {
	br := bufio.NewReaderSize(conn, 32*1024)
	var current *upstreamStream
	defer func() {
		if current != nil {
			current.close()
		}
	}()
	for {
		req, perr := h.readRequest(conn, br)
		if perr != nil {
			if !perr.silent {
				h.writeErrorResponse(conn, perr)
			}
			return
		}
		if h.srv.isClosing() {
			deadline := errShuttingDown()
			h.p.finishRequest(model.ProtoHTTP, "", "", "", "", "", reasonShuttingDown, time.Now(), deadline)
			h.writeErrorResponse(conn, deadline)
			return
		}
		if req.method == http.MethodConnect {
			if current != nil {
				current.close()
				current = nil
			}
			h.serveConnect(ctx, conn, br, req)
			return
		}
		keep, next := h.serveHTTP(ctx, conn, br, req, current)
		current = next
		if !keep {
			return
		}
	}
}

// readRequest reads and parses one request head with the read-head timeout.
func (h *HTTPProxy) readRequest(conn net.Conn, br *bufio.Reader) (*httpRequest, *proxyError) {
	t := h.p.timeouts()
	_ = conn.SetReadDeadline(time.Now().Add(t.readHeader))
	req, err := parseRequestHead(br, h.p.maxHeaderBytes)
	if err != nil {
		var perr *proxyError
		if errors.As(err, &perr) {
			return nil, perr
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isClosedError(err) || isTimeout(err) {
			return nil, errClientGone(err)
		}
		return nil, errInvalidRequest("无法解析代理请求", err)
	}
	return req, nil
}

// readHeadBlock reads the request line and header lines up to and including the
// terminating empty line, enforcing the maximum head size.
func readHeadBlock(br *bufio.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxHeaderBytes
	}
	var block bytes.Buffer
	block.Grow(512)
	for {
		line, err := br.ReadSlice('\n')
		if block.Len()+len(line) > maxBytes {
			return nil, errHeaderTooLarge()
		}
		block.Write(line)
		if err == nil {
			trimmed := line
			if n := len(trimmed); n > 0 && trimmed[n-1] == '\n' {
				trimmed = trimmed[:n-1]
			}
			if n := len(trimmed); n > 0 && trimmed[n-1] == '\r' {
				trimmed = trimmed[:n-1]
			}
			if len(trimmed) == 0 {
				return block.Bytes(), nil
			}
			if trimmed[0] == ' ' || trimmed[0] == '\t' {
				return nil, errInvalidRequest("请求头不支持续行", nil)
			}
			continue
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return nil, err
	}
}

// parseRequestHead parses one HTTP proxy request head and attaches the body
// reader that streams directly from br.
func parseRequestHead(br *bufio.Reader, maxHeaderBytes int) (*httpRequest, error) {
	block, err := readHeadBlock(br, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	req, headErr := parseHead(block)
	if headErr != nil {
		return nil, headErr
	}
	switch {
	case req.chunked:
		req.body = newChunkedBody(br)
	case req.contentLength > 0:
		req.body = &fixedBody{br: br, remaining: req.contentLength}
	}
	return req, nil
}

// parseHead parses the request line and header block.
func parseHead(block []byte) (*httpRequest, *proxyError) {
	newline := bytes.IndexByte(block, '\n')
	if newline < 0 {
		return nil, errInvalidRequest("代理请求行不完整", nil)
	}
	requestLine := strings.TrimSuffix(string(block[:newline]), "\r")
	rest := block[newline+1:]
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return nil, errInvalidRequest("代理请求行格式错误", nil)
	}
	req := &httpRequest{
		method:     parts[0],
		requestURI: parts[1],
		header:     make(http.Header),
	}
	if !validHeaderToken(req.method) {
		return nil, errInvalidRequest("代理请求方法非法", nil)
	}
	major, minor, ok := parseHTTPVersion(parts[2])
	if !ok || major != 1 {
		return nil, errInvalidRequest("仅支持 HTTP/1.x 代理请求", nil)
	}
	req.protoMajor, req.protoMinor = major, minor
	for len(rest) > 0 {
		var line []byte
		if idx := bytes.IndexByte(rest, '\n'); idx >= 0 {
			line = rest[:idx]
			rest = rest[idx+1:]
		} else {
			return nil, errInvalidRequest("代理请求头不完整", nil)
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, errInvalidRequest("代理请求头不支持续行", nil)
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, errInvalidRequest("代理请求头格式错误", nil)
		}
		name := string(line[:colon])
		if !validHeaderToken(name) {
			return nil, errInvalidRequest("代理请求头名称非法", nil)
		}
		value := strings.TrimSpace(string(line[colon+1:]))
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, errInvalidRequest("代理请求头值非法", nil)
		}
		key := http.CanonicalHeaderKey(name)
		req.header[key] = append(req.header[key], value)
	}
	req.host = req.header.Get("Host")
	connectionTokens := headerTokens(req.header.Get("Connection"))
	if req.protoMinor == 0 {
		req.keepAlive = headerTokenPresent(connectionTokens, "keep-alive")
	} else {
		req.keepAlive = !headerTokenPresent(connectionTokens, "close")
	}

	transferEncodings := req.header["Transfer-Encoding"]
	if len(transferEncodings) > 0 {
		joined := strings.ToLower(strings.TrimSpace(strings.Join(transferEncodings, ",")))
		if joined != "chunked" {
			return nil, errInvalidRequest("不支持的 Transfer-Encoding", nil)
		}
		req.chunked = true
		req.contentLength = -1
	}
	contentLengths := req.header["Content-Length"]
	if len(contentLengths) > 0 {
		if req.chunked {
			return nil, errInvalidRequest("Content-Length 与 Transfer-Encoding 不能同时出现", nil)
		}
		first := strings.TrimSpace(contentLengths[0])
		for _, other := range contentLengths[1:] {
			if strings.TrimSpace(other) != first {
				return nil, errInvalidRequest("多个 Content-Length 值冲突", nil)
			}
		}
		n, err := strconv.ParseInt(first, 10, 64)
		if err != nil || n < 0 {
			return nil, errInvalidRequest("Content-Length 非法", err)
		}
		req.contentLength = n
	}

	if req.method == http.MethodConnect {
		if req.requestURI == "" || strings.HasPrefix(req.requestURI, "/") {
			return nil, errInvalidRequest("CONNECT 目标格式错误", nil)
		}
		return req, nil
	}
	u, err := url.ParseRequestURI(req.requestURI)
	if err != nil || u.Scheme == "" {
		return nil, errInvalidRequest("代理请求必须使用绝对形式（http://host/path）", err)
	}
	if u.Host == "" {
		return nil, errInvalidRequest("代理请求目标主机为空", nil)
	}
	req.url = u
	if req.host == "" {
		req.host = u.Host
	}
	return req, nil
}

// parseHTTPVersion parses "HTTP/major.minor".
func parseHTTPVersion(proto string) (major, minor int, ok bool) {
	if !strings.HasPrefix(proto, "HTTP/") {
		return 0, 0, false
	}
	rest := proto[len("HTTP/"):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(rest[dot+1:])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// validHeaderToken reports whether s is an RFC 7230 token.
func validHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return false
		}
		switch c {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}

// headerTokens splits a comma separated header value into lower case tokens.
func headerTokens(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if token := strings.ToLower(strings.TrimSpace(part)); token != "" {
			out = append(out, token)
		}
	}
	return out
}

// headerTokenPresent reports whether tokens contains want.
func headerTokenPresent(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

// fixedBody streams exactly remaining bytes from br.
type fixedBody struct {
	br        *bufio.Reader
	remaining int64
}

// Read implements io.Reader.
func (b *fixedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.br.Read(p)
	b.remaining -= int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, err
	}
	if err != nil && b.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

// chunkedBody decodes an HTTP/1.1 chunked request body and consumes the trailer
// section after the final chunk so the connection can be reused.
type chunkedBody struct {
	br        *bufio.Reader
	remaining int64
	done      bool
}

func newChunkedBody(br *bufio.Reader) *chunkedBody { return &chunkedBody{br: br} }

// Read implements io.Reader.
func (b *chunkedBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	if b.remaining == 0 {
		if err := b.beginChunk(); err != nil {
			return 0, err
		}
		if b.done {
			return 0, io.EOF
		}
	}
	limit := int64(len(p))
	if limit > b.remaining {
		limit = b.remaining
	}
	n, err := b.br.Read(p[:limit])
	b.remaining -= int64(n)
	if b.remaining == 0 && err == nil {
		if cerr := consumeCRLF(b.br); cerr != nil {
			return n, cerr
		}
	}
	if err != nil && errors.Is(err, io.EOF) {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// beginChunk reads one chunk size line (and the trailer section after 0).
func (b *chunkedBody) beginChunk() error {
	line, err := readLimitedLine(b.br, 4096)
	if err != nil {
		return err
	}
	if idx := strings.IndexByte(line, ';'); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	size, err := strconv.ParseUint(line, 16, 64)
	if err != nil {
		return fmt.Errorf("proxy: invalid chunk size %q: %w", line, err)
	}
	if size == 0 {
		if err := consumeTrailers(b.br); err != nil {
			return err
		}
		b.done = true
		return nil
	}
	b.remaining = int64(size)
	return nil
}

// readLimitedLine reads one CRLF terminated line up to limit bytes.
func readLimitedLine(br *bufio.Reader, limit int) (string, error) {
	var buf bytes.Buffer
	for {
		part, err := br.ReadSlice('\n')
		if buf.Len()+len(part) > limit {
			return "", fmt.Errorf("proxy: line exceeds %d bytes", limit)
		}
		buf.Write(part)
		if err == nil {
			line := strings.TrimSuffix(buf.String(), "\n")
			line = strings.TrimSuffix(line, "\r")
			return line, nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}

// consumeCRLF consumes the two bytes trailing a chunk.
func consumeCRLF(br *bufio.Reader) error {
	var crlf [2]byte
	if _, err := io.ReadFull(br, crlf[:]); err != nil {
		return err
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return errors.New("proxy: malformed chunked encoding")
	}
	return nil
}

// consumeTrailers discards the trailer section of a chunked body.
func consumeTrailers(br *bufio.Reader) error {
	for {
		line, err := readLimitedLine(br, 8192)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

// buildRequestPlan validates the target and prepares the upstream request.
func buildRequestPlan(req *httpRequest) (*requestPlan, *proxyError) {
	if req.method == http.MethodConnect {
		return nil, errInvalidRequest("CONNECT 请求不能作为普通 HTTP 转发", nil)
	}
	if req.url == nil {
		return nil, errInvalidRequest("代理请求缺少目标 URL", nil)
	}
	scheme := strings.ToLower(req.url.Scheme)
	if scheme != "http" {
		return nil, errInvalidRequest("仅支持 http:// 绝对形式，https 目标请使用 CONNECT", nil)
	}
	host := req.url.Hostname()
	port := 80
	if portStr := req.url.Port(); portStr != "" {
		parsed, err := parsePort(portStr)
		if err != nil {
			return nil, errInvalidTarget("目标端口非法", err)
		}
		port = parsed
	}
	if perr := validateTarget(host, port); perr != nil {
		return nil, perr
	}
	uri := req.url.RequestURI()
	if uri == "" {
		uri = "/"
	}
	header, upgrade := cleanRequestHeaders(req.header)
	hostHeader := req.host
	if hostHeader == "" {
		hostHeader = canonicalTargetKey(host, port)
	}
	expectContinue := strings.Contains(strings.ToLower(req.header.Get("Expect")), "100-continue")
	return &requestPlan{
		method:         req.method,
		uri:            uri,
		hostHeader:     hostHeader,
		header:         header,
		targetHost:     host,
		targetPort:     port,
		key:            canonicalTargetKey(host, port),
		contentLength:  req.contentLength,
		chunked:        req.chunked,
		hasBody:        req.hasBody(),
		upgrade:        upgrade,
		keepAlive:      req.keepAlive,
		expectContinue: expectContinue,
	}, nil
}

// hopByHopHeaders are the headers that must never be forwarded by a proxy,
// except Upgrade which is preserved for protocol switches.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// cleanRequestHeaders removes hop-by-hop headers and returns the headers to
// forward plus whether this is a protocol upgrade request.
func cleanRequestHeaders(src http.Header) (http.Header, bool) {
	tokens := headerTokens(src.Get("Connection"))
	upgrade := headerTokenPresent(tokens, "upgrade") && src.Get("Upgrade") != ""
	out := make(http.Header, len(src))
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "host" || lower == "expect" || lower == "content-length" {
			// Host is written explicitly, Expect is handled locally and the
			// request framing (Content-Length or chunked) is rebuilt from the
			// parsed body: forwarding the original Content-Length here would
			// emit a duplicate header and origin servers reject that.
			continue
		}
		if hopByHopHeaders[lower] {
			continue
		}
		if headerTokenPresent(tokens, lower) {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	if upgrade {
		out.Set("Connection", "Upgrade")
		out.Set("Upgrade", src.Get("Upgrade"))
	}
	return out, upgrade
}

// cleanResponseHeaders removes hop-by-hop headers from an origin response.
// keepUpgrade preserves Connection/Upgrade for a 101 response.
func cleanResponseHeaders(src http.Header, keepUpgrade bool) http.Header {
	tokens := headerTokens(src.Get("Connection"))
	out := make(http.Header, len(src))
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "content-length" || lower == "transfer-encoding" || lower == "connection" {
			continue // framing headers are rebuilt by the proxy
		}
		if hopByHopHeaders[lower] && !(keepUpgrade && (lower == "upgrade" || lower == "connection")) {
			continue
		}
		if headerTokenPresent(tokens, lower) && !(keepUpgrade && lower == "upgrade") {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	if keepUpgrade {
		if upgrade := src.Get("Upgrade"); upgrade != "" {
			out.Set("Upgrade", upgrade)
		}
		out.Set("Connection", "Upgrade")
	}
	return out
}

// writeUpstreamRequestHead writes the origin-form request head to the stream.
func writeUpstreamRequestHead(up *upstreamStream, plan *requestPlan, writeBlock time.Duration) error {
	var buf bytes.Buffer
	buf.Grow(256 + len(plan.uri))
	buf.WriteString(plan.method)
	buf.WriteByte(' ')
	buf.WriteString(plan.uri)
	buf.WriteString(" HTTP/1.1\r\n")
	buf.WriteString("Host: ")
	buf.WriteString(plan.hostHeader)
	buf.WriteString("\r\n")
	for key, values := range plan.header {
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}
	switch {
	case plan.chunked:
		buf.WriteString("Transfer-Encoding: chunked\r\n")
	case plan.contentLength > 0:
		buf.WriteString("Content-Length: ")
		buf.WriteString(strconv.FormatInt(plan.contentLength, 10))
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	up.setWriteDeadline(time.Now().Add(writeBlock))
	return writeFull(up.conn, buf.Bytes())
}

// trackedReader / trackedWriter remember the first error of each side so a
// failed copy can be attributed to the client or to the tunnel.
type trackedReader struct {
	r   io.Reader
	err error
}

func (t *trackedReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil {
		t.err = err
	}
	return n, err
}

type trackedWriter struct {
	w   io.Writer
	err error
}

func (t *trackedWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if err != nil {
		t.err = err
	}
	return n, err
}

// requestOutcome describes the result of one upstream round trip.
type requestOutcome struct {
	keepAlive bool
	reusable  bool
	committed bool
	retrySafe bool
	err       *proxyError
	cause     error
	upBytes   int64
	downBytes int64
}

// serveHTTP handles one plain HTTP proxy request. It returns whether the client
// connection stays open and the upstream stream to reuse for the next request.
func (h *HTTPProxy) serveHTTP(ctx context.Context, conn net.Conn, br *bufio.Reader, req *httpRequest, current *upstreamStream) (bool, *upstreamStream) {
	p := h.p
	start := time.Now()
	traceID, traceHex := newTrace()
	sourceIP := remoteIP(conn.RemoteAddr())
	if perr := p.authBanBlocked(sourceIP, model.ProtoHTTP); perr != nil {
		track := p.trackRequest(model.ProtoHTTP, "", "")
		defer track.finish(perr)
		p.finishRequest(model.ProtoHTTP, traceHex, "", "", "", "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return false, current
	}
	plan, perr := buildRequestPlan(req)
	if perr != nil {
		track := p.trackRequest(model.ProtoHTTP, "", "")
		defer track.finish(perr)
		p.finishRequest(model.ProtoHTTP, traceHex, "", "", "", "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return false, current
	}
	target := model.RequestTarget{
		Protocol: model.ProtoHTTP,
		Host:     plan.targetHost,
		Port:     plan.targetPort,
		SourceIP: sourceIP,
		TraceID:  traceHex,
	}
	track := p.trackRequest(model.ProtoHTTP, target.String(), "")
	var trackErr *proxyError
	defer func() { track.finish(trackErr) }()
	cred, perr := p.authenticateHTTP(req.header.Get("Proxy-Authorization"), sourceIP, model.ProtoHTTP)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoHTTP, traceHex, target.String(), "", "", "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return false, current
	}
	target.Credential = credentialID(cred)
	target.Username = credentialUsername(cred)
	track.credentialID = target.Credential
	release, perr := p.acquire(cred, model.ProtoHTTP, traceHex, target.Username, sourceIP)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return false, current
	}
	defer release()
	candidates, perr := p.resolveCandidates(cred, model.ProtoHTTP, traceHex, target.Username)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return false, current
	}
	if perr := p.checkACL(target, traceHex, target.Username); perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return false, current
	}

	t := p.timeouts()
	maxAttempts := p.maxAttempts(true)
	excluded := make([]string, 0, 2)
	attempts := 0
	var lastErr *proxyError
	var lastNode string
	for {
		var st *upstreamStream
		if current != nil {
			if attempts == 0 && current.key == plan.key && containsNode(candidates, current.node.ID) {
				st = current
				current = nil
			} else {
				current.close()
				current = nil
			}
		}
		if st == nil {
			if attempts >= maxAttempts {
				if lastErr == nil {
					lastErr = errNoCandidates(nil)
				}
				trackErr = lastErr
				p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, lastNode, lastErr.reason, start, lastErr)
				h.writeErrorResponse(conn, lastErr)
				return false, current
			}
			out, openErr := p.openOnce(ctx, SelectRequest{
				CredentialID: target.Credential,
				Username:     target.Username,
				SourceIP:     sourceIP,
				Protocol:     model.ProtoHTTP,
				Target:       target,
				Exclude:      excluded,
			}, candidates, traceID, traceHex, track)
			if openErr != nil {
				if openErr.reason == reasonNoCandidates && lastErr != nil {
					openErr = lastErr
				}
				attempts++
				if out.Node != nil {
					lastNode = out.Node.ID
					track.serving(out.Node.ID)
				}
				if openErr.retryable && attempts < maxAttempts && ctx.Err() == nil && out.Node != nil {
					excluded = append(excluded, out.Node.ID)
					lastErr = openErr
					p.retry(out.Node.ID, traceHex, model.ProtoHTTP, target, openErr)
					continue
				}
				trackErr = openErr
				p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, lastNode, openErr.reason, start, openErr)
				h.writeErrorResponse(conn, openErr)
				return false, current
			}
			attempts++
			st = newUpstreamStream(out, plan.key, traceHex)
			lastNode = st.node.ID
			track.serving(lastNode)
		} else {
			attempts++
			lastNode = st.node.ID
			track.serving(lastNode)
		}
		outcome := h.forwardOnce(ctx, conn, br, req, plan, st, target, traceHex, t)
		track.addBytes(outcome.upBytes, outcome.downBytes)
		if outcome.committed {
			result := "ok"
			if outcome.err != nil {
				result = outcome.err.reason
			}
			trackErr = outcome.err
			p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, lastNode, result, start, outcome.err)
			if outcome.keepAlive && outcome.reusable {
				return true, st
			}
			st.close()
			return outcome.keepAlive, nil
		}
		st.close()
		if st.node != nil {
			p.selector.RecordResult(st.node.ID, outcome.cause)
		}
		lastErr = outcome.err
		if lastErr == nil {
			lastErr = errUpstreamClosed(outcome.cause)
		}
		if lastErr.silent {
			trackErr = lastErr
			return false, current
		}
		if outcome.retrySafe && ctx.Err() == nil && attempts < maxAttempts {
			if st.node != nil {
				excluded = append(excluded, st.node.ID)
			}
			lastNode = nodeOrEmpty(st)
			p.retry(lastNode, traceHex, model.ProtoHTTP, target, lastErr)
			continue
		}
		trackErr = lastErr
		p.finishRequest(model.ProtoHTTP, traceHex, target.String(), target.Username, target.Credential, nodeOrEmpty(st), lastErr.reason, start, lastErr)
		h.writeErrorResponse(conn, lastErr)
		return false, current
	}
}

// nodeOrEmpty returns the node id of a stream, or an empty string.
func nodeOrEmpty(st *upstreamStream) string {
	if st == nil || st.node == nil {
		return ""
	}
	return st.node.ID
}

// forwardOnce performs one full round trip on an already opened stream.
func (h *HTTPProxy) forwardOnce(ctx context.Context, conn net.Conn, br *bufio.Reader, req *httpRequest, plan *requestPlan, up *upstreamStream, target model.RequestTarget, traceHex string, t timeouts) requestOutcome {
	if err := writeUpstreamRequestHead(up, plan, t.writeBlock); err != nil {
		if isTimeout(err) {
			return requestOutcome{retrySafe: true, cause: err, err: newProxyError(504, 0x06, "connection_timeout", "向代理节点写入请求超时", err)}
		}
		return requestOutcome{retrySafe: true, cause: err, err: errUpstreamClosed(err)}
	}
	if plan.expectContinue && plan.hasBody {
		if err := h.writeContinue(conn); err != nil {
			return requestOutcome{cause: err, err: errClientGone(err)}
		}
	}
	bodySent := false
	bodyUp := int64(0)
	if plan.hasBody {
		src := &trackedReader{r: req.body}
		dst := &trackedWriter{w: up.conn}
		mode := copyExact
		length := plan.contentLength
		if plan.chunked {
			mode = copyChunked
			length = -1
		}
		beforeRead := func() { _ = conn.SetReadDeadline(time.Now().Add(t.idle)) }
		beforeWrite := func() { up.setWriteDeadline(time.Now().Add(t.writeBlock)) }
		var err error
		bodyUp, err = copyBody(ctx, dst, src, mode, length, h.p.limiterUp(target.Credential, nodeOrEmpty(up)), beforeRead, beforeWrite)
		if err != nil {
			if dst.err != nil {
				if isTimeout(dst.err) {
					return requestOutcome{upBytes: bodyUp, cause: dst.err, err: newProxyError(504, 0x06, "connection_timeout", "向代理节点写入请求超时", dst.err)}
				}
				return requestOutcome{upBytes: bodyUp, cause: dst.err, err: errUpstreamClosed(dst.err)}
			}
			return requestOutcome{upBytes: bodyUp, cause: src.err, err: errClientGone(src.err)}
		}
		bodySent = true
	}
	out := h.readAndRelayResponse(ctx, conn, br, req, plan, up, bodySent, traceHex, target.Credential, t)
	out.upBytes += bodyUp
	return out
}

// writeContinue answers Expect: 100-continue without waiting for the origin.
func (h *HTTPProxy) writeContinue(conn net.Conn) error {
	_ = conn.SetWriteDeadline(time.Now().Add(h.p.timeouts().writeBlock))
	return writeFull(conn, []byte("HTTP/1.1 100 Continue\r\n\r\n"))
}

// readAndRelayResponse reads the upstream response (consuming informational
// responses) and relays the final one to the client.
func (h *HTTPProxy) readAndRelayResponse(ctx context.Context, conn net.Conn, br *bufio.Reader, req *httpRequest, plan *requestPlan, up *upstreamStream, bodySent bool, traceHex, credID string, t timeouts) requestOutcome {
	retrySafe := !plan.hasBody || !bodySent
	readRequest := &http.Request{Method: req.method}
	for {
		up.setReadDeadline(time.Now().Add(t.idle))
		resp, err := http.ReadResponse(up.br, readRequest)
		if err != nil {
			if isTimeout(err) {
				return requestOutcome{retrySafe: retrySafe, cause: err, err: newProxyError(504, 0x06, "connection_timeout", "等待代理节点响应超时", err)}
			}
			return requestOutcome{retrySafe: retrySafe, cause: err, err: errUpstreamClosed(err)}
		}
		if resp.StatusCode >= 100 && resp.StatusCode <= 199 && resp.StatusCode != http.StatusSwitchingProtocols {
			if err := h.writeInformational(conn, resp); err != nil {
				return requestOutcome{cause: err, err: errClientGone(err), retrySafe: false}
			}
			continue
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			return h.handleUpgrade(ctx, conn, br, req, plan, up, resp, traceHex, credID, t)
		}
		return h.relayResponse(ctx, conn, req, plan, up, resp, traceHex, credID, t)
	}
}

// writeInformational forwards a 1xx response head to the client.
func (h *HTTPProxy) writeInformational(conn net.Conn, resp *http.Response) error {
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 ")
	buf.WriteString(resp.Status)
	buf.WriteString("\r\n")
	header := cleanResponseHeaders(resp.Header, false)
	for key, values := range header {
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}
	buf.WriteString("\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(h.p.timeouts().writeBlock))
	return writeFull(conn, buf.Bytes())
}

// responseFraming is the body framing chosen for the client response.
type responseFraming int

const (
	framingNone responseFraming = iota
	framingLength
	framingChunked
	framingClose
)

// handleUpgrade switches to raw byte forwarding after a 101 response.
func (h *HTTPProxy) handleUpgrade(ctx context.Context, conn net.Conn, br *bufio.Reader, req *httpRequest, plan *requestPlan, up *upstreamStream, resp *http.Response, traceHex, credID string, t timeouts) requestOutcome {
	header := cleanResponseHeaders(resp.Header, true)
	if header.Get("Upgrade") == "" {
		header.Set("Upgrade", plan.header.Get("Upgrade"))
	}
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 ")
	buf.WriteString(resp.Status)
	buf.WriteString("\r\n")
	for key, values := range header {
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}
	buf.WriteString("\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(t.writeBlock))
	if err := writeFull(conn, buf.Bytes()); err != nil {
		return requestOutcome{committed: true, cause: err, err: errClientGone(err)}
	}
	upBytes, downBytes, rerr := relayDuplex(ctx, clientHalf(conn, br), streamHalf(up.conn, up.br), relayConfig{
		idle:        t.idle,
		writeBlock:  t.writeBlock,
		linger:      t.linger,
		upLimiter:   h.p.limiterUp(credID, nodeOrEmpty(up)),
		downLimiter: h.p.limiterDown(credID, nodeOrEmpty(up)),
	})
	h.p.addBytes("in", nodeOrEmpty(up), upBytes)
	h.p.addBytes("out", nodeOrEmpty(up), downBytes)
	out := requestOutcome{
		keepAlive: false,
		reusable:  false,
		committed: true,
		upBytes:   upBytes,
		downBytes: downBytes,
	}
	if rerr != nil && !isClosedError(rerr) && !isTimeout(rerr) {
		out.cause = rerr
		out.err = errUpstreamClosed(rerr)
	}
	return out
}

// relayResponse writes the final response head and body to the client.
func (h *HTTPProxy) relayResponse(ctx context.Context, conn net.Conn, req *httpRequest, plan *requestPlan, up *upstreamStream, resp *http.Response, traceHex, credID string, t timeouts) requestOutcome {
	header := cleanResponseHeaders(resp.Header, false)
	noBody := req.method == http.MethodHead || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified
	framing := framingNone
	length := int64(0)
	chunked := len(resp.TransferEncoding) > 0 && strings.EqualFold(resp.TransferEncoding[len(resp.TransferEncoding)-1], "chunked")
	switch {
	case noBody:
		if req.method == http.MethodHead && resp.ContentLength >= 0 && !chunked {
			header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}
	case resp.ContentLength >= 0:
		framing = framingLength
		length = resp.ContentLength
		header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	case chunked:
		framing = framingChunked
		header.Set("Transfer-Encoding", "chunked")
	default:
		framing = framingClose
	}
	// The client connection can only be kept alive when both sides still want
	// it and the body is self delimiting.
	keepClient := plan.keepAlive && !resp.Close && framing != framingClose
	if !keepClient {
		header.Set("Connection", "close")
	}
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 ")
	buf.WriteString(resp.Status)
	buf.WriteString("\r\n")
	for key, values := range header {
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}
	buf.WriteString("\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(t.writeBlock))
	if err := writeFull(conn, buf.Bytes()); err != nil {
		return requestOutcome{committed: false, retrySafe: false, cause: err, err: errClientGone(err)}
	}
	out := requestOutcome{
		committed: true,
		keepAlive: keepClient,
		reusable:  keepClient && !resp.Close,
	}
	switch framing {
	case framingNone:
		return out
	case framingLength, framingChunked, framingClose:
		src := &trackedReader{r: resp.Body}
		dst := &trackedWriter{w: conn}
		mode := copyExact
		copyLen := length
		if framing == framingChunked {
			mode = copyChunked
			copyLen = -1
		} else if framing == framingClose {
			mode = copyRaw
			copyLen = -1
		}
		beforeRead := func() { up.setReadDeadline(time.Now().Add(t.idle)) }
		beforeWrite := func() { _ = conn.SetWriteDeadline(time.Now().Add(t.writeBlock)) }
		n, err := copyBody(ctx, dst, src, mode, copyLen, h.p.limiterDown(credID, nodeOrEmpty(up)), beforeRead, beforeWrite)
		out.downBytes = n
		if err != nil {
			out.keepAlive = false
			out.reusable = false
			if dst.err != nil {
				out.cause = dst.err
				out.err = errClientGone(dst.err)
			} else {
				out.cause = src.err
				out.err = errUpstreamClosed(src.err)
			}
			return out
		}
		return out
	}
	return out
}

// serveConnect handles a CONNECT tunnel request.
func (h *HTTPProxy) serveConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, req *httpRequest) {
	p := h.p
	start := time.Now()
	traceID, traceHex := newTrace()
	sourceIP := remoteIP(conn.RemoteAddr())
	if perr := p.authBanBlocked(sourceIP, model.ProtoConnect); perr != nil {
		track := p.trackRequest(model.ProtoConnect, "", "")
		defer track.finish(perr)
		p.finishRequest(model.ProtoConnect, traceHex, "", "", "", "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	host, port, perr := splitAuthority(req.requestURI, 443)
	if perr == nil {
		perr = validateTarget(host, port)
	}
	if perr != nil {
		track := p.trackRequest(model.ProtoConnect, req.requestURI, "")
		defer track.finish(perr)
		p.finishRequest(model.ProtoConnect, traceHex, req.requestURI, "", "", "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	target := model.RequestTarget{
		Protocol: model.ProtoConnect,
		Host:     host,
		Port:     port,
		SourceIP: sourceIP,
		TraceID:  traceHex,
	}
	track := p.trackRequest(model.ProtoConnect, target.String(), "")
	var trackErr *proxyError
	defer func() { track.finish(trackErr) }()
	cred, perr := p.authenticateHTTP(req.header.Get("Proxy-Authorization"), sourceIP, model.ProtoConnect)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoConnect, traceHex, target.String(), "", "", "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	target.Credential = credentialID(cred)
	target.Username = credentialUsername(cred)
	track.credentialID = target.Credential
	release, perr := p.acquire(cred, model.ProtoConnect, traceHex, target.Username, sourceIP)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoConnect, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	defer release()
	candidates, perr := p.resolveCandidates(cred, model.ProtoConnect, traceHex, target.Username)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoConnect, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	if perr := p.checkACL(target, traceHex, target.Username); perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoConnect, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	t := p.timeouts()
	out, perr := p.openStream(ctx, SelectRequest{
		CredentialID: target.Credential,
		Username:     target.Username,
		SourceIP:     sourceIP,
		Protocol:     model.ProtoConnect,
		Target:       target,
	}, candidates, traceID, traceHex, p.maxAttempts(true), track)
	if perr != nil {
		trackErr = perr
		p.finishRequest(model.ProtoConnect, traceHex, target.String(), target.Username, target.Credential, "", perr.reason, start, perr)
		h.writeErrorResponse(conn, perr)
		return
	}
	// Commit point: from here on no transparent retry is allowed.
	track.serving(out.Node.ID)
	_ = conn.SetWriteDeadline(time.Now().Add(t.writeBlock))
	if err := writeFull(conn, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		out.Conn.Close()
		trackErr = errClientGone(err)
		p.finishRequest(model.ProtoConnect, traceHex, target.String(), target.Username, target.Credential, out.Node.ID, reasonClientGone, start, trackErr)
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
	p.finishRequest(model.ProtoConnect, traceHex, target.String(), target.Username, target.Credential, out.Node.ID, result, start, failure)
}

// writeErrorResponse writes one proxy error response.
func (h *HTTPProxy) writeErrorResponse(conn net.Conn, perr *proxyError) {
	if perr == nil || perr.silent {
		return
	}
	status := perr.httpStatus()
	body := ""
	if perr.message != "" {
		body = perr.message + "\n"
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", status, statusText(status))
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	if status == http.StatusProxyAuthRequired {
		buf.WriteString("Proxy-Authenticate: Basic realm=\"proxygw\"\r\n")
	}
	buf.WriteString("Connection: close\r\n\r\n")
	buf.WriteString(body)
	_ = conn.SetWriteDeadline(time.Now().Add(h.p.timeouts().writeBlock))
	_ = writeFull(conn, buf.Bytes())
}

// finishRequest records metrics and the request log line.
func (p *pipeline) finishRequest(protocolName, traceHex, target, username, credID, nodeID, result string, start time.Time, perr *proxyError) {
	elapsed := time.Since(start)
	p.observeRequest(protocolName, nodeID, credID, result, elapsed)
	level := slog.LevelInfo
	if result != "ok" {
		level = slog.LevelWarn
	}
	attrs := []any{
		"event", "proxy_request",
		"protocol", protocolName,
		"trace_id", traceHex,
		"target", target,
		"credential", username,
		"node_id", nodeID,
		"result", result,
		"duration_ms", elapsed.Milliseconds(),
	}
	if perr != nil {
		attrs = append(attrs, "error", perr.Error())
	}
	p.logger.Log(context.Background(), level, "proxy request", attrs...)
}
