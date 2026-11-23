package proxy

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/auth"
	"proxygw/internal/compress"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// reasonSelectTimeout is the SelectionInfo.Reason set when the scheduler
// exceeded its budget and the request degraded to a random candidate.
const reasonSelectTimeout = "select_timeout"

// timeouts is a sanitized snapshot of the configurable timers.
type timeouts struct {
	open       time.Duration
	readHeader time.Duration
	idle       time.Duration
	writeBlock time.Duration
	linger     time.Duration
	drain      time.Duration
}

// pipeline is the shared request pipeline used by both entry points. It owns
// authentication, authorization, node resolution, scheduling, stream build with
// transparent retry, concurrency limits and instrumentation. The protocol
// specific bytes (CONNECT, absolute-form HTTP, SOCKS5) live in http.go and
// socks5.go; relay.go performs the bidirectional copy.
type pipeline struct {
	logger  *slog.Logger
	metrics *metrics.Metrics
	audit   func(event string, detail map[string]string)
	now     func() time.Time

	settings func() model.Settings
	authMode string

	authenticator Authenticator
	authBan       *AuthBanTracker
	candidates    CandidateResolver
	selector      Selector
	acl           ACLChecker
	dialer        StreamDialer
	limiter       Bandwidth

	onRequestStart func(credentialID, protocol, target, nodeID string)
	onRequestEnd   func(credentialID, protocol, target, nodeID string, bytesIn, bytesOut int64, err error)
	onRetry        func()

	maxHeaderBytes int

	globalSem    chan struct{} // nil = unlimited
	credInflight sync.Map      // credential id -> *atomic.Int64
}

// newPipeline validates the options and builds the shared pipeline.
func newPipeline(opts Options) (*pipeline, error) {
	norm, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	p := &pipeline{
		logger:         norm.Logger,
		metrics:        norm.Metrics,
		audit:          norm.Audit,
		now:            func() time.Time { return time.Now().UTC() },
		settings:       norm.Settings,
		authMode:       norm.AuthMode,
		authenticator:  norm.Authenticator,
		authBan:        norm.AuthBan,
		candidates:     norm.Candidates,
		selector:       norm.Selector,
		acl:            norm.ACL,
		dialer:         norm.Dialer,
		limiter:        norm.Limiter,
		onRequestStart: norm.OnRequestStart,
		onRequestEnd:   norm.OnRequestEnd,
		onRetry:        norm.OnRetry,
		maxHeaderBytes: norm.MaxHeaderBytes,
	}
	if norm.MaxConcurrent > 0 {
		p.globalSem = make(chan struct{}, norm.MaxConcurrent)
	}
	return p, nil
}

// settingsNow returns the current settings snapshot with an extra defensive
// layer against an adapter returning an uninitialized value.
func (p *pipeline) settingsNow() model.Settings {
	s := p.settings()
	if s.Timeouts == (model.TimeoutSettings{}) && s.Scheduler.Strategy == "" {
		return model.DefaultSettings()
	}
	return s
}

// timeouts returns the sanitized timeout snapshot.
func (p *pipeline) timeouts() timeouts {
	s := p.settingsNow().Timeouts
	return timeouts{
		open:       positive(s.Open.Std(), defaultSettingsOpen),
		readHeader: positive(s.ReadHeader.Std(), defaultReadHeader),
		idle:       positive(s.Idle.Std(), defaultIdle),
		writeBlock: positive(s.WriteBlock.Std(), defaultWriteBlock),
		linger:     positive(s.Linger.Std(), defaultLinger),
		drain:      positive(s.Drain.Std(), defaultDrain),
	}
}

func positive(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

// newTrace returns a 16 byte random trace id and its hexadecimal encoding. The
// id is written into the OPEN header and appears in every log line.
func newTrace() ([16]byte, string) {
	var id [16]byte
	if _, err := cryptorand.Read(id[:]); err != nil {
		binary.BigEndian.PutUint64(id[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(id[8:], uint64(time.Now().UnixMicro()))
	}
	return id, hex.EncodeToString(id[:])
}

// credential helpers.
func credentialID(c *model.Credential) string {
	if c == nil {
		return ""
	}
	return c.ID
}

func credentialUsername(c *model.Credential) string {
	if c == nil {
		return ""
	}
	return c.Username
}

// maxAttempts returns the total number of stream build attempts allowed for one
// request. Retries require the scheduler retry setting and MaxAttempts >= 2.
func (p *pipeline) maxAttempts(allowRetry bool) int {
	if !allowRetry {
		return 1
	}
	r := p.settingsNow().Scheduler.Retry
	if !r.Enabled || r.MaxAttempts < 2 {
		return 1
	}
	n := r.MaxAttempts
	if n > 3 {
		n = 3
	}
	return n
}

// parseProxyAuthorization parses a Proxy-Authorization header value. ok is
// false when the header is empty; a malformed value yields a proxyError.
func parseProxyAuthorization(value string) (username, password string, ok bool, perr *proxyError) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false, nil
	}
	scheme, payload, found := strings.Cut(value, " ")
	if !found {
		return "", "", true, errInvalidRequest("代理认证头格式错误", nil)
	}
	if !strings.EqualFold(scheme, "Basic") {
		return "", "", true, errInvalidRequest("代理认证方式不支持，仅支持 Basic", nil)
	}
	payload = strings.TrimSpace(payload)
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(payload)
		if err != nil {
			return "", "", true, errInvalidRequest("代理认证信息不是合法的 Base64", err)
		}
	}
	idx := strings.IndexByte(string(raw), ':')
	if idx < 0 {
		return "", "", true, errInvalidRequest("代理认证信息缺少分隔符", nil)
	}
	return string(raw[:idx]), string(raw[idx+1:]), true, nil
}

// verifyCredential validates a username / password pair. It never logs or
// returns the password.
func (p *pipeline) verifyCredential(username, password, protocolName, sourceIP string) (*model.Credential, *proxyError) {
	if p.authenticator == nil {
		return nil, errInternal(errors.New("proxy: authenticator is not configured"))
	}
	cred, err := p.authenticator.Verify(username, password)
	if err != nil || cred == nil {
		// A disabled/expired credential is an authorization state, not a
		// password guess. Classify it separately so it neither looks like
		// brute-force traffic in audits nor gets the source IP banned.
		var verr *auth.VerifyError
		if errors.As(err, &verr) {
			switch verr.Kind {
			case auth.VerifyDisabled:
				p.auditEvent("proxy.credential_rejected", map[string]string{
					"protocol": protocolName, "source_ip": sourceIP,
					"username": username, "reason": reasonCredentialDisabled,
				})
				return nil, errCredentialDisabled()
			case auth.VerifyExpired:
				p.auditEvent("proxy.credential_rejected", map[string]string{
					"protocol": protocolName, "source_ip": sourceIP,
					"username": username, "reason": reasonCredentialExpired,
				})
				return nil, errCredentialExpired()
			}
		}
		p.auditEvent("proxy.auth_failed", map[string]string{
			"protocol":  protocolName,
			"source_ip": sourceIP,
			"username":  username,
			"reason":    reasonBadCredential,
		})
		p.recordAuthFailure(sourceIP, protocolName, reasonBadCredential)
		return nil, errBadCredential()
	}
	p.recordAuthSuccess(sourceIP)
	return cred, nil
}

// authorizeCredential applies the credential level authorization rules in the
// order required by the specification: enabled, expiry, protocol allow list,
// source CIDR allow list.
func (p *pipeline) authorizeCredential(cred *model.Credential, sourceIP, protocolName string) *proxyError {
	if cred == nil {
		return errBadCredential()
	}
	auditReject := func(reason, message string) *proxyError {
		p.auditEvent("proxy.credential_rejected", map[string]string{
			"protocol":  protocolName,
			"source_ip": sourceIP,
			"username":  cred.Username,
			"reason":    reason,
		})
		return newProxyError(403, 0x02, reason, message, nil)
	}
	if !cred.Enabled {
		e := errCredentialDisabled()
		p.auditEvent("proxy.credential_rejected", map[string]string{
			"protocol": protocolName, "source_ip": sourceIP, "username": cred.Username,
			"reason": reasonCredentialDisabled,
		})
		return e
	}
	if cred.ExpiresAt != nil && !p.now().Before(*cred.ExpiresAt) {
		e := errCredentialExpired()
		p.auditEvent("proxy.credential_rejected", map[string]string{
			"protocol": protocolName, "source_ip": sourceIP, "username": cred.Username,
			"reason": reasonCredentialExpired,
		})
		return e
	}
	if !protocolAllowed(cred.AllowedProtocols, protocolName) {
		return auditReject(reasonProtocolNotAllowed,
			fmt.Sprintf("当前凭据不允许使用 %s 代理协议", protocolName))
	}
	if !sourceAllowed(cred.SourceCIDRs, sourceIP) {
		return auditReject(reasonSourceNotAllowed, "当前来源地址不在凭据允许的网段内")
	}
	return nil
}

// protocolAllowed reports whether the credential may use protocolName. An empty
// list allows everything; "tcp" is accepted as an alias for all entry protocols.
func protocolAllowed(allowed []string, protocolName string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, entry := range allowed {
		v := strings.ToLower(strings.TrimSpace(entry))
		switch v {
		case "":
			continue
		case "tcp", "all", "*":
			return true
		case protocolName:
			return true
		}
	}
	return false
}

// sourceAllowed reports whether sourceIP matches one of the configured CIDRs. An
// empty list allows everything; an invalid source address fails closed.
func sourceAllowed(cidrs []string, sourceIP string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(sourceIP))
	if ip == nil {
		return false
	}
	for _, entry := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// authenticateHTTP runs the full HTTP authentication / authorization step and
// returns the credential, or nil for an anonymous request.
func (p *pipeline) authenticateHTTP(proxyAuthorization, sourceIP, protocolName string) (*model.Credential, *proxyError) {
	if p.authMode == model.AuthNone {
		return nil, nil
	}
	username, password, hasCreds, perr := parseProxyAuthorization(proxyAuthorization)
	if perr != nil {
		perr.auth = true
		perr.status = 407
		p.auditEvent("proxy.auth_failed", map[string]string{
			"protocol": protocolName, "source_ip": sourceIP, "reason": reasonAuthMalformed,
		})
		p.recordAuthFailure(sourceIP, protocolName, reasonAuthMalformed)
		return nil, perr
	}
	if !hasCreds {
		if p.authMode == model.AuthOptional {
			return nil, nil
		}
		p.auditEvent("proxy.auth_failed", map[string]string{
			"protocol": protocolName, "source_ip": sourceIP, "reason": reasonNoCredential,
		})
		p.recordAuthFailure(sourceIP, protocolName, reasonNoCredential)
		return nil, errNoCredential()
	}
	cred, perr := p.verifyCredential(username, password, protocolName, sourceIP)
	if perr != nil {
		return nil, perr
	}
	if perr := p.authorizeCredential(cred, sourceIP, protocolName); perr != nil {
		return nil, perr
	}
	return cred, nil
}

// resolveCandidates returns the enabled and online nodes visible to the
// credential. An empty or failed resolution is a hard fail-closed condition.
func (p *pipeline) resolveCandidates(cred *model.Credential, protocolName, traceHex, username string) ([]*model.Node, *proxyError) {
	var groups []string
	if cred != nil {
		groups = cred.Groups
	}
	nodes, err := p.candidates.Candidates(groups)
	if err != nil {
		p.logger.Warn("candidate resolution failed",
			"event", "no_candidates", "reason", reasonNoCandidates,
			"protocol", protocolName, "trace_id", traceHex, "credential", username,
			"error", err.Error())
		return nil, errNoCandidates(err)
	}
	usable := make([]*model.Node, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || node.ID == "" || !node.Enabled || !node.Online {
			continue
		}
		usable = append(usable, node)
	}
	if len(usable) == 0 {
		p.logger.Warn("no candidate nodes for credential",
			"event", "no_candidates", "reason", reasonNoCandidates,
			"protocol", protocolName, "trace_id", traceHex, "credential", username,
			"groups", strings.Join(groups, ","))
		return nil, errNoCandidates(nil)
	}
	return usable, nil
}

// checkACL applies the access control engine, if any. Denials are audited.
func (p *pipeline) checkACL(target model.RequestTarget, traceHex, username string) *proxyError {
	if p.acl == nil {
		return nil
	}
	err := p.acl.Check(target)
	if err == nil {
		return nil
	}
	detail := map[string]string{
		"protocol":  target.Protocol,
		"source_ip": target.SourceIP,
		"target":    target.String(),
		"username":  username,
		"trace_id":  traceHex,
		"reason":    reasonACLDenied,
	}
	if err.Error() != "" {
		detail["error"] = err.Error()
	}
	p.auditEvent("proxy.acl_denied", detail)
	return errACLDenied(err)
}

// acquire reserves one global slot and, when configured, one slot of the
// credential concurrency budget. The returned function releases both exactly
// once.
func (p *pipeline) acquire(cred *model.Credential, protocolName, traceHex, username, sourceIP string) (func(), *proxyError) {
	if p.globalSem != nil {
		select {
		case p.globalSem <- struct{}{}:
		default:
			p.rateLimitHit("global")
			p.auditEvent("proxy.rate_limited", map[string]string{
				"protocol": protocolName, "source_ip": sourceIP, "username": username,
				"trace_id": traceHex, "reason": reasonGlobalConcurrency,
			})
			return nil, errGlobalConcurrency()
		}
	}
	releaseGlobal := func() {
		if p.globalSem != nil {
			<-p.globalSem
		}
	}
	var counter *atomic.Int64
	if cred != nil && cred.MaxConcurrent > 0 {
		counter = p.credentialCounter(cred.ID)
		if counter.Add(1) > int64(cred.MaxConcurrent) {
			counter.Add(-1)
			releaseGlobal()
			p.rateLimitHit("credential")
			p.auditEvent("proxy.rate_limited", map[string]string{
				"protocol": protocolName, "source_ip": sourceIP, "username": username,
				"trace_id": traceHex, "reason": reasonCredentialConcurrency,
			})
			return nil, errCredentialConcurrency()
		}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			if counter != nil {
				counter.Add(-1)
			}
			releaseGlobal()
		})
	}
	return release, nil
}

// credentialCounter returns the in-flight counter for one credential.
func (p *pipeline) credentialCounter(id string) *atomic.Int64 {
	if v, ok := p.credInflight.Load(id); ok {
		return v.(*atomic.Int64)
	}
	c := new(atomic.Int64)
	actual, _ := p.credInflight.LoadOrStore(id, c)
	return actual.(*atomic.Int64)
}

// randomCandidate degrades to a uniformly random candidate when the scheduler
// cannot answer inside its budget.
func randomCandidate(candidates []*model.Node, reason string) (*model.Node, SelectionInfo) {
	node := candidates[rand.IntN(len(candidates))]
	return node, SelectionInfo{Strategy: model.StrategyRandom, Reason: reason}
}

// containsNode reports whether nodeID is part of the candidate set.
func containsNode(candidates []*model.Node, nodeID string) bool {
	for _, node := range candidates {
		if node != nil && node.ID == nodeID {
			return true
		}
	}
	return false
}

// filterCandidates removes excluded node ids and re-checks the enabled/online
// invariant defensively.
func filterCandidates(candidates []*model.Node, exclude []string) []*model.Node {
	var excluded map[string]struct{}
	if len(exclude) > 0 {
		excluded = make(map[string]struct{}, len(exclude))
		for _, id := range exclude {
			excluded[id] = struct{}{}
		}
	}
	out := make([]*model.Node, 0, len(candidates))
	for _, node := range candidates {
		if node == nil || node.ID == "" || !node.Enabled || !node.Online {
			continue
		}
		if excluded != nil {
			if _, skip := excluded[node.ID]; skip {
				continue
			}
		}
		out = append(out, node)
	}
	return out
}

// selectNode runs the scheduler with the 5ms budget mandated by the attachment
// and degrades to random selection on timeout.
func (p *pipeline) selectNode(ctx context.Context, req SelectRequest, candidates []*model.Node, traceHex string) (*model.Node, SelectionInfo, *proxyError) {
	if len(candidates) == 0 {
		return nil, SelectionInfo{}, errNoCandidates(nil)
	}
	type selectResult struct {
		node *model.Node
		info SelectionInfo
		err  error
	}
	selCtx, cancel := context.WithTimeout(ctx, selectBudget)
	results := make(chan selectResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				results <- selectResult{err: fmt.Errorf("proxy: selector panicked: %v", r)}
			}
		}()
		node, info, err := p.selector.Select(selCtx, req, candidates)
		results <- selectResult{node: node, info: info, err: err}
	}()
	timer := time.NewTimer(selectBudget)
	var res selectResult
	select {
	case res = <-results:
		timer.Stop()
		cancel()
	case <-timer.C:
		cancel()
		node, info := randomCandidate(candidates, reasonSelectTimeout)
		p.logger.Debug("scheduler budget exhausted, degrading to random",
			"event", "select_timeout", "reason", reasonSelectTimeout,
			"protocol", req.Protocol, "trace_id", traceHex, "credential", req.Username)
		return node, info, nil
	case <-ctx.Done():
		timer.Stop()
		cancel()
		return nil, SelectionInfo{}, errClientGone(ctx.Err())
	}
	if res.err != nil {
		if errors.Is(res.err, context.DeadlineExceeded) || selCtx.Err() != nil {
			node, info := randomCandidate(candidates, reasonSelectTimeout)
			return node, info, nil
		}
		if ctx.Err() != nil {
			return nil, SelectionInfo{}, errClientGone(ctx.Err())
		}
		return nil, SelectionInfo{}, errSelectFailure(res.err)
	}
	if res.node == nil || res.node.ID == "" {
		node, info := randomCandidate(candidates, "selector_nil")
		return node, info, nil
	}
	if !containsNode(candidates, res.node.ID) {
		p.logger.Warn("scheduler returned a node outside the candidate set",
			"event", "selector_invalid", "protocol", req.Protocol,
			"trace_id", traceHex, "node_id", res.node.ID)
		node, info := randomCandidate(candidates, "selector_invalid")
		return node, info, nil
	}
	return res.node, res.info, nil
}

// openResult is one successfully opened tunnel stream.
type openResult struct {
	Node    *model.Node
	Conn    StreamConn
	Info    SelectionInfo
	TraceID [16]byte
}

// openOnce performs exactly one selection and one stream build attempt and
// records the node side result for the circuit breaker.
func (p *pipeline) openOnce(ctx context.Context, req SelectRequest, candidates []*model.Node, traceID [16]byte, traceHex string, track *requestTracker) (*openResult, *proxyError) {
	out := &openResult{TraceID: traceID}
	available := filterCandidates(candidates, req.Exclude)
	if len(available) == 0 {
		return out, errNoCandidates(nil)
	}
	node, info, perr := p.selectNode(ctx, req, available, traceHex)
	if perr != nil {
		return out, perr
	}
	out.Node = node
	out.Info = info
	// OnRequestStart runs after authorization/selection and before the stream
	// is opened, exactly once per client request.
	track.start(node.ID)
	settings := p.settingsNow()
	// Compression is a three way intersection: the operator enabled it, the node
	// negotiated zstd in HELLO and the OPEN header carries the flag. The OPEN
	// header and the build result travel uncompressed; only the payload bytes
	// after a successful OPEN are wrapped below.
	compressed := settings.Compression && node.Compression
	openReq := protocol.TargetToOpen(req.Target.Host, req.Target.Port, traceID, compressed)
	openCtx, cancel := context.WithTimeout(ctx, p.timeouts().open)
	conn, err := p.dialer.OpenStream(openCtx, node.ID, openReq)
	timedOut := openCtx.Err() == context.DeadlineExceeded && (ctx == nil || ctx.Err() == nil)
	cancel()
	if err == nil && conn == nil {
		err = fmt.Errorf("proxy: dialer returned a nil stream for node %s", node.ID)
	}
	if err != nil {
		p.selector.RecordResult(node.ID, err)
		return out, mapOpenFailure(err, ctx, timedOut)
	}
	if compressed {
		wrapped, werr := compress.WrapStream(conn, compress.DefaultLevel)
		if werr != nil {
			// The stream is unusable once the payload wrapper cannot be built:
			// close it and report an internal error instead of relaying
			// plaintext over a stream the node expects to be zstd.
			_ = conn.Close()
			p.selector.RecordResult(node.ID, werr)
			return out, errInternal(fmt.Errorf("proxy: wrap stream to node %s with zstd: %w", node.ID, werr))
		}
		conn = wrapped
	}
	p.selector.RecordResult(node.ID, nil)
	out.Conn = conn
	return out, nil
}

// openStream performs the stream build with the transparent retry policy: it
// may switch nodes while nothing has been committed to the client yet.
func (p *pipeline) openStream(ctx context.Context, req SelectRequest, candidates []*model.Node, traceID [16]byte, traceHex string, maxAttempts int, track *requestTracker) (*openResult, *proxyError) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	exclude := append([]string(nil), req.Exclude...)
	var lastErr *proxyError
	for attempt := 1; ; attempt++ {
		sreq := req
		sreq.Exclude = exclude
		out, perr := p.openOnce(ctx, sreq, candidates, traceID, traceHex, track)
		if perr == nil {
			return out, nil
		}
		if perr.silent || (ctx != nil && ctx.Err() != nil) {
			return out, perr
		}
		if perr.reason == reasonNoCandidates {
			if lastErr != nil {
				return out, lastErr
			}
			return out, perr
		}
		if out == nil || out.Node == nil || !perr.retryable {
			return out, perr
		}
		lastErr = perr
		exclude = append(exclude, out.Node.ID)
		if attempt >= maxAttempts {
			return out, perr
		}
		p.retry(out.Node.ID, traceHex, sreq.Protocol, sreq.Target, perr)
	}
}

// retry records one transparent retry and its log line.
func (p *pipeline) retry(nodeID, traceHex, protocolName string, target model.RequestTarget, cause *proxyError) {
	// Count real transparent retries for the panel overview.
	if p.onRetry != nil {
		p.onRetry()
	}
	if p.metrics != nil {
		p.metrics.ProxyRetriesTotal.WithLabelValues(p.metrics.NodeLabel(nodeID)).Inc()
	}
	base := "transparent retry before response commit"
	if cause != nil {
		p.logger.Warn(base, "event", "proxy_retry", "trace_id", traceHex,
			"protocol", protocolName, "node_id", nodeID, "target", target.String(),
			"reason", cause.reason, "error", cause.Error())
	} else {
		p.logger.Warn(base, "event", "proxy_retry", "trace_id", traceHex,
			"protocol", protocolName, "node_id", nodeID, "target", target.String())
	}
}

// observeRequest records the per request counters and duration.
func (p *pipeline) observeRequest(protocolName, nodeID, credID, result string, elapsed time.Duration) {
	if p.metrics == nil {
		return
	}
	nodeLabel := p.metrics.NodeLabel(nodeID)
	p.metrics.ProxyRequestsTotal.WithLabelValues(protocolName, nodeLabel, p.metrics.CredentialLabel(credID), result).Inc()
	p.metrics.ProxyDuration.WithLabelValues(protocolName, nodeLabel).Observe(elapsed.Seconds())
}

// rateLimitHit records one limiter backpressure event.
func (p *pipeline) rateLimitHit(scope string) {
	if p.metrics != nil {
		p.metrics.RateLimitHits.WithLabelValues(scope).Inc()
	}
}

// addBytes records relayed bytes. direction "in" is client to node, "out" is
// node to client, matching the tunnel layer convention.
func (p *pipeline) addBytes(direction, nodeID string, n int64) {
	if p.metrics == nil || n <= 0 {
		return
	}
	p.metrics.TunnelBytesTotal.WithLabelValues(direction, p.metrics.NodeLabel(nodeID)).Add(float64(n))
}

// activeConn adds one to the active connection gauge.
func (p *pipeline) activeConn(delta int) {
	if p.metrics == nil {
		return
	}
	if delta > 0 {
		p.metrics.ProxyActiveConns.Inc()
	} else {
		p.metrics.ProxyActiveConns.Dec()
	}
}

// auditEvent delivers one audit record through the injected callback. A
// panicking callback must never take the proxy down.
func (p *pipeline) auditEvent(event string, detail map[string]string) {
	if p.audit == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("audit callback panicked", "event", event, "panic", fmt.Sprint(r))
		}
	}()
	p.audit(event, detail)
}

// authBanBlocked rejects a source IP before authentication when it is inside an
// active failure ban.
func (p *pipeline) authBanBlocked(sourceIP, protocolName string) *proxyError {
	if p.authBan == nil || strings.TrimSpace(sourceIP) == "" {
		return nil
	}
	remaining, blocked := p.authBan.Blocked(sourceIP)
	if !blocked {
		return nil
	}
	retryAfter := int(remaining.Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	p.auditEvent("proxy.auth_blocked", map[string]string{
		"protocol":            protocolName,
		"source_ip":           sourceIP,
		"retry_after_seconds": fmt.Sprint(retryAfter),
	})
	return errSourceBanned()
}

// recordAuthFailure counts one of the countable credential failures. Disabled
// and expired credentials, source-CIDR rejection and ACL denials are not routed
// here on purpose.
func (p *pipeline) recordAuthFailure(sourceIP, protocolName, reason string) {
	if p.authBan == nil || strings.TrimSpace(sourceIP) == "" {
		return
	}
	banned, banFor, failures := p.authBan.RecordFailure(sourceIP, reason)
	if !banned {
		return
	}
	seconds := int(banFor.Seconds())
	p.auditEvent("proxy.source_banned", map[string]string{
		"protocol":    protocolName,
		"source_ip":   sourceIP,
		"reason":      reason,
		"failures":    fmt.Sprint(failures),
		"ban_seconds": fmt.Sprint(seconds),
	})
	p.logger.Warn("代理来源 IP 因认证失败次数过多被临时封禁",
		"event", "proxy.source_banned",
		"source_ip", sourceIP,
		"protocol", protocolName,
		"reason", reason,
		"failures", failures,
		"ban_seconds", seconds)
}

func (p *pipeline) recordAuthSuccess(sourceIP string) {
	if p.authBan == nil || strings.TrimSpace(sourceIP) == "" {
		return
	}
	p.authBan.RecordSuccess(sourceIP)
}

// limiterUp returns the upload limiter for a stream, or nil.
func (p *pipeline) limiterUp(credID, nodeID string) ByteLimiter {
	if p.limiter == nil {
		return nil
	}
	return p.limiter.Up(credID, nodeID)
}

// limiterDown returns the download limiter for a stream, or nil.
func (p *pipeline) limiterDown(credID, nodeID string) ByteLimiter {
	if p.limiter == nil {
		return nil
	}
	return p.limiter.Down(credID, nodeID)
}

// requestTracker pairs the optional OnRequestStart / OnRequestEnd callbacks so
// every client request delivers exactly one start and one end event, including
// requests that fail before a node could be selected.
type requestTracker struct {
	p            *pipeline
	credentialID string
	protocol     string
	target       string
	nodeID       string
	started      bool
	finished     bool
	bytesIn      int64
	bytesOut     int64
}

// trackRequest creates a tracker for one client request.
func (p *pipeline) trackRequest(protocolName, target, credentialID string) *requestTracker {
	return &requestTracker{p: p, protocol: protocolName, target: target, credentialID: credentialID}
}

// start fires OnRequestStart exactly once.
func (t *requestTracker) start(nodeID string) {
	if t == nil || t.started {
		return
	}
	t.started = true
	if nodeID != "" {
		t.nodeID = nodeID
	}
	if t.p.onRequestStart == nil {
		return
	}
	defer t.p.recoverCallback("OnRequestStart")
	t.p.onRequestStart(t.credentialID, t.protocol, t.target, t.nodeID)
}

// serving records the node that actually serves the request; it may differ from
// the first attempted node after a transparent retry.
func (t *requestTracker) serving(nodeID string) {
	if t == nil || nodeID == "" {
		return
	}
	t.nodeID = nodeID
}

// addBytes accumulates the relayed byte counts.
func (t *requestTracker) addBytes(in, out int64) {
	if t == nil {
		return
	}
	t.bytesIn += in
	t.bytesOut += out
}

// finish fires OnRequestEnd exactly once.
func (t *requestTracker) finish(perr *proxyError) {
	if t == nil || t.finished {
		return
	}
	t.finished = true
	t.start(t.nodeID)
	if t.p.onRequestEnd == nil {
		return
	}
	var errValue error
	if perr != nil {
		errValue = perr
	}
	defer t.p.recoverCallback("OnRequestEnd")
	t.p.onRequestEnd(t.credentialID, t.protocol, t.target, t.nodeID, t.bytesIn, t.bytesOut, errValue)
}

// recoverCallback protects the proxy from a panicking user callback.
func (p *pipeline) recoverCallback(name string) {
	if r := recover(); r != nil {
		p.logger.Error("proxy request callback panicked", "callback", name, "panic", fmt.Sprint(r))
	}
}
