package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxygw/internal/logx"
	"proxygw/internal/model"
	"proxygw/internal/version"
)

// Panel constants. The cookie names match the config defaults; the session
// cookie name can be overridden through Options.CookieName (the CSRF cookie is
// internal and always uses the default).
const (
	defaultSessionCookie = "np_admin"
	defaultCSRFCookie    = "np_csrf"

	csrfHeaderName = "X-CSRF-Token"

	apiPrefix      = "/api/v1"
	apiPathPrefix  = "/api/"
	staticPrefix   = "/static/"
	maxRequestBody = 1 << 20 // 1 MiB
	indexFileName  = "index.html"

	sseTickInterval      = 3 * time.Second
	sseHeartbeatInterval = 15 * time.Second
)

// cspPolicy is the Content-Security-Policy required by docs/PANEL_API.md.
const cspPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"

// fieldError is one entry of the field_errors array in an error response.
type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// errorResponse is the unified JSON error envelope.
type errorResponse struct {
	Error       string       `json:"error"`
	Message     string       `json:"message,omitempty"`
	FieldErrors []fieldError `json:"field_errors,omitempty"`
}

// lockedOutResponse is the 429 login rate limit response.
type lockedOutResponse struct {
	Error             string `json:"error"`
	Message           string `json:"message,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// Server serves the panel API, the embedded web assets and the SPA fallback.
// It is safe for concurrent use.
type Server struct {
	opts Options
	log  *slog.Logger
	now  func() time.Time

	routes []routeEntry
	hub    *sseHub

	sessionCookie string
	csrfCookie    string
	serverURL     string
}

// New validates the options and builds the panel server.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Admin == nil:
		return nil, errors.New("panel: Options.Admin 不能为空")
	case opts.Auth == nil:
		return nil, errors.New("panel: Options.Auth 不能为空")
	case opts.Groups == nil:
		return nil, errors.New("panel: Options.Groups 不能为空")
	case opts.Rules == nil:
		return nil, errors.New("panel: Options.Rules 不能为空")
	case opts.Registry == nil:
		return nil, errors.New("panel: Options.Registry 不能为空")
	case opts.ACL == nil:
		return nil, errors.New("panel: Options.ACL 不能为空")
	case opts.Settings == nil:
		return nil, errors.New("panel: Options.Settings 不能为空")
	case opts.Audit == nil:
		return nil, errors.New("panel: Options.Audit 不能为空")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	sessionCookie := strings.TrimSpace(opts.CookieName)
	if sessionCookie == "" {
		sessionCookie = defaultSessionCookie
	}
	csrfCookie := strings.TrimSpace(opts.CSRFCookieName)
	if csrfCookie == "" {
		csrfCookie = defaultCSRFCookie
	}

	s := &Server{
		opts:          opts,
		log:           logx.WithFields(opts.Logger, "component", "panel"),
		now:           now,
		hub:           newSSEHub(),
		sessionCookie: sessionCookie,
		csrfCookie:    csrfCookie,
		serverURL:     strings.TrimRight(strings.TrimSpace(opts.ServerURL), "/"),
	}
	s.routes = s.buildRoutes()
	return s, nil
}

// Handler returns the panel HTTP handler (API + static assets + SPA fallback).
// It intentionally does not serve /healthz, /version or /metrics: the app mux
// mounts those separately.
func (s *Server) Handler() http.Handler { return s }

// ServeHTTP implements http.Handler. Security headers are applied to every
// response; panics are recovered and turned into a JSON 500 for API calls.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("面板请求处理发生 panic", "path", r.URL.Path, "method", r.Method, "panic", fmt.Sprint(rec))
			s.writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误，请稍后重试", nil)
		}
	}()

	path := r.URL.Path
	switch {
	case path == apiPrefix+"/login":
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w, []string{http.MethodPost})
			return
		}
		s.handleLogin(w, r)
	case strings.HasPrefix(path, apiPrefix+"/") || path == apiPrefix:
		if !s.authenticate(w, r) {
			return
		}
		if isWriteMethod(r.Method) && !s.checkCSRF(w, r) {
			return
		}
		s.dispatchAPI(w, r)
	case strings.HasPrefix(path, apiPathPrefix):
		s.writeError(w, http.StatusNotFound, "not_found", "接口不存在", nil)
	default:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.writeMethodNotAllowed(w, []string{http.MethodGet, http.MethodHead})
			return
		}
		s.serveWeb(w, r)
	}
}

// setSecurityHeaders applies the panel security headers to every response.
func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", cspPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

// --- routing ---------------------------------------------------------------

// routeEntry is one method+path handler. Patterns use "{name}" wildcards for a
// single path segment; static segments must match exactly.
type routeEntry struct {
	method   string
	segments []string
	handle   func(http.ResponseWriter, *http.Request)
}

// route adds one entry to the table, pre-splitting its pattern.
func route(method, pattern string, handle func(http.ResponseWriter, *http.Request)) routeEntry {
	return routeEntry{method: method, segments: splitPath(pattern), handle: handle}
}

// buildRoutes assembles the full /api/v1 route table.
func (s *Server) buildRoutes() []routeEntry {
	routes := []routeEntry{
		// Authentication and realtime.
		route(http.MethodPost, "/api/v1/logout", s.handleLogout),
		route(http.MethodGet, "/api/v1/session", s.handleSession),
		route(http.MethodGet, "/api/v1/events", s.handleEvents),

		// Overview.
		route(http.MethodGet, "/api/v1/overview", s.handleOverview),

		// Nodes.
		route(http.MethodGet, "/api/v1/nodes", s.handleNodesList),
		route(http.MethodGet, "/api/v1/nodes/install-template", s.handleInstallTemplate),
		route(http.MethodGet, "/api/v1/nodes/tokens", s.handleNodeTokensList),
		route(http.MethodPost, "/api/v1/nodes/tokens", s.handleNodeTokenIssue),
		route(http.MethodDelete, "/api/v1/nodes/tokens/{id}", s.handleNodeTokenRevoke),
		route(http.MethodPatch, "/api/v1/nodes/{id}", s.handleNodePatch),
		route(http.MethodPost, "/api/v1/nodes/{id}/kick", s.handleNodeKick),
		route(http.MethodPost, "/api/v1/nodes/{id}/probe", s.handleNodeProbe),
		route(http.MethodPost, "/api/v1/nodes/{id}/update", s.handleNodeUpdate),
		route(http.MethodPost, "/api/v1/nodes/update", s.handleNodesUpdate),
		route(http.MethodGet, "/api/v1/nodes/{id}/install-command", s.handleInstallCommand),

		// Node groups.
		route(http.MethodGet, "/api/v1/groups", s.handleGroupsList),
		route(http.MethodPost, "/api/v1/groups", s.handleGroupCreate),
		route(http.MethodPatch, "/api/v1/groups/{id}", s.handleGroupUpdate),
		route(http.MethodDelete, "/api/v1/groups/{id}", s.handleGroupDelete),
		route(http.MethodGet, "/api/v1/groups/{id}/members", s.handleGroupMembers),

		// Credentials.
		route(http.MethodGet, "/api/v1/credentials", s.handleCredentialsList),
		route(http.MethodPost, "/api/v1/credentials", s.handleCredentialCreate),
		route(http.MethodPatch, "/api/v1/credentials/{id}", s.handleCredentialUpdate),
		route(http.MethodDelete, "/api/v1/credentials/{id}", s.handleCredentialDelete),
		route(http.MethodPost, "/api/v1/credentials/{id}/kick-sessions", s.handleCredentialKickSessions),
		route(http.MethodGet, "/api/v1/credentials/{id}/usage", s.handleCredentialUsage),
		route(http.MethodGet, "/api/v1/credentials/{id}/visible-nodes", s.handleCredentialVisibleNodes),

		// Rules: ACL.
		route(http.MethodGet, "/api/v1/rules/acl", s.handleACLGet),
		route(http.MethodPut, "/api/v1/rules/acl", s.handleACLReplace),
		route(http.MethodPost, "/api/v1/rules/acl", s.handleACLCreate),
		route(http.MethodGet, "/api/v1/rules/acl/forced", s.handleACLForced),
		route(http.MethodPatch, "/api/v1/rules/acl/{id}", s.handleACLUpdate),
		route(http.MethodDelete, "/api/v1/rules/acl/{id}", s.handleACLDelete),

		// Rules: sticky blacklist.
		route(http.MethodGet, "/api/v1/rules/sticky", s.handleStickyList),
		route(http.MethodPost, "/api/v1/rules/sticky", s.handleStickyCreate),
		route(http.MethodPost, "/api/v1/rules/sticky/preview", s.handleStickyPreview),
		route(http.MethodPatch, "/api/v1/rules/sticky/{id}", s.handleStickyUpdate),
		route(http.MethodDelete, "/api/v1/rules/sticky/{id}", s.handleStickyDelete),

		// Runtime settings.
		route(http.MethodGet, "/api/v1/settings", s.handleSettingsGet),
		route(http.MethodPut, "/api/v1/settings", s.handleSettingsPut),
		route(http.MethodPost, "/api/v1/settings/undo", s.handleSettingsUndo),
		route(http.MethodPost, "/api/v1/settings/reset", s.handleSettingsReset),

		// Audit.
		route(http.MethodGet, "/api/v1/audit", s.handleAudit),

		// Tunnel sessions.
		route(http.MethodGet, "/api/v1/tunnel/sessions", s.handleTunnelSessions),

		// Certificate identity.
		route(http.MethodGet, "/api/v1/cert", s.handleCertGet),
		route(http.MethodPost, "/api/v1/cert/rotate-pin", s.handleCertRotatePin),
		route(http.MethodPost, "/api/v1/cert/reload", s.handleCertReload),

		// Geolocation providers.
		route(http.MethodGet, "/api/v1/geo/providers", s.handleGeoProviders),
		route(http.MethodPatch, "/api/v1/geo/providers/{name}", s.handleGeoProviderUpdate),
		route(http.MethodPost, "/api/v1/geo/providers/{name}/test", s.handleGeoProviderTest),

		// Statistics.
		route(http.MethodGet, "/api/v1/stats/topn", s.handleStatsTopN),
	}
	return routes
}

// dispatchAPI matches the request against the route table.
func (s *Server) dispatchAPI(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path)
	var allowed []string
	for i := range s.routes {
		params, ok := matchSegments(s.routes[i].segments, segments)
		if !ok {
			continue
		}
		if s.routes[i].method != r.Method {
			allowed = append(allowed, s.routes[i].method)
			continue
		}
		for name, value := range params {
			r.SetPathValue(name, value)
		}
		s.routes[i].handle(w, r)
		return
	}
	if len(allowed) > 0 {
		sort.Strings(allowed)
		s.writeMethodNotAllowed(w, dedupeStrings(allowed))
		return
	}
	s.writeError(w, http.StatusNotFound, "not_found", "接口不存在", nil)
}

// splitPath splits a URL path into non-empty segments.
func splitPath(path string) []string {
	trimmed := strings.Trim(strings.TrimSpace(path), "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// matchSegments matches pattern segments against actual segments, returning the
// wildcard values. Both slices must have the same length.
func matchSegments(pattern, actual []string) (map[string]string, bool) {
	if len(pattern) != len(actual) {
		return nil, false
	}
	var params map[string]string
	for i := range pattern {
		seg := pattern[i]
		if len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}' {
			if actual[i] == "" {
				return nil, false
			}
			if params == nil {
				params = make(map[string]string, 1)
			}
			params[seg[1:len(seg)-1]] = actual[i]
			continue
		}
		if seg != actual[i] {
			return nil, false
		}
	}
	return params, true
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// --- authentication / CSRF -------------------------------------------------

// adminSession is stored in the request context after JWT verification.
type adminSession struct {
	Username string
	Expires  time.Time
}

type sessionContextKey struct{}

// sessionFromRequest returns the verified administrator session, if any.
func sessionFromRequest(r *http.Request) *adminSession {
	if r == nil {
		return nil
	}
	if v, ok := r.Context().Value(sessionContextKey{}).(*adminSession); ok {
		return v
	}
	return nil
}

// authenticate verifies the np_admin cookie and attaches the session to the
// request context. It writes a 401 JSON response and returns false on failure.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(s.sessionCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期", nil)
		return false
	}
	claims, err := s.opts.Admin.VerifyToken(cookie.Value)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期", nil)
		return false
	}
	sess := &adminSession{Username: claims.Username, Expires: claims.Expires}
	*r = *r.WithContext(contextWithSession(r.Context(), sess))
	return true
}

// contextWithSession stores the verified administrator session in the context.
func contextWithSession(ctx context.Context, sess *adminSession) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, sess)
}

// isWriteMethod reports whether the method must carry a CSRF token.
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

// checkCSRF validates the double-submit CSRF token: the X-CSRF-Token header must
// equal the np_csrf cookie (constant time comparison).
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(s.csrfCookie)
	header := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if err != nil || cookie.Value == "" || header == "" ||
		subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) != 1 {
		s.writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF 校验失败，请刷新页面后重试", nil)
		return false
	}
	return true
}

// --- response helpers ------------------------------------------------------

// writeJSON writes one JSON payload with the given status code.
func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.log.Debug("面板响应写入失败", "error", err)
	}
}

// writeError writes the unified error envelope.
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string, fields []fieldError) {
	s.writeJSON(w, status, errorResponse{Error: code, Message: message, FieldErrors: fields})
}

// writeValidationError writes a 422 validation_failed response.
func (s *Server) writeValidationError(w http.ResponseWriter, message string, fields ...fieldError) {
	s.writeError(w, http.StatusUnprocessableEntity, "validation_failed", message, fields)
}

// writeMethodNotAllowed writes a 405 JSON response with the Allow header.
func (s *Server) writeMethodNotAllowed(w http.ResponseWriter, allowed []string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不被允许", nil)
}

// writeInternalError logs err and writes a 500 JSON response.
func (s *Server) writeInternalError(w http.ResponseWriter, err error, message string) {
	s.log.Error("面板接口内部错误", "error", err)
	if message == "" {
		message = "服务器内部错误，请稍后重试"
	}
	s.writeError(w, http.StatusInternalServerError, "internal_error", message, nil)
}

// writeUnavailable writes a 503 for endpoints whose injected dependency is nil.
func (s *Server) writeUnavailable(w http.ResponseWriter, component string) {
	s.writeError(w, http.StatusServiceUnavailable, "unavailable", component+" 尚未就绪", nil)
}

// readJSON decodes an optional/required JSON request body. strict enables
// DisallowUnknownFields (settings only). Decode problems are answered with a
// 422/413 JSON response and the function returns false.
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, dst any, required, strict bool) bool {
	if r.Body == nil {
		if required {
			s.writeValidationError(w, "请求体为空", fieldError{Field: "body", Message: "缺少请求体"})
			return false
		}
		return true
	}
	limit := http.MaxBytesReader(w, r.Body, maxRequestBody)
	data, err := io.ReadAll(limit)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "请求体过大（上限 1 MiB）", nil)
			return false
		}
		s.writeValidationError(w, "读取请求体失败", fieldError{Field: "body", Message: err.Error()})
		return false
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		if required {
			s.writeValidationError(w, "请求体为空", fieldError{Field: "body", Message: "缺少请求体"})
			return false
		}
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		s.writeDecodeError(w, err)
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		s.writeValidationError(w, "请求体包含多余内容", fieldError{Field: "body", Message: "只允许一个 JSON 对象"})
		return false
	}
	return true
}

// writeDecodeError maps a JSON decoding error to a field_errors entry.
func (s *Server) writeDecodeError(w http.ResponseWriter, err error) {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		s.writeValidationError(w, "请求字段类型不正确", fieldError{Field: field, Message: typeErr.Error()})
		return
	}
	msg := err.Error()
	const unknownPrefix = "json: unknown field "
	if strings.HasPrefix(msg, unknownPrefix) {
		name := strings.Trim(strings.TrimPrefix(msg, unknownPrefix), `"`)
		s.writeValidationError(w, "请求包含未知字段", fieldError{Field: name, Message: "不支持的字段"})
		return
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		s.writeValidationError(w, "JSON 格式错误", fieldError{Field: "body", Message: msg})
		return
	}
	s.writeValidationError(w, "JSON 解析失败", fieldError{Field: "body", Message: msg})
}

// --- request metadata / audit ---------------------------------------------

// remoteIP extracts the client IP from the request address. Proxy headers are
// deliberately not trusted: the panel is normally reachable directly and a
// forged X-Forwarded-For must not poison the login limiter or the audit trail.
func remoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	addr := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// audit appends one audit record. Failures are logged but never fail the
// request: auditing must not break the panel.
func (s *Server) audit(action, object, actor, sourceIP, result string, detail map[string]string) {
	if s.opts.Audit == nil {
		return
	}
	if err := s.opts.Audit.LogSimple(action, object, actor, sourceIP, result, detail); err != nil {
		s.log.Warn("写入审计日志失败", "action", action, "object", object, "error", err)
	}
}

// auditRequest writes an audit record attributed to the current session.
func (s *Server) auditRequest(r *http.Request, action, object, result string, detail map[string]string) {
	actor := ""
	if sess := sessionFromRequest(r); sess != nil {
		actor = sess.Username
	}
	s.audit(action, object, actor, remoteIP(r), result, detail)
}

// notify wakes the SSE subscribers so the panel refreshes immediately after a
// mutation.
func (s *Server) notify() {
	s.hub.broadcast()
}

// --- cookies ---------------------------------------------------------------

// cookieSecure reports whether cookies must carry the Secure attribute. Plain
// HTTP (local dev, httptest) omits it so sessions still work; production always
// terminates TLS and therefore sets it.
func cookieSecure(r *http.Request) bool { return r != nil && r.TLS != nil }

// sessionCookieTTL returns the cookie Max-Age derived from the token expiry.
func (s *Server) sessionCookieTTL(expires time.Time) int {
	secs := int(expires.Sub(s.now()).Seconds())
	if secs < 1 {
		secs = 1
	}
	return secs
}

// setAuthCookies stores the session JWT and the CSRF token.
func (s *Server) setAuthCookies(w http.ResponseWriter, r *http.Request, token string, expires time.Time, csrf string) {
	ttl := s.sessionCookieTTL(expires)
	secure := cookieSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   ttl,
		Expires:  expires.UTC(),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     s.csrfCookie,
		Value:    csrf,
		Path:     "/",
		MaxAge:   ttl,
		Expires:  expires.UTC(),
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearAuthCookies removes both panel cookies.
func (s *Server) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	expired := time.Unix(0, 0).UTC()
	secure := cookieSecure(r)
	for _, name := range []string{s.sessionCookie, s.csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  expired,
			HttpOnly: name == s.sessionCookie,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// --- misc helpers ----------------------------------------------------------

// randomToken returns a URL-safe random token with n bytes of entropy.
func randomToken(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		bytesLen = 32
	}
	buf := make([]byte, bytesLen)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("生成随机令牌失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// serverURLFor returns the externally reachable base URL used in install
// commands, preferring Options.ServerURL and falling back to the request host.
func (s *Server) serverURLFor(r *http.Request) string {
	if s.serverURL != "" {
		return s.serverURL
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return ""
	}
	scheme := "https"
	if !cookieSecure(r) {
		scheme = "http"
	}
	return scheme + "://" + host
}

// versionInfo fills in the Go runtime version when the wired version.Value is
// zero-valued (tests often pass version.Info{}).
func (s *Server) versionInfo() version.Info {
	info := s.opts.Version
	if info.GoVersion == "" {
		info.GoVersion = runtime.Version()
	}
	return info
}

// sortNodes orders nodes deterministically by alias, then id, so pagination is
// stable across requests.
func sortNodes(nodes []model.Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		ai := strings.ToLower(strings.TrimSpace(nodes[i].Alias))
		aj := strings.ToLower(strings.TrimSpace(nodes[j].Alias))
		if ai != aj {
			return ai < aj
		}
		return nodes[i].ID < nodes[j].ID
	})
}

// --- validation helpers ----------------------------------------------------

// parseStoreFieldError converts a domain store validation error into one
// field_errors entry. Store errors look like "groups: name: must not be empty"
// or "rules: acl[0]: action must be..." so the leading known prefix is stripped
// and the first "field: message" pair is used when the field token is simple.
func parseStoreFieldError(err error, fallback string) fieldError {
	if err == nil {
		return fieldError{Field: fallback, Message: "校验失败"}
	}
	message := err.Error()
	for _, prefix := range []string{"groups: ", "rules: ", "acl: ", "凭据", "settings: "} {
		message = strings.TrimPrefix(message, prefix)
	}
	if idx := strings.Index(message, ": "); idx > 0 && idx < 160 {
		field := message[:idx]
		if isValidFieldToken(field) {
			return fieldError{Field: field, Message: message[idx+2:]}
		}
	}
	return fieldError{Field: fallback, Message: message}
}

// isValidFieldToken reports whether s looks like a JSON field path.
func isValidFieldToken(s string) bool {
	if s == "" || len(s) > 160 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '[', c == ']':
		default:
			return false
		}
	}
	return true
}

// itoa renders an int (small helper to keep call sites short).
func itoa(n int) string { return strconv.Itoa(n) }
