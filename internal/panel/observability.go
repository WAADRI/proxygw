package panel

import (
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxygw/internal/audit"
	"proxygw/internal/model"
)

// auditResponse is the GET /api/v1/audit payload.
type auditResponse struct {
	Items []model.AuditEvent `json:"items"`
}

// handleAudit serves GET /api/v1/audit with time/action/actor filters.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := audit.Filter{}

	since, err := parseOptionalTimestamp(query.Get("since"))
	if err != nil {
		s.writeValidationError(w, "since 参数非法", fieldError{Field: "since", Message: "期望 RFC3339 时间或 Unix 秒"})
		return
	}
	until, err := parseOptionalTimestamp(query.Get("until"))
	if err != nil {
		s.writeValidationError(w, "until 参数非法", fieldError{Field: "until", Message: "期望 RFC3339 时间或 Unix 秒"})
		return
	}
	filter.Since = since
	filter.Until = until

	filter.Action = strings.TrimSpace(query.Get("action"))
	if len(filter.Action) > 128 {
		s.writeValidationError(w, "action 过长", fieldError{Field: "action", Message: "最多 128 字节"})
		return
	}
	filter.Actor = strings.TrimSpace(query.Get("actor"))
	if len(filter.Actor) > 128 {
		s.writeValidationError(w, "actor 过长", fieldError{Field: "actor", Message: "最多 128 字节"})
		return
	}

	filter.Limit = defaultAuditLimit
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 1 || value > 10000 {
			s.writeValidationError(w, "limit 参数非法", fieldError{Field: "limit", Message: "期望 1-10000 的整数"})
			return
		}
		filter.Limit = value
	}

	items, err := s.opts.Audit.Query(filter)
	if err != nil {
		s.writeInternalError(w, err, "查询审计日志失败")
		return
	}
	if items == nil {
		items = []model.AuditEvent{}
	}
	s.writeJSON(w, http.StatusOK, auditResponse{Items: items})
}

// defaultAuditLimit is the default /audit page size required by the contract.
const defaultAuditLimit = 200

// parseOptionalTimestamp parses an empty/RFC3339/Unix-seconds timestamp.
func parseOptionalTimestamp(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}
	secs, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(secs, 0).UTC(), nil
}

// --- tunnel sessions -------------------------------------------------------

// tunnelSessionJSON is one item of GET /tunnel/sessions.
type tunnelSessionJSON struct {
	NodeID         string    `json:"node_id"`
	NodeAlias      string    `json:"node_alias"`
	Transport      string    `json:"transport"`
	State          string    `json:"state"`
	Planes         int       `json:"planes"`
	Epoch          uint32    `json:"epoch"`
	LastError      string    `json:"last_error,omitempty"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
	LastHeartbeat  time.Time `json:"last_heartbeat,omitempty"`
}

// tunnelSessionsResponse is the GET /api/v1/tunnel/sessions payload.
type tunnelSessionsResponse struct {
	Items        []tunnelSessionJSON `json:"items"`
	TransportMix map[string]int      `json:"transport_mix"`
}

// handleTunnelSessions serves GET /api/v1/tunnel/sessions.
func (s *Server) handleTunnelSessions(w http.ResponseWriter, r *http.Request) {
	resp := tunnelSessionsResponse{Items: []tunnelSessionJSON{}, TransportMix: map[string]int{}}
	if s.opts.Tunnel != nil {
		sessions := s.opts.Tunnel.Sessions()
		sort.SliceStable(sessions, func(i, j int) bool {
			if sessions[i].NodeID != sessions[j].NodeID {
				return sessions[i].NodeID < sessions[j].NodeID
			}
			return sessions[i].Alias < sessions[j].Alias
		})
		for _, sess := range sessions {
			planes := sess.Planes
			if planes == 0 {
				planes = s.opts.Tunnel.NodePlaneCount(sess.NodeID)
			}
			resp.Items = append(resp.Items, tunnelSessionJSON{
				NodeID:         sess.NodeID,
				NodeAlias:      sess.Alias,
				Transport:      sess.Transport,
				State:          sess.State,
				Planes:         planes,
				Epoch:          sess.Epoch,
				LastError:      sess.LastError,
				ConnectedSince: sess.ConnectedSince,
				LastHeartbeat:  sess.LastHeartbeat,
			})
			transport := strings.ToLower(strings.TrimSpace(sess.Transport))
			if transport != "" && sessionHasTransport(sess.State) {
				resp.TransportMix[transport]++
			}
		}
	}
	// The contract renders transport_mix with quic/ws keys; keep both present so
	// the dashboard can rely on them even while no session exists.
	if _, ok := resp.TransportMix["quic"]; !ok {
		resp.TransportMix["quic"] = 0
	}
	if _, ok := resp.TransportMix["ws"]; !ok {
		resp.TransportMix["ws"] = 0
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// sessionHasTransport reports whether a session state implies a live transport
// connection. Offline/closed placeholders (the app adapter reports known nodes
// without a session with state "offline") must not inflate transport_mix.
func sessionHasTransport(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "offline", "closed", "none", "disconnected":
		return false
	default:
		return true
	}
}

// --- certificate -----------------------------------------------------------

// certResponse is the GET /api/v1/cert payload.
type certResponse struct {
	Mode       string `json:"mode"`
	Pin        string `json:"pin"`
	PinNext    string `json:"pin_next"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	NotAfter   string `json:"not_after,omitempty"`
	LastReload string `json:"last_reload,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

// handleCertGet serves GET /api/v1/cert.
func (s *Server) handleCertGet(w http.ResponseWriter, r *http.Request) {
	if s.opts.Cert == nil {
		s.writeUnavailable(w, "证书管理器")
		return
	}
	status := s.opts.Cert.Status()
	resp := certResponse{
		Mode:      status.Mode,
		Pin:       status.Pin,
		PinNext:   status.PinNext,
		CertPath:  status.CertPath,
		KeyPath:   status.KeyPath,
		LastError: status.LastError,
	}
	if !status.NotAfter.IsZero() {
		resp.NotAfter = status.NotAfter.UTC().Format(time.RFC3339)
	}
	if !status.LastReload.IsZero() {
		resp.LastReload = status.LastReload.UTC().Format(time.RFC3339)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// certRotatePinResponse is the POST /cert/rotate-pin payload.
type certRotatePinResponse struct {
	Pin     string `json:"pin"`
	Message string `json:"message"`
}

// handleCertRotatePin serves POST /api/v1/cert/rotate-pin. It only generates the
// next pin; switching the active key pair stays a manual operation.
func (s *Server) handleCertRotatePin(w http.ResponseWriter, r *http.Request) {
	if s.opts.Cert == nil {
		s.writeUnavailable(w, "证书管理器")
		return
	}
	pin, err := s.opts.Cert.RotatePin()
	if err != nil {
		s.writeInternalError(w, err, "生成下一枚 pin 失败")
		return
	}
	s.auditRequest(r, "cert.rotate_pin", "", "ok", map[string]string{"pin_next": pin})
	s.log.Info("已生成下一枚轮换 pin", "pin_next", pin, "actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, certRotatePinResponse{
		Pin:     pin,
		Message: "已生成下一枚 SPKI pin；请先下发到全部节点并确认后，再切换证书",
	})
}

// handleCertReload serves POST /api/v1/cert/reload.
func (s *Server) handleCertReload(w http.ResponseWriter, r *http.Request) {
	if s.opts.Cert == nil {
		s.writeUnavailable(w, "证书管理器")
		return
	}
	if err := s.opts.Cert.Reload(); err != nil {
		s.auditRequest(r, "cert.reload", "", "failure", nil)
		s.writeInternalError(w, err, "证书热重载失败")
		return
	}
	s.auditRequest(r, "cert.reload", "", "ok", nil)
	s.log.Info("证书已热重载", "actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- geo providers ---------------------------------------------------------

// geoProvidersResponse is the GET /geo/providers payload.
type geoProvidersResponse struct {
	Items []ProviderStatus `json:"items"`
}

// geoProviderUpdateRequest is the PATCH /geo/providers/{name} body.
type geoProviderUpdateRequest struct {
	Enabled *bool `json:"enabled"`
}

// geoProviderTestRequest is the POST /geo/providers/{name}/test body.
type geoProviderTestRequest struct {
	IP string `json:"ip"`
}

// handleGeoProviders serves GET /api/v1/geo/providers.
func (s *Server) handleGeoProviders(w http.ResponseWriter, r *http.Request) {
	items := []ProviderStatus{}
	if s.opts.Geo != nil {
		if statuses := s.opts.Geo.ProviderStatuses(); statuses != nil {
			items = statuses
		}
	}
	s.writeJSON(w, http.StatusOK, geoProvidersResponse{Items: items})
}

// handleGeoProviderUpdate serves PATCH /api/v1/geo/providers/{name}.
func (s *Server) handleGeoProviderUpdate(w http.ResponseWriter, r *http.Request) {
	if s.opts.Geo == nil {
		s.writeUnavailable(w, "归属地解析器")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "provider 不存在", nil)
		return
	}
	var req geoProviderUpdateRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	if req.Enabled == nil {
		s.writeValidationError(w, "缺少 enabled 字段", fieldError{Field: "enabled", Message: "必须提供布尔值"})
		return
	}
	if err := s.opts.Geo.SetProviderEnabled(name, *req.Enabled); err != nil {
		if isNotFoundError(err) {
			s.writeError(w, http.StatusNotFound, "not_found", "provider 不存在", nil)
			return
		}
		s.writeInternalError(w, err, "更新 provider 状态失败")
		return
	}
	status, found := s.providerStatus(name)
	if !found {
		status = ProviderStatus{Name: name, Enabled: *req.Enabled}
	}
	s.auditRequest(r, "geo.provider.update", name, "ok", map[string]string{"enabled": boolText(*req.Enabled)})
	s.log.Info("归属地 provider 状态已更新", "provider", name, "enabled", *req.Enabled,
		"actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, status)
}

// handleGeoProviderTest serves POST /api/v1/geo/providers/{name}/test.
func (s *Server) handleGeoProviderTest(w http.ResponseWriter, r *http.Request) {
	if s.opts.Geo == nil {
		s.writeUnavailable(w, "归属地解析器")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "provider 不存在", nil)
		return
	}
	var req geoProviderTestRequest
	if !s.readJSON(w, r, &req, false, false) {
		return
	}
	rawIP := strings.TrimSpace(req.IP)
	var ip net.IP
	if rawIP != "" {
		ip = net.ParseIP(rawIP)
		if ip == nil {
			s.writeValidationError(w, "IP 地址非法", fieldError{Field: "ip", Message: "期望合法的 IPv4/IPv6 地址"})
			return
		}
	}
	result, err := s.opts.Geo.TestProvider(r.Context(), name, ip)
	if err != nil && result == nil {
		if isNotFoundError(err) {
			s.writeError(w, http.StatusNotFound, "not_found", "provider 不存在", nil)
			return
		}
		s.writeInternalError(w, err, "provider 测试失败")
		return
	}
	resp := ProviderTestResult{}
	if result != nil {
		resp = *result
	}
	if err != nil && resp.Error == "" {
		resp.Error = err.Error()
	}
	if resp.Provider == "" {
		resp.Provider = name
	}
	if resp.IP == "" && ip != nil {
		resp.IP = ip.String()
	}
	if resp.Result == nil {
		resp.Result = map[string]any{}
	}
	if resp.HitPaths == nil {
		resp.HitPaths = map[string]string{}
	}
	s.auditRequest(r, "geo.provider.test", name, resultText(resp.Error), map[string]string{
		"ip":          resp.IP,
		"duration_ms": strconv.FormatFloat(resp.DurationMS, 'f', 3, 64),
	})
	s.writeJSON(w, http.StatusOK, resp)
}

// providerStatus looks up one provider status.
func (s *Server) providerStatus(name string) (ProviderStatus, bool) {
	if s.opts.Geo == nil {
		return ProviderStatus{}, false
	}
	for _, status := range s.opts.Geo.ProviderStatuses() {
		if strings.EqualFold(status.Name, name) {
			return status, true
		}
	}
	return ProviderStatus{}, false
}

// isNotFoundError heuristically classifies "unknown provider" style errors.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"not found", "unknown", "不存在", "未找到"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// resultText renders an error string as an audit result.
func resultText(errMessage string) string {
	if strings.TrimSpace(errMessage) == "" {
		return "ok"
	}
	return "error"
}

// --- TopN statistics -------------------------------------------------------

// topNWindowRe validates the window query parameter.
var topNWindowRe = regexp.MustCompile(`^[0-9]{1,5}(ms|s|m|h)$`)

// topNResponse is the GET /stats/topn payload. The contract spells the window
// echo "windows".
type topNResponse struct {
	Windows     string       `json:"windows"`
	Targets     []TargetStat `json:"targets"`
	Nodes       []TargetStat `json:"nodes"`
	Credentials []TargetStat `json:"credentials"`
}

// handleStatsTopN serves GET /api/v1/stats/topn.
func (s *Server) handleStatsTopN(w http.ResponseWriter, r *http.Request) {
	if s.opts.Stats == nil {
		s.writeUnavailable(w, "统计")
		return
	}
	query := r.URL.Query()
	window := strings.TrimSpace(query.Get("window"))
	if window == "" {
		window = "15m"
	}
	if !topNWindowRe.MatchString(window) {
		s.writeValidationError(w, "window 参数非法", fieldError{Field: "window", Message: "期望形如 15m / 1h 的时间窗"})
		return
	}
	limit := 10
	if raw := strings.TrimSpace(query.Get("n")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			s.writeValidationError(w, "n 参数非法", fieldError{Field: "n", Message: "期望 1-100 的整数"})
			return
		}
		limit = value
	}
	targets, nodes, credentials := s.opts.Stats.TopN(r.Context(), window, limit)
	s.writeJSON(w, http.StatusOK, topNResponse{
		Windows:     window,
		Targets:     nonNilStats(targets),
		Nodes:       nonNilStats(nodes),
		Credentials: nonNilStats(credentials),
	})
}

// nonNilStats returns a non-nil TargetStat slice so JSON renders [] not null.
func nonNilStats(in []TargetStat) []TargetStat {
	if in == nil {
		return []TargetStat{}
	}
	return in
}
