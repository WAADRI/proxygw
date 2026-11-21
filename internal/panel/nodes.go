package panel

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// tokenPlaceholder is the only token value ever rendered into an install
// command. The real node token never leaves the console/state file.
const tokenPlaceholder = "<节点接入令牌>"

// pinPlaceholder is used when the certificate manager is not wired yet.
const pinPlaceholder = "<服务端 SPKI pin>"

// nodesSummary is the fleet summary of GET /nodes.
type nodesSummary struct {
	Nodes           int `json:"nodes"`
	Online          int `json:"online"`
	UniqueEgressIPs int `json:"unique_egress_ips"`
}

// nodesListResponse is the GET /api/v1/nodes payload.
type nodesListResponse struct {
	Items   []model.Node `json:"items"`
	Total   int          `json:"total"`
	Summary nodesSummary `json:"summary"`
}

// handleNodesList serves GET /api/v1/nodes with filters and pagination.
func (s *Server) handleNodesList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	nodeList := s.opts.Registry.List()

	search := strings.ToLower(strings.TrimSpace(query.Get("q")))
	country := model.NormalizeCountry(query.Get("country"))
	isp := strings.ToLower(strings.TrimSpace(query.Get("isp")))
	groupID := strings.TrimSpace(query.Get("group"))

	asn := 0
	if rawASN := strings.TrimSpace(query.Get("asn")); rawASN != "" {
		parsed, err := model.NormalizeASN(rawASN)
		if err != nil {
			s.writeValidationError(w, "asn 参数非法", fieldError{Field: "asn", Message: "期望 AS15169 或 15169"})
			return
		}
		asn = parsed
	}

	onlineFilter, onlineSet, err := parseOptionalBool(query.Get("online"))
	if err != nil {
		s.writeValidationError(w, "online 参数非法", fieldError{Field: "online", Message: "期望 1/0/true/false"})
		return
	}
	uniqueOnly, err := parseOptionalFlag(query.Get("unique"))
	if err != nil {
		s.writeValidationError(w, "unique 参数非法", fieldError{Field: "unique", Message: "期望 1/true"})
		return
	}

	filtered := make([]model.Node, 0, len(nodeList))
	for i := range nodeList {
		node := nodeList[i]
		if search != "" && !nodeMatchesSearch(&node, search) {
			continue
		}
		if country != "" && model.NormalizeCountry(node.Geo.Country) != country {
			continue
		}
		if asn != 0 && node.Geo.ASN != asn {
			continue
		}
		if isp != "" && !strings.Contains(strings.ToLower(node.EffectiveISP()), isp) {
			continue
		}
		if groupID != "" && !containsString(node.Groups, groupID) {
			continue
		}
		if onlineSet && node.Online != onlineFilter {
			continue
		}
		if uniqueOnly && node.DuplicateOf != "" {
			continue
		}
		filtered = append(filtered, node)
	}
	sortNodes(filtered)

	page, size, paramErr := parsePagination(query.Get("page"), query.Get("size"))
	if paramErr != nil {
		s.writeValidationError(w, "分页参数非法", fieldError{Field: paramErr.field, Message: paramErr.message})
		return
	}
	total := len(filtered)
	items := paginateNodes(filtered, page, size)
	s.writeJSON(w, http.StatusOK, nodesListResponse{
		Items: items,
		Total: total,
		Summary: nodesSummary{
			Nodes:           s.opts.Registry.Count(),
			Online:          s.opts.Registry.OnlineCount(),
			UniqueEgressIPs: s.opts.Registry.UniqueEgressCount(),
		},
	})
}

// nodeMatchesSearch reports whether the lower-cased search term occurs in any
// human readable node field.
func nodeMatchesSearch(node *model.Node, search string) bool {
	candidates := []string{
		node.ID, node.Alias, node.Region, node.ISPLabel, node.Version, node.Transport,
		node.EgressIP.V4, node.EgressIP.V6,
		node.Geo.Country, node.Geo.Region, node.Geo.City, node.Geo.ISP, node.Geo.ASNOrg,
	}
	candidates = append(candidates, node.Tags...)
	candidates = append(candidates, node.Groups...)
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(strings.ToLower(candidate), search) {
			return true
		}
	}
	return false
}

// containsString reports whether list contains want.
func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// parseOptionalBool parses a tri-state boolean query parameter.
func parseOptionalBool(raw string) (value, set bool, err error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "all", "any":
		return false, false, nil
	case "1", "true", "yes", "online", "on":
		return true, true, nil
	case "0", "false", "no", "offline", "off":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("invalid bool %q", raw)
	}
}

// parseOptionalFlag parses a query flag (empty or 1/true).
func parseOptionalFlag(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("invalid flag %q", raw)
	}
}

// paramError describes one invalid query parameter.
type paramError struct {
	field   string
	message string
}

// parsePagination parses and bounds the page/size query parameters.
func parsePagination(rawPage, rawSize string) (page, size int, perr *paramError) {
	page, size = 1, 50
	if rawPage = strings.TrimSpace(rawPage); rawPage != "" {
		v, err := strconv.Atoi(rawPage)
		if err != nil || v < 1 || v > 1_000_000 {
			return 0, 0, &paramError{field: "page", message: "期望正整数"}
		}
		page = v
	}
	if rawSize = strings.TrimSpace(rawSize); rawSize != "" {
		v, err := strconv.Atoi(rawSize)
		if err != nil || v < 1 || v > 500 {
			return 0, 0, &paramError{field: "size", message: "期望 1-500 的整数"}
		}
		size = v
	}
	return page, size, nil
}

// paginateNodes applies page/size to a sorted node slice.
func paginateNodes(nodes []model.Node, page, size int) []model.Node {
	total := len(nodes)
	start := (page - 1) * size
	if start >= total {
		return []model.Node{}
	}
	end := start + size
	if end > total {
		end = total
	}
	out := make([]model.Node, end-start)
	copy(out, nodes[start:end])
	return out
}

// nodePatchRequest is the PATCH /nodes/{id} body. Pointer fields distinguish an
// absent field from an explicit zero value.
type nodePatchRequest struct {
	Alias    *string   `json:"alias"`
	Tags     *[]string `json:"tags"`
	Weight   *int      `json:"weight"`
	Region   *string   `json:"region"`
	ISPLabel *string   `json:"isp_label"`
	Enabled  *bool     `json:"enabled"`
}

// handleNodePatch updates the operator override of a node.
func (s *Server) handleNodePatch(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if nodeID == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	current, ok := s.opts.Registry.Get(nodeID)
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	var req nodePatchRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}

	override := model.NodeOverride{
		ID:       nodeID,
		Alias:    current.Alias,
		Region:   current.Region,
		ISPLabel: current.ISPLabel,
		Tags:     append([]string(nil), current.Tags...),
		Weight:   current.Weight,
		Enabled:  current.Enabled,
	}
	changed := make([]string, 0, 6)
	if req.Alias != nil {
		alias := strings.TrimSpace(*req.Alias)
		if len(alias) > 128 {
			s.writeValidationError(w, "别名过长", fieldError{Field: "alias", Message: "最多 128 字节"})
			return
		}
		override.Alias = alias
		changed = append(changed, "alias")
	}
	if req.Region != nil {
		region := strings.TrimSpace(*req.Region)
		if len(region) > 64 {
			s.writeValidationError(w, "地域标签过长", fieldError{Field: "region", Message: "最多 64 字节"})
			return
		}
		override.Region = region
		changed = append(changed, "region")
	}
	if req.ISPLabel != nil {
		isp := strings.TrimSpace(*req.ISPLabel)
		if len(isp) > 64 {
			s.writeValidationError(w, "ISP 标签过长", fieldError{Field: "isp_label", Message: "最多 64 字节"})
			return
		}
		override.ISPLabel = isp
		changed = append(changed, "isp_label")
	}
	if req.Tags != nil {
		tags, err := normalizeTags(*req.Tags)
		if err != nil {
			s.writeValidationError(w, "标签非法", fieldError{Field: "tags", Message: err.Error()})
			return
		}
		override.Tags = tags
		changed = append(changed, "tags")
	}
	if req.Weight != nil {
		weight := *req.Weight
		if weight < 0 || weight > 100_000 {
			s.writeValidationError(w, "权重超出范围", fieldError{Field: "weight", Message: "期望 0-100000"})
			return
		}
		override.Weight = weight
		changed = append(changed, "weight")
	}
	if req.Enabled != nil {
		override.Enabled = *req.Enabled
		changed = append(changed, "enabled")
	}
	if len(changed) == 0 {
		s.writeValidationError(w, "没有需要更新的字段", fieldError{Field: "body", Message: "至少提供一个可修改字段"})
		return
	}

	if err := s.opts.Registry.UpdateNodeOverride(override); err != nil {
		s.writeInternalError(w, err, "更新节点失败")
		return
	}
	updated, ok := s.opts.Registry.Get(nodeID)
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	s.auditRequest(r, "node.update", nodeID, "ok", map[string]string{
		"fields": strings.Join(changed, ","),
	})
	s.log.Info("节点覆盖配置已更新", "node_id", nodeID, "fields", strings.Join(changed, ","),
		"actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, updated)
}

// normalizeTags trims and validates operator tags.
func normalizeTags(in []string) ([]string, error) {
	if len(in) > 64 {
		return nil, fmt.Errorf("最多 64 个标签")
	}
	tags := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			return nil, fmt.Errorf("标签不能为空")
		}
		if len(tag) > 64 {
			return nil, fmt.Errorf("标签 %q 过长（最多 64 字节）", tag)
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		tags = append(tags, tag)
	}
	return tags, nil
}

// kickRequest is the optional POST /nodes/{id}/kick body.
type kickRequest struct {
	Reason string `json:"reason"`
}

// handleNodeKick force-disconnects every tunnel session of one node.
func (s *Server) handleNodeKick(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if _, ok := s.opts.Registry.Get(nodeID); !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	var req kickRequest
	if !s.readJSON(w, r, &req, false, false) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 128 {
		s.writeValidationError(w, "下线原因过长", fieldError{Field: "reason", Message: "最多 128 字节"})
		return
	}
	if reason == "" {
		reason = protocol.KickDisabled
	}
	kickErr := ""
	if s.opts.Tunnel != nil {
		if err := s.opts.Tunnel.KickNode(nodeID, reason, "panel forced offline"); err != nil {
			// "no active sessions" is not a failure for a force-offline action:
			// the node is already down, but we still mark it offline below.
			kickErr = err.Error()
			s.log.Warn("强制下线时隧道无活动会话", "node_id", nodeID, "error", err)
		}
	}
	s.opts.Registry.SetNodeOnline(nodeID, false)
	detail := map[string]string{"reason": reason}
	if kickErr != "" {
		detail["tunnel_error"] = kickErr
	}
	s.auditRequest(r, "node.kick", nodeID, "ok", detail)
	s.log.Warn("面板强制下线节点", "node_id", nodeID, "reason", reason,
		"actor", sessionUsername(r), "source_ip", remoteIP(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// probeRequest is the POST /nodes/{id}/probe body.
type probeRequest struct {
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	PayloadB64 string `json:"payload_b64"`
}

// probeResponse is the probe API payload (also matches protocol.ProbeResult).
type probeResponse struct {
	OK        bool    `json:"ok"`
	LatencyMS float64 `json:"latency_ms"`
	Detail    string  `json:"detail,omitempty"`
	ResultB64 string  `json:"result_b64,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// maxProbePayload is the decoded payload size limit for probe requests.
const maxProbePayload = 64 << 10

// handleNodeProbe runs ping/tcping/http/dns against one node.
func (s *Server) handleNodeProbe(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if _, ok := s.opts.Registry.Get(nodeID); !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	var req probeRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	switch kind {
	case protocol.ProbePing, protocol.ProbeTCPing, protocol.ProbeHTTP, protocol.ProbeDNS:
	default:
		s.writeValidationError(w, "拨测类型非法", fieldError{Field: "kind", Message: "支持 ping/tcping/http/dns"})
		return
	}
	target := strings.TrimSpace(req.Target)
	if kind != protocol.ProbePing && target == "" {
		s.writeValidationError(w, "缺少拨测目标", fieldError{Field: "target", Message: "该拨测类型需要目标"})
		return
	}
	if len(target) > 2048 {
		s.writeValidationError(w, "拨测目标过长", fieldError{Field: "target", Message: "最多 2048 字节"})
		return
	}
	payload, err := decodePayload(req.PayloadB64)
	if err != nil {
		s.writeValidationError(w, "payload_b64 非法", fieldError{Field: "payload_b64", Message: err.Error()})
		return
	}
	if s.opts.Tunnel == nil {
		s.writeUnavailable(w, "隧道")
		return
	}

	var (
		resp   probeResponse
		result = "ok"
	)
	if kind == protocol.ProbePing {
		latency, pingErr := s.opts.Tunnel.PingNode(r.Context(), nodeID)
		if pingErr != nil {
			result = "error"
			resp = probeResponse{OK: false, Error: pingErr.Error()}
		} else {
			resp = probeResponse{OK: true, LatencyMS: durationMillis(latency), Detail: "pong"}
		}
	} else {
		probe, probeErr := s.opts.Tunnel.ProbeNode(r.Context(), nodeID, kind, target, payload)
		switch {
		case probeErr != nil:
			result = "error"
			resp = probeResponse{OK: false, Error: probeErr.Error()}
		case probe == nil:
			result = "error"
			resp = probeResponse{OK: false, Error: "拨测结果为空"}
		default:
			resp = probeResponse{
				OK:        probe.OK,
				LatencyMS: probe.LatencyMS,
				Detail:    probe.Detail,
				Error:     probe.Error,
			}
			if len(probe.Result) > 0 {
				resp.ResultB64 = base64.StdEncoding.EncodeToString(probe.Result)
			}
			if !probe.OK {
				result = "error"
			}
		}
	}
	s.auditRequest(r, "node.probe", nodeID, result, map[string]string{
		"kind":       kind,
		"latency_ms": strconv.FormatFloat(resp.LatencyMS, 'f', -1, 64),
	})
	s.log.Info("节点拨测", "node_id", nodeID, "kind", kind, "ok", resp.OK,
		"latency_ms", resp.LatencyMS, "actor", sessionUsername(r))
	s.writeJSON(w, http.StatusOK, resp)
}

// decodePayload decodes an optional base64 payload (standard or raw alphabet).
func decodePayload(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("不是合法的 base64 编码")
		}
	}
	if len(decoded) > maxProbePayload {
		return nil, fmt.Errorf("解码后超过 %d 字节上限", maxProbePayload)
	}
	return decoded, nil
}

// durationMillis converts a duration to milliseconds, rounding to 0.001 ms.
func durationMillis(d time.Duration) float64 {
	ms := float64(d.Microseconds()) / 1000
	return math.Round(ms*1000) / 1000
}

// installCommandResponse is the GET /nodes/{id}/install-command payload.
type installCommandResponse struct {
	Command   string `json:"command"`
	Pin       string `json:"pin"`
	ServerURL string `json:"server_url"`
}

// installTemplateResponse is the GET /nodes/install-template payload.
type installTemplateResponse struct {
	Linux   string `json:"linux"`
	Windows string `json:"windows"`
}

// handleInstallCommand builds a node install command that carries the server URL
// and the current pin, but never a real access token.
func (s *Server) handleInstallCommand(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if nodeID == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	if _, ok := s.opts.Registry.Get(nodeID); !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	serverURL := s.serverURLFor(r)
	pin := s.currentPin()
	s.writeJSON(w, http.StatusOK, installCommandResponse{
		Command:   linuxInstallCommand(serverURL, pin),
		Pin:       pin,
		ServerURL: serverURL,
	})
}

// handleInstallTemplate returns the generic install templates with a token
// placeholder.
func (s *Server) handleInstallTemplate(w http.ResponseWriter, r *http.Request) {
	serverURL := s.serverURLFor(r)
	pin := s.currentPin()
	s.writeJSON(w, http.StatusOK, installTemplateResponse{
		Linux:   linuxInstallCommand(serverURL, pin),
		Windows: windowsInstallCommand(serverURL, pin),
	})
}

// currentPin returns the active SPKI pin, or an empty string when unknown.
func (s *Server) currentPin() string {
	if s.opts.Cert == nil {
		return ""
	}
	return strings.TrimSpace(s.opts.Cert.Status().Pin)
}

// linuxInstallCommand renders the POSIX install command.
func linuxInstallCommand(serverURL, pin string) string {
	return fmt.Sprintf("install-node.sh --server %s --pin %s --token %s",
		shellQuote(orPlaceholder(serverURL, "<服务端地址>")),
		shellQuote(orPlaceholder(pin, pinPlaceholder)),
		shellQuote(tokenPlaceholder))
}

// windowsInstallCommand renders the PowerShell install command.
func windowsInstallCommand(serverURL, pin string) string {
	return fmt.Sprintf("install-node.ps1 -Server %s -Pin %s -Token %s",
		powershellQuote(orPlaceholder(serverURL, "<服务端地址>")),
		powershellQuote(orPlaceholder(pin, pinPlaceholder)),
		powershellQuote(tokenPlaceholder))
}

// orPlaceholder returns fallback when value is blank.
func orPlaceholder(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// shellQuote single-quotes a POSIX shell argument.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// powershellQuote single-quotes a PowerShell argument.
func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
