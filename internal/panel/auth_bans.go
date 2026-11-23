package panel

import (
	"net"
	"net/http"
	"strings"
)

// authBanListResponse is the GET /proxy/auth-bans payload.
type authBanListResponse struct {
	Items []AuthBanView `json:"items"`
}

// handleAuthBanList serves GET /api/v1/proxy/auth-bans.
func (s *Server) handleAuthBanList(w http.ResponseWriter, r *http.Request) {
	if s.opts.AuthBans == nil {
		s.writeUnavailable(w, "代理认证封禁表")
		return
	}
	items := s.opts.AuthBans.AuthBans()
	if items == nil {
		items = []AuthBanView{}
	}
	s.writeJSON(w, http.StatusOK, authBanListResponse{Items: items})
}

// handleAuthBanUnban serves DELETE /api/v1/proxy/auth-bans/{ip}.
func (s *Server) handleAuthBanUnban(w http.ResponseWriter, r *http.Request) {
	if s.opts.AuthBans == nil {
		s.writeUnavailable(w, "代理认证封禁表")
		return
	}
	raw := strings.TrimSpace(r.PathValue("ip"))
	if raw == "" || net.ParseIP(raw) == nil {
		s.writeValidationError(w, "来源 IP 非法", fieldError{Field: "ip", Message: "期望 IPv4/IPv6 地址"})
		return
	}
	if !s.opts.AuthBans.UnbanAuthBan(raw) {
		s.writeError(w, http.StatusNotFound, "not_found", "该来源 IP 当前没有封禁记录", nil)
		return
	}
	s.auditRequest(r, "auth_ban.unban", raw, "ok", nil)
	s.log.Warn("面板解除代理认证封禁", "source_ip", raw,
		"actor", sessionUsername(r), "admin_ip", remoteIP(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
