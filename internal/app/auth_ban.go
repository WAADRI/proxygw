package app

import (
	"proxygw/internal/panel"
)

// authBanAPIAdapter exposes the proxy auth failure bans to the panel.
type authBanAPIAdapter struct{ srv *Server }

func (a *authBanAPIAdapter) AuthBans() []panel.AuthBanView {
	if a.srv.authBan == nil {
		return []panel.AuthBanView{}
	}
	entries := a.srv.authBan.Snapshot()
	out := make([]panel.AuthBanView, 0, len(entries))
	for _, e := range entries {
		out = append(out, panel.AuthBanView{
			SourceIP:    e.SourceIP,
			Failures:    e.Failures,
			Reason:      e.Reason,
			BannedAt:    e.BannedAt,
			BannedUntil: e.BannedUntil,
			LastSeen:    e.LastSeen,
		})
	}
	return out
}

func (a *authBanAPIAdapter) UnbanAuthBan(sourceIP string) bool {
	if a.srv.authBan == nil {
		return false
	}
	return a.srv.authBan.Unban(sourceIP)
}
