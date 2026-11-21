package app

import (
	"context"
	"fmt"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/webhook"
)

// alertsLoop evaluates the alert sources required by the specification: node
// offline, error rate spike and certificate expiration. A failed webhook never
// affects serving; delivery is asynchronous and rate limited internally.
func (s *Server) startAlerts(ctx context.Context) {
	if s.hook == nil {
		return
	}
	nodeTicker := time.NewTicker(15 * time.Second)
	certTicker := time.NewTicker(time.Hour)
	defer nodeTicker.Stop()
	defer certTicker.Stop()

	wasOnline := map[string]bool{}
	lastCertAlert := time.Time{}
	lastSpikeAlert := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-nodeTicker.C:
			if s.tunnel == nil {
				continue
			}
			for _, n := range s.registry.List() {
				was, seen := wasOnline[n.ID]
				wasOnline[n.ID] = n.Online
				if seen && was && !n.Online {
					s.hook.Send(webhook.Alert{
						Name:     "node_offline",
						Severity: webhook.SeverityWarning,
						Message:  fmt.Sprintf("节点 %s 离线", nodeDisplayName(n)),
						Detail: map[string]string{
							"node_id":   n.ID,
							"alias":     n.Alias,
							"transport": n.Transport,
							"egress_v4": n.EgressIP.V4,
						},
					})
				}
			}
			// Error rate spike: evaluate the last minute against the previous
			// window using the panel counters (rough but operator friendly).
			if reqs, errs, _, _, _ := s.panelDeps.counters.Snapshot(); reqs > 100 && errs*100/reqs >= 20 {
				if time.Since(lastSpikeAlert) > 10*time.Minute {
					lastSpikeAlert = time.Now()
					s.hook.Send(webhook.Alert{
						Name:     "error_rate_spike",
						Severity: webhook.SeverityCritical,
						Message:  fmt.Sprintf("代理错误率升高：%d 次请求中 %d 次失败", reqs, errs),
						Detail: map[string]string{
							"requests": fmt.Sprintf("%d", reqs),
							"errors":   fmt.Sprintf("%d", errs),
						},
					})
				}
			}
		case <-certTicker.C:
			if s.certMgr == nil {
				continue
			}
			st := s.certMgr.Status()
			if st.NotAfter.IsZero() {
				continue
			}
			if time.Until(st.NotAfter) < 30*24*time.Hour && time.Since(lastCertAlert) > 24*time.Hour {
				lastCertAlert = time.Now()
				s.hook.Send(webhook.Alert{
					Name:     "cert_expiring",
					Severity: webhook.SeverityWarning,
					Message:  fmt.Sprintf("服务端证书将在 %s 到期（模式 %s）", st.NotAfter.Format(time.RFC3339), st.Mode),
					Detail: map[string]string{
						"mode":      st.Mode,
						"not_after": st.NotAfter.Format(time.RFC3339),
						"pin":       st.Pin,
					},
				})
			}
		}
	}
}

func nodeDisplayName(n model.Node) string {
	if n.Alias != "" {
		return n.Alias + " (" + n.ID + ")"
	}
	return n.ID
}
