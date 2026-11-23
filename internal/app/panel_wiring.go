package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"proxygw/internal/auth"
	"proxygw/internal/certs"
	"proxygw/internal/config"
	"proxygw/internal/geo"
	"proxygw/internal/model"
	"proxygw/internal/panel"
	"proxygw/internal/protocol"
	"proxygw/internal/stats"
	"proxygw/internal/version"

	"proxygw/web"
)

// panelDeps bundles the runtime statistics shared by the panel overview/SSE
// endpoints and the TopN queries.
type panelDeps struct {
	mu           sync.Mutex
	counters     stats.Counters
	trend        *stats.Trend
	targets      *stats.TopN
	nodes        *stats.TopN
	credentials  *stats.TopN
	activeByCred map[string]int64
	active       int64
}

func newPanelDeps() *panelDeps {
	return &panelDeps{
		trend:        stats.NewTrend(15*time.Minute, 15*time.Second),
		targets:      stats.NewTopN(15*time.Minute, time.Minute, 2048),
		nodes:        stats.NewTopN(15*time.Minute, time.Minute, 512),
		credentials:  stats.NewTopN(15*time.Minute, time.Minute, 512),
		activeByCred: map[string]int64{},
	}
}

// onRequestStart implements proxy.Options.OnRequestStart.
func (d *panelDeps) onRequestStart(credentialID, protocolName, target, nodeID string) {
	d.mu.Lock()
	d.activeByCred[credentialID]++
	d.active++
	active := d.active
	d.mu.Unlock()
	// Update the active gauge immediately; request completion alone would make
	// the 15s trend sample lag behind real concurrency.
	d.trend.Record(0, 0, active)
}

// onRequestEnd implements proxy.Options.OnRequestEnd.
func (d *panelDeps) onRequestEnd(credentialID, protocolName, target, nodeID string, bytesIn, bytesOut int64, err error) {
	ok := err == nil
	d.mu.Lock()
	if d.activeByCred[credentialID] > 0 {
		d.activeByCred[credentialID]--
		if d.activeByCred[credentialID] == 0 {
			delete(d.activeByCred, credentialID)
		}
	}
	if d.active > 0 {
		d.active--
	}
	active := d.active
	d.mu.Unlock()
	d.counters.AddRequests(ok)
	total := bytesIn + bytesOut
	d.targets.Record(target, total, !ok)
	if nodeID != "" {
		d.nodes.Record(nodeID, total, !ok)
	}
	if credentialID != "" {
		d.credentials.Record(credentialID, total, !ok)
	}
	d.trend.Record(1, boolToInt64(!ok), active)
}

// onRetry counts one real transparent retry (proxy pipeline OnRetry callback).
func (d *panelDeps) onRetry() { d.counters.AddRetry() }

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ActiveCredentialSessions returns the number of in-flight requests for one
// credential (used by the panel's kick endpoint to report the effective state).
func (d *panelDeps) activeCredentialSessions(credentialID string) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activeByCred[credentialID]
}

// initPanel builds the admin manager and the panel server.
func (s *Server) initPanel() error {
	cfg := s.cfg
	admin, err := auth.NewAdminManager(auth.AdminOptions{
		Username:        cfg.Admin.Username,
		PasswordHash:    cfg.Admin.PasswordHash,
		TOTPSecret:      cfg.Admin.TOTPSecret,
		StatePath:       cfg.AdminPath(),
		JWTSecretPath:   cfg.JWTSecretPath(),
		SessionTTL:      cfg.Admin.SessionTTL.Std(),
		LoginRatePerMin: cfg.Admin.LoginRateMin,
		LockThreshold:   cfg.Admin.LockThreshold,
		LockWindow:      cfg.Admin.LockWindow.Std(),
		Logger:          s.logger,
	})
	if err != nil {
		return fmt.Errorf("app: init admin auth: %w", err)
	}
	s.gateway.admin = admin
	if pw := admin.BootstrapPassword(); pw != "" {
		s.bootMessages = append(s.bootMessages,
			"面板管理员密码（仅本次显示，请立即保存）：用户名 "+cfg.Admin.Username+"  密码 "+pw+"   面板地址 https://<server>:443/")
	}

	pn, err := panel.New(panel.Options{
		Logger:      s.logger,
		Version:     version.Current(),
		Auth:        s.gateway.creds,
		Admin:       admin,
		Groups:      s.gateway.groups,
		Rules:       s.gateway.rules,
		Registry:    s.registry,
		ACL:         s.gateway.acl,
		Settings:    s.settings,
		Audit:       s.gateway.audit,
		Metrics:     s.metrics,
		Tunnel:      &tunnelAPIAdapter{srv: s},
		Geo:         &geoAPIAdapter{srv: s},
		Sched:       &schedAPIAdapter{srv: s},
		Cert:        &certAPIAdapter{srv: s},
		Stats:       &statsAPIAdapter{srv: s},
		NodeTokens:  s.authn,
		NodeUpdates: &nodeUpdateAPIAdapter{srv: s},
		KickCredential: func(credentialID string) int {
			// The tunnel state machine attachment (9.11) allows in-flight streams
			// to finish naturally; the panel can still report the live count.
			return int(s.panelDeps.activeCredentialSessions(credentialID))
		},
		ServerURL:  publicBaseURL(cfg),
		WebFS:      web.Assets,
		CookieName: cfg.Admin.CookieName,
	})
	if err != nil {
		return fmt.Errorf("app: init panel: %w", err)
	}
	s.gateway.panel = pn
	return nil
}

// ---- panel.TunnelAPI ----

type tunnelAPIAdapter struct{ srv *Server }

func (a *tunnelAPIAdapter) Sessions() []panel.SessionInfo {
	nodes := a.srv.registry.List()
	out := make([]panel.SessionInfo, 0, len(nodes))
	for i := range nodes {
		n := nodes[i]
		state, transport, ok := a.srv.tunnel.SessionState(n.ID)
		if !ok {
			state = "offline"
			transport = n.Transport
		}
		out = append(out, panel.SessionInfo{
			NodeID:         n.ID,
			Alias:          n.Alias,
			Transport:      transport,
			State:          state,
			Planes:         a.srv.tunnel.NodePlaneCount(n.ID),
			Epoch:          a.srv.registry.Epoch(n.ID),
			LastError:      a.srv.tunnel.NodeLastError(n.ID),
			ConnectedSince: n.CreatedAt,
			LastHeartbeat:  n.LastHeartbeat,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func (a *tunnelAPIAdapter) KickNode(nodeID, reason, message string) error {
	if err := a.srv.tunnel.KickNode(nodeID, reason, message); err != nil {
		return err
	}
	// The registry stays online until the drain finishes; mark it offline so
	// the panel reflects the operator intent immediately.
	a.srv.registry.SetNodeOnline(nodeID, false)
	return nil
}

func (a *tunnelAPIAdapter) ProbeNode(ctx context.Context, nodeID, kind, target string, payload []byte) (*protocol.ProbeResult, error) {
	return a.srv.tunnel.ProbeNode(ctx, nodeID, kind, target, payload)
}

func (a *tunnelAPIAdapter) PingNode(ctx context.Context, nodeID string) (time.Duration, error) {
	return a.srv.tunnel.PingNode(ctx, nodeID)
}

func (a *tunnelAPIAdapter) NodePlaneCount(nodeID string) int {
	return a.srv.tunnel.NodePlaneCount(nodeID)
}

func (a *tunnelAPIAdapter) ActiveStreams() int64 { return a.srv.tunnel.ActiveStreams() }

// ---- panel.GeoAPI ----

type geoAPIAdapter struct{ srv *Server }

func (a *geoAPIAdapter) statuses() []geo.ProviderStatus {
	if a.srv.metadata == nil || a.srv.metadata.geoResolver == nil {
		return nil
	}
	return a.srv.metadata.geoResolver.ProviderStatuses()
}

func (a *geoAPIAdapter) ProviderStatuses() []panel.ProviderStatus {
	src := a.statuses()
	out := make([]panel.ProviderStatus, 0, len(src))
	for _, p := range src {
		out = append(out, panel.ProviderStatus{
			Name: p.Name, Type: p.Type, Preset: p.Preset, Enabled: p.Enabled,
			Healthy: p.Healthy, Failures: p.Failures, LastError: p.LastError, Priority: p.Priority,
		})
	}
	return out
}

func (a *geoAPIAdapter) SetProviderEnabled(name string, enabled bool) error {
	if a.srv.metadata == nil || a.srv.metadata.geoResolver == nil {
		return fmt.Errorf("geo resolver is disabled")
	}
	return a.srv.metadata.geoResolver.SetProviderEnabled(name, enabled)
}

func (a *geoAPIAdapter) TestProvider(ctx context.Context, name string, ip net.IP) (*panel.ProviderTestResult, error) {
	if a.srv.metadata == nil || a.srv.metadata.geoResolver == nil {
		return nil, fmt.Errorf("geo resolver is disabled")
	}
	if ip == nil {
		raw, err := a.srv.ServerEgress(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolve server egress: %w", err)
		}
		ip = net.ParseIP(raw)
	}
	res, err := a.srv.metadata.geoResolver.TestProvider(ctx, name, ip)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	g := res.Result
	if g.Country != "" {
		fields["country"] = g.Country
	}
	if g.Region != "" {
		fields["region"] = g.Region
	}
	if g.City != "" {
		fields["city"] = g.City
	}
	if g.ASN != 0 {
		fields["asn"] = g.ASN
	}
	if g.ASNOrg != "" {
		fields["asn_org"] = g.ASNOrg
	}
	if g.ISP != "" {
		fields["isp"] = g.ISP
	}
	return &panel.ProviderTestResult{
		Provider:   res.Provider,
		IP:         res.IP,
		RawSnippet: res.RawSnippet,
		Result:     fields,
		DurationMS: res.DurationMS,
		HitPaths:   res.HitPaths,
		Error:      res.Error,
	}, nil
}

// ---- panel.SchedAPI ----

type schedAPIAdapter struct{ srv *Server }

func (a *schedAPIAdapter) PreviewSticky(target model.RequestTarget, sourceIP, nodeID string, groups []string) panel.StickyPreview {
	ruleID, hit := a.srv.StickyPreview(target, sourceIP, nodeID, groups)
	return panel.StickyPreview{Hit: hit, RuleID: ruleID, ForcedNodeID: ""}
}

func (a *schedAPIAdapter) SetRules(list []model.StickyRule) error {
	if a.srv.gateway == nil {
		return nil
	}
	return a.srv.gateway.sched.SetStickyRules(list)
}

// ---- panel.CertAPI ----

type certAPIAdapter struct{ srv *Server }

func (a *certAPIAdapter) Status() panel.CertStatus {
	st := a.srv.certMgr.Status()
	return panel.CertStatus{
		Mode: st.Mode, Pin: st.Pin, PinNext: st.PinNext, CertPath: st.CertPath,
		KeyPath: st.KeyPath, NotAfter: st.NotAfter, LastReload: st.LastReload, LastError: st.LastError,
	}
}

func (a *certAPIAdapter) RotatePin() (string, error) {
	hosts, ips := certSANs(a.srv.cfg)
	_, _, pin, err := certs.GenerateAdditionalKey(hosts, ips, a.srv.cfg.EffectiveCertDir())
	if err != nil {
		return "", err
	}
	// Advertise the upcoming pin immediately: panel status and HELLO_ACK must
	// show it so operators can roll it out to all nodes before switching keys.
	if err := a.srv.certMgr.SetPinNext(pin); err != nil {
		return "", err
	}
	a.srv.tunnel.SetPinNext(pin)
	return pin, nil
}

func (a *certAPIAdapter) Reload() error { return a.srv.certMgr.Reload() }

// ---- panel.StatsAPI ----

type statsAPIAdapter struct{ srv *Server }

func (a *statsAPIAdapter) Overview(ctx context.Context) panel.OverviewSnapshot {
	d := a.srv.panelDeps
	reqs, errs, retries, limited, trips := d.counters.Snapshot()
	snap := panel.OverviewSnapshot{
		OnlineNodes:       int64(a.srv.registry.OnlineCount()),
		NodesTotal:        int64(a.srv.registry.Count()),
		UniqueEgressIPs:   int64(a.srv.registry.UniqueEgressCount()),
		ActiveConnections: a.srv.tunnel.ActiveStreams(),
		TransportMix:      map[string]int{},
		Requests:          reqs,
		Errors:            errs,
		Retries:           retries,
		RateLimited:       limited,
		BreakerTrips:      trips,
		ClockSkewMS:       a.srv.maxClockSkewMS(),
	}
	for _, n := range a.srv.registry.List() {
		if n.Online && n.Transport != "" {
			snap.TransportMix[n.Transport]++
		}
	}
	for _, p := range d.trend.Snapshot() {
		snap.Trend = append(snap.Trend, panel.TrendPoint{TS: p.TS, Requests: p.Requests, Errors: p.Errors, Active: p.Active})
	}
	for _, t := range d.targets.Top(10) {
		snap.TopTargets = append(snap.TopTargets, panel.TargetStat{Target: t.Target, Count: t.Count, Bytes: t.Bytes, Errors: t.Errors})
	}
	return snap
}

func (a *statsAPIAdapter) TopN(_ context.Context, window string, n int) (targets, nodes, credentials []panel.TargetStat) {
	d := a.srv.panelDeps
	convert := func(in []stats.TargetStat) []panel.TargetStat {
		out := make([]panel.TargetStat, 0, len(in))
		for _, t := range in {
			out = append(out, panel.TargetStat{Target: t.Target, Count: t.Count, Bytes: t.Bytes, Errors: t.Errors})
		}
		return out
	}
	if n <= 0 || n > 100 {
		n = 10
	}
	return convert(d.targets.Top(n)), convert(d.nodes.Top(n)), convert(d.credentials.Top(n))
}

// maxClockSkewMS returns the largest absolute clock offset observed across
// nodes (0 when the tunnel layer has not reported any yet).
func (s *Server) maxClockSkewMS() int64 {
	if s.tunnel == nil {
		return 0
	}
	return s.tunnel.MaxClockSkew()
}

// publicBaseURL builds the externally reachable URL used in install commands.
func publicBaseURL(cfg *config.ServerConfig) string {
	if cfg.Server.PublicURL != "" {
		return strings.TrimRight(cfg.Server.PublicURL, "/")
	}
	host, port, err := config.ListenHostPort(cfg.Server.ListenAddr)
	if err != nil {
		return "https://127.0.0.1"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if port == 443 {
		return "https://" + host
	}
	return fmt.Sprintf("https://%s:%d", host, port)
}

// newAuditID is kept for future audit correlation from the app layer.
func newAuditID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
