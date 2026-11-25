// Domain dependencies and injected interfaces of the panel. The exported types
// in this file are the public wiring surface used by internal/app.
package panel

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"time"

	"proxygw/internal/acl"
	"proxygw/internal/audit"
	"proxygw/internal/auth"
	"proxygw/internal/groups"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/registry"
	"proxygw/internal/rules"
	"proxygw/internal/settings"
	"proxygw/internal/version"
)

// Options carries every dependency of the panel. The zero value is not usable:
// New validates that the domain stores are present and returns an error
// otherwise. The injected interfaces (Tunnel/Geo/Sched/Cert/Stats) may be nil;
// the related endpoints then degrade gracefully (empty data or 503) instead of
// panicking.
type Options struct {
	Logger   *slog.Logger
	Version  version.Info
	Auth     *auth.CredentialStore
	Admin    *auth.AdminManager
	Groups   *groups.Store
	Rules    *rules.Store
	Registry *registry.Registry
	ACL      *acl.Engine
	Settings *settings.Manager
	Audit    *audit.Store
	Metrics  *metrics.Metrics
	Tunnel   TunnelAPI
	Geo      GeoAPI
	Sched    SchedAPI
	Cert     CertAPI
	Stats    StatsAPI
	// NodeTokens manages node tunnel credentials. When nil the token endpoints
	// degrade to 503 and the rest of the panel keeps working.
	NodeTokens NodeTokensAPI
	// NodeUpdates drives binary-only node self-updates. Docker nodes are
	// rejected before this interface is called.
	NodeUpdates NodeUpdatesAPI
	// AuthBans lists and clears proxy source-IP authentication bans.
	AuthBans AuthBansAPI
	// KickCredential immediately closes every existing proxy session of the
	// credential and returns how many were kicked. Provided by app.
	KickCredential func(credentialID string) int
	// ActiveCredentialSessions reports the current in-flight request count for
	// one credential. It is optional; nil reports 0.
	ActiveCredentialSessions func(credentialID string) int64
	// ServerURL is the externally reachable panel/tunnel base URL used to build
	// the node install command.
	ServerURL string
	// WebFS is the embedded web/ asset tree: index.html, app.js and style.css at
	// its root. Assets are served under the /static/ prefix.
	WebFS fs.FS
	// Now is the panel clock; nil means time.Now.
	Now func() time.Time

	// CookieName and CSRFCookieName are additive extensions: they default to
	// np_admin / np_csrf (the config defaults). app should pass
	// cfg.Admin.CookieName for CookieName so a renamed session cookie keeps
	// working. CSRFCookieName has no config equivalent and normally stays "".
	CookieName     string
	CSRFCookieName string
}

// NodeTokensAPI is the subset of the node authenticator needed to issue, list
// and revoke tunnel credentials.
type NodeTokensAPI interface {
	Issue(nodeID, note string) (string, error)
	Revoke(nodeID string) error
	List() []model.NodeToken
}

// NodeUpdatesAPI starts binary self-updates. Rolling updates are driven by app
// so the queue survives a closed browser tab.
type NodeUpdatesAPI interface {
	StartNodeUpdate(nodeID string) error
	StartRollingUpdate(nodeIDs []string) (int, error)
	ClearNodeUpdateStatus(nodeID string) bool
}

// AuthBanView is one active proxy authentication ban.
type AuthBanView struct {
	SourceIP    string    `json:"source_ip"`
	Failures    int       `json:"failures"`
	Reason      string    `json:"reason"`
	BannedAt    time.Time `json:"banned_at"`
	BannedUntil time.Time `json:"banned_until"`
	LastSeen    time.Time `json:"last_seen"`
}

// AuthBansAPI exposes the proxy auth failure ban table.
type AuthBansAPI interface {
	AuthBans() []AuthBanView
	UnbanAuthBan(sourceIP string) bool
}

// SessionInfo is one tunnel session as exposed by the tunnel layer.
type SessionInfo struct {
	NodeID         string
	Alias          string
	Transport      string
	State          string
	Planes         int
	Epoch          uint32
	LastError      string
	ConnectedSince time.Time
	LastHeartbeat  time.Time
}

// TunnelAPI is the subset of the tunnel server needed by the panel.
type TunnelAPI interface {
	Sessions() []SessionInfo
	KickNode(nodeID, reason, message string) error
	ProbeNode(ctx context.Context, nodeID, kind, target string, payload []byte) (*protocol.ProbeResult, error)
	PingNode(ctx context.Context, nodeID string) (time.Duration, error)
	NodePlaneCount(nodeID string) int
	ActiveStreams() int64
}

// ProviderStatus is the panel view of one geolocation provider.
type ProviderStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Preset    string `json:"preset"`
	Enabled   bool   `json:"enabled"`
	Healthy   bool   `json:"healthy"`
	Failures  int    `json:"failures"`
	LastError string `json:"last_error"`
	Priority  int    `json:"priority"`
}

// ProviderTestResult is the outcome of a panel provider test.
type ProviderTestResult struct {
	Provider   string            `json:"provider"`
	IP         string            `json:"ip"`
	RawSnippet string            `json:"raw_snippet"`
	Result     map[string]any    `json:"result"`
	DurationMS float64           `json:"duration_ms"`
	HitPaths   map[string]string `json:"hit_paths"`
	Error      string            `json:"error"`
}

// GeoAPI is the subset of the geo resolver needed by the panel.
type GeoAPI interface {
	ProviderStatuses() []ProviderStatus
	SetProviderEnabled(name string, enabled bool) error
	TestProvider(ctx context.Context, name string, ip net.IP) (*ProviderTestResult, error)
}

// StickyPreview is the dry-run result of the sticky blacklist for a request.
type StickyPreview struct {
	Hit          bool
	RuleID       string
	Reason       string
	ForcedNodeID string
}

// SchedAPI is the subset of the scheduler needed by the panel. SetRules is an
// additive extension over the original task list: the panel must push sticky
// rule changes into the running selector immediately (app adapts it to
// sched.Selector.SetStickyRules).
type SchedAPI interface {
	PreviewSticky(target model.RequestTarget, sourceIP, nodeID string, groups []string) StickyPreview
	SetRules(rules []model.StickyRule) error
}

// CertStatus is the panel view of the server certificate identity.
type CertStatus struct {
	Mode       string
	Pin        string
	PinNext    string
	CertPath   string
	KeyPath    string
	NotAfter   time.Time
	LastReload time.Time
	LastError  string
}

// CertAPI is the subset of the certificate manager needed by the panel.
type CertAPI interface {
	Status() CertStatus
	RotatePin() (string, error)
	Reload() error
}

// TrendPoint is one sample of the in-memory 15 minute trend ring. The JSON
// tags are part of the API contract.
type TrendPoint struct {
	TS       int64 `json:"ts"`
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
	Active   int64 `json:"active"`
}

// TargetStat is one TopN entry.
type TargetStat struct {
	Target string `json:"target"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
	Errors int64  `json:"errors"`
}

// OverviewSnapshot is the pre-aggregated data the stats layer hands to the
// panel for the overview page and the SSE stream.
type OverviewSnapshot struct {
	OnlineNodes       int64
	NodesTotal        int64
	UniqueEgressIPs   int64
	ActiveConnections int64
	TransportMix      map[string]int
	Requests          int64
	Errors            int64
	Retries           int64
	RateLimited       int64
	BreakerTrips      int64
	Trend             []TrendPoint
	TopTargets        []TargetStat
	ClockSkewMS       int64
}

// StatsAPI is the subset of the statistics layer needed by the panel.
type StatsAPI interface {
	Overview(ctx context.Context) OverviewSnapshot
	// TopN returns the top targets, nodes and credentials for the window.
	TopN(ctx context.Context, window string, n int) (targets, nodes, credentials []TargetStat)
}
