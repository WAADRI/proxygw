package proxy

import (
	"fmt"
	"log/slog"
	"time"

	"proxygw/internal/metrics"
	"proxygw/internal/model"
)

// Defaults for the entry points. Everything configurable at runtime comes from
// Options.Settings; these are the fallbacks used when a settings snapshot is
// missing or invalid.
const (
	defaultMaxHeaderBytes = 64 * 1024
	defaultSettingsOpen   = 10 * time.Second
	defaultReadHeader     = 10 * time.Second
	defaultIdle           = 30 * time.Minute
	defaultWriteBlock     = 30 * time.Second
	defaultLinger         = 30 * time.Second
	defaultDrain          = 10 * time.Second
	// selectBudget is the scheduler budget from the attachment (chapter 4).
	selectBudget = 5 * time.Millisecond
)

// Options configures one proxy entry point. HTTPProxy and SOCKS5Proxy share the
// same pipeline, so the fields are identical for both.
type Options struct {
	// Logger is the structured logger. nil means slog.Default().
	Logger *slog.Logger
	// Settings returns the current hot-reloadable settings. nil means
	// model.DefaultSettings(). It is called on every request, never cached.
	Settings func() model.Settings
	// AuthMode is one of model.AuthNone, model.AuthOptional, model.AuthRequired.
	// The empty string means required (secure default).
	AuthMode string
	// Authenticator validates proxy credentials. Required unless AuthMode is
	// model.AuthNone.
	Authenticator Authenticator
	// Candidates resolves the nodes visible to a credential (fail closed).
	Candidates CandidateResolver
	// Selector picks a node and records node side results for the breaker.
	Selector Selector
	// ACL checks target authorization. nil means no ACL.
	ACL ACLChecker
	// Dialer opens tunnel streams through the selected node.
	Dialer StreamDialer
	// Limiter applies bandwidth backpressure. nil means unlimited.
	Limiter Bandwidth
	// Metrics receives counters and gauges. nil disables instrumentation.
	Metrics *metrics.Metrics
	// MaxHeaderBytes caps the HTTP request head (default 65536).
	MaxHeaderBytes int
	// MaxConcurrent is the global number of in-flight proxy requests;
	// 0 means unlimited.
	MaxConcurrent int
	// Audit receives security relevant events (auth failures, ACL denials,
	// rate limiting). nil disables auditing. It must be safe for concurrent use.
	Audit func(event string, detail map[string]string)
	// AuthBan counts credential failures per source IP and temporarily blocks
	// abusive sources before the expensive credential verification. nil
	// disables the feature.
	AuthBan *AuthBanTracker
	// OnRequestStart is called once per client request after authorization and
	// node selection, before the tunnel stream is opened. nil-safe.
	OnRequestStart func(credentialID, protocol, target, nodeID string)
	// OnRequestEnd is called exactly once when the request finishes (success or
	// error), with the relayed byte counts relative to the client direction:
	// bytesIn is client to target, bytesOut is target to client. The final
	// error is nil on success. nil-safe.
	OnRequestEnd func(credentialID, protocol, target, nodeID string, bytesIn, bytesOut int64, err error)
	// OnRetry is called once for every transparent retry before the response
	// commit point. It lets the panel count real retries instead of inferring
	// them from failed requests. nil-safe.
	OnRetry func()
}

// normalized validates the options and fills in the defaults.
func (o Options) normalized() (Options, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Settings == nil {
		o.Settings = model.DefaultSettings
	}
	switch o.AuthMode {
	case "":
		o.AuthMode = model.AuthRequired
	case model.AuthNone, model.AuthOptional, model.AuthRequired:
	default:
		return Options{}, fmt.Errorf("proxy: unsupported auth mode %q (want none, optional or required)", o.AuthMode)
	}
	if o.AuthMode != model.AuthNone && o.Authenticator == nil {
		return Options{}, fmt.Errorf("proxy: Authenticator is required when auth mode is %q", o.AuthMode)
	}
	if o.Candidates == nil {
		return Options{}, fmt.Errorf("proxy: Candidates resolver is required")
	}
	if o.Selector == nil {
		return Options{}, fmt.Errorf("proxy: Selector is required")
	}
	if o.Dialer == nil {
		return Options{}, fmt.Errorf("proxy: Dialer is required")
	}
	if o.MaxHeaderBytes < 0 {
		return Options{}, fmt.Errorf("proxy: MaxHeaderBytes must be >= 0")
	}
	if o.MaxHeaderBytes == 0 {
		o.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if o.MaxConcurrent < 0 {
		return Options{}, fmt.Errorf("proxy: MaxConcurrent must be >= 0")
	}
	return o, nil
}
