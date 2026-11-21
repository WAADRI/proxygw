// Package nodeagent implements the node side of the tunnel. It dials the
// server from behind NAT (QUIC first, wss fallback), registers with HELLO,
// keeps the session alive, reports statistics, answers probes and serves the
// server initiated data streams by dialing the real target from the node
// network and relaying bytes in both directions.
//
// Transport construction is deliberately decoupled: the agent only depends on
// the interfaces in proxygw/internal/transport and receives two dial functions
// from the application (cmd/proxygw-client), which owns TLS material and the
// concrete QUIC/WebSocket dialers.
package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
	"proxygw/internal/version"
)

// Timeouts and backoff parameters mandated by the tunnel design attachment
// (tunnel-state-machine.md chapter 6). They are exported so tests and the
// assembly layer can reason about the production values; per node behaviour
// must never drift, therefore they are not configuration file options.
const (
	// FallbackTimeout is the default budget for the QUIC handshake in
	// transport: auto mode. The effective value comes from
	// ClientConfig.QUICFallback (1s-5s), this constant is the documented
	// default.
	FallbackTimeout = 2 * time.Second
	// HandshakeTimeout bounds one transport handshake (TLS + wss upgrade).
	HandshakeTimeout = 10 * time.Second
	// HelloTimeout bounds the HELLO/HELLO_ACK registration exchange.
	HelloTimeout = 5 * time.Second
	// HeartbeatInterval is the server PING interval. The node never originates
	// heartbeats; it only answers them and watches for silence.
	HeartbeatInterval = 15 * time.Second
	// HeartbeatMissLimit is the number of consecutive missed heartbeats after
	// which the plane is considered dead (15s * 3 = 45s).
	HeartbeatMissLimit = 3
	// DrainTimeout bounds how long in-flight streams may continue after a KICK
	// or a local shutdown before the transport connection is closed.
	DrainTimeout = 10 * time.Second
	// OpenDialTimeout is the fixed node -> target TCP dial timeout, including
	// DNS resolution.
	OpenDialTimeout = 10 * time.Second
	// StatsInterval is the periodic STATS report interval.
	StatsInterval = 10 * time.Second
	// ReProbeInterval is how long the agent waits on a healthy wss session
	// before re-probing QUIC in the background.
	ReProbeInterval = 10 * time.Minute
	// BackoffBase and BackoffMax describe the reconnect backoff sequence
	// 1m/2m/4m/8m/10m used when every transport fails.
	BackoffBase = time.Minute
	BackoffMax  = 10 * time.Minute
)

// Internal tuning constants that are not part of the wire contract.
const (
	controlWriteTimeout = 5 * time.Second
	probeTimeout        = 3 * time.Second
	probeDNSTimeout     = 2 * time.Second
	probeDNSMaxResponse = 4 * 1024
	relayBufSize        = 32 * 1024
	maxProbeConcurrency = 8
	maxStreamsDefault   = 1000
	// quicConfirmInterval is the delay between the first and the second
	// successful QUIC re-probe used to apply the ±2 success hysteresis.
	quicConfirmInterval = 30 * time.Second
	// quicSuccessThreshold is the number of consecutive successful QUIC
	// connection establishments required before switching the preferred
	// transport back to QUIC.
	quicSuccessThreshold = 2
	// quicRevertWindow: a QUIC session that fails within this window after the
	// switch reverts to wss and resets the backoff.
	quicRevertWindow = 60 * time.Second
	// egressRefreshInterval is how often the Egress callback is refreshed.
	egressRefreshInterval = 60 * time.Second
	// egressTimeout bounds a single Egress callback invocation.
	egressTimeout = 2 * time.Second
	// kickRetryDelay is the small reconnect delay after a replaced/revoked
	// KICK; 3 replaced KICKs within replacedWindow escalate to replacedCooldown.
	kickRetryDelay = time.Second
	replacedWindow = 60 * time.Second
	replacedLimit  = 3
	// replacedCooldown prevents two agents sharing one client_id from kicking
	// each other in an endless loop.
	replacedCooldown = time.Minute
	// migrateStagger spaces out the plane re-dials when switching back to QUIC
	// so that not every plane loses its session at the same instant.
	migrateStagger = 200 * time.Millisecond
	// planeDrainPoll is the polling interval used to watch the active stream
	// count while draining.
	planeDrainPoll = 10 * time.Millisecond
	// controlCloseCode is the QUIC/WS application error code used for abnormal
	// connection shutdown. 0 is a graceful close.
	closeCodeGraceful = 0
	closeCodeError    = 1
)

// Options configures an Agent. Only Config is mandatory; the dial functions are
// provided by the application because they own TLS material (certs package)
// and concrete transport constructors.
type Options struct {
	Config   *config.ClientConfig
	ClientID string
	Logger   *slog.Logger
	Version  string
	// QUICDial dials the primary transport. nil means "QUIC unavailable" (for
	// example the app only built a WebSocket dialer).
	QUICDial func(ctx context.Context) (transport.Conn, error)
	// WSDial dials the fallback transport. nil means "wss unavailable".
	WSDial func(ctx context.Context) (transport.Conn, error)
	// Egress returns the node public egress addresses. nil means the agent uses
	// ClientConfig.Egress.ManualV4/ManualV6 (before M5 the app passes nil).
	Egress func(ctx context.Context) (v4, v6 string)
	// Metrics optionally receives reconnect/plane/probe counters. nil is fine:
	// the node does not expose Prometheus by default.
	Metrics *metrics.Metrics
	// IsFatal classifies dial/handshake errors that must never be retried (pin
	// mismatch, authentication failure, incompatible version). The app injects
	// a classifier wrapping certs.IsPinMismatch. The built-in heuristic is used
	// when nil; *FatalError is always fatal regardless.
	IsFatal func(error) bool
	// Settings optionally supplies runtime timeouts (write_block, drain).
	// nil uses model.DefaultSettings().
	Settings *model.Settings
	// TestHooks only exists for unit tests. Production must leave it nil.
	TestHooks *TestHooks
}

// TestHooks overrides production timing and injects test doubles. Every zero
// field falls back to the production value, so tests only override what they
// need. Scale multiplies all resolved durations (default 1).
type TestHooks struct {
	Scale               float64
	FallbackTimeout     time.Duration
	HandshakeTimeout    time.Duration
	HelloTimeout        time.Duration
	HeartbeatInterval   time.Duration
	HeartbeatMissLimit  int
	DrainTimeout        time.Duration
	WriteBlock          time.Duration
	OpenDialTimeout     time.Duration
	StatsInterval       time.Duration
	ReProbeInterval     time.Duration
	BackoffBase         time.Duration
	BackoffMax          time.Duration
	ReconnectBase       time.Duration
	QuicConfirmInterval time.Duration
	QuicRevertWindow    time.Duration
	ProbeTick           time.Duration
	ReplacedWindow      time.Duration
	ReplacedLimit       int
	ReplacedCooldown    time.Duration
	KickRetryDelay      time.Duration
	EgressRefresh       time.Duration
	EgressTimeout       time.Duration
	// DialTarget overrides the node -> target TCP dialer (blackhole tests).
	DialTarget func(ctx context.Context, network, addr string) (net.Conn, error)
}

// timings is the resolved timing table of one Agent.
type timings struct {
	fallbackTimeout     time.Duration
	handshakeTimeout    time.Duration
	helloTimeout        time.Duration
	heartbeatInterval   time.Duration
	heartbeatMissLimit  int
	drainTimeout        time.Duration
	writeBlock          time.Duration
	openDialTimeout     time.Duration
	statsInterval       time.Duration
	reProbeInterval     time.Duration
	backoffBase         time.Duration
	backoffMax          time.Duration
	reconnectBase       time.Duration
	quicConfirmInterval time.Duration
	quicRevertWindow    time.Duration
	probeTick           time.Duration
	replacedWindow      time.Duration
	replacedLimit       int
	replacedCooldown    time.Duration
	kickRetryDelay      time.Duration
	egressRefresh       time.Duration
	egressTimeout       time.Duration
	probeDrainTimeout   time.Duration
}

// Status is a point in time snapshot of the agent, safe for the panel.
type Status struct {
	Connected bool
	Transport string
	Planes    int
	Streams   int64
	BytesIn   uint64
	BytesOut  uint64
	Inflight  int64

	LastFallbackReason string
	LastError          string
	ConnectedSince     time.Time
	EgressV4           string
	EgressV6           string
	Version            string
}

// FatalError marks an error that must stop the agent instead of triggering a
// reconnect (certificate pin mismatch, rejected authentication, incompatible
// protocol version, takeover cooldown).
type FatalError struct {
	Reason string
	Err    error
}

// Error implements the error interface.
func (e *FatalError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Reason == "" {
		if e.Err != nil {
			return "nodeagent: fatal: " + e.Err.Error()
		}
		return "nodeagent: fatal error"
	}
	if e.Err == nil {
		return "nodeagent: fatal: " + e.Reason
	}
	return "nodeagent: fatal: " + e.Reason + ": " + e.Err.Error()
}

// Unwrap exposes the wrapped cause.
func (e *FatalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsFatal reports whether err is a fatal (never retried) agent error. It checks
// for *FatalError first and then applies the documented textual heuristic.
func IsFatal(err error) bool {
	if err == nil {
		return false
	}
	var fe *FatalError
	if errors.As(err, &fe) {
		return true
	}
	return isFatalText(err.Error())
}

// cooldownError is a retryable server imposed delay (takeover cooldown). It is
// never fatal: the plane waits for Delay and reconnects.
type cooldownError struct {
	Reason string
	Delay  time.Duration
}

func (e *cooldownError) Error() string {
	if e.Reason == "" {
		return "server requested takeover cooldown"
	}
	return "server requested takeover cooldown: " + e.Reason
}

func isFatalText(msg string) bool {
	lower := asciiLower(msg)
	for _, needle := range []string{
		"pin mismatch",
		"certificate",
		"authentication failed",
		"unsupported version",
	} {
		if containsFold(lower, needle) {
			return true
		}
	}
	return false
}

// asciiLower lowercases ASCII only to keep the hot path allocation free for
// short error strings.
func asciiLower(s string) string {
	b := []byte(s)
	changed := false
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

func containsFold(lower, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(lower) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(lower); i++ {
		if lower[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Agent is one node agent. Create it with New, drive it with Run and release it
// with Close. All exported methods are safe for concurrent use.
type Agent struct {
	opts     Options
	cfg      *config.ClientConfig
	log      *slog.Logger
	clientID string
	version  string
	server   string
	timings  timings
	settings model.Settings

	probeClient *http.Client
	probeDialer *net.Dialer
	probeSem    chan struct{}

	started   atomic.Bool
	done      chan struct{}
	closeOnce sync.Once
	forceOnce sync.Once
	forceCh   chan struct{}

	cancelMu sync.Mutex
	cancel   context.CancelFunc
	runCtx   context.Context

	wg        sync.WaitGroup
	fatalOnce sync.Once
	fatalCh   chan error
	stopOnce  sync.Once
	stopCh    chan struct{}

	planes []*plane
	gate   retryGate
	sel    transportSelector

	metrics *metrics.Metrics

	sessMu   sync.Mutex
	sessions map[*session]struct{}

	stMu           sync.Mutex
	readyKinds     map[int]transport.Kind
	lastErr        string
	connectedSince time.Time
	readyCount     atomic.Int32

	bytesIn       atomic.Uint64
	bytesOut      atomic.Uint64
	activeStreams atomic.Int64
	inflight      atomic.Int64
	latencyBits   atomic.Uint64

	egressMu          sync.RWMutex
	egressV4          string
	egressV6          string
	egressRefreshBusy atomic.Bool

	replacedMu sync.Mutex
	replacedAt []time.Time
}

// New validates the options, resolves the timing table and builds an Agent. It
// performs no network I/O.
func New(opts Options) (*Agent, error) {
	if opts.Config == nil {
		return nil, errors.New("nodeagent: 缺少配置（Options.Config 为空）")
	}
	cfg := opts.Config
	clientID := opts.ClientID
	if clientID == "" {
		clientID = cfg.ClientID
	}
	if clientID == "" {
		return nil, errors.New("nodeagent: client_id 不能为空（由 app 生成或配置）")
	}
	if cfg.Planes < 1 || cfg.Planes > 8 {
		return nil, fmt.Errorf("nodeagent: planes 必须在 1..8 之间，当前 %d", cfg.Planes)
	}
	switch cfg.Transport {
	case model.TransportAuto, model.TransportQUIC, model.TransportWS:
	default:
		return nil, fmt.Errorf("nodeagent: 不支持的 transport %q", cfg.Transport)
	}
	if cfg.Transport == model.TransportQUIC && opts.QUICDial == nil {
		return nil, errors.New("nodeagent: transport=quic 但未注入 QUICDial")
	}
	if cfg.Transport == model.TransportWS && opts.WSDial == nil {
		return nil, errors.New("nodeagent: transport=ws 但未注入 WSDial")
	}
	if cfg.Transport == model.TransportAuto && opts.QUICDial == nil && opts.WSDial == nil {
		return nil, errors.New("nodeagent: transport=auto 但 QUICDial 与 WSDial 均为空")
	}
	ep, err := config.ParseServerURL(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("nodeagent: 解析 server_url 失败: %w", err)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ver := opts.Version
	if ver == "" {
		ver = version.Version
	}
	settings := model.DefaultSettings()
	if opts.Settings != nil {
		settings = *opts.Settings
	}
	t := resolveTimings(cfg, settings, opts.TestHooks)

	a := &Agent{
		opts:       opts,
		cfg:        cfg,
		log:        logger.With("client_id", clientID, "server", ep.HostPort(), "version", ver),
		clientID:   clientID,
		version:    ver,
		server:     ep.HostPort(),
		timings:    t,
		settings:   settings,
		done:       make(chan struct{}),
		forceCh:    make(chan struct{}),
		fatalCh:    make(chan error, 1),
		stopCh:     make(chan struct{}),
		sessions:   make(map[*session]struct{}),
		readyKinds: make(map[int]transport.Kind),
		metrics:    opts.Metrics,
		probeSem:   make(chan struct{}, maxProbeConcurrency),
		gate:       retryGate{wake: make(chan struct{})},
	}
	a.sel.a = a
	a.sel.preferred = transport.KindQUIC
	if cfg.Transport == model.TransportWS || opts.QUICDial == nil {
		a.sel.preferred = transport.KindWS
	}
	if cfg.Transport == model.TransportAuto && opts.QUICDial == nil && opts.WSDial != nil {
		a.sel.lastFallbackReason = "QUIC 拨号器不可用（未注入），使用 wss"
		a.log.Warn("auto 模式下未注入 QUIC 拨号器，直接使用 wss", "event", "transport.fallback")
	}
	dialer := &net.Dialer{Timeout: t.openDialTimeout}
	a.probeDialer = dialer
	a.probeClient = &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			Proxy:               nil, // probes must never go through a local proxy
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: probeTimeout,
		},
	}
	for i := 0; i < cfg.Planes; i++ {
		a.planes = append(a.planes, &plane{
			index:    i,
			log:      a.log.With("plane_index", i),
			redialCh: make(chan string, 1),
		})
	}
	// Egress: manual values are the baseline; an Egress callback (M5) fills in
	// and refreshes them but manual configuration always wins.
	a.egressV4 = cfg.Egress.ManualV4
	a.egressV6 = cfg.Egress.ManualV6
	return a, nil
}

// resolveTimings applies TestHooks on top of the production defaults.
func resolveTimings(cfg *config.ClientConfig, settings model.Settings, hooks *TestHooks) timings {
	fallback := FallbackTimeout
	if d := cfg.QUICFallback.Std(); d > 0 {
		fallback = clampDuration(d, time.Second, 5*time.Second)
	}
	t := timings{
		fallbackTimeout:     fallback,
		handshakeTimeout:    HandshakeTimeout,
		helloTimeout:        HelloTimeout,
		heartbeatInterval:   HeartbeatInterval,
		heartbeatMissLimit:  HeartbeatMissLimit,
		drainTimeout:        defaultDrainTimeout(settings),
		writeBlock:          settings.Timeouts.WriteBlock.Std(),
		openDialTimeout:     OpenDialTimeout,
		statsInterval:       StatsInterval,
		reProbeInterval:     ReProbeInterval,
		backoffBase:         BackoffBase,
		backoffMax:          BackoffMax,
		reconnectBase:       time.Second,
		quicConfirmInterval: quicConfirmInterval,
		quicRevertWindow:    quicRevertWindow,
		probeTick:           time.Second,
		replacedWindow:      replacedWindow,
		replacedLimit:       replacedLimit,
		replacedCooldown:    replacedCooldown,
		kickRetryDelay:      kickRetryDelay,
		egressRefresh:       egressRefreshInterval,
		egressTimeout:       egressTimeout,
	}
	if t.drainTimeout <= 0 {
		t.drainTimeout = DrainTimeout
	}
	t.probeDrainTimeout = t.drainTimeout
	if t.writeBlock <= 0 {
		t.writeBlock = model.DefaultSettings().Timeouts.WriteBlock.Std()
	}
	if t.drainTimeout <= 0 {
		t.drainTimeout = DrainTimeout
	}
	if hooks == nil {
		return t
	}
	if d := hooks.FallbackTimeout; d > 0 {
		t.fallbackTimeout = d
	}
	if d := hooks.HandshakeTimeout; d > 0 {
		t.handshakeTimeout = d
	}
	if d := hooks.HelloTimeout; d > 0 {
		t.helloTimeout = d
	}
	if d := hooks.HeartbeatInterval; d > 0 {
		t.heartbeatInterval = d
	}
	if n := hooks.HeartbeatMissLimit; n > 0 {
		t.heartbeatMissLimit = n
	}
	if d := hooks.DrainTimeout; d > 0 {
		t.drainTimeout = d
		t.probeDrainTimeout = d
	}
	if d := hooks.WriteBlock; d > 0 {
		t.writeBlock = d
	}
	if d := hooks.OpenDialTimeout; d > 0 {
		t.openDialTimeout = d
	}
	if d := hooks.StatsInterval; d > 0 {
		t.statsInterval = d
	}
	if d := hooks.ReProbeInterval; d > 0 {
		t.reProbeInterval = d
	}
	if d := hooks.BackoffBase; d > 0 {
		t.backoffBase = d
	}
	if d := hooks.BackoffMax; d > 0 {
		t.backoffMax = d
	}
	if d := hooks.ReconnectBase; d > 0 {
		t.reconnectBase = d
	}
	if d := hooks.QuicConfirmInterval; d > 0 {
		t.quicConfirmInterval = d
	}
	if d := hooks.QuicRevertWindow; d > 0 {
		t.quicRevertWindow = d
	}
	if d := hooks.ProbeTick; d > 0 {
		t.probeTick = d
	}
	if d := hooks.ReplacedWindow; d > 0 {
		t.replacedWindow = d
	}
	if n := hooks.ReplacedLimit; n > 0 {
		t.replacedLimit = n
	}
	if d := hooks.ReplacedCooldown; d > 0 {
		t.replacedCooldown = d
	}
	if d := hooks.KickRetryDelay; d > 0 {
		t.kickRetryDelay = d
	}
	if d := hooks.EgressRefresh; d > 0 {
		t.egressRefresh = d
	}
	if d := hooks.EgressTimeout; d > 0 {
		t.egressTimeout = d
	}
	if hooks.Scale > 0 && hooks.Scale != 1 {
		scale := hooks.Scale
		t.fallbackTimeout = scaleDur(t.fallbackTimeout, scale)
		t.handshakeTimeout = scaleDur(t.handshakeTimeout, scale)
		t.helloTimeout = scaleDur(t.helloTimeout, scale)
		t.heartbeatInterval = scaleDur(t.heartbeatInterval, scale)
		t.drainTimeout = scaleDur(t.drainTimeout, scale)
		t.writeBlock = scaleDur(t.writeBlock, scale)
		t.openDialTimeout = scaleDur(t.openDialTimeout, scale)
		t.statsInterval = scaleDur(t.statsInterval, scale)
		t.reProbeInterval = scaleDur(t.reProbeInterval, scale)
		t.backoffBase = scaleDur(t.backoffBase, scale)
		t.backoffMax = scaleDur(t.backoffMax, scale)
		t.reconnectBase = scaleDur(t.reconnectBase, scale)
		t.quicConfirmInterval = scaleDur(t.quicConfirmInterval, scale)
		t.quicRevertWindow = scaleDur(t.quicRevertWindow, scale)
		t.probeTick = scaleDur(t.probeTick, scale)
		t.replacedWindow = scaleDur(t.replacedWindow, scale)
		t.replacedCooldown = scaleDur(t.replacedCooldown, scale)
		t.kickRetryDelay = scaleDur(t.kickRetryDelay, scale)
		t.egressRefresh = scaleDur(t.egressRefresh, scale)
		t.egressTimeout = scaleDur(t.egressTimeout, scale)
		t.probeDrainTimeout = scaleDur(t.probeDrainTimeout, scale)
	}
	if t.heartbeatMissLimit < 1 {
		t.heartbeatMissLimit = HeartbeatMissLimit
	}
	return t
}

// Run starts all planes and blocks until ctx is cancelled (graceful exit, nil
// return), a fatal error occurs (the *FatalError is returned immediately) or
// the server sends KICK(reason=shutdown) (graceful exit, nil return).
func (a *Agent) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nodeagent: Run 需要非 nil 的 context")
	}
	if !a.started.CompareAndSwap(false, true) {
		return errors.New("nodeagent: Run 不允许重复调用")
	}
	defer close(a.done)

	runCtx, cancel := context.WithCancel(ctx)
	a.cancelMu.Lock()
	a.cancel = cancel
	a.runCtx = runCtx
	a.cancelMu.Unlock()

	a.log.Info("节点代理开始运行",
		"event", "agent.start",
		"planes", len(a.planes),
		"transport", a.cfg.Transport,
		"server", a.server,
		"fallback_timeout_ms", a.timings.fallbackTimeout.Milliseconds(),
		"re_probe_interval_ms", a.timings.reProbeInterval.Milliseconds())

	// Warm the egress cache once (bounded) so the first HELLO can carry it.
	a.refreshEgress(runCtx, true)

	a.wg.Add(1)
	go a.egressLoop(runCtx)
	if a.cfg.Transport == model.TransportAuto && a.opts.QUICDial != nil && a.opts.WSDial != nil {
		a.wg.Add(1)
		go a.probeLoop(runCtx)
	}
	for _, p := range a.planes {
		a.wg.Add(1)
		go a.runPlane(runCtx, p)
	}

	var runErr error
	select {
	case <-ctx.Done():
		a.log.Info("收到停机信号，进入优雅退出", "event", "agent.stop", "reason", "context_canceled")
	case err := <-a.fatalCh:
		runErr = err
		a.log.Error("致命错误，停止重连并退出", "event", "agent.fatal", "error", err)
	case <-a.stopCh:
		a.log.Info("服务端要求停机，进入优雅退出", "event", "agent.stop", "reason", "kick_shutdown")
	case <-a.forceCh:
		a.log.Info("Close 被调用，强制退出", "event", "agent.stop", "reason", "close")
	}
	// Cancelling the run context makes every plane stop dialing and makes
	// serving sessions enter draining (bounded by DrainTimeout).
	cancel()
	if runErr != nil {
		a.abortAllSessions("fatal_error")
	}
	select {
	case <-a.forceCh:
		// Close was called while Run was already shutting down: force abort.
		a.abortAllSessions("close")
	default:
	}
	a.wg.Wait()
	a.log.Info("节点代理已退出", "event", "agent.closed", "error", runErr)
	return runErr
}

// Close releases the agent. It is idempotent, closes every connection and every
// stream, and waits for Run to finish (when it was started).
func (a *Agent) Close() error {
	a.closeOnce.Do(func() {
		close(a.forceCh)
		a.cancelMu.Lock()
		cancel := a.cancel
		a.cancelMu.Unlock()
		if cancel != nil {
			cancel()
		}
		a.abortAllSessions("close")
	})
	if a.started.Load() {
		<-a.done
	}
	return nil
}

// Status returns a consistent snapshot of the agent.
func (a *Agent) Status() Status {
	st := Status{
		BytesIn:  a.bytesIn.Load(),
		BytesOut: a.bytesOut.Load(),
		Streams:  a.activeStreams.Load(),
		Inflight: a.inflight.Load(),
		Version:  a.version,
	}
	a.stMu.Lock()
	st.Connected = len(a.readyKinds) > 0
	st.Planes = len(a.readyKinds)
	st.Transport = transportNames(a.readyKinds)
	st.LastError = a.lastErr
	st.ConnectedSince = a.connectedSince
	a.stMu.Unlock()
	st.LastFallbackReason = a.sel.fallbackReason()
	st.EgressV4, st.EgressV6 = a.egress()
	return st
}

// reportFatal signals Run to stop with err. The channel is buffered, so the
// first fatal error wins and later reports are ignored.
func (a *Agent) reportFatal(err error) {
	if err == nil {
		return
	}
	a.fatalOnce.Do(func() {
		a.fatalCh <- err
	})
}

// requestStop asks Run to perform a graceful shutdown (KICK shutdown).
func (a *Agent) requestStop() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

// isFatal consults the injected classifier first, then the built-in heuristic.
// *FatalError is always fatal.
func (a *Agent) isFatal(err error) bool {
	if err == nil {
		return false
	}
	var fe *FatalError
	if errors.As(err, &fe) {
		return true
	}
	if a.opts.IsFatal != nil && a.opts.IsFatal(err) {
		return true
	}
	return IsFatal(err)
}

func fatalWrap(reason string, err error) *FatalError {
	if err == nil {
		return &FatalError{Reason: reason}
	}
	var fe *FatalError
	if errors.As(err, &fe) {
		return fe
	}
	return &FatalError{Reason: reason, Err: err}
}

// registerSession adds a ready or handshaking session to the agent registry so
// Close/fatal shutdown can abort it.
func (a *Agent) registerSession(s *session) {
	a.sessMu.Lock()
	a.sessions[s] = struct{}{}
	a.sessMu.Unlock()
}

func (a *Agent) unregisterSession(s *session) {
	a.sessMu.Lock()
	delete(a.sessions, s)
	a.sessMu.Unlock()
}

func (a *Agent) abortAllSessions(reason string) {
	a.sessMu.Lock()
	list := make([]*session, 0, len(a.sessions))
	for s := range a.sessions {
		list = append(list, s)
	}
	a.sessMu.Unlock()
	for _, s := range list {
		s.abort(reason)
	}
}

func (a *Agent) notifySessionsStats() {
	a.sessMu.Lock()
	list := make([]*session, 0, len(a.sessions))
	for s := range a.sessions {
		list = append(list, s)
	}
	a.sessMu.Unlock()
	for _, s := range list {
		s.requestStats()
	}
}

// sessionReady publishes a registered session.
func (a *Agent) sessionReady(s *session) {
	a.gate.success()
	a.sel.onSessionReady(s.kind)
	a.planes[s.plane].setReady(s.kind)
	a.stMu.Lock()
	a.readyKinds[s.plane] = s.kind
	if a.connectedSince.IsZero() {
		a.connectedSince = time.Now()
	}
	a.stMu.Unlock()
	n := a.readyCount.Add(1)
	a.recordPlanes(int(n))
	s.log.Info("会话注册成功，进入 ready",
		"event", "session.ready",
		"transport", string(s.kind),
		"plane_index", s.plane,
		"epoch", s.ack.Epoch,
		"heartbeat_ms", s.heartbeat.Milliseconds(),
		"max_streams", s.maxStreams)
}

// sessionClosed removes a session from the ready set.
func (a *Agent) sessionClosed(s *session, endErr error) {
	a.planes[s.plane].clearReady()
	a.stMu.Lock()
	delete(a.readyKinds, s.plane)
	if len(a.readyKinds) == 0 {
		a.connectedSince = time.Time{}
	}
	if endErr != nil {
		a.lastErr = endErr.Error()
	}
	a.stMu.Unlock()
	n := a.readyCount.Add(-1)
	if n < 0 {
		a.readyCount.Store(0)
		n = 0
	}
	a.recordPlanes(int(n))
	s.log.Info("会话已关闭",
		"event", "session.closed",
		"transport", string(s.kind),
		"plane_index", s.plane,
		"error", endErr,
		"ready_planes", n)
}

// setLastError records the most recent session/transport error for Status.
func (a *Agent) setLastError(err error) {
	if err == nil {
		return
	}
	a.stMu.Lock()
	a.lastErr = err.Error()
	a.stMu.Unlock()
}

// noteLatency feeds the EWMA latency used in STATS.
func (a *Agent) noteLatency(d time.Duration) {
	if d <= 0 {
		return
	}
	ms := float64(d) / float64(time.Millisecond)
	for {
		old := a.latencyBits.Load()
		oldMS := math.Float64frombits(old)
		next := ms
		if oldMS > 0 {
			next = oldMS*0.8 + ms*0.2
		}
		if a.latencyBits.CompareAndSwap(old, math.Float64bits(next)) {
			return
		}
	}
}

func (a *Agent) latencyMS() float64 {
	return math.Float64frombits(a.latencyBits.Load())
}

func (a *Agent) egress() (string, string) {
	a.egressMu.RLock()
	defer a.egressMu.RUnlock()
	return a.egressV4, a.egressV6
}

// setEgress updates the cache and returns true when the value changed.
func (a *Agent) setEgress(v4, v6 string) bool {
	a.egressMu.Lock()
	changed := a.egressV4 != v4 || a.egressV6 != v6
	a.egressV4 = v4
	a.egressV6 = v6
	a.egressMu.Unlock()
	return changed
}

// refreshEgress calls the injected Egress callback once, bounded by the egress
// timeout. A slow callback never blocks HELLO/STATS forever and never leaks more
// than one in-flight refresh.
func (a *Agent) refreshEgress(ctx context.Context, initial bool) {
	if a.opts.Egress == nil {
		return
	}
	if !a.egressRefreshBusy.CompareAndSwap(false, true) {
		return
	}
	defer a.egressRefreshBusy.Store(false)
	cctx, cancel := context.WithTimeout(ctx, a.timings.egressTimeout)
	defer cancel()
	type result struct{ v4, v6 string }
	ch := make(chan result, 1)
	egress := a.opts.Egress
	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.log.Error("出口 IP 探测 panic，已忽略", "event", "egress.panic", "panic", fmt.Sprint(r))
			}
		}()
		v4, v6 := egress(cctx)
		select {
		case ch <- result{v4: v4, v6: v6}:
		default:
		}
	}()
	select {
	case r := <-ch:
		// Manual configuration always overrides dynamic detection (main spec
		// E.1: manual egress_ip wins over automatic results). An empty family
		// result keeps the previous cached value to avoid flapping.
		v4, v6 := a.applyEgressOverride(r.v4, r.v6)
		cur4, cur6 := a.egress()
		if v4 == "" {
			v4 = cur4
		}
		if v6 == "" {
			v6 = cur6
		}
		if a.setEgress(v4, v6) {
			a.log.Info("出口 IP 发生变化", "event", "egress.changed", "egress_v4", v4, "egress_v6", v6)
			a.notifySessionsStats()
		}
	case <-cctx.Done():
		if initial {
			a.log.Warn("出口 IP 探测超时，先使用历史值", "event", "egress.timeout")
		}
	}
}

// applyEgressOverride lets the configured manual values win over detection.
func (a *Agent) applyEgressOverride(v4, v6 string) (string, string) {
	if manual := a.cfg.Egress.ManualV4; manual != "" {
		v4 = manual
	}
	if manual := a.cfg.Egress.ManualV6; manual != "" {
		v6 = manual
	}
	return v4, v6
}

func (a *Agent) egressLoop(ctx context.Context) {
	defer a.wg.Done()
	if a.opts.Egress == nil {
		return
	}
	timer := time.NewTimer(a.timings.egressRefresh)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			a.refreshEgress(ctx, false)
			timer.Reset(a.timings.egressRefresh)
		}
	}
}

// noteReplaced records a replaced KICK and returns how many happened inside the
// debounce window.
func (a *Agent) noteReplaced(now time.Time) int {
	a.replacedMu.Lock()
	defer a.replacedMu.Unlock()
	cutoff := now.Add(-a.timings.replacedWindow)
	kept := a.replacedAt[:0]
	for _, t := range a.replacedAt {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.replacedAt = append(kept, now)
	return len(a.replacedAt)
}

// kickRetryDelay computes the reconnect delay after a non-shutdown KICK.
func (a *Agent) kickRetryDelay(reason string) time.Duration {
	switch reason {
	case protocol.KickCooldown:
		// The server is rate limiting takeovers: do not hammer it.
		a.log.Warn("服务端要求接管冷却，退避后重连",
			"event", "kick.cooldown",
			"reason", reason,
			"delay_ms", a.timings.replacedCooldown.Milliseconds())
		return a.timings.replacedCooldown
	case protocol.KickReplaced, protocol.KickDuplicate:
		if n := a.noteReplaced(time.Now()); n >= a.timings.replacedLimit {
			a.log.Warn("短时间内多次被 replaced，进入冷却退避，避免双 agent 互踢",
				"event", "kick.cooldown",
				"reason", reason,
				"count", n,
				"window_ms", a.timings.replacedWindow.Milliseconds(),
				"delay_ms", a.timings.replacedCooldown.Milliseconds())
			return a.timings.replacedCooldown
		}
	}
	base := a.timings.kickRetryDelay
	if base <= 0 {
		base = time.Second
	}
	return base + jitter(base/2)
}

// planeRetryDelay is the small exponential retry used while at least one other
// plane is still serving.
func (a *Agent) planeRetryDelay(p *plane) time.Duration {
	p.retry++
	base := a.timings.reconnectBase
	if base <= 0 {
		base = time.Second
	}
	d := base
	for i := 1; i < p.retry && d < 30*time.Second; i++ {
		d *= 2
	}
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d + jitter(d/4)
}

// recordReconnect feeds the optional Prometheus counter.
func (a *Agent) recordReconnect(reason string) {
	if a.metrics == nil || a.metrics.TunnelReconnects == nil {
		return
	}
	label := a.metrics.NodeLabel(a.clientID)
	a.metrics.TunnelReconnects.WithLabelValues(label, reason).Inc()
}

func (a *Agent) recordPlanes(n int) {
	if a.metrics == nil || a.metrics.TunnelPlanes == nil {
		return
	}
	label := a.metrics.NodeLabel(a.clientID)
	a.metrics.TunnelPlanes.WithLabelValues(label).Set(float64(n))
}

func (a *Agent) recordOpenError(code protocol.OpenErrorCode) {
	if a.metrics == nil || a.metrics.TunnelOpenErrors == nil {
		return
	}
	label := a.metrics.NodeLabel(a.clientID)
	a.metrics.TunnelOpenErrors.WithLabelValues(label, code.String()).Inc()
}

func (a *Agent) recordDNSProbe(result string) {
	if a.metrics == nil || a.metrics.DNSPassthroughTotal == nil {
		return
	}
	label := a.metrics.NodeLabel(a.clientID)
	a.metrics.DNSPassthroughTotal.WithLabelValues(label, result).Inc()
}

// transportNames renders the ready transports for Status.Transport.
func transportNames(ready map[int]transport.Kind) string {
	if len(ready) == 0 {
		return ""
	}
	first := transport.Kind("")
	mixed := false
	for _, k := range ready {
		if first == "" {
			first = k
			continue
		}
		if k != first {
			mixed = true
		}
	}
	if mixed {
		return "mixed"
	}
	return string(first)
}

func scaleDur(d time.Duration, scale float64) time.Duration {
	v := float64(d) * scale
	if v < 1 {
		return time.Duration(1)
	}
	return time.Duration(v)
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// defaultDrainTimeout takes the draining budget from the runtime settings when
// provided, otherwise from the attachment constant.
func defaultDrainTimeout(settings model.Settings) time.Duration {
	if d := settings.Timeouts.Drain.Std(); d > 0 {
		return d
	}
	return DrainTimeout
}
