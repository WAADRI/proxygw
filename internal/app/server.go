// Package app wires the server and client components together: configuration,
// certificates, transports, tunnel, proxy entries, panel and observability.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxygw/internal/certs"
	"proxygw/internal/config"
	"proxygw/internal/geo"
	"proxygw/internal/health"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/nodesauth"
	"proxygw/internal/proxyproto"
	"proxygw/internal/registry"
	"proxygw/internal/settings"
	"proxygw/internal/transport"
	"proxygw/internal/tunnel"
	"proxygw/internal/version"
	"proxygw/internal/webhook"
)

// Server is the fully wired gateway server.
type Server struct {
	cfg    *config.ServerConfig
	logger *slog.Logger

	certMgr   *certs.Manager
	metrics   *metrics.Metrics
	health    *health.Server
	registry  *registry.Registry
	authn     *nodesauth.Authenticator
	settings  *settings.Manager
	tunnel    *tunnel.Server
	metadata  *metadataCoordinator
	gateway   *gateway
	panelDeps *panelDeps
	hook      *webhook.Sender

	quicListener transport.Listener
	wsListener   *transport.WSListener
	httpServer   *http.Server
	tcpListener  net.Listener
	httpErr      chan error

	// Bootstrap messages are printed once at startup (credentials, tokens, pin).
	bootMessages []string
}

// ServerOptions configures NewServer.
type ServerOptions struct {
	Config *config.ServerConfig
	Logger *slog.Logger
}

// NewServer constructs every component but does not bind sockets yet
// (Listen) or serve (Run).
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("app: server config is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cfg := opts.Config
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("app: create state dir: %w", err)
	}
	s := &Server{cfg: cfg, logger: logger}
	s.metrics = metrics.New()
	s.health = health.New()
	s.panelDeps = newPanelDeps()
	hook, err := webhook.New(webhook.Options{
		URL:           cfg.Observability.WebhookURL,
		Timeout:       cfg.Observability.WebhookTimeout.Std(),
		Logger:        logger,
		Metrics:       s.metrics,
		RatePerMinute: 30,
	})
	if err != nil {
		return nil, fmt.Errorf("app: init alert webhook: %w", err)
	}
	s.hook = hook

	hosts, ips := certSANs(cfg)
	certMgr, err := certs.NewServerManager(certs.ServerOptions{
		Mode:       cfg.TLS.Mode,
		CertFile:   cfg.TLS.CertFile,
		KeyFile:    cfg.TLS.KeyFile,
		CAFile:     cfg.TLS.CAFile,
		Dir:        cfg.EffectiveCertDir(),
		PinNext:    cfg.TLS.PinNext,
		HotReload:  cfg.TLS.HotReload,
		ClientAuth: cfg.TLS.ClientAuth,
		Hosts:      hosts,
		IPs:        ips,
		Logger:     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("app: load server identity: %w", err)
	}
	s.certMgr = certMgr
	status := certMgr.Status()
	s.bootMessages = append(s.bootMessages, certBootstrapMessage(status))

	overrides, err := settings.NewManager(cfg.OverridesPath(), cfg.Settings, logger)
	if err != nil {
		return nil, fmt.Errorf("app: load runtime settings: %w", err)
	}
	s.settings = overrides

	reg, err := registry.New(logger, s.metrics, cfg.NodesPath())
	if err != nil {
		return nil, fmt.Errorf("app: load node registry: %w", err)
	}
	s.registry = reg
	s.health.AddCheck("registry", func() error { return nil })

	authn, err := nodesauth.New(cfg.Nodes, cfg.NodeTokensPath(), logger)
	if err != nil {
		return nil, fmt.Errorf("app: init node authenticator: %w", err)
	}
	s.authn = authn
	if cfg.Nodes.MTLS {
		logger.Warn("mTLS 模式已启用：面板、/healthz 与 wss 隧道共用同一 TCP 监听，浏览器访问面板时同样会被要求出示客户端证书；生产建议为面板保留独立入口或仅在隧道侧启用客户端证书校验")
	}
	if len(cfg.Nodes.Tokens) == 0 && !cfg.Nodes.MTLS && len(authn.List()) == 0 {
		// Only mint the bootstrap shared token on a genuinely empty token store.
		// Issuing "*" on every restart would replace the persisted wildcard token
		// and invalidate every node that was configured with the previous value.
		token, issueErr := authn.Issue("*", "bootstrap shared token")
		if issueErr != nil {
			return nil, fmt.Errorf("app: generate bootstrap node token: %w", issueErr)
		}
		s.bootMessages = append(s.bootMessages,
			"节点接入令牌（仅本次显示，请立即保存）："+token+"   （node_id 使用任意值或 \"*\" 共享令牌）")
	}

	// Tunnel listeners: auto = QUIC (primary) + WebSocket (fallback), otherwise
	// only the configured transport is accepted.
	tlsCfg := certMgr.TLSConfig()
	if tlsCfg == nil {
		return nil, errors.New("app: server identity has no TLS config")
	}
	var quicLn transport.Listener
	var wsLn *transport.WSListener
	if cfg.Tunnel.Transport == model.TransportAuto || cfg.Tunnel.Transport == model.TransportQUIC {
		quicTLS := tlsCfg.Clone()
		quicTLS.NextProtos = []string{alpnOrDefault(cfg.Tunnel.ALPN)}
		ql, err := transport.ListenQUIC(transport.QUICOptions{
			Addr:              cfg.Server.ListenAddr,
			TLS:               quicTLS,
			ALPN:              alpnOrDefault(cfg.Tunnel.ALPN),
			MaxIdleTimeout:    60 * time.Second,
			KeepAlivePeriod:   15 * time.Second,
			EnableDatagrams:   true,
			Allow0RTT:         true,
			CongestionControl: cfg.Tunnel.QUICCC,
			QLogDir:           cfg.Tunnel.QLogDir,
			InitialPacketSize: 1200,
		})
		if err != nil {
			return nil, fmt.Errorf("app: listen QUIC on %s: %w", cfg.Server.ListenAddr, err)
		}
		quicLn = ql
	}
	if cfg.Tunnel.Transport == model.TransportAuto || cfg.Tunnel.Transport == model.TransportWS {
		wsLn = transport.NewWSListener(transport.WSOptions{
			Path:          "/tunnel",
			MaxFrameBytes: cfg.Tunnel.MaxFrameBytes,
			WindowStall:   s.settings.Current().Timeouts.WindowStall.Std(),
		})
	}
	s.quicListener = quicLn
	s.wsListener = wsLn

	tun, err := tunnel.NewServer(tunnel.ServerOptions{
		Logger:        logger,
		QUICListener:  quicLn,
		WSListener:    wsLn,
		Registry:      s.registry,
		Auth:          s.authn,
		Settings:      s.settings.Current,
		Metrics:       s.metrics,
		PinNext:       status.PinNext,
		ALPN:          alpnOrDefault(cfg.Tunnel.ALPN),
		MaxFrameBytes: cfg.Tunnel.MaxFrameBytes,
		Version:       version.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("app: init tunnel server: %w", err)
	}
	s.tunnel = tun
	s.health.AddCheck("tunnel", func() error {
		if s.tunnel == nil {
			return errors.New("tunnel not initialised")
		}
		return nil
	})

	// Geolocation enrichment runs out of band (never on the proxy hot path).
	if cfg.Geo.Enabled {
		gr, err := geo.New(geo.Options{
			Config:  cfg.Geo,
			Logger:  logger,
			Metrics: s.metrics,
			OnProviderDown: func(name, reason string) {
				s.hook.Send(webhook.Alert{
					Name:     "geo_provider_down",
					Severity: webhook.SeverityWarning,
					Message:  fmt.Sprintf("归属地 provider %s 连续失败已摘除", name),
					Detail:   map[string]string{"provider": name, "reason": reason},
				})
			},
		})
		if err != nil {
			return nil, fmt.Errorf("app: init geo resolver: %w", err)
		}
		eg := geo.NewEgressResolver(geo.EgressOptions{
			EchoURLsV4: cfg.Geo.Egress.EchoURLsV4,
			EchoURLsV6: cfg.Geo.Egress.EchoURLsV6,
			Timeout:    cfg.Geo.Egress.Timeout.Std(),
			Logger:     logger,
		})
		s.metadata = newMetadataCoordinator(gr, eg)
		s.health.AddCheck("geo", func() error { return nil })
	}
	if err := s.initGateway(); err != nil {
		return nil, err
	}
	return s, nil
}

// BootMessages returns one-time startup messages that must be printed to the
// operator console (secrets are never persisted in plain text).
func (s *Server) BootMessages() []string { return s.bootMessages }

// Listen binds the shared TCP listener used by the panel, health endpoints and
// the WebSocket tunnel.
func (s *Server) Listen() error {
	mux := http.NewServeMux()
	if s.wsListener != nil {
		mux.Handle("/tunnel", s.wsListener.Handler())
	}
	mux.Handle("/healthz", s.health.Handler())
	mux.Handle("/version", health.VersionHandler())
	if s.cfg.Observability.MetricsEnabled {
		mux.Handle(s.cfg.Observability.MetricsPath, s.metrics.Handler())
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !s.panelHostAllowed(r) {
			s.closePanelConnection(w, r)
			return
		}
		if s.gateway != nil && s.gateway.panel != nil {
			s.gateway.panel.Handler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    s.cfg.Proxy.MaxHeaderBytes,
	}
	s.httpServer = srv
	ln, err := net.Listen("tcp", s.cfg.Server.ListenAddr)
	if err != nil {
		return fmt.Errorf("app: listen TCP %s: %w", s.cfg.Server.ListenAddr, err)
	}
	if s.cfg.Server.ProxyProtocol {
		// Optional PROXY protocol v2 header in front of TLS: connections without
		// the header are passed through unchanged, so direct access keeps working
		// while a CDN/load balancer can supply the real client address.
		wrapped, werr := proxyproto.NewListener(ln, 5*time.Second)
		if werr != nil {
			_ = ln.Close()
			return fmt.Errorf("app: enable PROXY protocol: %w", werr)
		}
		ln = wrapped
		s.logger.Info("PROXY protocol v2 已启用（共享 TLS 监听；无头连接按普通 TCP 处理）")
	}
	if s.cfg.Server.PanelDomain != "" {
		s.logger.Info("面板域名限制已启用，仅匹配 Host 的面板请求会被处理",
			"panel_domain", s.cfg.Server.PanelDomain)
	}
	baseTLS := s.certMgr.TLSConfig().Clone()
	baseTLS.NextProtos = []string{"http/1.1"}
	tlsLn := tls.NewListener(ln, baseTLS)
	s.tcpListener = ln
	if err := s.bindProxyListeners(); err != nil {
		_ = ln.Close()
		return err
	}
	if httpAddr, socksAddr := s.ProxyAddrs(); httpAddr != "" || socksAddr != "" {
		s.logger.Info("代理入口已就绪", "http", httpAddr, "socks5", socksAddr, "auth_mode", s.cfg.Proxy.AuthMode)
	}
	s.logger.Info("共享监听已就绪（面板/wss/健康检查）", "addr", ln.Addr().String(), "tls_mode", s.cfg.TLS.Mode,
		"hint", "QUIC 使用同端口 UDP；若部署在 nginx 之后只能走 wss")
	return s.serveTLS(tlsLn)
}

// panelHostAllowed reports whether the request may reach the panel. When
// server.panel_domain is empty every Host is accepted (the historical
// behaviour); otherwise only the configured domain is allowed and the port is
// ignored during comparison. The tunnel and operational endpoints are routed
// before the panel fallback and are therefore not affected.
func (s *Server) panelHostAllowed(r *http.Request) bool {
	want := strings.TrimSpace(s.cfg.Server.PanelDomain)
	if want != "" {
		if h, _, err := net.SplitHostPort(want); err == nil {
			want = h
		}
		want = strings.TrimSuffix(strings.ToLower(want), ".")
	}
	if want == "" {
		return true
	}
	host := strings.TrimSpace(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == want
}

// closePanelConnection closes the underlying connection without writing an
// HTTP response. The panel is a browser-facing surface, so a mismatched Host
// gets no status line, no body and no hint that the panel exists there.
func (s *Server) closePanelConnection(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("面板域名不匹配，关闭连接",
		"host", r.Host, "remote", r.RemoteAddr)
	if hj, ok := w.(http.Hijacker); ok {
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
			return
		}
	}
	// HTTP/2 or a non-hijackable writer: abort without a response.
	panic(http.ErrAbortHandler)
}

func (s *Server) serveTLS(ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.httpServer.Serve(ln) }()
	// Surface serving errors asynchronously; Run observes the same channel.
	s.httpErr = errCh
	return nil
}

// httpErr is set by Listen and consumed by Run.
// (kept as a field to avoid a second error path in callers)

// Run serves until ctx is cancelled or a fatal serve error occurs, then shuts
// down gracefully.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var serveErr error
	pipeErr := make(chan error, 4)
	go func() { pipeErr <- s.tunnel.Serve(ctx) }()
	go func() {
		if s.httpErr != nil {
			pipeErr <- <-s.httpErr
		}
	}()
	s.serveProxy(ctx, pipeErr)
	go s.certMgr.Watch(ctx)
	go s.sessionLoop(ctx)
	go s.startAlerts(ctx)

	select {
	case <-ctx.Done():
	case err := <-pipeErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			serveErr = err
			s.logger.Error("服务异常退出", "error", err)
		}
		cancel()
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), s.drainTimeout()+5*time.Second)
	defer cancelShutdown()
	if err := s.Close(shutdownCtx); err != nil {
		s.logger.Warn("优雅停机期间出现问题", "error", err)
	}
	return serveErr
}

// sessionLoop updates gauges and trend buffers periodically.
func (s *Server) sessionLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.metrics.NodesOnline.Set(float64(s.registry.OnlineCount()))
			s.metrics.UniqueEgressIPs.Set(float64(s.registry.UniqueEgressCount()))
			s.metrics.SetNodeCount(int64(s.registry.Count()))
			s.enrich(ctx)
		}
	}
}

// Close performs an orderly shutdown: drain tunnels, stop HTTP, close
// listeners and persist state. It is idempotent.
func (s *Server) Close(ctx context.Context) error {
	var errs []error
	if err := s.closeGateway(ctx); err != nil {
		errs = append(errs, err)
	}
	if s.tunnel != nil {
		if err := s.tunnel.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.quicListener != nil {
		if err := s.quicListener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.wsListener != nil {
		_ = s.wsListener.Close()
	}
	if s.certMgr != nil {
		_ = s.certMgr.Close()
	}
	if s.registry != nil {
		_ = s.registry.Close()
	}
	if s.authn != nil {
		_ = s.authn.Close()
	}
	if s.metadata != nil && s.metadata.geoResolver != nil {
		_ = s.metadata.geoResolver.Close()
	}
	if s.hook != nil {
		_ = s.hook.Close()
	}
	return errors.Join(errs...)
}

func (s *Server) drainTimeout() time.Duration {
	return s.settings.Current().Timeouts.Drain.Std()
}

// Status returns the certificate status for the panel.
func (s *Server) CertStatus() certs.Status { return s.certMgr.Status() }

// TLSConfig returns a clone of the server TLS config (mainly for tests).
func (s *Server) TLSConfig() *tls.Config { return s.certMgr.TLSConfig().Clone() }

// ListenAddr returns the bound shared TCP address.
func (s *Server) ListenAddr() string {
	if s.tcpListener == nil {
		return s.cfg.Server.ListenAddr
	}
	return s.tcpListener.Addr().String()
}

// Metrics exposes the metrics registry (tests / panel adapters).
func (s *Server) Metrics() *metrics.Metrics { return s.metrics }

// Registry exposes the node registry (tests / panel adapters).
func (s *Server) Registry() *registry.Registry { return s.registry }

// TunnelServer exposes the tunnel server (tests / panel adapters).
func (s *Server) TunnelServer() *tunnel.Server { return s.tunnel }

// Authenticator exposes the node authenticator (tests / panel adapters).
func (s *Server) Authenticator() *nodesauth.Authenticator { return s.authn }

// Settings exposes the runtime settings manager.
func (s *Server) Settings() *settings.Manager { return s.settings }

func certSANs(cfg *config.ServerConfig) (hosts, ips []string) {
	host, _, err := config.ListenHostPort(cfg.Server.ListenAddr)
	if err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, host)
		} else {
			hosts = append(hosts, host)
		}
	}
	hosts = append(hosts, "localhost")
	ips = append(ips, "127.0.0.1", "::1")
	if cfg.Server.PublicURL != "" {
		if h := publicURLHost(cfg.Server.PublicURL); h != "" {
			if ip := net.ParseIP(h); ip != nil {
				ips = append(ips, h)
			} else {
				hosts = append(hosts, h)
			}
		}
	}
	return dedupeStrings(hosts), dedupeStrings(ips)
}

func publicURLHost(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		return h
	}
	return rest
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func alpnOrDefault(alpn string) string {
	if strings.TrimSpace(alpn) == "" {
		return "proxygw/1"
	}
	return alpn
}

func certBootstrapMessage(st certs.Status) string {
	msg := "服务端证书模式=" + st.Mode + " SPKI 指纹=" + st.Pin
	if st.PinNext != "" {
		msg += "（下一枚 pin=" + st.PinNext + "）"
	}
	if !st.NotAfter.IsZero() {
		msg += fmt.Sprintf(" 有效期至 %s", st.NotAfter.Format(time.RFC3339))
	}
	return msg
}

// StateDir returns the absolute state directory (for the panel/logs).
func (s *Server) StateDir() string { return filepath.Clean(config.AbsState(s.cfg.StateDir)) }
