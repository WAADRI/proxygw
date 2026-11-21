package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxygw/internal/certs"
	"proxygw/internal/config"
	"proxygw/internal/geo"
	"proxygw/internal/identity"
	"proxygw/internal/model"
	"proxygw/internal/nodeagent"
	"proxygw/internal/protocol"
	"proxygw/internal/stats"
	"proxygw/internal/transport"
	"proxygw/internal/version"
)

// Client is the wired node agent.
type Client struct {
	cfg      *config.ClientConfig
	logger   *slog.Logger
	clientID string
	agent    *nodeagent.Agent
	egress   *geo.EgressResolver
	tlsCfg   *tls.Config
	statsTr  *stats.Trend
}

// ClientOptions configures NewClient.
type ClientOptions struct {
	Config *config.ClientConfig
	Logger *slog.Logger
}

// NewClient builds the node agent, including TLS verification material, egress
// resolution and both transport dialers.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Config == nil {
		return nil, errors.New("app: client config is required")
	}
	cfg := opts.Config
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("app: create state dir: %w", err)
	}
	clientID := cfg.ClientID
	if clientID == "" {
		id, generated, err := identity.LoadOrCreate(cfg.StateDir)
		if err != nil {
			return nil, fmt.Errorf("app: init client id: %w", err)
		}
		clientID = id
		if generated {
			logger.Info("已生成并持久化节点 ID", "client_id", clientID,
				"path", filepath.Join(cfg.StateDir, identity.ClientIDFile))
		}
	}
	ep, err := config.ParseServerURL(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("app: parse server_url: %w", err)
	}
	pins := append([]string{}, cfg.TLS.Pins...)
	if cfg.TLS.Pin != "" {
		pins = append(pins, cfg.TLS.Pin)
	}
	tlsCfg, err := certs.ClientTLSConfig(certs.ClientOptions{
		Mode:            cfg.TLS.Mode,
		Pins:            pins,
		CAFile:          cfg.TLS.CAFile,
		ServerName:      cfg.TLS.ServerName,
		TrustOnFirstUse: cfg.TLS.TrustOnFirstUse,
		TOFUDir:         cfg.TLS.Dir,
		CertFile:        cfg.TLS.CertFile,
		KeyFile:         cfg.TLS.KeyFile,
		Logger:          logger,
	})
	if err != nil {
		return nil, fmt.Errorf("app: build client TLS config: %w", err)
	}
	if tlsCfg.ServerName == "" && cfg.TLS.Mode != "ca" {
		tlsCfg.ServerName = ep.Host
	}

	egressResolver := geo.NewEgressResolver(geo.EgressOptions{
		ManualV4:   cfg.Egress.ManualV4,
		ManualV6:   cfg.Egress.ManualV6,
		EchoURLsV4: cfg.Egress.EchoURLsV4,
		EchoURLsV6: cfg.Egress.EchoURLsV6,
		Timeout:    2 * time.Second,
		Logger:     logger,
	})
	egressFn := func(ctx context.Context) (string, string) {
		eg, err := egressResolver.Detect(ctx, nil)
		if err != nil && eg.V4 == "" && eg.V6 == "" {
			return cfg.Egress.ManualV4, cfg.Egress.ManualV6
		}
		return eg.V4, eg.V6
	}

	quicDial := func(ctx context.Context) (transport.Conn, error) {
		qtls := tlsCfg.Clone()
		qtls.NextProtos = []string{protocol.ALPN}
		return transport.DialQUIC(ctx, transport.QUICOptions{
			Addr:              ep.HostPort(),
			TLS:               qtls,
			ALPN:              protocol.ALPN,
			HandshakeTimeout:  nodeagent.HandshakeTimeout,
			MaxIdleTimeout:    60 * time.Second,
			KeepAlivePeriod:   15 * time.Second,
			EnableDatagrams:   true,
			Allow0RTT:         true,
			InitialPacketSize: 1200,
		})
	}
	wsDial := func(ctx context.Context) (transport.Conn, error) {
		wtls := tlsCfg.Clone()
		wtls.NextProtos = []string{"http/1.1"}
		return transport.DialWS(ctx, transport.WSOptions{
			URL:              ep.WSURL(),
			TLS:              wtls,
			HandshakeTimeout: nodeagent.HandshakeTimeout,
			MaxFrameBytes:    protocol.MaxFramePayload,
			WindowStall:      model.DefaultSettings().Timeouts.WindowStall.Std(),
		})
	}

	var quicFn, wsFn func(context.Context) (transport.Conn, error)
	switch cfg.Transport {
	case model.TransportQUIC:
		quicFn = quicDial
	case model.TransportWS:
		wsFn = wsDial
	default: // auto
		quicFn = quicDial
		wsFn = wsDial
	}

	agent, err := nodeagent.New(nodeagent.Options{
		Config:   cfg,
		ClientID: clientID,
		Logger:   logger,
		Version:  version.Version,
		QUICDial: quicFn,
		WSDial:   wsFn,
		Egress:   egressFn,
		IsFatal: func(err error) bool {
			if err == nil {
				return false
			}
			if certs.IsPinMismatch(err) {
				return true
			}
			return nodeagent.IsFatal(err)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("app: init node agent: %w", err)
	}
	return &Client{
		cfg:      cfg,
		logger:   logger,
		clientID: clientID,
		agent:    agent,
		egress:   egressResolver,
		tlsCfg:   tlsCfg,
		statsTr:  stats.NewTrend(15*time.Minute, 15*time.Second),
	}, nil
}

// Run blocks while the agent maintains its sessions until ctx is cancelled, a
// fatal error happens or the server sends KICK(shutdown).
func (c *Client) Run(ctx context.Context) error {
	return c.agent.Run(ctx)
}

// Close releases agent resources (idempotent).
func (c *Client) Close() error { return c.agent.Close() }

// Status exposes the live agent status for logs / a future client panel.
func (c *Client) Status() nodeagent.Status { return c.agent.Status() }

// ClientID returns the stable node id used in HELLO.
func (c *Client) ClientID() string { return c.clientID }

// Config returns the loaded configuration.
func (c *Client) Config() *config.ClientConfig { return c.cfg }

// BootMessages returns one-time startup advisories.
func (c *Client) BootMessages() []string {
	var out []string
	if c.cfg.TLS.Mode == "insecure" {
		out = append(out, "安全警告：tls.mode=insecure，节点不校验服务端证书，仅限本地开发")
	}
	if c.cfg.TLS.TrustOnFirstUse && len(c.cfg.TLS.Pins) == 0 && c.cfg.TLS.Pin == "" {
		out = append(out, "安全警告：已启用 trust-on-first-use，首次连接将记录服务端指纹；生产请显式下发 pin")
	}
	return out
}

// ListenAddr is unused for clients (no inbound port); kept for symmetry so
// tooling can query both binaries uniformly.
func (c *Client) ListenAddr() string { return "" }

// serverURLHost is a helper for logs.
func serverURLHost(raw string) string {
	ep, err := config.ParseServerURL(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return net.JoinHostPort(ep.Host, fmt.Sprintf("%d", ep.Port))
}
