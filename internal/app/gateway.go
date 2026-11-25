package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"proxygw/internal/acl"
	"proxygw/internal/audit"
	"proxygw/internal/auth"
	"proxygw/internal/groups"
	"proxygw/internal/model"
	"proxygw/internal/panel"
	"proxygw/internal/protocol"
	"proxygw/internal/proxy"
	"proxygw/internal/proxyproto"
	"proxygw/internal/rules"
	"proxygw/internal/sched"
	"proxygw/internal/tunnel"
)

// gateway owns everything related to the three proxy entry points and the
// credential/group/ACL/scheduler wiring behind them.
type gateway struct {
	creds   *auth.CredentialStore
	admin   *auth.AdminManager
	groups  *groups.Store
	rules   *rules.Store
	acl     *acl.Engine
	sched   *sched.Selector
	limiter *sched.Limiters
	audit   *audit.Store
	panel   *panel.Server
	authBan *proxy.AuthBanTracker

	httpProxy  *proxy.HTTPProxy
	socksProxy *proxy.SOCKS5Proxy
	httpLn     net.Listener
	socksLn    net.Listener
}

// initGateway builds the stores and adapters. Listeners are bound in Listen.
func (s *Server) initGateway() error {
	cfg := s.cfg
	logger := s.logger

	creds, err := auth.NewCredentialStore(cfg.CredentialsPath(), logger)
	if err != nil {
		return fmt.Errorf("app: load credentials: %w", err)
	}
	groupStore, err := groups.NewStore(cfg.GroupsPath(), logger)
	if err != nil {
		return fmt.Errorf("app: load node groups: %w", err)
	}
	rulesStore, err := rules.NewStore(cfg.RulesPath(), logger)
	if err != nil {
		return fmt.Errorf("app: load rules: %w", err)
	}
	auditStore, err := audit.NewWithOptions(cfg.AuditPath(), cfg.Audit.Enabled, audit.Options{
		MaxSize:    int64(cfg.Audit.MaxSizeMB) * 1024 * 1024,
		MaxBackups: cfg.Audit.MaxBackups,
	})
	if err != nil {
		return fmt.Errorf("app: init audit store: %w", err)
	}
	// Share the audit trail with the tunnel layer (auth failures, protocol
	// violations, takeover throttling).
	if s.tunnel != nil {
		s.tunnel.SetAudit(func(action string, detail map[string]string) {
			s.auditEvent(auditStore, action, detail)
		})
	}
	aclEngine := acl.New(acl.Options{
		DefaultAction: func() string { return s.settings.Current().DefaultACLAction },
	})
	if err := aclEngine.SetRules(rulesStore.ACL()); err != nil {
		return fmt.Errorf("app: compile ACL rules: %w", err)
	}
	selector := sched.NewSelector(sched.Options{
		Settings: s.settings.Current,
		OnAudit: func(event string, detail map[string]string) {
			s.auditEvent(auditStore, event, detail)
		},
	})
	if err := selector.SetStickyRules(rulesStore.Sticky()); err != nil {
		return fmt.Errorf("app: compile sticky rules: %w", err)
	}
	limiters := sched.NewLimiters(s.settings.Current)
	s.registry.SetGroupsResolver(groupStore.Resolver())

	if cfg.Proxy.AuthMode != model.AuthNone {
		username, password, generated, err := creds.EnsureBootstrap()
		if err != nil {
			return fmt.Errorf("app: bootstrap proxy credential: %w", err)
		}
		if generated {
			s.bootMessages = append(s.bootMessages,
				"代理凭据（仅本次显示，请立即保存）：用户名 "+username+"  密码 "+password+"   （认证模式 "+cfg.Proxy.AuthMode+"）")
		}
	}

	g := &gateway{
		creds:   creds,
		groups:  groupStore,
		rules:   rulesStore,
		acl:     aclEngine,
		sched:   selector,
		limiter: limiters,
		audit:   auditStore,
	}
	authBan := proxy.NewAuthBanTracker(proxy.AuthBanConfig{
		Enabled:          cfg.Proxy.AuthBan.Enabled,
		FailureWindow:    cfg.Proxy.AuthBan.FailureWindow.Std(),
		FailureThreshold: cfg.Proxy.AuthBan.FailureThreshold,
		BanDuration:      cfg.Proxy.AuthBan.BanDuration.Std(),
		MaxEntries:       cfg.Proxy.AuthBan.MaxEntries,
		Exempt:           cfg.Proxy.AuthBan.Exempt,
	})
	if authBan != nil {
		g.authBan = authBan
		s.authBan = authBan
	}
	deps := s.panelDeps
	opts := proxy.Options{
		Logger:         logger,
		Settings:       s.settings.Current,
		AuthMode:       cfg.Proxy.AuthMode,
		Authenticator:  &credentialAuthAdapter{store: creds},
		Candidates:     &candidateAdapter{reg: s.registry, groups: groupStore},
		Selector:       &selectorAdapter{sel: selector},
		ACL:            &aclAdapter{engine: aclEngine},
		Dialer:         &dialerAdapter{tun: s.tunnel, sel: selector},
		Limiter:        &limiterAdapter{limiters: limiters},
		Metrics:        s.metrics,
		AuthBan:        authBan,
		MaxHeaderBytes: cfg.Proxy.MaxHeaderBytes,
		MaxConcurrent:  cfg.Proxy.MaxConcurrent,
		Audit: func(event string, detail map[string]string) {
			s.auditEvent(auditStore, event, detail)
		},
		OnRequestStart: func(credentialID, protocolName, target, nodeID string) {
			deps.onRequestStart(credentialID, protocolName, target, nodeID)
		},
		OnRequestEnd: func(credentialID, protocolName, target, nodeID string, bytesIn, bytesOut int64, err error) {
			deps.onRequestEnd(credentialID, protocolName, target, nodeID, bytesIn, bytesOut, err)
		},
	}
	httpProxy, err := proxy.NewHTTPProxy(opts)
	if err != nil {
		return fmt.Errorf("app: init HTTP proxy: %w", err)
	}
	socksProxy, err := proxy.NewSOCKS5Proxy(opts)
	if err != nil {
		return fmt.Errorf("app: init SOCKS5 proxy: %w", err)
	}
	g.httpProxy = httpProxy
	g.socksProxy = socksProxy
	s.gateway = g
	s.health.AddCheck("credentials", func() error { return nil })
	if cfg.Server.UIEnabled {
		if err := s.initPanel(); err != nil {
			return err
		}
	}
	return nil
}

// auditEvent writes one audit record (best effort: audit problems must never
// break the proxy path).
func (s *Server) auditEvent(store *audit.Store, action string, detail map[string]string) {
	if store == nil {
		return
	}
	ev := model.AuditEvent{Action: action, Detail: detail}
	if err := store.Log(ev); err != nil {
		s.logger.Warn("审计写入失败", "action", action, "error", err)
	}
}

// bindProxyListeners opens the HTTP and SOCKS5 listeners.
func (s *Server) bindProxyListeners() error {
	if s.gateway == nil {
		return nil
	}
	wrap := func(ln net.Listener, label string) net.Listener {
		if !s.cfg.Server.ProxyProtocol {
			return ln
		}
		wrapped, err := proxyproto.NewListener(ln, 5*time.Second)
		if err != nil {
			s.logger.Warn("PROXY protocol listener wrapping failed, using plain TCP",
				"listener", label, "error", err)
			return ln
		}
		return wrapped
	}
	var errs []error
	if addr := s.cfg.Proxy.HTTPListen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("app: listen HTTP proxy %s: %w", addr, err))
		} else {
			s.gateway.httpLn = wrap(ln, "http")
		}
	}
	if addr := s.cfg.Proxy.SOCKS5Listen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("app: listen SOCKS5 %s: %w", addr, err))
		} else {
			s.gateway.socksLn = wrap(ln, "socks5")
		}
	}
	if s.cfg.Server.ProxyProtocol && s.gateway.httpLn != nil {
		s.logger.Info("PROXY protocol v2 已启用（HTTP/SOCKS5 入口与共享 TCP 监听）")
	}
	return errors.Join(errs...)
}

// serveProxy runs the proxy entry points until ctx is cancelled.
func (s *Server) serveProxy(ctx context.Context, errCh chan<- error) {
	if s.gateway == nil {
		return
	}
	if s.gateway.httpLn != nil {
		go func() {
			if err := s.gateway.httpProxy.Serve(ctx, s.gateway.httpLn); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("http proxy: %w", err)
			}
		}()
	}
	if s.gateway.socksLn != nil {
		go func() {
			if err := s.gateway.socksProxy.Serve(ctx, s.gateway.socksLn); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("socks5 proxy: %w", err)
			}
		}()
	}
}

// closeGateway stops proxy entry points and closes the credential stores.
func (s *Server) closeGateway(ctx context.Context) error {
	if s.gateway == nil {
		return nil
	}
	var errs []error
	if s.gateway.httpProxy != nil {
		if err := s.gateway.httpProxy.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.gateway.socksProxy != nil {
		if err := s.gateway.socksProxy.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.gateway.httpLn != nil {
		_ = s.gateway.httpLn.Close()
	}
	if s.gateway.socksLn != nil {
		_ = s.gateway.socksLn.Close()
	}
	if s.gateway.creds != nil {
		_ = s.gateway.creds.Close()
	}
	return errors.Join(errs...)
}

// ProxyAddrs returns the bound proxy entry addresses (empty when disabled).
func (s *Server) ProxyAddrs() (httpAddr, socksAddr string) {
	if s.gateway == nil {
		return "", ""
	}
	if s.gateway.httpLn != nil {
		httpAddr = s.gateway.httpLn.Addr().String()
	}
	if s.gateway.socksLn != nil {
		socksAddr = s.gateway.socksLn.Addr().String()
	}
	return
}

// ---- adapters between the proxy package interfaces and the concrete stores ----

type credentialAuthAdapter struct{ store *auth.CredentialStore }

func (a *credentialAuthAdapter) Verify(username, password string) (*model.Credential, error) {
	c, err := a.store.Verify(username, password)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

type candidateAdapter struct {
	reg    registryLister
	groups *groups.Store
}

type registryLister interface {
	List() []model.Node
}

func (a *candidateAdapter) Candidates(groupIDs []string) ([]*model.Node, error) {
	list := a.reg.List()
	visible := make([]*model.Node, 0, len(list))
	for i := range list {
		n := list[i]
		if !n.Enabled || !n.Online {
			continue
		}
		visible = append(visible, &n)
	}
	// Seed group membership so sticky-blacklist node-group matching works.
	return a.groups.Candidates(groupIDs, visible), nil
}

type selectorAdapter struct{ sel *sched.Selector }

func (a *selectorAdapter) Select(_ context.Context, req proxy.SelectRequest, candidates []*model.Node) (*model.Node, proxy.SelectionInfo, error) {
	filtered := candidates
	if len(req.Exclude) > 0 {
		excluded := make(map[string]bool, len(req.Exclude))
		for _, id := range req.Exclude {
			excluded[id] = true
		}
		filtered = make([]*model.Node, 0, len(candidates))
		for _, n := range candidates {
			if n != nil && !excluded[n.ID] {
				filtered = append(filtered, n)
			}
		}
	}
	node, dec, err := a.sel.Select(sched.Request{
		CredentialID: req.CredentialID,
		Username:     req.Username,
		SourceIP:     req.SourceIP,
		Protocol:     req.Protocol,
		Target:       req.Target,
	}, filtered)
	if err != nil {
		return nil, proxy.SelectionInfo{Reason: dec.Reason}, err
	}
	return node, proxy.SelectionInfo{
		Strategy:       dec.Strategy,
		StickyHit:      dec.StickyHit,
		StickyMigrated: dec.StickyMigrated,
		Blacklisted:    dec.Blacklisted,
		BlacklistRule:  dec.BlacklistRule,
		Reason:         dec.Reason,
	}, nil
}

func (a *selectorAdapter) RecordResult(nodeID string, err error) {
	a.sel.OnStreamResult(nodeID, err)
}

type aclAdapter struct{ engine *acl.Engine }

func (a *aclAdapter) Check(t model.RequestTarget) error { return a.engine.Check(t) }

// ForcedGroups is required by proxy.ACLGroupRouter. Without this method the
// proxy layer only sees ACLChecker and silently ignores route-action groups.
func (a *aclAdapter) ForcedGroups(t model.RequestTarget) ([]string, error) {
	return a.engine.ForcedGroups(t)
}

var _ proxy.ACLGroupRouter = (*aclAdapter)(nil)

type dialerAdapter struct {
	tun *tunnel.Server
	sel *sched.Selector
}

// OpenStream records the latency of successful stream opens for the fastest
// strategy; failures are recorded by the proxy layer exactly once.
func (a *dialerAdapter) OpenStream(ctx context.Context, nodeID string, req protocol.OpenRequest) (proxy.StreamConn, error) {
	start := time.Now()
	st, err := a.tun.DialStream(ctx, nodeID, req)
	if err != nil {
		return nil, err
	}
	a.sel.OnLatency(nodeID, time.Since(start))
	return st, nil
}

type limiterAdapter struct{ limiters *sched.Limiters }

func (a *limiterAdapter) Down(credentialID, nodeID string) proxy.ByteLimiter {
	return a.limiters.Down(credentialID, nodeID)
}

func (a *limiterAdapter) Up(credentialID, nodeID string) proxy.ByteLimiter {
	return a.limiters.Up(credentialID, nodeID)
}

// StickyPreview implements the panel preview endpoint.
func (s *Server) StickyPreview(target model.RequestTarget, sourceIP, nodeID string, nodeGroups []string) (ruleID string, hit bool) {
	if s.gateway == nil {
		return "", false
	}
	n := &model.Node{ID: nodeID, Groups: nodeGroups}
	return s.gateway.sched.StickyExplainSource(sourceIP, target, n, nodeGroups)
}

// ReloadRules recompiles ACL/scheduler rules after an operator change.
func (s *Server) ReloadRules() error {
	if s.gateway == nil {
		return nil
	}
	if err := s.gateway.acl.SetRules(s.gateway.rules.ACL()); err != nil {
		return err
	}
	if err := s.gateway.sched.SetStickyRules(s.gateway.rules.Sticky()); err != nil {
		return err
	}
	return nil
}

// ACLForcedDenies exposes the immutable default-deny list to the panel.
func (s *Server) ACLForcedDenies() []acl.ForcedRule {
	if s.gateway == nil {
		return nil
	}
	return s.gateway.acl.ForcedDenies()
}

// trim is a tiny helper to keep logs tidy.
func trim(s string) string { return strings.TrimSpace(s) }
