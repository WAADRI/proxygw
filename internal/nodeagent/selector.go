package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/transport"
)

// transportSelector owns the QUIC <-> wss preference state machine of one
// agent: fallback after a QUIC handshake timeout, exponential QUIC backoff,
// background re-probe with hysteresis and the revert rule after switching back.
// It is shared by all planes so that the whole agent changes transport once.
type transportSelector struct {
	a *Agent

	mu                 sync.Mutex
	preferred          transport.Kind
	quicFailures       int
	quicNextTry        time.Time
	quicSuccessStreak  int
	lastQuicSwitch     time.Time
	lastFallbackReason string
	probing            bool
}

// current returns the preferred transport.
func (sel *transportSelector) current() transport.Kind {
	sel.mu.Lock()
	defer sel.mu.Unlock()
	return sel.preferred
}

// fallbackReason returns the most recent fallback explanation for Status.
func (sel *transportSelector) fallbackReason() string {
	sel.mu.Lock()
	defer sel.mu.Unlock()
	return sel.lastFallbackReason
}

// quicRetryDue reports whether the QUIC retry backoff has elapsed.
func (sel *transportSelector) quicRetryDue() bool {
	sel.mu.Lock()
	defer sel.mu.Unlock()
	if sel.quicNextTry.IsZero() {
		return false
	}
	return !time.Now().Before(sel.quicNextTry)
}

// probeDue reports whether the background QUIC re-probe should run now.
func (sel *transportSelector) probeDue() bool {
	return sel.quicRetryDue()
}

// startProbe acquires the single-flight probe guard.
func (sel *transportSelector) startProbe() bool {
	sel.mu.Lock()
	defer sel.mu.Unlock()
	if sel.probing {
		return false
	}
	sel.probing = true
	return true
}

func (sel *transportSelector) endProbe() {
	sel.mu.Lock()
	sel.probing = false
	sel.mu.Unlock()
}

// onQuicDialFailed records a failed QUIC dial (regular reconnect or initial
// fallback), engages the QUIC backoff and moves the preference to wss.
func (sel *transportSelector) onQuicDialFailed(err error) {
	now := time.Now()
	sel.mu.Lock()
	sel.quicFailures++
	sel.quicSuccessStreak = 0
	sel.preferred = transport.KindWS
	reverting := !sel.lastQuicSwitch.IsZero() && now.Sub(sel.lastQuicSwitch) < sel.a.timings.quicRevertWindow
	if reverting {
		// The switch happened moments ago: go back to wss and reset the backoff
		// so a flapping QUIC path cannot degrade service.
		sel.quicFailures = 0
		sel.quicNextTry = now.Add(sel.a.timings.reProbeInterval)
		sel.lastFallbackReason = "切回 QUIC 后短时间失败，已回退 wss 并重置退避"
	} else {
		sel.quicNextTry = now.Add(backoffDuration(sel.quicFailures, sel.a.timings.backoffBase, sel.a.timings.backoffMax))
		sel.lastFallbackReason = truncateMsg(fmt.Sprintf("QUIC 建连失败（%v），已回退 wss", err), 256)
	}
	reason := sel.lastFallbackReason
	retryAfter := time.Until(sel.quicNextTry)
	sel.mu.Unlock()
	sel.a.recordReconnect("quic_fallback")
	sel.a.log.Warn("QUIC 建连失败，自动回退 wss",
		"event", "transport.fallback",
		"reason", reason,
		"error", err,
		"retry_after_ms", retryAfter.Milliseconds())
}

// onWSEstablished schedules the background QUIC re-probe after a wss session
// has been registered: per the design attachment, re-probe starts 10 minutes
// after wss becomes the working transport.
func (sel *transportSelector) onWSEstablished() {
	next := time.Now().Add(sel.a.timings.reProbeInterval)
	sel.mu.Lock()
	sel.quicSuccessStreak = 0
	if sel.quicNextTry.IsZero() || sel.quicNextTry.Before(next) {
		sel.quicNextTry = next
	}
	sel.mu.Unlock()
}

// recordQuicSessionReady feeds a successful QUIC session establishment into the
// hysteresis counter. It returns true when the agent has switched its
// preference back to QUIC.
func (sel *transportSelector) recordQuicSessionReady() bool {
	now := time.Now()
	sel.mu.Lock()
	sel.quicFailures = 0
	if sel.preferred == transport.KindQUIC {
		sel.quicSuccessStreak = 0
		sel.mu.Unlock()
		return false
	}
	sel.quicSuccessStreak++
	if sel.quicSuccessStreak < quicSuccessThreshold {
		sel.quicNextTry = now.Add(sel.a.timings.quicConfirmInterval)
		sel.mu.Unlock()
		return false
	}
	sel.preferred = transport.KindQUIC
	sel.lastQuicSwitch = now
	sel.quicSuccessStreak = 0
	sel.quicNextTry = time.Time{}
	sel.mu.Unlock()
	return true
}

// recordQuicProbeFailure records a failed background re-probe.
func (sel *transportSelector) recordQuicProbeFailure(err error) {
	now := time.Now()
	sel.mu.Lock()
	sel.quicSuccessStreak = 0
	sel.quicFailures++
	sel.quicNextTry = now.Add(backoffDuration(sel.quicFailures, sel.a.timings.backoffBase, sel.a.timings.backoffMax))
	retryAfter := time.Until(sel.quicNextTry)
	sel.lastFallbackReason = truncateMsg(fmt.Sprintf("QUIC 重探失败（%v），继续使用 wss", err), 256)
	sel.mu.Unlock()
	sel.a.log.Warn("后台重探 QUIC 失败，继续使用 wss",
		"event", "transport.reprobe_failed",
		"error", err,
		"retry_after_ms", retryAfter.Milliseconds())
}

// recordQuicProbeSuccess records a successful background re-probe. It returns
// true when the hysteresis threshold was reached and the agent switched to QUIC.
func (sel *transportSelector) recordQuicProbeSuccess() bool {
	now := time.Now()
	sel.mu.Lock()
	sel.quicFailures = 0
	sel.quicSuccessStreak++
	if sel.quicSuccessStreak < quicSuccessThreshold {
		sel.quicNextTry = now.Add(sel.a.timings.quicConfirmInterval)
		streak := sel.quicSuccessStreak
		sel.mu.Unlock()
		sel.a.log.Info("后台重探 QUIC 成功，等待二次确认",
			"event", "transport.reprobe_ok",
			"streak", streak,
			"confirm_after_ms", sel.a.timings.quicConfirmInterval.Milliseconds())
		return false
	}
	sel.preferred = transport.KindQUIC
	sel.lastQuicSwitch = now
	sel.quicSuccessStreak = 0
	sel.quicNextTry = time.Time{}
	sel.mu.Unlock()
	return true
}

// onSessionReady is called after a session finished registration.
func (sel *transportSelector) onSessionReady(kind transport.Kind) {
	switch kind {
	case transport.KindWS:
		sel.onWSEstablished()
	case transport.KindQUIC:
		if sel.recordQuicSessionReady() {
			sel.a.recordReconnect("quic_switch_back")
			sel.a.log.Info("QUIC 已连续建连成功，切回主用传输", "event", "transport.switch_back", "transport", "quic")
			// Other planes may still be on wss: migrate them with a stagger.
			sel.a.migrateToQUIC()
		}
	}
}

// onSessionEnd inspects a closed session and may revert the preference when a
// freshly switched QUIC session dies inside the revert window.
func (sel *transportSelector) onSessionEnd(kind transport.Kind) {
	if kind != transport.KindQUIC {
		return
	}
	now := time.Now()
	sel.mu.Lock()
	revert := sel.preferred == transport.KindQUIC &&
		!sel.lastQuicSwitch.IsZero() &&
		now.Sub(sel.lastQuicSwitch) < sel.a.timings.quicRevertWindow
	if revert {
		sel.preferred = transport.KindWS
		sel.quicFailures = 0
		sel.quicSuccessStreak = 0
		sel.quicNextTry = now.Add(sel.a.timings.reProbeInterval)
		sel.lastFallbackReason = "切回 QUIC 后短时间内会话失败，已回退 wss 并重置退避"
	}
	sel.mu.Unlock()
	if revert {
		sel.a.recordReconnect("quic_revert")
		sel.a.log.Warn("切回 QUIC 后短时间内会话失败，回退 wss 并重置退避",
			"event", "transport.revert",
			"window_ms", sel.a.timings.quicRevertWindow.Milliseconds())
	}
}

// dialTransport performs one transport dial according to the configured mode,
// the QUIC fallback budget and the selector state.
func (a *Agent) dialTransport(ctx context.Context, planeIndex int) (transport.Conn, transport.Kind, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	switch a.cfg.Transport {
	case model.TransportQUIC:
		conn, err := a.dialQUIC(ctx, a.timings.handshakeTimeout)
		if err != nil {
			return nil, transport.KindQUIC, err
		}
		return conn, connKind(conn, transport.KindQUIC), nil
	case model.TransportWS:
		conn, err := a.dialWS(ctx, a.timings.handshakeTimeout)
		if err != nil {
			return nil, transport.KindWS, err
		}
		return conn, connKind(conn, transport.KindWS), nil
	case model.TransportAuto:
		var quicErr error
		tryQUIC := a.sel.current() == transport.KindQUIC || a.sel.quicRetryDue()
		if tryQUIC && a.opts.QUICDial != nil {
			conn, err := a.dialQUIC(ctx, a.timings.fallbackTimeout)
			if err == nil {
				return conn, connKind(conn, transport.KindQUIC), nil
			}
			if a.isFatal(err) {
				return nil, transport.KindQUIC, fatalWrap("QUIC 建连致命错误", err)
			}
			quicErr = err
			a.sel.onQuicDialFailed(err)
		}
		if a.opts.WSDial == nil {
			if quicErr != nil {
				return nil, transport.KindQUIC, quicErr
			}
			return nil, transport.KindWS, errors.New("nodeagent: wss 拨号器不可用")
		}
		conn, err := a.dialWS(ctx, a.timings.handshakeTimeout)
		if err != nil {
			if a.isFatal(err) {
				return nil, transport.KindWS, fatalWrap("wss 建连致命错误", err)
			}
			if quicErr != nil {
				return nil, transport.KindWS, fmt.Errorf("QUIC 与 wss 均建连失败: QUIC: %v; wss: %w", quicErr, err)
			}
			return nil, transport.KindWS, fmt.Errorf("wss 建连失败: %w", err)
		}
		a.sel.onWSEstablished()
		return conn, connKind(conn, transport.KindWS), nil
	}
	return nil, "", fmt.Errorf("nodeagent: 不支持的 transport 模式 %q", a.cfg.Transport)
}

// dialQUIC runs the injected QUIC dialer with the given handshake budget.
func (a *Agent) dialQUIC(ctx context.Context, timeout time.Duration) (transport.Conn, error) {
	if a.opts.QUICDial == nil {
		return nil, errors.New("nodeagent: QUIC 拨号器不可用")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := a.opts.QUICDial(cctx)
	if err != nil {
		if cctx.Err() != nil {
			return nil, fmt.Errorf("QUIC 建连超时（%s）: %w", timeout, cctx.Err())
		}
		return nil, err
	}
	if conn == nil {
		return nil, errNilConn
	}
	return conn, nil
}

// dialWS runs the injected WebSocket dialer with the handshake budget.
func (a *Agent) dialWS(ctx context.Context, timeout time.Duration) (transport.Conn, error) {
	if a.opts.WSDial == nil {
		return nil, errors.New("nodeagent: wss 拨号器不可用")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := a.opts.WSDial(cctx)
	if err != nil {
		if cctx.Err() != nil {
			return nil, fmt.Errorf("wss 握手超时（%s）: %w", timeout, cctx.Err())
		}
		return nil, err
	}
	if conn == nil {
		return nil, errNilConn
	}
	return conn, nil
}

func connKind(conn transport.Conn, fallback transport.Kind) transport.Kind {
	if conn == nil {
		return fallback
	}
	if k := conn.Kind(); k != "" {
		return k
	}
	return fallback
}

// probeLoop periodically re-probes QUIC while the agent is healthy on wss.
func (a *Agent) probeLoop(ctx context.Context) {
	defer a.wg.Done()
	tick := a.timings.probeTick
	if tick <= 0 {
		tick = time.Second
	}
	timer := time.NewTimer(tick)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			a.maybeProbeQUIC(ctx)
			timer.Reset(tick)
		}
	}
}

// maybeProbeQUIC performs at most one background probe per call.
func (a *Agent) maybeProbeQUIC(ctx context.Context) {
	if a.readyCount.Load() == 0 {
		return
	}
	if a.sel.current() != transport.KindWS {
		return
	}
	if !a.sel.probeDue() {
		return
	}
	if !a.sel.startProbe() {
		return
	}
	defer a.sel.endProbe()

	conn, err := a.dialQUIC(ctx, a.timings.handshakeTimeout)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if a.isFatal(err) {
			a.reportFatal(fatalWrap("QUIC 重探致命错误", err))
			return
		}
		a.sel.recordQuicProbeFailure(err)
		return
	}
	// The probe connection is a pure reachability check: close it immediately
	// and let the migration re-dial through the normal path (HELLO included).
	_ = conn.CloseWithError(closeCodeGraceful, "probe_ok")
	if a.sel.recordQuicProbeSuccess() {
		a.recordReconnect("quic_probe_ok")
		a.log.Info("后台重探 QUIC 成功，切回主用传输", "event", "transport.switch_back", "transport", "quic")
		a.migrateToQUIC()
	}
}

// migrateToQUIC asks wss planes to re-dial so they migrate to QUIC. Planes are
// staggered to avoid a moment where every plane is reconnecting at once.
func (a *Agent) migrateToQUIC() {
	ctx := a.runContext()
	if ctx == nil {
		return
	}
	for i, p := range a.planes {
		if i > 0 {
			if !sleepCtx(ctx, migrateStagger) {
				return
			}
		}
		if !p.isReadyWS() {
			continue
		}
		a.log.Info("迁移平面到 QUIC", "event", "transport.migrate", "plane_index", p.index)
		p.requestRedial("transport_switch")
	}
}

// runContext returns the running context, or nil when the agent is not running.
func (a *Agent) runContext() context.Context {
	a.cancelMu.Lock()
	defer a.cancelMu.Unlock()
	return a.runCtx
}
