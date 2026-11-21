package nodeagent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"proxygw/internal/fsm"
	"proxygw/internal/transport"
)

// plane is one transport connection slot. Every plane runs its own dial loop:
// a failure on one plane only reconnects that plane, the other planes keep
// serving. The agent-wide retry gate is only engaged when all planes are down.
type plane struct {
	index    int
	log      *slog.Logger
	redialCh chan string

	mu    sync.Mutex
	ready bool
	kind  transport.Kind
	retry int
	// attempt counts failed transport sessions, used for log rate limiting.
	attempt int
}

func (p *plane) setReady(kind transport.Kind) {
	p.mu.Lock()
	p.ready = true
	p.kind = kind
	p.retry = 0
	p.mu.Unlock()
}

func (p *plane) clearReady() {
	p.mu.Lock()
	p.ready = false
	p.kind = ""
	p.mu.Unlock()
}

func (p *plane) isReadyWS() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready && p.kind == transport.KindWS
}

// requestRedial interrupts a healthy session so the plane re-dials with the new
// transport preference. Non-blocking: if a redial is already pending it is
// coalesced.
func (p *plane) requestRedial(reason string) {
	select {
	case p.redialCh <- reason:
	default:
	}
}

// sessionEnd describes how one connection attempt ended.
type sessionEnd struct {
	err           error
	kind          transport.Kind
	fatal         bool
	graceful      bool
	kicked        bool
	kickReason    string
	probe         bool
	cooldownDelay time.Duration
}

// runPlane is the reconnect loop of one plane.
func (a *Agent) runPlane(ctx context.Context, p *plane) {
	defer a.wg.Done()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		// While all planes are down the retry gate enforces the
		// 1m/2m/4m/8m/10m backoff; when another plane is ready it returns
		// immediately so a single plane recovers on its own cadence.
		if err := a.gate.wait(ctx); err != nil {
			return
		}
		end := a.runSession(ctx, p)
		if ctx.Err() != nil {
			return
		}
		switch {
		case end.fatal:
			a.reportFatal(end.err)
			return
		case end.cooldownDelay > 0:
			a.recordReconnect("takeover_cooldown")
			p.log.Warn("服务端要求接管冷却，等待后重连",
				"event", "conn.cooldown",
				"delay_ms", end.cooldownDelay.Milliseconds(),
				"transport", string(end.kind),
				"plane_index", p.index)
			if !sleepCtx(ctx, end.cooldownDelay) {
				return
			}
			continue
		case end.graceful:
			return
		case end.probe:
			// Forced re-dial for transport migration: reconnect immediately with
			// the new preference and without touching the backoff.
			continue
		}
		if end.kicked {
			delay := a.kickRetryDelay(end.kickReason)
			a.recordReconnect("kick_" + end.kickReason)
			p.log.Warn("被服务端踢下线，稍后重连",
				"event", "kick.retry",
				"reason", end.kickReason,
				"delay_ms", delay.Milliseconds(),
				"transport", string(end.kind),
				"plane_index", p.index)
			if !sleepCtx(ctx, delay) {
				return
			}
			continue
		}
		// Transport level failure.
		p.attempt++
		a.recordReconnect("transport_error")
		if a.readyCount.Load() == 0 {
			a.gate.fail(a.timings.backoffBase, a.timings.backoffMax)
			wait := a.gateRemaining()
			if p.attempt <= 2 || p.attempt%10 == 0 {
				p.log.Warn("全部传输平面不可用，按退避重连",
					"event", "conn.retry",
					"attempt", p.attempt,
					"retry_after_ms", wait.Milliseconds(),
					"transport", string(end.kind),
					"error", end.err)
			} else {
				p.log.Debug("全部传输平面不可用，按退避重连",
					"event", "conn.retry",
					"attempt", p.attempt,
					"retry_after_ms", wait.Milliseconds(),
					"error", end.err)
			}
			continue
		}
		delay := a.planeRetryDelay(p)
		p.log.Debug("单平面掉线，独立重连，其余平面继续服务",
			"event", "conn.plane_retry",
			"attempt", p.attempt,
			"delay_ms", delay.Milliseconds(),
			"transport", string(end.kind),
			"error", end.err)
		if !sleepCtx(ctx, delay) {
			return
		}
	}
}

// runSession dials, registers and serves exactly one transport session.
func (a *Agent) runSession(ctx context.Context, p *plane) sessionEnd {
	start := time.Now()
	var machine *fsm.SessionFSM
	machine = fsm.NewSessionFSM(fsm.SessionDialing, func(from, to fsm.SessionState, event fsm.SessionEvent) {
		p.log.Info("会话状态迁移",
			"event", "session.state",
			"from", string(from),
			"to", string(to),
			"reason", string(event),
			"duration_ms", time.Since(start).Milliseconds(),
			"plane_index", p.index)
	})
	fire := func(ev fsm.SessionEvent) {
		if _, err := machine.Fire(ev); err != nil {
			p.log.Debug("会话状态迁移被拒绝",
				"event", "session.state_rejected",
				"event_name", string(ev),
				"error", err)
		}
	}

	dialStart := time.Now()
	conn, kind, err := a.dialTransport(ctx, p.index)
	a.noteLatency(time.Since(dialStart))
	if err != nil {
		fire(fsm.SessEvTransportErr)
		if ctx.Err() != nil {
			return sessionEnd{err: ctx.Err(), kind: kind}
		}
		if a.isFatal(err) {
			return sessionEnd{err: fatalWrap("传输建连失败", err), kind: kind, fatal: true}
		}
		a.setLastError(err)
		if p.attempt == 0 || p.attempt%10 == 9 {
			p.log.Warn("传输建连失败",
				"event", "conn.dial_fail",
				"transport", string(kind),
				"duration_ms", time.Since(dialStart).Milliseconds(),
				"error", err)
		} else {
			p.log.Debug("传输建连失败",
				"event", "conn.dial_fail",
				"transport", string(kind),
				"duration_ms", time.Since(dialStart).Milliseconds(),
				"error", err)
		}
		return sessionEnd{err: err, kind: kind}
	}
	fire(fsm.SessEvConnected)
	p.log.Info("传输连接已建立",
		"event", "conn.dial_ok",
		"transport", string(kind),
		"duration_ms", time.Since(dialStart).Milliseconds(),
		"remote_addr", remoteAddrString(conn))

	s := newSession(a, p, conn, kind, machine)
	a.registerSession(s)
	defer a.unregisterSession(s)

	if helloErr := s.hello(ctx); helloErr != nil {
		fire(fsm.SessEvHelloFail)
		s.shutdown(closeCodeError, "hello_failed")
		waitGroupTimeout(&s.loopWG, time.Second)
		if a.isFatal(helloErr) {
			return sessionEnd{err: fatalWrap("HELLO 注册致命失败", helloErr), kind: kind, fatal: true}
		}
		var cd *cooldownError
		if errors.As(helloErr, &cd) {
			a.setLastError(helloErr)
			return sessionEnd{err: helloErr, kind: kind, cooldownDelay: cd.Delay}
		}
		a.setLastError(helloErr)
		p.log.Warn("HELLO 注册失败",
			"event", "conn.hello_fail",
			"transport", string(kind),
			"error", helloErr)
		return sessionEnd{err: helloErr, kind: kind}
	}

	a.sessionReady(s)
	end := s.serve(ctx)
	a.sessionClosed(s, end.err)
	a.sel.onSessionEnd(kind)
	return end
}

// gateRemaining returns the time left in the current reconnect backoff window.
func (a *Agent) gateRemaining() time.Duration {
	a.gate.mu.Lock()
	defer a.gate.mu.Unlock()
	d := time.Until(a.gate.nextAt)
	if d < 0 {
		return 0
	}
	return d
}

func remoteAddrString(conn transport.Conn) string {
	if conn == nil {
		return ""
	}
	return addrStringSafe(conn.RemoteAddr())
}

func addrStringSafe(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

var errSessionClosed = errors.New("nodeagent: 会话已关闭")
