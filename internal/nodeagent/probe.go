package nodeagent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"proxygw/internal/protocol"
)

// startProbe executes a panel dial test asynchronously so the control loop keeps
// answering heartbeats. Concurrency is bounded; a busy node rejects extra probes
// instead of queueing them.
func (s *session) startProbe(p protocol.Probe) {
	select {
	case s.a.probeSem <- struct{}{}:
	default:
		s.sendProbeResult(protocol.ProbeResult{
			ID:    p.ID,
			OK:    false,
			Error: "节点拨测并发已满，请稍后重试",
		})
		return
	}
	go func() {
		defer func() { <-s.a.probeSem }()
		s.handlers.Add(1)
		defer s.handlers.Add(-1)
		res := s.a.runProbe(s.ctx, p)
		s.sendProbeResult(res)
	}()
}

func (s *session) sendProbeResult(res protocol.ProbeResult) {
	payload, err := protocol.Marshal(res)
	if err != nil {
		s.log.Warn("编码 PROBE_RESULT 失败", "event", "probe.encode_fail", "error", err)
		return
	}
	if err := s.sendControl(protocol.FrameProbeRes, payload); err != nil {
		s.log.Debug("回传 PROBE_RESULT 失败", "event", "probe.result_fail", "error", err)
	}
}

// runProbe executes one probe. It never panics: the caller always receives a
// result carrying the original probe ID.
func (a *Agent) runProbe(ctx context.Context, p protocol.Probe) (res protocol.ProbeResult) {
	res.ID = p.ID
	defer func() {
		if r := recover(); r != nil {
			res.OK = false
			res.Error = fmt.Sprintf("拨测执行 panic: %v", r)
			res.Result = nil
			a.log.Error("拨测执行发生 panic，已捕获", "event", "probe.panic", "kind", p.Kind, "panic", fmt.Sprint(r))
		}
	}()
	switch p.Kind {
	case protocol.ProbePing:
		res.OK = true
		res.LatencyMS = a.latencyMS()
		res.Detail = "pong"
	case protocol.ProbeTCPing:
		start := time.Now()
		dctx, cancel := context.WithTimeout(ctx, probeTimeout)
		conn, err := a.probeDialer.DialContext(dctx, "tcp", p.Target)
		cancel()
		if err != nil {
			res.Error = fmt.Sprintf("TCP 连接失败: %v", err)
			return res
		}
		_ = conn.Close()
		res.OK = true
		res.LatencyMS = msSince(start)
		res.Detail = "tcp_connect_ok"
	case protocol.ProbeHTTP:
		start := time.Now()
		target := p.Target
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		hctx, cancel := context.WithTimeout(ctx, probeTimeout)
		req, err := http.NewRequestWithContext(hctx, http.MethodGet, target, nil)
		if err != nil {
			cancel()
			res.Error = fmt.Sprintf("构造 HTTP 请求失败: %v", err)
			return res
		}
		req.Header.Set("User-Agent", "proxygw-node-probe/1")
		resp, err := a.probeClient.Do(req)
		if err != nil {
			cancel()
			res.Error = fmt.Sprintf("HTTP GET 失败: %v", err)
			return res
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
		_ = resp.Body.Close()
		cancel()
		res.OK = true
		res.LatencyMS = msSince(start)
		res.Detail = fmt.Sprintf("status=%d", resp.StatusCode)
	case protocol.ProbeDNS:
		res = a.probeDNS(ctx, p, res, time.Now())
	default:
		res.Error = fmt.Sprintf("不支持的拨测类型 %q", p.Kind)
	}
	return res
}

// probeDNS forwards one UDP/53 query and returns the response (<= 4 KiB), as
// required by the DNS passthrough feature (main spec E.15).
func (a *Agent) probeDNS(ctx context.Context, p protocol.Probe, res protocol.ProbeResult, start time.Time) protocol.ProbeResult {
	if len(p.Payload) == 0 {
		res.Error = "DNS 探测缺少查询报文"
		a.recordDNSProbe("error")
		return res
	}
	if p.Target == "" {
		res.Error = "DNS 探测缺少目标 ip:53"
		a.recordDNSProbe("error")
		return res
	}
	dctx, cancel := context.WithTimeout(ctx, probeDNSTimeout)
	defer cancel()
	conn, err := a.probeDialer.DialContext(dctx, "udp", p.Target)
	if err != nil {
		res.Error = fmt.Sprintf("DNS 连接失败: %v", err)
		a.recordDNSProbe("error")
		return res
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(probeDNSTimeout))
	if _, err := conn.Write(p.Payload); err != nil {
		res.Error = fmt.Sprintf("DNS 查询发送失败: %v", err)
		a.recordDNSProbe("error")
		return res
	}
	buf := make([]byte, probeDNSMaxResponse+1)
	n, err := conn.Read(buf)
	if err != nil {
		res.Error = fmt.Sprintf("DNS 查询失败: %v", err)
		a.recordDNSProbe("error")
		return res
	}
	if n <= 0 {
		res.Error = "DNS 响应为空"
		a.recordDNSProbe("error")
		return res
	}
	if n > probeDNSMaxResponse {
		res.Error = fmt.Sprintf("DNS 响应超过 %d 字节上限", probeDNSMaxResponse)
		a.recordDNSProbe("too_large")
		return res
	}
	res.OK = true
	res.LatencyMS = msSince(start)
	res.Result = append([]byte(nil), buf[:n]...)
	res.Detail = fmt.Sprintf("dns_response_bytes=%d", n)
	a.recordDNSProbe("ok")
	return res
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}
