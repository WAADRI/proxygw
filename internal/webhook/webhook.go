// Package webhook delivers operational alerts (node offline, error rate spike,
// certificate or GeoIP expiry) to an operator configured HTTP endpoint.
//
// Sending never blocks the caller: alerts go through a bounded queue served by a
// single background worker that retries failed deliveries with exponential
// backoff and rate limits each alert name. When the queue is full, or an alert
// name exceeds its per-minute rate, the alert is dropped and counted instead of
// stalling the request path. Delivery statistics are exposed via Stats and
// optionally mirrored to Prometheus through Options.Metrics.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/metrics"
)

// Severity values used by the gateway alerts.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// result labels reported to the webhook_alerts_total metric.
const (
	resultSent    = "sent"
	resultDropped = "dropped"
	resultFailed  = "failed"
	resultRetried = "retried"
)

// Defaults applied by New when the corresponding option is zero.
const (
	DefaultTimeout    = 5 * time.Second
	DefaultMaxRetries = 2
	DefaultQueueSize  = 256
	// DefaultRatePerMin is the recommended per-alert-name delivery rate. It is
	// not applied implicitly because Options.RatePerMinute uses 0 to mean
	// "unlimited"; callers that want protection against alert storms pass it
	// explicitly.
	DefaultRatePerMin  = 30
	maxRateLimitKeys   = 256
	maxResponseDrain   = 4 << 10
	maxBackoff         = 5 * time.Second
	firstRetryBackoff  = 200 * time.Millisecond
	secondRetryBackoff = 500 * time.Millisecond
)

// errNoRedirects is returned for redirect responses. Following redirects would
// silently resend the alert to an unexpected host (and replay the POST body), so
// a misconfigured endpoint fails loudly instead.
var errNoRedirects = errors.New("webhook: redirects are not followed")

// Alert is one operator notification.
type Alert struct {
	Name     string            // e.g. node_offline / error_rate_spike / cert_expiring / geoip_expiring
	Severity string            // info | warning | critical
	Message  string            // human readable summary
	Time     time.Time         // event time; zero means "now"
	Detail   map[string]string // structured context (node_id, certificate, error, ...)
}

// Options configures a Sender. The zero value of every field selects the
// documented default except URL: an empty URL disables the sender (New still
// succeeds and Send becomes a no-op).
type Options struct {
	URL           string
	Timeout       time.Duration // per delivery attempt; default 5s
	MaxRetries    int           // retries after the first attempt; default 2 (3 attempts total)
	QueueSize     int           // bounded queue length; default 256
	RatePerMinute int           // max deliveries per alert name per minute; 0 = unlimited
	Logger        *slog.Logger

	// Metrics is optional (nil disables metric collection). When set, delivery
	// results are counted in webhook_alerts_total{result=...}.
	Metrics *metrics.Metrics
}

// Stats is a snapshot of the delivery counters. Sent counts alerts that were
// accepted by the endpoint (2xx); Failed counts alerts that exhausted every
// attempt; Dropped counts alerts rejected before delivery (full queue, rate
// limit or a closed sender); Retried counts individual retry attempts.
type Stats struct {
	Sent    uint64
	Dropped uint64
	Failed  uint64
	Retried uint64
}

// Sender queues and delivers alerts. It is safe for concurrent use.
type Sender struct {
	disabled      bool
	url           string
	timeout       time.Duration
	maxRetries    int
	ratePerMinute int
	logger        *slog.Logger
	metrics       *metrics.Metrics
	client        *http.Client

	ctx    context.Context
	cancel context.CancelFunc

	jobs      chan Alert
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	gate     sync.RWMutex
	shutdown bool

	sent    atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64
	retried atomic.Uint64

	rateMu sync.Mutex
	rate   map[string][]time.Time

	// now and backoff are injectable for tests.
	now     func() time.Time
	backoff func(retry int) time.Duration
}

// New validates opts and starts the delivery worker. An empty URL yields a
// disabled sender: New returns a non-nil Sender with no error, Send does
// nothing, and Close is a no-op. Invalid URLs (unsupported scheme, missing host)
// return an error.
func New(opts Options) (*Sender, error) {
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("webhook: timeout must not be negative (got %v)", opts.Timeout)
	}
	if opts.MaxRetries < 0 {
		return nil, fmt.Errorf("webhook: max_retries must not be negative (got %d)", opts.MaxRetries)
	}
	if opts.QueueSize < 0 {
		return nil, fmt.Errorf("webhook: queue_size must not be negative (got %d)", opts.QueueSize)
	}
	if opts.RatePerMinute < 0 {
		return nil, fmt.Errorf("webhook: rate_per_minute must not be negative (got %d)", opts.RatePerMinute)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Sender{
		url:           strings.TrimSpace(opts.URL),
		timeout:       opts.Timeout,
		maxRetries:    opts.MaxRetries,
		ratePerMinute: opts.RatePerMinute,
		logger:        logger,
		metrics:       opts.Metrics,
		rate:          make(map[string][]time.Time),
		now:           time.Now,
		backoff:       defaultBackoff,
	}
	if s.timeout == 0 {
		s.timeout = DefaultTimeout
	}
	if s.maxRetries == 0 {
		s.maxRetries = DefaultMaxRetries
	}
	if opts.QueueSize == 0 {
		s.jobs = make(chan Alert, DefaultQueueSize)
	} else {
		s.jobs = make(chan Alert, opts.QueueSize)
	}
	if s.url == "" {
		s.disabled = true
		s.logger.Debug("webhook: alert webhook disabled (no URL configured)")
		return s, nil
	}
	u, err := url.Parse(s.url)
	if err != nil {
		return nil, fmt.Errorf("webhook: invalid URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("webhook: unsupported URL scheme %q (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("webhook: URL has no host")
	}
	s.url = u.String()
	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return errNoRedirects },
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.quit = make(chan struct{})
	s.done = make(chan struct{})
	go s.worker()
	return s, nil
}

// Send queues an alert for delivery without blocking. The alert is dropped and
// counted when the queue is full, when its name exceeds the per-minute rate, or
// when the sender has been closed.
func (s *Sender) Send(a Alert) {
	if s == nil || s.disabled {
		return
	}
	a = s.prepare(a)
	if !s.allowRate(a.Name) {
		s.countDrop()
		return
	}
	s.gate.RLock()
	if s.shutdown {
		s.gate.RUnlock()
		s.countDrop()
		return
	}
	select {
	case s.jobs <- a:
		s.gate.RUnlock()
	default:
		s.gate.RUnlock()
		s.countDrop()
	}
}

// Sendf formats a message and queues it. It is a convenience wrapper around
// Send for the alert emitters.
func (s *Sender) Sendf(name, severity, format string, args ...any) {
	s.Send(Alert{Name: name, Severity: severity, Message: fmt.Sprintf(format, args...)})
}

// Stats returns a snapshot of the delivery counters.
func (s *Sender) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{
		Sent:    s.sent.Load(),
		Dropped: s.dropped.Load(),
		Failed:  s.failed.Load(),
		Retried: s.retried.Load(),
	}
}

// Close stops accepting alerts, drains the queue (delivering what is already
// queued) and stops the worker. Draining is bounded by 3*Timeout; if that
// expires the in-flight deliveries are canceled and the remaining queued alerts
// are counted as failed. Close is idempotent and safe to call concurrently.
func (s *Sender) Close() error {
	if s == nil || s.disabled || s.done == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.gate.Lock()
		s.shutdown = true
		s.gate.Unlock()
		close(s.quit)
	})
	limit := s.timeout * 3
	if limit <= 0 {
		limit = DefaultTimeout * 3
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-s.done:
		s.cancel()
		return nil
	case <-timer.C:
		// Abort whatever is in flight so the worker can finish draining.
		s.cancel()
		select {
		case <-s.done:
			return nil
		case <-time.After(2 * time.Second):
			return fmt.Errorf("webhook: close timed out after %v with pending deliveries", limit)
		}
	}
}

// prepare normalizes an alert and snapshots its detail map on the caller side so
// later mutation cannot race with the worker.
func (s *Sender) prepare(a Alert) Alert {
	if a.Time.IsZero() {
		a.Time = s.now()
	}
	a.Severity = normalizeSeverity(a.Severity)
	if a.Detail != nil {
		detail := make(map[string]string, len(a.Detail))
		for k, v := range a.Detail {
			detail[k] = v
		}
		a.Detail = detail
	}
	return a
}

// normalizeSeverity lowercases the severity and defaults it to info.
func normalizeSeverity(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	if severity == "" {
		return SeverityInfo
	}
	return severity
}

// allowRate implements the per-name sliding window rate limit. It reports
// whether the alert may be queued.
func (s *Sender) allowRate(name string) bool {
	if s.ratePerMinute <= 0 {
		return true
	}
	now := s.now()
	cutoff := now.Add(-time.Minute)
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	times := s.rate[name]
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= s.ratePerMinute {
		s.rate[name] = kept
		return false
	}
	if _, exists := s.rate[name]; !exists && len(s.rate) >= maxRateLimitKeys {
		// Bound memory if a caller keeps inventing alert names.
		return false
	}
	s.rate[name] = append(kept, now)
	return true
}

// countDrop records one dropped alert.
func (s *Sender) countDrop() {
	s.dropped.Add(1)
	s.countResult(resultDropped)
}

// countResult mirrors a delivery result into the optional metrics collector.
func (s *Sender) countResult(result string) {
	if s.metrics == nil || s.metrics.WebhookAlertsTotal == nil {
		return
	}
	s.metrics.WebhookAlertsTotal.WithLabelValues(result).Inc()
}

// worker is the single delivery goroutine.
func (s *Sender) worker() {
	defer close(s.done)
	for {
		select {
		case a := <-s.jobs:
			s.deliver(a)
		case <-s.quit:
			// Drain everything that was queued before Close. New Send calls
			// are rejected by the shutdown gate, so this terminates.
			for {
				select {
				case a := <-s.jobs:
					s.deliver(a)
				default:
					return
				}
			}
		}
	}
}

// payload is the JSON body POSTed to the configured endpoint.
type payload struct {
	Alert    string            `json:"alert"`
	Severity string            `json:"severity"`
	Message  string            `json:"message"`
	Time     time.Time         `json:"time"`
	Detail   map[string]string `json:"detail,omitempty"`
}

// deliver attempts one alert with retries. It never panics and never blocks the
// caller (it runs on the worker goroutine).
func (s *Sender) deliver(a Alert) {
	defer func() {
		if r := recover(); r != nil {
			s.failed.Add(1)
			s.countResult(resultFailed)
			s.logger.Error("webhook: panic while delivering alert", "alert", a.Name, "panic", fmt.Sprint(r))
		}
	}()
	body, err := json.Marshal(payload{
		Alert:    a.Name,
		Severity: a.Severity,
		Message:  a.Message,
		Time:     a.Time,
		Detail:   a.Detail,
	})
	if err != nil {
		s.failed.Add(1)
		s.countResult(resultFailed)
		s.logger.Warn("webhook: cannot encode alert", "alert", a.Name, "severity", a.Severity)
		return
	}
	attempts := s.maxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			s.retried.Add(1)
			s.countResult(resultRetried)
			if !sleepContext(s.ctx, s.backoffDelay(attempt-1)) {
				s.failed.Add(1)
				s.countResult(resultFailed)
				s.logger.Warn("webhook: alert delivery canceled by shutdown", "alert", a.Name)
				return
			}
		}
		status, reqErr := s.post(body)
		if reqErr == nil && status >= http.StatusOK && status < http.StatusMultipleChoices {
			s.sent.Add(1)
			s.countResult(resultSent)
			return
		}
		if attempt < attempts-1 {
			s.logger.Debug("webhook: alert attempt failed, retrying",
				"alert", a.Name, "severity", a.Severity, "attempt", attempt+1,
				"status", status, "reason", safeErrorReason(reqErr))
		}
	}
	s.failed.Add(1)
	s.countResult(resultFailed)
	s.logger.Warn("webhook: alert delivery failed",
		"alert", a.Name, "severity", a.Severity, "attempts", attempts)
}

// post performs one HTTP POST attempt and returns the status code. The response
// body is drained (bounded) so connections can be reused.
func (s *Sender) post(body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "proxygw-webhook/1")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseDrain))
	return resp.StatusCode, nil
}

// backoffDelay returns the wait before retry number retry (0-based).
func (s *Sender) backoffDelay(retry int) time.Duration {
	if s.backoff != nil {
		return s.backoff(retry)
	}
	return defaultBackoff(retry)
}

// defaultBackoff is 200ms then 500ms, doubling afterwards and capped at 5s.
func defaultBackoff(retry int) time.Duration {
	if retry <= 0 {
		return firstRetryBackoff
	}
	if retry == 1 {
		return secondRetryBackoff
	}
	d := secondRetryBackoff
	for i := 1; i < retry; i++ {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return d
}

// sleepContext waits for d, aborting early when ctx is done. It reports whether
// the full wait elapsed.
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// safeErrorReason renders an error for logs without leaking the webhook URL,
// which may contain a secret token in its query string. url.Error embeds the
// full URL, so it is unwrapped to its operation and inner network error.
func safeErrorReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + safeErrorReason(ue.Err)
	}
	return err.Error()
}
