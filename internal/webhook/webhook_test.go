package webhook

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/metrics"
)

// recordedAlert mirrors the JSON payload the webhook endpoint receives.
type recordedAlert struct {
	Alert    string            `json:"alert"`
	Severity string            `json:"severity"`
	Message  string            `json:"message"`
	Time     time.Time         `json:"time"`
	Detail   map[string]string `json:"detail"`
}

// newTestSender builds a Sender with a fast backoff so retry tests do not sleep
// for the production 200ms/500ms delays, and with a quiet logger so failure
// tests do not spam the test output.
func newTestSender(t *testing.T, rawURL string, mutate func(*Options)) *Sender {
	t.Helper()
	opts := Options{
		URL:       rawURL,
		Timeout:   time.Second,
		QueueSize: 64,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.backoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// waitForStats polls Stats until cond is true or the timeout expires.
func waitForStats(t *testing.T, s *Sender, timeout time.Duration, cond func(Stats) bool) Stats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st := s.Stats()
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("stats condition not met within %v (stats = %+v)", timeout, st)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{"bad scheme", Options{URL: "ftp://example.com/hook"}},
		{"no host", Options{URL: "http://"}},
		{"no scheme", Options{URL: "example.com/hook"}},
		{"unparsable", Options{URL: "://bad-url"}},
		{"negative timeout", Options{URL: "http://example.com/hook", Timeout: -time.Second}},
		{"negative retries", Options{URL: "http://example.com/hook", MaxRetries: -1}},
		{"negative queue", Options{URL: "http://example.com/hook", QueueSize: -1}},
		{"negative rate", Options{URL: "http://example.com/hook", RatePerMinute: -1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if s, err := New(tc.opts); err == nil {
				_ = s.Close()
				t.Fatalf("New(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestDisabledSender(t *testing.T) {
	s, err := New(Options{})
	if err != nil {
		t.Fatalf("New(disabled): %v", err)
	}
	if s == nil {
		t.Fatal("New(disabled) = nil sender")
	}
	// These must be no-ops that never panic.
	s.Send(Alert{Name: "node_offline", Severity: SeverityWarning, Message: "boom"})
	s.Sendf("node_offline", SeverityCritical, "node %s offline", "n1")
	if got := s.Stats(); got != (Stats{}) {
		t.Errorf("Stats() = %+v, want zero", got)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close() = %v, want nil", err)
	}
}

func TestSendSuccess(t *testing.T) {
	var (
		mu      sync.Mutex
		got     recordedAlert
		gotCT   string
		gotMeth string
		calls   int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls++
		gotCT = r.Header.Get("Content-Type")
		gotMeth = r.Method
		_ = json.Unmarshal(body, &got)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, nil)
	before := time.Now()
	s.Send(Alert{
		Name:     "node_offline",
		Severity: SeverityWarning,
		Message:  "node n1 went offline",
		Detail:   map[string]string{"node_id": "n1", "reason": "heartbeat timeout"},
	})
	st := waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Sent == 1 })

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("endpoint calls = %d, want 1", calls)
	}
	if gotMeth != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMeth)
	}
	if !strings.HasPrefix(gotCT, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if got.Alert != "node_offline" || got.Severity != SeverityWarning || got.Message != "node n1 went offline" {
		t.Errorf("payload = %+v", got)
	}
	if got.Detail["node_id"] != "n1" || got.Detail["reason"] != "heartbeat timeout" {
		t.Errorf("detail = %v", got.Detail)
	}
	if got.Time.IsZero() || got.Time.Before(before.Add(-time.Minute)) {
		t.Errorf("time = %v, want a recent timestamp", got.Time)
	}
	if st.Failed != 0 || st.Retried != 0 || st.Dropped != 0 {
		t.Errorf("stats = %+v, want only Sent=1", st)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, func(o *Options) { o.MaxRetries = 2 })
	s.Send(Alert{Name: "error_rate_spike", Severity: SeverityCritical, Message: "error rate above threshold"})
	st := waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Sent == 1 })

	if st.Retried != 2 {
		t.Errorf("Retried = %d, want 2", st.Retried)
	}
	if st.Failed != 0 {
		t.Errorf("Failed = %d, want 0", st.Failed)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("endpoint calls = %d, want 3", got)
	}
}

func TestRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, func(o *Options) { o.MaxRetries = 2 })
	s.Send(Alert{Name: "geoip_expiring", Severity: SeverityWarning, Message: "GeoIP db expires in 3 days"})
	st := waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Failed == 1 })

	if st.Sent != 0 {
		t.Errorf("Sent = %d, want 0", st.Sent)
	}
	if st.Retried != 2 {
		t.Errorf("Retried = %d, want 2", st.Retried)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("endpoint calls = %d, want 3", got)
	}
}

func TestDeliveryTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never answer before the client timeout; unblock when the client has
		// gone away so the test server can close promptly.
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, func(o *Options) {
		o.Timeout = 25 * time.Millisecond
		o.MaxRetries = 2
	})
	s.Send(Alert{Name: "cert_expiring", Severity: SeverityWarning, Message: "certificate expires in 7 days"})
	st := waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Failed == 1 })

	if st.Retried != 2 {
		t.Errorf("Retried = %d, want 2", st.Retried)
	}
}

func TestSendDoesNotBlockWhenQueueIsFull(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer releaseFn()

	s := newTestSender(t, srv.URL, func(o *Options) {
		o.QueueSize = 2
		o.Timeout = 5 * time.Second
	})
	start := time.Now()
	for i := 0; i < 200; i++ {
		s.Send(Alert{Name: "node_offline", Severity: SeverityInfo, Message: "node offline"})
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("200 Send calls took %v, want non-blocking behaviour", elapsed)
	}
	if st := s.Stats(); st.Dropped < 100 {
		t.Errorf("Dropped = %d, want many drops with a full queue", st.Dropped)
	}
	// Unblock the endpoint: the worker delivers the alerts that fit. The queue
	// holds at most QueueSize alerts while the worker is blocked, so at least
	// that many must eventually be delivered.
	releaseFn()
	waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Sent >= 2 })
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, func(o *Options) {
		o.RatePerMinute = 2
		o.QueueSize = 32
	})
	for i := 0; i < 5; i++ {
		s.Send(Alert{Name: "node_offline", Severity: SeverityWarning, Message: "flapping"})
	}
	s.Send(Alert{Name: "cert_expiring", Severity: SeverityWarning, Message: "other alert type"})
	// The rate limiter rejects synchronously, so the drops are visible before
	// the worker has had time to deliver anything.
	if st := s.Stats(); st.Dropped != 3 {
		t.Errorf("Dropped immediately after Send = %d, want 3", st.Dropped)
	}
	st := waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Sent == 3 })
	if st.Failed != 0 {
		t.Errorf("Failed = %d, want 0", st.Failed)
	}
}

func TestRateLimitZeroIsUnlimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, func(o *Options) {
		o.RatePerMinute = 0 // unlimited per the Options contract
		o.QueueSize = 64
	})
	for i := 0; i < 40; i++ {
		s.Send(Alert{Name: "node_offline", Severity: SeverityInfo, Message: "burst"})
	}
	st := waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Sent == 40 })
	if st.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0 with unlimited rate", st.Dropped)
	}
}

func TestCloseDrainsAndSendAfterCloseIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, nil)
	for i := 0; i < 5; i++ {
		s.Send(Alert{Name: "node_offline", Severity: SeverityInfo, Message: "drain me"})
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.Stats().Sent; got != 5 {
		t.Errorf("Sent after Close = %d, want 5 (queue must drain)", got)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}

	before := s.Stats().Dropped
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Send after Close panicked: %v", r)
			}
		}()
		s.Send(Alert{Name: "node_offline", Severity: SeverityInfo})
		s.Sendf("node_offline", SeverityInfo, "still safe")
	}()
	if got := s.Stats().Dropped; got != before+2 {
		t.Errorf("Dropped after closed Send = %d, want %d", got, before+2)
	}
}

func TestConcurrentSendAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, func(o *Options) {
		o.QueueSize = 512
		o.MaxRetries = 1
	})
	const (
		goroutines = 8
		perRoutine = 25
	)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perRoutine; i++ {
				s.Send(Alert{Name: "error_rate_spike", Severity: SeverityWarning, Message: "concurrent"})
			}
		}()
	}
	time.Sleep(time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	st := s.Stats()
	total := st.Sent + st.Failed + st.Dropped
	if want := uint64(goroutines * perRoutine); total != want {
		t.Errorf("Sent+Failed+Dropped = %d, want %d (no alert may vanish)", total, want)
	}
}

func TestDetailMapIsSnapshotted(t *testing.T) {
	got := make(chan recordedAlert, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var a recordedAlert
		_ = json.Unmarshal(body, &a)
		got <- a
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSender(t, srv.URL, nil)
	detail := map[string]string{"node_id": "n1"}
	s.Send(Alert{Name: "node_offline", Severity: SeverityInfo, Message: "snapshot", Detail: detail})
	detail["node_id"] = "mutated" // must not race with the worker's encoding
	detail["extra"] = "injected"

	select {
	case a := <-got:
		if a.Detail["node_id"] != "n1" || a.Detail["extra"] != "" {
			t.Errorf("detail = %v, want the snapshot taken at Send time", a.Detail)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("alert was not delivered")
	}
}

func TestMetricsResults(t *testing.T) {
	m := metrics.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := New(Options{URL: srv.URL, Timeout: time.Second, Metrics: m})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()
	s.Send(Alert{Name: "node_offline", Severity: SeverityWarning, Message: "metric test"})
	waitForStats(t, s, 5*time.Second, func(st Stats) bool { return st.Sent == 1 })

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, family := range families {
		if family.GetName() != "webhook_alerts_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			label := ""
			for _, l := range metric.GetLabel() {
				if l.GetName() == "result" {
					label = l.GetValue()
				}
			}
			if label == resultSent && metric.GetCounter().GetValue() >= 1 {
				found = true
			}
		}
	}
	if !found {
		t.Error("webhook_alerts_total{result=\"sent\"} was not incremented")
	}
}

func TestDefaultBackoff(t *testing.T) {
	if got := defaultBackoff(0); got != 200*time.Millisecond {
		t.Errorf("defaultBackoff(0) = %v, want 200ms", got)
	}
	if got := defaultBackoff(1); got != 500*time.Millisecond {
		t.Errorf("defaultBackoff(1) = %v, want 500ms", got)
	}
	if got := defaultBackoff(2); got != time.Second {
		t.Errorf("defaultBackoff(2) = %v, want 1s", got)
	}
	if got := defaultBackoff(10); got != 5*time.Second {
		t.Errorf("defaultBackoff(10) = %v, want capped 5s", got)
	}
}

func TestSafeErrorReasonHidesURL(t *testing.T) {
	ue := &url.Error{
		Op:  "Post",
		URL: "https://alerts.example.com/hook?token=super-secret-token",
		Err: errors.New("dial tcp 203.0.113.9:443: connect: connection refused"),
	}
	reason := safeErrorReason(ue)
	if strings.Contains(reason, "super-secret-token") || strings.Contains(reason, "alerts.example.com") {
		t.Errorf("safeErrorReason leaked the webhook URL: %q", reason)
	}
	if !strings.Contains(reason, "dial tcp") {
		t.Errorf("safeErrorReason = %q, want the network error to remain", reason)
	}
	if got := safeErrorReason(nil); got != "" {
		t.Errorf("safeErrorReason(nil) = %q, want empty", got)
	}
}

func TestCloseWithBlockedEndpointReturns(t *testing.T) {
	// An endpoint that hangs forever must not make Close hang forever: the
	// bounded drain cancels the in-flight request.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)

	s := newTestSender(t, srv.URL, func(o *Options) {
		o.Timeout = 100 * time.Millisecond
	})
	s.backoff = func(int) time.Duration { return time.Millisecond }
	s.Send(Alert{Name: "node_offline", Severity: SeverityInfo, Message: "hang"})
	time.Sleep(10 * time.Millisecond) // let the worker pick the job up
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Close took %v, want bounded drain", elapsed)
	}
	if got := s.Stats().Failed; got != 1 {
		t.Errorf("Failed = %d, want 1 after canceled delivery", got)
	}
}
