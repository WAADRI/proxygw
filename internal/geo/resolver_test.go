package geo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
)

// mustResolver builds a resolver for tests and closes it afterwards.
func mustResolver(t *testing.T, cfg config.GeoConfig, client *http.Client, opts ...func(*Options)) *Resolver {
	t.Helper()
	options := Options{Config: cfg, Logger: testLogger(), HTTPClient: client}
	for _, apply := range opts {
		apply(&options)
	}
	resolver, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	return resolver
}

func TestResolveIPInfoPreset(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"ip":"8.8.8.8","country":"US","region":"California","city":"Mountain View","org":"AS15169 Google LLC"}`)
	})
	cfg := testGeoConfig(config.ProviderConfig{
		Name: "ipinfo", Type: "preset", Preset: "ipinfo",
		URL: srv.URL + "/{ip}/json", Enabled: true,
	})
	resolver := mustResolver(t, cfg, srv.Client())
	geo, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if geo.Country != "US" || geo.Region != "California" || geo.City != "Mountain View" {
		t.Fatalf("unexpected geo: %+v", geo)
	}
	if geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("unexpected ASN fields: %+v", geo)
	}
	if geo.Provider != "ipinfo" {
		t.Fatalf("Provider = %q, want ipinfo", geo.Provider)
	}
	if geo.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt must be set")
	}
	for _, field := range []string{geoFieldCountry, geoFieldRegion, geoFieldCity, geoFieldASN, geoFieldASNOrg} {
		source, ok := geo.Sources[field]
		if !ok {
			t.Fatalf("missing source for field %q: %+v", field, geo.Sources)
		}
		if source.Source != "ipinfo" || source.FetchedAt.IsZero() {
			t.Fatalf("unexpected source for %q: %+v", field, source)
		}
	}
	if srv.hits.Load() != 1 {
		t.Fatalf("provider hits = %d, want 1", srv.hits.Load())
	}
}

func TestMMDBPrimaryPartialFill(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"country":"DE","city":"Berlin","isp":"Deutsche Telekom"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{
		"country": "$.country",
		"city":    "$.city",
		"isp":     "$.isp",
	}))
	resolver := mustResolver(t, cfg, srv.Client())
	resolver.mmdb = &mmdbLayer{
		names:   []string{"mmdb"},
		primary: "mmdb",
		enabled: true,
		testLookup: func(net.IP) (model.Geo, map[string]string, error) {
			return model.Geo{
				Country: "US",
				Region:  "California",
				City:    "Mountain View",
				ASN:     15169,
				ASNOrg:  "Google LLC",
			}, map[string]string{geoFieldCountry: "country.iso_code"}, nil
		},
	}
	geo, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// MMDB fields win, online provider only fills the missing ISP field.
	if geo.Country != "US" || geo.Region != "California" || geo.City != "Mountain View" {
		t.Fatalf("MMDB fields were overwritten: %+v", geo)
	}
	if geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("MMDB ASN fields were overwritten: %+v", geo)
	}
	if geo.ISP != "Deutsche Telekom" {
		t.Fatalf("ISP = %q, want the online provider value", geo.ISP)
	}
	if got := geo.Sources[geoFieldCountry].Source; got != "mmdb" {
		t.Fatalf("country source = %q, want mmdb", got)
	}
	if got := geo.Sources[geoFieldRegion].Source; got != "mmdb" {
		t.Fatalf("region source = %q, want mmdb", got)
	}
	if got := geo.Sources[geoFieldISP].Source; got != "custom" {
		t.Fatalf("isp source = %q, want custom", got)
	}
	if geo.Provider != "custom" {
		t.Fatalf("Provider = %q, want the last contributing provider", geo.Provider)
	}
	if srv.hits.Load() != 1 {
		t.Fatalf("online provider hits = %d, want 1", srv.hits.Load())
	}
	status := providerStatusByName(t, resolver.ProviderStatuses(), "mmdb")
	if !status.Healthy || !status.Enabled {
		t.Fatalf("mmdb status = %+v, want enabled+healthy", status)
	}
}

func TestResolveCacheHitAndTTL(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	cfg.CacheTTL = model.D(time.Hour)
	var clockMu sync.Mutex
	now := time.Unix(1700000000, 0).UTC()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	resolver := mustResolver(t, cfg, srv.Client(), func(o *Options) { o.Now = clock })
	ip := net.ParseIP("8.8.8.8")
	first, err := resolver.Resolve(context.Background(), ip)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	second, err := resolver.Resolve(context.Background(), ip)
	if err != nil {
		t.Fatalf("Resolve (cached): %v", err)
	}
	if first.Country != "JP" || second.Country != "JP" {
		t.Fatalf("unexpected results: %+v / %+v", first, second)
	}
	if srv.hits.Load() != 1 {
		t.Fatalf("cache miss: provider hits = %d, want 1", srv.hits.Load())
	}

	clockMu.Lock()
	now = now.Add(2 * time.Hour) // entry expired
	clockMu.Unlock()
	if _, err := resolver.Resolve(context.Background(), ip); err != nil {
		t.Fatalf("Resolve (expired): %v", err)
	}
	if srv.hits.Load() != 2 {
		t.Fatalf("expired entry was not refreshed: provider hits = %d, want 2", srv.hits.Load())
	}
}

func TestResolveSingleflight(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	resolver := mustResolver(t, cfg, srv.Client())

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	geos := make([]model.Geo, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			geos[idx], errs[idx] = resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8"))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i, geo := range geos {
		if geo.Country != "JP" {
			t.Fatalf("goroutine %d got %+v", i, geo)
		}
	}
	if hits := srv.hits.Load(); hits != 1 {
		t.Fatalf("singleflight failed: provider hits = %d, want 1", hits)
	}
}

func TestProviderBreakerTripAndRecover(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	down := make(chan string, 4)
	resolver := mustResolver(t, cfg, srv.Client(), func(o *Options) {
		o.OnProviderDown = func(name, reason string) { down <- name }
	})

	for i := 1; i <= providerFailureThreshold; i++ {
		ip := net.ParseIP(fmt.Sprintf("8.8.8.%d", i))
		geo, err := resolver.Resolve(context.Background(), ip)
		if err != nil {
			t.Fatalf("Resolve(%v): %v", ip, err)
		}
		if !geo.IsZero() {
			t.Fatalf("Resolve(%v) returned data despite provider failures: %+v", ip, geo)
		}
	}
	if srv.hits.Load() != int64(providerFailureThreshold) {
		t.Fatalf("provider hits = %d, want %d", srv.hits.Load(), providerFailureThreshold)
	}
	status := providerStatusByName(t, resolver.ProviderStatuses(), "custom")
	if status.Healthy {
		t.Fatalf("provider must be auto removed after %d failures: %+v", providerFailureThreshold, status)
	}
	if status.Failures != providerFailureThreshold {
		t.Fatalf("Failures = %d, want %d", status.Failures, providerFailureThreshold)
	}
	if !status.Enabled {
		t.Fatalf("auto removal must keep Enabled=true (only Healthy flips): %+v", status)
	}
	select {
	case name := <-down:
		if name != "custom" {
			t.Fatalf("OnProviderDown name = %q", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnProviderDown was not called")
	}
	select {
	case extra := <-down:
		t.Fatalf("OnProviderDown called more than once: %q", extra)
	default:
	}

	// A removed provider is skipped without any HTTP request.
	failing.Store(false)
	geo, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.100"))
	if err != nil {
		t.Fatalf("Resolve after removal: %v", err)
	}
	if !geo.IsZero() || srv.hits.Load() != int64(providerFailureThreshold) {
		t.Fatalf("removed provider must not be called: hits=%d geo=%+v", srv.hits.Load(), geo)
	}

	// Manual recovery clears the failure counter and health state.
	if err := resolver.SetProviderEnabled("custom", true); err != nil {
		t.Fatalf("SetProviderEnabled: %v", err)
	}
	status = providerStatusByName(t, resolver.ProviderStatuses(), "custom")
	if !status.Healthy || status.Failures != 0 {
		t.Fatalf("manual recovery did not reset state: %+v", status)
	}
	geo, err = resolver.Resolve(context.Background(), net.ParseIP("8.8.8.101"))
	if err != nil {
		t.Fatalf("Resolve after recovery: %v", err)
	}
	if geo.Country != "JP" {
		t.Fatalf("unexpected geo after recovery: %+v", geo)
	}
	if srv.hits.Load() != int64(providerFailureThreshold)+1 {
		t.Fatalf("provider hits = %d, want %d", srv.hits.Load(), providerFailureThreshold+1)
	}
}

func TestRemoteConsentFalse(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	cfg.RemoteConsent = false
	resolver := mustResolver(t, cfg, srv.Client())
	geo, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !geo.IsZero() {
		t.Fatalf("remote provider must not be called without consent: %+v", geo)
	}
	if srv.hits.Load() != 0 {
		t.Fatalf("provider hits = %d, want 0", srv.hits.Load())
	}
	status := providerStatusByName(t, resolver.ProviderStatuses(), "custom")
	if status.Enabled {
		t.Fatalf("consent-disabled provider must be marked disabled: %+v", status)
	}
	if !strings.Contains(status.LastError, "remote_consent") {
		t.Fatalf("status must explain the missing consent: %+v", status)
	}
	if err := resolver.SetProviderEnabled("custom", true); err == nil || !strings.Contains(err.Error(), "remote_consent") {
		t.Fatalf("enabling without consent must fail, got %v", err)
	}
	test, err := resolver.TestProvider(context.Background(), "custom", net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("TestProvider: %v", err)
	}
	if test.Error == "" || !strings.Contains(test.Error, "remote_consent") {
		t.Fatalf("test button must report the consent requirement: %+v", test)
	}
	if srv.hits.Load() != 0 {
		t.Fatalf("TestProvider must not call a remote provider without consent, hits=%d", srv.hits.Load())
	}
}

func TestSSRFProtection(t *testing.T) {
	t.Run("non https URL is rejected in production mode", func(t *testing.T) {
		cfg := testGeoConfig(templateProvider("custom", "http://example.com/lookup", map[string]string{"country": "$.country"}))
		if _, err := New(Options{Config: cfg, Logger: testLogger()}); err == nil || !strings.Contains(err.Error(), "only https") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("userinfo is rejected", func(t *testing.T) {
		cfg := testGeoConfig(templateProvider("custom", "https://user:pass@example.com/lookup", map[string]string{"country": "$.country"}))
		if _, err := New(Options{Config: cfg, Logger: testLogger()}); err == nil || !strings.Contains(err.Error(), "userinfo") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("hostname resolving to loopback is blocked", func(t *testing.T) {
		cfg := testGeoConfig(templateProvider("custom", "https://localhost/lookup", map[string]string{"country": "$.country"}))
		resolver := mustResolver(t, cfg, nil)
		geo, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8"))
		if err != nil {
			t.Fatalf("Resolve must not surface provider failures as errors: %v", err)
		}
		if !geo.IsZero() {
			t.Fatalf("expected no data, got %+v", geo)
		}
		status := providerStatusByName(t, resolver.ProviderStatuses(), "custom")
		if !strings.Contains(status.LastError, "blocked address") {
			t.Fatalf("LastError = %q, want an SSRF rejection", status.LastError)
		}
	})

	t.Run("redirect to a private address is blocked", func(t *testing.T) {
		srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://10.1.2.3/secret", http.StatusFound)
		})
		cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
		resolver := mustResolver(t, cfg, srv.Client())
		if _, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8")); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		status := providerStatusByName(t, resolver.ProviderStatuses(), "custom")
		if !strings.Contains(status.LastError, "unsafe redirect target") {
			t.Fatalf("LastError = %q, want a redirect SSRF rejection", status.LastError)
		}
	})

	t.Run("redirect loop is capped at two redirects", func(t *testing.T) {
		srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/loop", http.StatusFound)
		})
		cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
		resolver := mustResolver(t, cfg, srv.Client())
		if _, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8")); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		status := providerStatusByName(t, resolver.ProviderStatuses(), "custom")
		if !strings.Contains(status.LastError, "too many redirects") {
			t.Fatalf("LastError = %q, want the redirect cap", status.LastError)
		}
	})
}

func TestTestProvider(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			writeJSON(t, w, `{"country":"JP","asn":"AS2516"}`)
		case "/fail":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "/echo":
			_, _ = io.WriteString(w, "203.0.113.50")
		default:
			http.NotFound(w, r)
		}
	})
	cfg := testGeoConfig(
		templateProvider("custom", srv.URL+"/ok", map[string]string{"country": "$.country", "asn": "$.asn"}),
		templateProvider("bad", srv.URL+"/fail", map[string]string{"country": "$.country"}),
	)
	cfg.Egress = config.EgressConfig{EchoURLsV4: []string{srv.URL + "/echo"}, Timeout: model.D(500 * time.Millisecond)}
	resolver := mustResolver(t, cfg, srv.Client())

	test, err := resolver.TestProvider(context.Background(), "custom", net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("TestProvider: %v", err)
	}
	if test.Error != "" {
		t.Fatalf("unexpected test error: %s", test.Error)
	}
	if test.Result.Country != "JP" || test.Result.ASN != 2516 {
		t.Fatalf("unexpected test result: %+v", test.Result)
	}
	if test.RawSnippet == "" || !strings.Contains(test.RawSnippet, "country") {
		t.Fatalf("raw snippet = %q", test.RawSnippet)
	}
	if test.DurationMS < 0 {
		t.Fatalf("DurationMS = %f", test.DurationMS)
	}
	if got := test.HitPaths["country"]; got != "$.country" {
		t.Fatalf("hit path for country = %q", got)
	}

	if _, err := resolver.TestProvider(context.Background(), "nobody", net.ParseIP("8.8.8.8")); err == nil {
		t.Fatal("unknown provider must return an error")
	}

	failed, err := resolver.TestProvider(context.Background(), "bad", net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("TestProvider(bad): %v", err)
	}
	if failed.Error == "" || !strings.Contains(failed.Error, "500") {
		t.Fatalf("unexpected failure test result: %+v", failed)
	}
	if !strings.Contains(failed.RawSnippet, "boom") {
		t.Fatalf("raw snippet of a failing provider = %q, want the response body", failed.RawSnippet)
	}

	// No node IP provided: the server egress is resolved through the echo
	// endpoint and used as the test IP.
	serverTest, err := resolver.TestProvider(context.Background(), "custom", nil)
	if err != nil {
		t.Fatalf("TestProvider(nil ip): %v", err)
	}
	if serverTest.IP != "203.0.113.50" {
		t.Fatalf("test IP = %q, want the server egress address", serverTest.IP)
	}
	if serverTest.Error != "" {
		t.Fatalf("unexpected test error: %s", serverTest.Error)
	}
}

func TestMMDBUnavailable(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		cfg := testGeoConfig()
		cfg.MMDBPath = filepath.Join(t.TempDir(), "missing.mmdb")
		resolver := mustResolver(t, cfg, nil)
		status := providerStatusByName(t, resolver.ProviderStatuses(), "mmdb")
		if status.Healthy {
			t.Fatalf("missing MMDB must be unhealthy: %+v", status)
		}
		if status.LastError == "" {
			t.Fatalf("missing MMDB must carry a LastError: %+v", status)
		}
		geo, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8"))
		if err != nil {
			t.Fatalf("Resolve must not fail without MMDB: %v", err)
		}
		if !geo.IsZero() {
			t.Fatalf("expected unknown geo, got %+v", geo)
		}
		if err := resolver.SetProviderEnabled("mmdb", false); err != nil {
			t.Fatalf("SetProviderEnabled: %v", err)
		}
		if status := providerStatusByName(t, resolver.ProviderStatuses(), "mmdb"); status.Enabled {
			t.Fatalf("mmdb must be disabled: %+v", status)
		}
	})

	t.Run("corrupt file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "broken.mmdb")
		if err := os.WriteFile(path, []byte("definitely not a maxmind database"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		cfg := testGeoConfig()
		cfg.MMDBPath = path
		resolver := mustResolver(t, cfg, nil)
		status := providerStatusByName(t, resolver.ProviderStatuses(), "mmdb")
		if status.Healthy {
			t.Fatalf("corrupt MMDB must be unhealthy: %+v", status)
		}
		if !strings.Contains(status.LastError, "mmdb") && !strings.Contains(status.LastError, "invalid") {
			t.Fatalf("unexpected LastError: %q", status.LastError)
		}
	})
}

func TestResolveBatch(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	resolver := mustResolver(t, cfg, srv.Client())
	ips := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1"), net.ParseIP("2001:db8::1"), nil}
	batch := resolver.ResolveBatch(context.Background(), ips)
	if len(batch) != 3 {
		t.Fatalf("ResolveBatch returned %d entries, want 3: %+v", len(batch), batch)
	}
	for key, geo := range batch {
		if geo.Country != "JP" {
			t.Fatalf("entry %q = %+v", key, geo)
		}
	}
}

func TestMetricsOptional(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	m := metrics.New()
	resolver := mustResolver(t, cfg, srv.Client(), func(o *Options) { o.Metrics = m })
	if _, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8")); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	recorder := httptest.NewRecorder()
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(recorder, metricsReq)
	body := recorder.Body.String()
	if !strings.Contains(body, `geo_lookups_total{provider="custom",result="success"} 1`) {
		t.Fatalf("geo_lookups_total with success result not exported:\n%s", body)
	}
}

func TestResolveInvalidInputAndClosed(t *testing.T) {
	cfg := testGeoConfig()
	resolver := mustResolver(t, cfg, nil)
	if _, err := resolver.Resolve(context.Background(), nil); err == nil {
		t.Fatal("nil IP must be rejected")
	}
	if _, err := resolver.Resolve(context.Background(), net.IP{1, 2, 3}); err == nil {
		t.Fatal("malformed IP must be rejected")
	}
	if err := resolver.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8")); err == nil {
		t.Fatal("Resolve after Close must fail")
	}
	if err := resolver.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestGeoCacheLRUEviction(t *testing.T) {
	cache := newGeoCache(2, time.Hour, nil)
	cache.set("a", model.Geo{Country: "US"})
	cache.set("b", model.Geo{Country: "DE"})
	cache.set("c", model.Geo{Country: "JP"})
	if got := cache.len(); got != 2 {
		t.Fatalf("cache len = %d, want 2", got)
	}
	if _, ok := cache.get("a"); ok {
		t.Fatal("least recently used entry must be evicted")
	}
	if geo, ok := cache.get("b"); !ok || geo.Country != "DE" {
		t.Fatalf("unexpected entry b: %+v %v", geo, ok)
	}
	if geo, ok := cache.get("c"); !ok || geo.Country != "JP" {
		t.Fatalf("unexpected entry c: %+v %v", geo, ok)
	}
}

func TestTokenBucketRateLimiting(t *testing.T) {
	if newTokenBucket(0) != nil {
		t.Fatal("rate_per_min=0 must disable the limiter")
	}
	fast := newTokenBucket(6000) // 100/s: no meaningful wait inside a test
	for i := 0; i < 5; i++ {
		if err := fast.wait(context.Background()); err != nil {
			t.Fatalf("fast bucket wait: %v", err)
		}
	}
	slow := newTokenBucket(1) // 1/min: one burst token, then wait
	if err := slow.wait(context.Background()); err != nil {
		t.Fatalf("first slow bucket wait: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := slow.wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rate limiter must respect context cancellation, got %v", err)
	}
}

func TestProviderConcurrencyLimit(t *testing.T) {
	var inflight, peak atomic.Int64
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		current := inflight.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inflight.Add(-1)
		writeJSON(t, w, `{"country":"JP"}`)
	})
	cfg := testGeoConfig(templateProvider("custom", srv.URL, map[string]string{"country": "$.country"}))
	cfg.MaxConcurrent = 1
	resolver := mustResolver(t, cfg, srv.Client())
	batch := resolver.ResolveBatch(context.Background(), []net.IP{
		net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1"), net.ParseIP("9.9.9.9"),
	})
	if len(batch) != 3 {
		t.Fatalf("ResolveBatch returned %d entries, want 3", len(batch))
	}
	if got := peak.Load(); got > 1 {
		t.Fatalf("MaxConcurrent=1 violated: observed %d concurrent provider calls", got)
	}
}

func TestProviderErrorsDoNotLeakToken(t *testing.T) {
	const token = "super-secret-provider-token"
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		// A misbehaving endpoint that echoes the token in its error body.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"bad request token=`+r.URL.Query().Get("token")+`"}`)
	})
	provider := templateProvider("custom", srv.URL, map[string]string{"country": "$.country"})
	provider.Token = token
	resolver := mustResolver(t, testGeoConfig(provider), srv.Client())
	if _, err := resolver.Resolve(context.Background(), net.ParseIP("8.8.8.8")); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	status := providerStatusByName(t, resolver.ProviderStatuses(), "custom")
	if strings.Contains(status.LastError, token) {
		t.Fatalf("provider status leaked the token: %q", status.LastError)
	}
	if !strings.Contains(status.LastError, "***") || !strings.Contains(status.LastError, "500") {
		t.Fatalf("unexpected provider status error: %q", status.LastError)
	}
}

func TestSetProviderEnabledUnknown(t *testing.T) {
	resolver := mustResolver(t, testGeoConfig(), nil)
	if err := resolver.SetProviderEnabled("nope", true); err == nil {
		t.Fatal("unknown provider must return an error")
	}
	if err := resolver.SetProviderEnabled("", true); err == nil {
		t.Fatal("empty provider name must return an error")
	}
}
