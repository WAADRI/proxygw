package geo

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
)

// testLogger discards all log output while still exercising the logging paths.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// countingServer is an httptest TLS server that counts requests.
type countingServer struct {
	*httptest.Server
	hits atomic.Int64
}

// newCountingTLSServer starts a TLS test server and registers cleanup.
func newCountingTLSServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *countingServer {
	t.Helper()
	cs := &countingServer{}
	cs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(cs.Close)
	return cs
}

// writeJSON is a tiny test helper.
func writeJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := io.WriteString(w, body); err != nil {
		t.Errorf("write test response: %v", err)
	}
}

// testGeoConfig builds an enabled geo configuration with sane test defaults.
func testGeoConfig(providers ...config.ProviderConfig) config.GeoConfig {
	return config.GeoConfig{
		Enabled:       true,
		CacheTTL:      model.D(time.Hour),
		RemoteConsent: true,
		MaxConcurrent: 8,
		Providers:     providers,
	}
}

// templateProvider builds a template provider configuration.
func templateProvider(name, url string, fields map[string]string) config.ProviderConfig {
	return config.ProviderConfig{Name: name, Type: "template", URL: url, Fields: fields, Enabled: true}
}

// providerStatusByName finds one provider status.
func providerStatusByName(t *testing.T, statuses []ProviderStatus, name string) ProviderStatus {
	t.Helper()
	for _, status := range statuses {
		if status.Name == name {
			return status
		}
	}
	t.Fatalf("provider %q not present in statuses %+v", name, statuses)
	return ProviderStatus{}
}
