// Package health exposes /healthz and /version handlers shared by both
// binaries.
package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"proxygw/internal/version"
)

// Check is one named health probe.
type Check struct {
	Name string
	Fn   func() error
}

// Status is the /healthz response body.
type Status struct {
	OK            bool              `json:"ok"`
	Checks        map[string]string `json:"checks"`
	UptimeSeconds float64           `json:"uptime_seconds"`
	Version       version.Info      `json:"version"`
}

// Server tracks registered checks and renders health responses.
type Server struct {
	mu      sync.Mutex
	started time.Time
	checks  []Check
}

// New returns an empty health server.
func New() *Server { return &Server{started: time.Now()} }

// AddCheck registers a named probe. Checks run on every /healthz request.
func (s *Server) AddCheck(name string, fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, Check{Name: name, Fn: fn})
}

// Snapshot runs all checks and returns the aggregated status.
func (s *Server) Snapshot() Status {
	s.mu.Lock()
	checks := append([]Check(nil), s.checks...)
	s.mu.Unlock()
	st := Status{
		OK:            true,
		Checks:        map[string]string{},
		UptimeSeconds: time.Since(s.started).Seconds(),
		Version:       version.Current(),
	}
	for _, c := range checks {
		if c.Fn == nil {
			continue
		}
		if err := c.Fn(); err != nil {
			st.OK = false
			st.Checks[c.Name] = "error: " + err.Error()
		} else {
			st.Checks[c.Name] = "ok"
		}
	}
	return st
}

// Handler returns the /healthz handler (200 when healthy, 503 otherwise).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st := s.Snapshot()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !st.OK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(st)
	})
}

// VersionHandler returns the /version handler.
func VersionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(version.Current())
	})
}
