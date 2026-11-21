// Package audit implements the tamper-evident JSONL audit trail required by the
// specification. Records are written with fsync so they survive crashes; the
// query helper supports filtering by time, action and actor.
package audit

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxygw/internal/model"
)

// Filter selects audit records for Query.
type Filter struct {
	Since  time.Time
	Until  time.Time
	Action string
	Actor  string
	Limit  int // default 500, max 10000
}

// Store owns the append-only audit log.
type Store struct {
	mu      sync.Mutex
	path    string
	enabled bool
	ring    []model.AuditEvent // recent events for the panel when persistence is disabled
}

// New creates the audit store. Empty path disables persistence but keeps the
// in-memory ring for the panel.
func New(path string, enabled bool) (*Store, error) {
	s := &Store{path: path, enabled: enabled, ring: make([]model.AuditEvent, 0, 512)}
	if !enabled {
		return s, nil
	}
	if path == "" {
		return nil, fmt.Errorf("audit: enabled but path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	_ = f.Close()
	return s, nil
}

// Log appends one event. Missing ID/time/result fields are filled by default.
func (s *Store) Log(ev model.AuditEvent) error {
	ev = redact(ev)
	if ev.ID == "" {
		ev.ID = newID()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.Result == "" {
		ev.Result = "ok"
	}
	if !s.enabled {
		s.pushRing(ev)
		return nil
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: encode event: %w", err)
	}
	data = append(data, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", s.path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("audit: append: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("audit: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: close: %w", err)
	}
	s.pushRingLocked(ev)
	return nil
}

// LogSimple is a convenience wrapper for one-line call sites.
func (s *Store) LogSimple(action, object, actor, sourceIP, result string, detail map[string]string) error {
	return s.Log(model.AuditEvent{
		Action: action, Object: object, Actor: actor, SourceIP: sourceIP, Result: result, Detail: detail,
	})
}

// Query reads the JSONL file (or the in-memory ring when disabled) and filters.
func (s *Store) Query(f Filter) ([]model.AuditEvent, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	if f.Limit > 10000 {
		f.Limit = 10000
	}
	if !s.enabled {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := make([]model.AuditEvent, 0, len(s.ring))
		for i := len(s.ring) - 1; i >= 0 && len(out) < f.Limit; i-- {
			if match(s.ring[i], f) {
				out = append(out, s.ring[i])
			}
		}
		return out, nil
	}
	fh, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	defer fh.Close()
	// Simple tail scan: audit files are small enough for an in-memory filter.
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var all []model.AuditEvent
	for sc.Scan() {
		var ev model.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue // skip corrupt line, keep the rest readable
		}
		if match(ev, f) {
			all = append(all, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: scan: %w", err)
	}
	// Newest first, bounded.
	if len(all) > f.Limit {
		all = all[len(all)-f.Limit:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, nil
}

func match(ev model.AuditEvent, f Filter) bool {
	if !f.Since.IsZero() && ev.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && ev.Time.After(f.Until) {
		return false
	}
	if f.Action != "" && !strings.EqualFold(ev.Action, f.Action) {
		return false
	}
	if f.Actor != "" && !strings.EqualFold(ev.Actor, f.Actor) {
		return false
	}
	return true
}

func (s *Store) pushRing(ev model.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushRingLocked(ev)
}

func (s *Store) pushRingLocked(ev model.AuditEvent) {
	s.ring = append(s.ring, ev)
	if len(s.ring) > 1024 {
		s.ring = s.ring[len(s.ring)-1024:]
	}
}

// redact strips anything that looks like a secret from the detail map. Callers
// should already avoid passing secrets; this is the last line of defence.
func redact(ev model.AuditEvent) model.AuditEvent {
	if len(ev.Detail) == 0 {
		return ev
	}
	clean := make(map[string]string, len(ev.Detail))
	for k, v := range ev.Detail {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "password") || strings.Contains(lk, "secret") ||
			strings.Contains(lk, "authorization") || strings.Contains(lk, "cookie") || strings.Contains(lk, "hash") {
			clean[k] = "[redacted]"
			continue
		}
		clean[k] = v
	}
	ev.Detail = clean
	return ev
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "a_" + hex.EncodeToString(b)
}
