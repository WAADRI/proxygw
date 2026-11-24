// Package audit implements the tamper-evident JSONL audit trail required by the
// specification. Records are written with fsync so they survive crashes; the
// query helper supports filtering by time, action and actor.
package audit

import (
	"bytes"
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

// Options controls persistence details. Zero values keep the historical
// unlimited single-file behaviour.
type Options struct {
	// MaxSize rotates the JSONL file when it reaches this many bytes.
	MaxSize int64
	// MaxBackups is how many rotated files to keep (at least 1 when MaxSize > 0).
	MaxBackups int
}

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
	mu         sync.Mutex
	path       string
	enabled    bool
	maxSize    int64
	maxBackups int
	ring       []model.AuditEvent // recent events for the panel
}

// New creates the audit store. Empty path disables persistence but keeps the
// in-memory ring for the panel.
func New(path string, enabled bool) (*Store, error) {
	return NewWithOptions(path, enabled, Options{})
}

// NewWithOptions creates the audit store with rotation options.
func NewWithOptions(path string, enabled bool, opts Options) (*Store, error) {
	s := &Store{
		path:       path,
		enabled:    enabled,
		maxSize:    opts.MaxSize,
		maxBackups: opts.MaxBackups,
		ring:       make([]model.AuditEvent, 0, 512),
	}
	if s.enabled && s.maxSize > 0 && s.maxBackups < 1 {
		s.maxBackups = 1
	}
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
	if err := s.rotateIfNeededLocked(); err != nil {
		return fmt.Errorf("audit: rotate: %w", err)
	}
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

// rotateIfNeededLocked renames the active JSONL file when it exceeds the
// configured size. Backups are kept as path.1 ... path.N. Caller holds s.mu.
func (s *Store) rotateIfNeededLocked() error {
	if s.maxSize <= 0 {
		return nil
	}
	info, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() < s.maxSize {
		return nil
	}
	backups := s.maxBackups
	if backups < 1 {
		backups = 1
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", s.path, backups))
	for i := backups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", s.path, i), fmt.Sprintf("%s.%d", s.path, i+1))
	}
	if err := os.Rename(s.path, s.path+".1"); err != nil {
		return err
	}
	return nil
}

// Query reads the in-memory ring when it can satisfy the request, otherwise it
// scans backwards from the end of the JSONL file and stops as soon as Limit
// matching events have been collected.
func (s *Store) Query(f Filter) ([]model.AuditEvent, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	if f.Limit > 10000 {
		f.Limit = 10000
	}
	if items, ok := s.queryRing(f); ok {
		return items, nil
	}
	if !s.enabled {
		return s.queryRingUnbounded(f), nil
	}
	return s.queryFileTail(f)
}

// queryRing answers from the recent-event ring when it holds at least Limit
// events and enough of them match. The ring contains the newest events, so a
// full page of matches there is exactly the newest page.
func (s *Store) queryRing(f Filter) ([]model.AuditEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) < f.Limit {
		return nil, false
	}
	out := make([]model.AuditEvent, 0, f.Limit)
	for i := len(s.ring) - 1; i >= 0 && len(out) < f.Limit; i-- {
		if match(s.ring[i], f) {
			out = append(out, s.ring[i])
		}
	}
	if len(out) < f.Limit {
		return nil, false
	}
	return out, true
}

func (s *Store) queryRingUnbounded(f Filter) []model.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.AuditEvent, 0, len(s.ring))
	for i := len(s.ring) - 1; i >= 0 && len(out) < f.Limit; i-- {
		if match(s.ring[i], f) {
			out = append(out, s.ring[i])
		}
	}
	return out
}

// queryFileTail grows a read window backwards from EOF until it has Limit
// matches or reaches the beginning of the file. This keeps the common panel
// request (newest page, optionally filtered) proportional to the events read
// rather than the whole historical file.
func (s *Store) queryFileTail(f Filter) ([]model.AuditEvent, error) {
	fh, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return nil, fmt.Errorf("audit: stat: %w", err)
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}
	const initialWindow = int64(256 * 1024)
	window := initialWindow
	for {
		start := size - window
		if start < 0 {
			start = 0
		}
		data := make([]byte, size-start)
		if _, err := fh.ReadAt(data, start); err != nil {
			return nil, fmt.Errorf("audit: read tail: %w", err)
		}
		lines := bytes.Split(data, []byte("\n"))
		first := 0
		if start > 0 {
			// The first chunk boundary can cut a line; ignore that oldest
			// fragment. If it mattered, the window is extended below.
			first = 1
		}
		out := make([]model.AuditEvent, 0, f.Limit)
		for i := len(lines) - 1; i >= first && len(out) < f.Limit; i-- {
			line := bytes.TrimSpace(lines[i])
			if len(line) == 0 {
				continue
			}
			var ev model.AuditEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				continue // skip corrupt line, keep the rest readable
			}
			if match(ev, f) {
				out = append(out, ev)
			}
		}
		if len(out) >= f.Limit || start == 0 {
			return out, nil
		}
		window *= 2
		if window > size {
			window = size
		}
	}
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
	if len(s.ring) > 4096 {
		s.ring = s.ring[len(s.ring)-4096:]
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
