// Package proxy: per-source-IP authentication failure banning.
//
// The panel admin login already has a per-IP limiter (internal/auth), but the
// proxy entry points previously only audited proxy.auth_failed and allowed an
// unlimited number of credential guesses. AuthBanTracker adds a small bounded
// in-memory failure window on the hot path, before Argon2 verification.
package proxy

import (
	"net"
	"strings"
	"sync"
	"time"
)

// AuthBanConfig configures the proxy auth failure source-IP ban.
type AuthBanConfig struct {
	Enabled          bool
	FailureWindow    time.Duration // sliding window used to count failures
	FailureThreshold int           // failures in the window before a ban
	BanDuration      time.Duration // how long a source stays blocked
	MaxEntries       int           // hard memory bound; oldest entries are evicted
	Exempt           []string      // source IPs/CIDRs that are never banned
}

// DefaultAuthBanConfig returns the production defaults.
func DefaultAuthBanConfig() AuthBanConfig {
	return AuthBanConfig{
		Enabled:          true,
		FailureWindow:    5 * time.Minute,
		FailureThreshold: 10,
		BanDuration:      30 * time.Minute,
		MaxEntries:       4096,
	}
}

type authBanEntry struct {
	failures    []time.Time
	bannedUntil time.Time
	bannedAt    time.Time
	banFailures int
	lastFailure time.Time
	lastSeen    time.Time
	reason      string
}

// AuthBanEntry is the panel/management view of one active ban.
type AuthBanEntry struct {
	SourceIP    string    `json:"source_ip"`
	Failures    int       `json:"failures"`
	Reason      string    `json:"reason"`
	BannedAt    time.Time `json:"banned_at"`
	BannedUntil time.Time `json:"banned_until"`
	LastSeen    time.Time `json:"last_seen"`
}

// AuthBanTracker is safe for concurrent use. A nil tracker disables the
// feature; callers must nil-check or use the helpers on pipeline.
type AuthBanTracker struct {
	mu      sync.Mutex
	cfg     AuthBanConfig
	now     func() time.Time
	exempt  []*net.IPNet
	entries map[string]*authBanEntry
}

// NewAuthBanTracker builds a tracker or returns nil when disabled.
func NewAuthBanTracker(cfg AuthBanConfig) *AuthBanTracker {
	if !cfg.Enabled {
		return nil
	}
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = 5 * time.Minute
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 10
	}
	if cfg.BanDuration <= 0 {
		cfg.BanDuration = 30 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 4096
	}
	t := &AuthBanTracker{
		cfg:     cfg,
		now:     func() time.Time { return time.Now().UTC() },
		entries: make(map[string]*authBanEntry),
	}
	for _, raw := range cfg.Exempt {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			mask := net.CIDRMask(128, 128)
			if v4 := ip.To4(); v4 != nil {
				ip = v4
				mask = net.CIDRMask(32, 32)
			}
			t.exempt = append(t.exempt, &net.IPNet{IP: ip, Mask: mask})
			continue
		}
		if _, network, err := net.ParseCIDR(raw); err == nil {
			t.exempt = append(t.exempt, network)
		}
	}
	return t
}

func (t *AuthBanTracker) sourceKey(sourceIP string) string {
	ip := net.ParseIP(strings.TrimSpace(sourceIP))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String()
}

func (t *AuthBanTracker) exemptIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	for _, network := range t.exempt {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Blocked reports whether sourceIP is currently banned and the remaining time.
func (t *AuthBanTracker) Blocked(sourceIP string) (time.Duration, bool) {
	if t == nil {
		return 0, false
	}
	key := t.sourceKey(sourceIP)
	if key == "" {
		return 0, false
	}
	ip := net.ParseIP(key)
	if t.exemptIP(ip) {
		return 0, false
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[key]
	if e == nil {
		return 0, false
	}
	if now.Before(e.bannedUntil) {
		return e.bannedUntil.Sub(now), true
	}
	// The ban expired; keep only failures that are still inside the window so
	// a slow scan cannot immediately re-ban on the next attempt.
	t.trimLocked(e, now)
	if len(e.failures) == 0 {
		delete(t.entries, key)
		return 0, false
	}
	e.bannedUntil = time.Time{}
	return 0, false
}

// RecordFailure counts one authentication failure. It returns whether this
// failure triggered a ban, the ban duration and the current in-window count.
func (t *AuthBanTracker) RecordFailure(sourceIP, reason string) (banned bool, banFor time.Duration, failures int) {
	if t == nil {
		return false, 0, 0
	}
	key := t.sourceKey(sourceIP)
	if key == "" {
		return false, 0, 0
	}
	ip := net.ParseIP(key)
	if t.exemptIP(ip) {
		return false, 0, 0
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[key]
	if e == nil {
		e = &authBanEntry{}
		t.entries[key] = e
	}
	if now.Before(e.bannedUntil) {
		e.lastSeen = now
		return false, 0, len(e.failures)
	}
	t.trimLocked(e, now)
	e.failures = append(e.failures, now)
	e.lastFailure = now
	e.lastSeen = now
	e.reason = reason
	if len(e.failures) >= t.cfg.FailureThreshold {
		e.bannedAt = now
		e.bannedUntil = now.Add(t.cfg.BanDuration)
		e.banFailures = len(e.failures)
		e.failures = nil
		t.evictIfNeededLocked(now)
		return true, t.cfg.BanDuration, e.banFailures
	}
	t.evictIfNeededLocked(now)
	return false, 0, len(e.failures)
}

// RecordSuccess clears pending failures for sourceIP. A currently banned source
// is never authenticated (Blocked rejects it first), so this mainly resets the
// window for legitimate clients that had one or two typos.
func (t *AuthBanTracker) RecordSuccess(sourceIP string) {
	if t == nil {
		return
	}
	key := t.sourceKey(sourceIP)
	if key == "" {
		return
	}
	t.mu.Lock()
	delete(t.entries, key)
	t.mu.Unlock()
}

// Snapshot returns active bans, newest first.
func (t *AuthBanTracker) Snapshot() []AuthBanEntry {
	if t == nil {
		return []AuthBanEntry{}
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]AuthBanEntry, 0, len(t.entries))
	for key, e := range t.entries {
		if now.Before(e.bannedUntil) {
			out = append(out, AuthBanEntry{
				SourceIP:    key,
				Failures:    e.banFailures,
				Reason:      e.reason,
				BannedAt:    e.bannedAt,
				BannedUntil: e.bannedUntil,
				LastSeen:    e.lastSeen,
			})
		}
	}
	return out
}

// Unban removes an active ban and any pending count for sourceIP.
func (t *AuthBanTracker) Unban(sourceIP string) bool {
	if t == nil {
		return false
	}
	key := t.sourceKey(sourceIP)
	if key == "" {
		return false
	}
	t.mu.Lock()
	_, existed := t.entries[key]
	delete(t.entries, key)
	t.mu.Unlock()
	return existed
}

func (t *AuthBanTracker) trimLocked(e *authBanEntry, now time.Time) {
	cutoff := now.Add(-t.cfg.FailureWindow)
	kept := e.failures[:0]
	for _, at := range e.failures {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	e.failures = kept
}

func (t *AuthBanTracker) evictIfNeededLocked(now time.Time) {
	if len(t.entries) <= t.cfg.MaxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, e := range t.entries {
		if now.Before(e.bannedUntil) {
			continue
		}
		if oldest.IsZero() || e.lastSeen.Before(oldest) {
			oldest = e.lastSeen
			oldestKey = key
		}
	}
	if oldestKey == "" {
		// All entries are active bans: still enforce the hard memory bound by
		// evicting the oldest ban.
		for key, e := range t.entries {
			if oldest.IsZero() || e.lastSeen.Before(oldest) {
				oldest = e.lastSeen
				oldestKey = key
			}
		}
	}
	if oldestKey != "" {
		delete(t.entries, oldestKey)
	}
}
