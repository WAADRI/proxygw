package auth

import (
	"sync"
	"time"
)

// Login limiter defaults (mirroring config.DefaultServerConfig).
const (
	defaultLoginRatePerMin = 10
	defaultLockThreshold   = 5
	defaultLockWindow      = 5 * time.Minute

	loginRateWindow = time.Minute // sliding window for LoginRatePerMin

	limiterCleanupEvery = 64   // run an idle-entry sweep every N begin() calls
	limiterMaxEntries   = 4096 // also sweep whenever the table grows past this
)

// loginEntry is the per-source-IP login state.
type loginEntry struct {
	attempts    []time.Time
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// loginLimiter implements the panel login protection:
//
//   - sliding one-minute window: at most ratePerMin attempts per source IP;
//   - consecutive failures: lockThreshold failures lock the IP for lockWindow;
//   - success resets both counters;
//   - idle entries are pruned lazily so the map cannot grow without bound.
type loginLimiter struct {
	mu         sync.Mutex
	entries    map[string]*loginEntry
	ratePerMin int
	threshold  int
	lockWindow time.Duration
	cleanups   int
}

func newLoginLimiter(ratePerMin, threshold int, lockWindow time.Duration) *loginLimiter {
	if ratePerMin <= 0 {
		ratePerMin = defaultLoginRatePerMin
	}
	if threshold <= 0 {
		threshold = defaultLockThreshold
	}
	if lockWindow <= 0 {
		lockWindow = defaultLockWindow
	}
	return &loginLimiter{
		entries:    make(map[string]*loginEntry),
		ratePerMin: ratePerMin,
		threshold:  threshold,
		lockWindow: lockWindow,
	}
}

// begin admits (and records) one login attempt, returning ErrLockedOut when the
// IP is inside a lock window or exhausted its per-minute budget.
func (l *loginLimiter) begin(ip string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entryLocked(ip, now)
	l.pruneAttemptsLocked(e, now)
	if !e.lockedUntil.IsZero() {
		if now.Before(e.lockedUntil) {
			e.lastSeen = now
			return ErrLockedOut
		}
		// The temporary lock expired: start over.
		e.lockedUntil = time.Time{}
		e.failures = 0
		e.attempts = e.attempts[:0]
	}
	if len(e.attempts) >= l.ratePerMin {
		e.lastSeen = now
		return ErrLockedOut
	}
	e.attempts = append(e.attempts, now)
	e.lastSeen = now
	l.maybeCleanupLocked(now)
	return nil
}

// fail records a failed attempt and returns base, or ErrLockedOut when the
// consecutive failure threshold is reached.
func (l *loginLimiter) fail(ip string, now time.Time, base error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entryLocked(ip, now)
	e.failures++
	e.lastSeen = now
	if e.failures >= l.threshold {
		e.lockedUntil = now.Add(l.lockWindow)
		e.failures = 0
		e.attempts = e.attempts[:0]
		return ErrLockedOut
	}
	return base
}

// success resets the counters for ip after a successful login.
func (l *loginLimiter) success(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entryLocked(ip, now)
	e.failures = 0
	e.lockedUntil = time.Time{}
	e.attempts = e.attempts[:0]
	e.lastSeen = now
}

// entryLocked returns the entry for ip, creating it and refreshing lastSeen.
func (l *loginLimiter) entryLocked(ip string, now time.Time) *loginEntry {
	e, ok := l.entries[ip]
	if !ok {
		e = &loginEntry{}
		l.entries[ip] = e
	}
	if e.lastSeen.Before(now) {
		e.lastSeen = now
	}
	return e
}

func (l *loginLimiter) pruneAttemptsLocked(e *loginEntry, now time.Time) {
	cutoff := now.Add(-loginRateWindow)
	keep := e.attempts[:0]
	for _, t := range e.attempts {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	e.attempts = keep
}

// maybeCleanupLocked removes entries that have been idle for longer than any
// window could still use. It runs periodically rather than on every call.
func (l *loginLimiter) maybeCleanupLocked(now time.Time) {
	l.cleanups++
	if len(l.entries) <= limiterMaxEntries && l.cleanups%limiterCleanupEvery != 0 {
		return
	}
	maxAge := 2 * l.lockWindow
	if 2*loginRateWindow > maxAge {
		maxAge = 2 * loginRateWindow
	}
	for ip, e := range l.entries {
		if !e.lockedUntil.IsZero() && now.Before(e.lockedUntil) {
			continue
		}
		if now.Sub(e.lastSeen) > maxAge {
			delete(l.entries, ip)
		}
	}
}
