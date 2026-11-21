package sched

import "time"

// clock abstracts the passage of time so the token buckets can be tested
// deterministically. The scheduler's breaker/sticky code only needs Now; the
// limiter also needs to wait, hence After.
type clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// realClock is the production clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// After uses a timer per wait. Waits are bounded by one bucket capacity (about
// one second of traffic), so no long lived timer can accumulate.
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
