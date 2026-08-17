// Package ratelimit is the token-bucket core shared by every limiter.
//
// ⚠ THE BUCKET MATH LIVES HERE ONCE. The gateway limits authenticated traffic
// by tenant and credential endpoints by address; the report service limits its
// one unauthenticated route by address. Those are different POLICIES over the
// same mechanism, and a second copy of the mechanism is a second place for the
// eviction sweep to be forgotten — at which point the limiter becomes the
// denial of service it was added to prevent.
//
// ⚠ IN-PROCESS, WHICH IS A REAL LIMIT AND NOT A DETAIL. With N replicas each
// enforces its own budget, so the effective limit is N times the configured
// one. That is acceptable for abuse control and NOT sufficient for quota
// billing. A shared Redis limiter is the Phase 16 upgrade.
package ratelimit

import (
	"sync"
	"time"
)

// bucket is one token bucket.
//
// Token bucket rather than a fixed window: a fixed window lets a client spend
// its whole quota in the last millisecond of one window and again in the first
// of the next, which is double the intended rate at exactly the wrong moment.
type bucket struct {
	tokens float64
	last   time.Time
}

// Buckets is a fixed-memory set of token buckets.
type Buckets struct {
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket

	// lastSweep bounds memory. Without eviction, one request per forged address
	// grows the map until the process dies.
	lastSweep time.Time
}

// New builds a bucket set. A nil clock uses time.Now.
func New(now func() time.Time) *Buckets {
	if now == nil {
		now = time.Now
	}
	return &Buckets{
		now:       now,
		buckets:   make(map[string]*bucket),
		lastSweep: now(),
	}
}

// sweepInterval and idleTTL bound the bucket map.
const (
	sweepInterval = 5 * time.Minute
	idleTTL       = 15 * time.Minute
)

// Allow reports whether a request keyed by `key` may proceed, and how long to
// wait if not.
//
// The wait is rounded UP to at least a second, because a client that retries
// after a rounded-down wait is immediately limited again — and then looks like
// an attacker.
func (b *Buckets) Allow(key string, rate float64, burst int) (bool, time.Duration) {
	if rate <= 0 || burst <= 0 {
		// A misconfigured limiter must not silently allow everything. Refusing
		// is the safe direction and it is loud: the endpoint stops working and
		// somebody looks at the configuration.
		return false, time.Second
	}

	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()

	if now.Sub(b.lastSweep) >= sweepInterval {
		for k, v := range b.buckets {
			if now.Sub(v.last) > idleTTL {
				delete(b.buckets, k)
			}
		}
		b.lastSweep = now
	}

	v, ok := b.buckets[key]
	if !ok {
		// A new client starts with a full bucket, so a first request is never
		// delayed.
		v = &bucket{tokens: float64(burst), last: now}
		b.buckets[key] = v
	}

	// Refill for elapsed time, capped at the burst size.
	if elapsed := now.Sub(v.last).Seconds(); elapsed > 0 {
		v.tokens += elapsed * rate
		if v.tokens > float64(burst) {
			v.tokens = float64(burst)
		}
		v.last = now
	}

	if v.tokens >= 1 {
		v.tokens--
		return true, 0
	}

	wait := time.Duration((1 - v.tokens) / rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// Len reports how many buckets are held. For tests and for a gauge that makes
// the eviction sweep observable rather than assumed.
func (b *Buckets) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}
