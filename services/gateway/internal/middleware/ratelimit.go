// Package middleware holds the gateway's request chain.
//
// Order is fixed and load-bearing (docs/02-CONTRACTS.md §8):
//
//	request id -> recovery -> logging -> RATE LIMIT -> authenticate -> tenant -> authorize
//
// Rate limiting sits BEFORE authentication on purpose. Login is the endpoint
// most worth brute-forcing, and it is unauthenticated by definition — a limiter
// that ran after auth would never see the attempts it exists to stop.
package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// RateLimitConfig configures the limiter.
type RateLimitConfig struct {
	// Rate is sustained requests per second; Burst is the bucket depth, which
	// is what an idle client may spend at once.
	Rate  float64
	Burst int

	// AuthRate and AuthBurst apply to the credential endpoints. They are
	// deliberately much tighter: a human logs in a handful of times a day, so
	// anything faster is a script.
	AuthRate  float64
	AuthBurst int

	// TrustedProxyHeader is honoured ONLY when the gateway sits behind a proxy
	// that overwrites it. Empty means the peer address is used.
	//
	// Reading X-Forwarded-For from a directly-exposed gateway would let any
	// client pick its own limiter bucket — that is, opt out of rate limiting.
	TrustedProxyHeader string

	Now func() time.Time
}

func (c RateLimitConfig) withDefaults() RateLimitConfig {
	if c.Rate <= 0 {
		c.Rate = 20
	}
	if c.Burst <= 0 {
		c.Burst = 40
	}
	if c.AuthRate <= 0 {
		c.AuthRate = 0.2 // one attempt per five seconds, sustained
	}
	if c.AuthBurst <= 0 {
		c.AuthBurst = 10
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// authPaths are the credential endpoints, held to the tighter budget.
var authPaths = []string{
	"/v1/auth/login",
	"/v1/auth/register",
	"/v1/auth/refresh",
	"/v1/auth/invitations/accept",
}

// bucket is one token bucket.
//
// Token bucket rather than a fixed window: a fixed window lets a client spend
// its whole quota in the last millisecond of one window and again in the first
// of the next, which is double the intended rate at exactly the wrong moment.
type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a fixed-memory in-process rate limiter.
//
// In-process is a deliberate limit worth stating: with several gateway
// replicas each enforces its own budget, so the effective limit is N times the
// configured one. That is acceptable for abuse control and NOT sufficient for
// quota billing. A shared Redis limiter is the Phase 16 upgrade.
type Limiter struct {
	cfg RateLimitConfig

	mu      sync.Mutex
	buckets map[string]*bucket

	// lastSweep bounds memory. Without eviction, one request per forged
	// address grows the map until the process dies — the limiter becomes the
	// denial of service.
	lastSweep time.Time
}

// NewLimiter builds a limiter.
func NewLimiter(cfg RateLimitConfig) *Limiter {
	cfg = cfg.withDefaults()
	return &Limiter{
		cfg:       cfg,
		buckets:   make(map[string]*bucket),
		lastSweep: cfg.Now(),
	}
}

// sweepInterval and idleTTL bound the bucket map.
const (
	sweepInterval = 5 * time.Minute
	idleTTL       = 15 * time.Minute
)

// allow reports whether a request may proceed, and how long to wait if not.
func (l *Limiter) allow(key string, rate float64, burst int) (bool, time.Duration) {
	now := l.cfg.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= sweepInterval {
		for k, b := range l.buckets {
			if now.Sub(b.last) > idleTTL {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.buckets[key]
	if !ok {
		// A new client starts with a full bucket, so a first request is never
		// delayed.
		b = &bucket{tokens: float64(burst), last: now}
		l.buckets[key] = b
	}

	// Refill for elapsed time, capped at the burst size.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	// Seconds until one token is available. Rounded UP, because a client that
	// retries after a rounded-down wait is immediately limited again.
	wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// RateLimit returns the middleware.
func RateLimit(l *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rate, burst := l.cfg.Rate, l.cfg.Burst
			scope := "general"
			if isAuthPath(r.URL.Path) {
				rate, burst = l.cfg.AuthRate, l.cfg.AuthBurst
				scope = "auth"
			}

			ok, wait := l.allow(scope+"|"+l.clientKey(r), rate, burst)
			if !ok {
				// Retry-After is REQUIRED here. Without it a client backs off
				// by guessing, and a well-behaved client that guesses badly
				// looks identical to an attacker.
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
				errs.Write(w, r, errs.Newf(errs.RateLimitExceeded,
					"too many requests; retry in %d seconds", int(wait.Seconds())).
					WithDetail(errs.Detail{"retry_after_seconds": int(wait.Seconds())}))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isAuthPath(path string) bool {
	for _, p := range authPaths {
		if path == p {
			return true
		}
	}
	return false
}

// clientKey identifies the caller for limiting purposes.
//
// An AUTHENTICATED caller is keyed by tenant and user: that is stable across
// their network changes and cannot be forged, since it comes from a verified
// token. Everyone else is keyed by address, which is the best available
// identifier before a token exists.
//
// Note the ordering consequence: because the limiter runs before
// authentication, the context is populated only when an upstream chain has
// already authenticated. That is intentional — the tighter auth budget applies
// to exactly the requests that have no identity yet.
func (l *Limiter) clientKey(r *http.Request) string {
	if tenantID, ok := ctxkey.TenantID(r.Context()); ok && tenantID != "" {
		return "t:" + tenantID + "/u:" + ctxkey.UserID(r.Context())
	}
	return "ip:" + l.clientIP(r)
}

func (l *Limiter) clientIP(r *http.Request) string {
	if h := l.cfg.TrustedProxyHeader; h != "" {
		if v := r.Header.Get(h); v != "" {
			// Left-most entry is the original client.
			if ip := strings.TrimSpace(strings.Split(v, ",")[0]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
