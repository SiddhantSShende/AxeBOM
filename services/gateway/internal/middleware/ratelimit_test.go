package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
)

// clock is a controllable time source, so refill behaviour is testable without
// sleeping.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(cfg RateLimitConfig) (*Limiter, *clock) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cfg.Now = c.Now
	return NewLimiter(cfg), c
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func request(path, remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestBurstIsAllowedThenLimited(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 3})
	h := RateLimit(l)(okHandler())

	for i := 1; i <= 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request("/v1/projects", "10.0.0.1:1234"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (within burst)", i, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", "10.0.0.1:1234"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the burst is spent", rec.Code)
	}
}

// A 429 without Retry-After forces the client to guess its backoff, and a
// client that guesses badly is indistinguishable from an attacker.
func TestLimitedResponseCarriesRetryAfter(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 1})
	h := RateLimit(l)(okHandler())

	h.ServeHTTP(httptest.NewRecorder(), request("/v1/projects", "10.0.0.2:1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", "10.0.0.2:1"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}

	raw := rec.Header().Get("Retry-After")
	if raw == "" {
		t.Fatal("no Retry-After header on a 429")
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs < 1 {
		t.Errorf("Retry-After = %q, want a positive integer number of seconds", raw)
	}

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the canonical error shape: %v", err)
	}
	if body.Error.Code != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("code = %q, want RATE_LIMIT_EXCEEDED", body.Error.Code)
	}
}

func TestBucketRefillsOverTime(t *testing.T) {
	l, c := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 1})
	h := RateLimit(l)(okHandler())

	h.ServeHTTP(httptest.NewRecorder(), request("/v1/projects", "10.0.0.3:1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", "10.0.0.3:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 before refill", rec.Code)
	}

	c.advance(2 * time.Second)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", "10.0.0.3:1"))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 after the bucket refilled", rec.Code)
	}
}

// One noisy client must not consume everyone else's budget.
func TestClientsAreLimitedIndependently(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 1})
	h := RateLimit(l)(okHandler())

	h.ServeHTTP(httptest.NewRecorder(), request("/v1/projects", "10.0.0.4:1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", "10.0.0.4:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("first client should be limited, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", "10.0.0.5:1"))
	if rec.Code != http.StatusOK {
		t.Errorf("a second client was limited by the first client's traffic: %d", rec.Code)
	}
}

// Signup is the endpoint worth abusing, so it gets a much tighter budget than
// ordinary API traffic.
//
// ⚠ THIS USED TO EXERCISE /v1/auth/login, WHICH NO LONGER EXISTS. The local-JWT
// auth surface was removed (services/auth/routes.go); the sanctioned
// unauthenticated endpoint is now POST /v1/auth/signup, which creates a real
// organisation in ZITADEL and is therefore the one a stranger can make cost
// something. A test pointed at a deleted path still passes — it just stops
// testing the limiter and starts testing the general budget instead.
func TestCredentialEndpointsAreLimitedSeparatelyAndMoreTightly(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{
		Rate: 100, Burst: 100, // generous general budget
		AuthRate: 0.1, AuthBurst: 2, // tight credential budget
	})
	h := RateLimit(l)(okHandler())

	const addr = "10.0.0.6:1"
	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request("/v1/auth/signup", addr))
		if rec.Code != http.StatusOK {
			t.Fatalf("signup %d: status = %d, want 200 within the auth burst", i, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/auth/signup", addr))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a third signup attempt was allowed: status = %d", rec.Code)
	}

	// The same client's ordinary API traffic must be unaffected: the buckets
	// are separate, so brute-force protection does not lock a legitimate
	// session out of the product.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request("/v1/projects", addr))
	if rec.Code != http.StatusOK {
		t.Errorf("general traffic was limited by the auth bucket: %d", rec.Code)
	}
}

// An authenticated caller is keyed by identity, not address, so a user on a
// shared NAT is not limited by their colleagues.
func TestAuthenticatedCallersAreKeyedByIdentity(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 1})
	h := RateLimit(l)(okHandler())

	withUser := func(user string) *http.Request {
		r := request("/v1/projects", "10.0.0.7:1") // SAME address for both
		ctx := ctxkey.WithTenantID(r.Context(), "tenant-a")
		ctx = ctxkey.WithUserID(ctx, user)
		return r.WithContext(ctx)
	}

	h.ServeHTTP(httptest.NewRecorder(), withUser("user-1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withUser("user-1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("user-1 should be limited, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, withUser("user-2"))
	if rec.Code != http.StatusOK {
		t.Errorf("user-2 was limited by user-1's traffic from the same address: %d", rec.Code)
	}
}

// Trusting a forwarding header by default would let any client choose its own
// bucket — that is, opt out of rate limiting entirely.
func TestForwardedHeaderIsIgnoredUnlessConfigured(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 1})
	h := RateLimit(l)(okHandler())

	spoof := func(value string) *http.Request {
		r := request("/v1/projects", "10.0.0.8:1")
		r.Header.Set("X-Forwarded-For", value)
		return r
	}

	h.ServeHTTP(httptest.NewRecorder(), spoof("1.1.1.1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, spoof("2.2.2.2")) // a different forged address
	if rec.Code != http.StatusTooManyRequests {
		t.Error("a client escaped its limit by changing X-Forwarded-For")
	}
}

func TestForwardedHeaderIsUsedWhenExplicitlyTrusted(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{
		Rate: 1, Burst: 1, TrustedProxyHeader: "X-Forwarded-For",
	})
	h := RateLimit(l)(okHandler())

	real := func(value string) *http.Request {
		r := request("/v1/projects", "10.0.0.9:1") // one proxy, one peer address
		r.Header.Set("X-Forwarded-For", value)
		return r
	}

	h.ServeHTTP(httptest.NewRecorder(), real("1.1.1.1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, real("1.1.1.1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("the same forwarded client was not limited: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, real("2.2.2.2"))
	if rec.Code != http.StatusOK {
		t.Errorf("a different client behind the same proxy was limited: %d", rec.Code)
	}
}

// Without eviction, one request per forged address grows the bucket map until
// the process dies — the limiter becomes the denial of service.
func TestIdleBucketsAreEvicted(t *testing.T) {
	l, c := newTestLimiter(RateLimitConfig{Rate: 1, Burst: 1})
	h := RateLimit(l)(okHandler())

	for i := 0; i < 50; i++ {
		h.ServeHTTP(httptest.NewRecorder(),
			request("/v1/projects", "10.1."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256)+":1"))
	}

	before := l.buckets.Len()
	if before < 50 {
		t.Fatalf("expected 50 buckets, got %d", before)
	}

	// Past both the sweep interval and the idle TTL, then one more request to
	// trigger the sweep.
	c.advance(21 * time.Minute) // past ratelimit's 5m sweep + 15m idle TTL
	h.ServeHTTP(httptest.NewRecorder(), request("/v1/projects", "10.9.9.9:1"))

	after := l.buckets.Len()

	if after >= before {
		t.Errorf("idle buckets were not evicted: %d before, %d after", before, after)
	}
}

// The limiter is shared across goroutines; a data race here would be a crash
// under load. Run with -race to make this meaningful.
func TestLimiterIsConcurrencySafe(t *testing.T) {
	l, _ := newTestLimiter(RateLimitConfig{Rate: 1000, Burst: 1000})
	h := RateLimit(l)(okHandler())

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				h.ServeHTTP(httptest.NewRecorder(),
					request("/v1/projects", "10.2.0."+strconv.Itoa(n)+":1"))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
