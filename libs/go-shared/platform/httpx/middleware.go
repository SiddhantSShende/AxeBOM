// Package httpx provides the standard middleware chain every service mounts.
//
// Order matters and is not arbitrary (docs/02-CONTRACTS.md §8):
//
//		RequestID -> Recovery -> Logging -> Metrics -> Timeout -> [auth -> tenant -> authz]
//
//	  - RequestID is first so every later layer, including a panic, has an id.
//	  - Recovery is second so it catches panics from everything after it.
//	  - Timeout is last of the platform layers so it wraps only the handler, not
//	    the logging that needs to run after the handler returns.
//
// Auth, tenant and authz are added by the gateway in Phase 3; they belong
// after this chain because they need the request id for their audit entries.
package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/libs/go-shared/platform/obs"
)

// Middleware is a standard HTTP decorator.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so the FIRST argument is the OUTERMOST layer, which
// is how the chain reads top-to-bottom in the package doc.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// RequestID assigns a request id and echoes it in the response.
//
// An inbound X-Request-ID is honoured so a trace spans a caller's own id, but
// it is length-capped and stripped of control characters: it is attacker-
// controlled input that ends up in logs, and a newline there is log injection.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeRequestID(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = uuid.NewString()
		}
		ctx := ctxkey.WithRequestID(r.Context(), id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const maxRequestIDLen = 64

func sanitizeRequestID(s string) string {
	if len(s) > maxRequestIDLen {
		s = s[:maxRequestIDLen]
	}
	return strings.Map(func(r rune) rune {
		// Printable ASCII only. Anything else is a log-injection vector.
		if r >= 0x20 && r < 0x7f {
			return r
		}
		return -1
	}, s)
}

// Recovery converts a panic into a 500 without taking the process down.
//
// CLAUDE.md: never panic in a request path. This exists because "never" is a
// rule about intent, and a nil map write in a rarely-taken branch does not care
// about intent.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// http.ErrAbortHandler is the documented way to abort a
				// response; it is not a bug and must not be logged as one.
				// errors.Is rather than ==, so a wrapped ErrAbortHandler still
				// propagates instead of being swallowed into a 500.
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec)
				}
				slog.ErrorContext(r.Context(), "panic recovered",
					"panic", rec,
					"stack", string(debug.Stack()),
					"method", r.Method,
					"path", r.URL.Path,
				)
				errs.Write(w, r, errs.New(errs.InternalUnexpected,
					"an unexpected error occurred"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// responseWriter captures the status and byte count for logging and metrics.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer, which
// WebSocket upgrades and streaming responses need.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Logging emits one structured line per request.
//
// It deliberately does not log request or response bodies. Bodies carry BOM
// content, which is confidential under CERT-In §5.3, and credentials.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health and metrics endpoints are polled every few seconds by
		// Kubernetes and Prometheus; logging them drowns everything else.
		if isNoiseEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		level := slog.LevelInfo
		switch {
		case rw.status >= 500:
			level = slog.LevelError
		case rw.status >= 400:
			// 4xx is the caller's problem. At info level a scanner hammering
			// 404s would drown the log.
			level = slog.LevelDebug
		}

		slog.Log(r.Context(), level, "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"bytes", rw.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", clientIP(r),
			"user_agent", r.UserAgent(),
		)
	})
}

func isNoiseEndpoint(p string) bool {
	return p == "/healthz" || p == "/readyz" || p == "/metrics"
}

// clientIP extracts the caller address.
//
// X-Forwarded-For is only honoured when TrustProxyHeaders is set, because it is
// client-controlled: trusting it unconditionally lets anyone forge the IP in
// audit logs and bypass IP rate limits.
var TrustProxyHeaders = false

func clientIP(r *http.Request) string {
	if TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	return r.RemoteAddr
}

// Metrics records request count and latency.
//
// `route` is the registered PATTERN, never the concrete path — a concrete path
// produces unbounded label cardinality and will take down the metrics backend.
func Metrics(m *obs.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isNoiseEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			m.HTTPInFlight.Inc()
			defer m.HTTPInFlight.Dec()

			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			route := r.Pattern
			if route == "" {
				// Unmatched request. Bucket it rather than emitting the raw
				// path, which is attacker-controlled and unbounded.
				route = "unmatched"
			}
			m.ObserveHTTP(r.Method, route, rw.status, time.Since(start))
		})
	}
}

// Timeout bounds handler execution.
//
// Not applied to WebSocket upgrades or streaming downloads: a long-lived
// connection is the point of those, and a timeout would sever a scan-progress
// stream mid-scan.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isStreaming(r) {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isStreaming(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	return strings.Contains(r.URL.Path, "/download") ||
		strings.HasSuffix(r.URL.Path, "/progress")
}

// SecurityHeaders sets conservative defaults.
//
// This service returns JSON and file downloads, never HTML that should run
// script, so the CSP is maximally restrictive.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// Default returns the standard platform chain.
func Default(m *obs.Metrics, timeout time.Duration) []Middleware {
	return []Middleware{
		RequestID,
		Recovery,
		SecurityHeaders,
		Logging,
		Metrics(m),
		Timeout(timeout),
	}
}
