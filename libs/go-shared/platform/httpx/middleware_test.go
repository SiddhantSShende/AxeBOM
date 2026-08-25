package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
)

func TestRequestIDGenerated(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ctxkey.RequestID(r.Context())
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" {
		t.Fatal("no request id placed in context")
	}
	if got := rec.Header().Get("X-Request-ID"); got != seen {
		t.Errorf("header %q != context %q", got, seen)
	}
}

func TestRequestIDHonoursInbound(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ctxkey.RequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "caller-supplied-123")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "caller-supplied-123" {
		t.Errorf("inbound id not honoured: %q", seen)
	}
}

// X-Request-ID is attacker-controlled and lands in logs. A newline there is log
// injection: it lets a caller forge whole log lines.
func TestRequestIDSanitized(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"newline stripped", "abc\ndef", "abcdef"},
		{"carriage return stripped", "abc\r\nFAKE-LOG-LINE", "abcFAKE-LOG-LINE"},
		{"null byte stripped", "abc\x00def", "abcdef"},
		{"tab stripped", "abc\tdef", "abcdef"},
		// U+202E RIGHT-TO-LEFT OVERRIDE, escaped rather than embedded so the
		// source file itself stays readable. This is a real log-spoofing vector:
		// it reverses rendering of everything after it in a terminal.
		{"rtl override stripped", "abc\u202edef", "abcdef"},
		{"over-long truncated", strings.Repeat("x", 200), strings.Repeat("x", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRequestID(tt.in); got != tt.want {
				t.Errorf("sanitizeRequestID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRecoveryReturns500(t *testing.T) {
	h := Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var m map[string]string
			//nolint:staticcheck // SA5000: the nil-map write IS the test — it
			// is the most common accidental panic in a request path.
			m["boom"] = "nil map write"
		}),
		RequestID, Recovery,
	)

	rec := httptest.NewRecorder()
	// Must not panic out of ServeHTTP — that would take the process down.
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INTERNAL_UNEXPECTED") {
		t.Errorf("body should carry the taxonomy code: %s", rec.Body.String())
	}
	// The panic text and stack must not reach the client.
	if strings.Contains(rec.Body.String(), "nil map") {
		t.Errorf("panic detail leaked to client: %s", rec.Body.String())
	}
}

// http.ErrAbortHandler is the documented way to abort a response and must pass
// through rather than being logged as a bug.
func TestRecoveryRepanicsAbortHandler(t *testing.T) {
	h := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("ErrAbortHandler should propagate, not be swallowed")
		} else if !errors.Is(rec.(error), http.ErrAbortHandler) {
			t.Fatalf("wrong panic value: %v", rec)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestChainOrder(t *testing.T) {
	var order []string
	mk := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}), mk("first"), mk("second"), mk("third"))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"first", "second", "third", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v (first arg must be outermost)", order, want)
		}
	}
}

// X-Forwarded-For is client-controlled. Trusting it unconditionally lets anyone
// forge the IP recorded in audit logs and bypass IP-based rate limits.
func TestClientIPIgnoresForwardedByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:44321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := clientIP(req); got != "10.0.0.5:44321" {
		t.Errorf("clientIP = %q; X-Forwarded-For must be ignored unless TrustProxyHeaders", got)
	}

	TrustProxyHeaders = true
	defer func() { TrustProxyHeaders = false }()
	if got := clientIP(req); got != "1.2.3.4" {
		t.Errorf("with TrustProxyHeaders, clientIP = %q, want 1.2.3.4", got)
	}
}
