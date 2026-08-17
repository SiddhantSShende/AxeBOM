package routeguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// routesFile writes a synthetic routes.go and returns its path.
func routesFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.go")
	src := "package main\n\nimport \"net/http\"\n\nfunc registerRoutes(mux *http.ServeMux, d *deps) {\n" +
		body + "\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

func messages(findings []Finding) string {
	var sb strings.Builder
	for _, f := range findings {
		sb.WriteString(f.String())
		sb.WriteString("\n")
	}
	return sb.String()
}

// TestAnAuthenticatedRouteIsAccepted — the baseline, so a guard that rejects
// everything cannot pass the rest of this file.
func TestAnAuthenticatedRouteIsAccepted(t *testing.T) {
	path := routesFile(t, `	mux.Handle("GET /v1/reports/{id}", guard(a, b, h.Get))`)

	findings, err := Check(path, nil)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a guarded route was rejected:\n%s", messages(findings))
	}
}

// TestABareHandleFuncIsRejected — the original case: no middleware at all.
func TestABareHandleFuncIsRejected(t *testing.T) {
	path := routesFile(t, `	mux.HandleFunc("GET /v1/reports/{id}", h.Get)`)

	findings, err := Check(path, nil)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("an unwrapped route was accepted")
	}
	if !strings.Contains(messages(findings), "without a token") {
		t.Errorf("the finding does not say what is wrong:\n%s", messages(findings))
	}
}

// TestWrappedInSomethingThatIsNotAuthenticationIsRejected.
//
// ⚠ THIS IS THE HOLE THE REPORT SERVICE FOUND, AND THE REASON THIS FILE EXISTS.
//
// The check previously asked "is it mounted with mux.Handle", and took yes to
// mean "it is wrapped, therefore authenticated". A route wrapped in a RATE
// LIMITER is mounted with mux.Handle, carries middleware, establishes no
// identity, and passed silently — while looking, in a diff, exactly like a
// protected route.
//
// A rate limiter is the realistic case because it is what an unauthenticated
// route legitimately needs. The next one will be a content-type check or a
// logger.
func TestWrappedInSomethingThatIsNotAuthenticationIsRejected(t *testing.T) {
	cases := map[string]string{
		"a rate limiter (method value)": `	mux.Handle("GET /shared/{token}", d.sharedLimiter(http.HandlerFunc(h.Shared)))`,
		"a plain function wrapper":      `	mux.Handle("GET /shared/{token}", withLogging(http.HandlerFunc(h.Shared)))`,
		"no wrapper at all":             `	mux.Handle("GET /shared/{token}", http.HandlerFunc(h.Shared))`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := Check(routesFile(t, body), nil)
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("an unauthenticated route mounted via mux.Handle was accepted; " +
					"being wrapped is not the same as being authenticated")
			}
			if !strings.Contains(messages(findings), "reachable without a token") {
				t.Errorf("the finding does not name the consequence:\n%s", messages(findings))
			}
		})
	}
}

// TestAPublicRouteMayCarryNonAuthenticatingMiddleware.
//
// The counterpart to the test above: an unauthenticated route SHOULD be
// rate-limited, and the guard must not force a choice between "listed public"
// and "protected from abuse".
func TestAPublicRouteMayCarryNonAuthenticatingMiddleware(t *testing.T) {
	path := routesFile(t,
		`	mux.Handle("GET /shared/{token}", d.sharedLimiter(http.HandlerFunc(h.Shared)))`)

	findings, err := Check(path, map[string]string{
		"GET /shared/{token}": "the share link is the credential; every access is audited",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a declared-public, rate-limited route was rejected:\n%s", messages(findings))
	}
}

// TestAPublicExemptionOnAnAuthenticatedRouteIsRejected — a stale exemption on a
// route that is now guarded is a lie in the security review surface.
func TestAPublicExemptionOnAnAuthenticatedRouteIsRejected(t *testing.T) {
	path := routesFile(t, `	mux.Handle("GET /v1/reports/{id}", guard(a, b, h.Get))`)

	findings, err := Check(path, map[string]string{
		"GET /v1/reports/{id}": "some outdated reason",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("an exemption on an authenticated route was accepted")
	}
}

// TestAnExemptionWithoutAReasonIsRejected — a list of exemptions with no
// reasons decays into a rubber stamp.
func TestAnExemptionWithoutAReasonIsRejected(t *testing.T) {
	path := routesFile(t, `	mux.HandleFunc("GET /shared/{token}", h.Shared)`)

	findings, err := Check(path, map[string]string{"GET /shared/{token}": "   "})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("an exemption with a blank reason was accepted")
	}
	if !strings.Contains(messages(findings), "no stated reason") {
		t.Errorf("the finding does not say what is missing:\n%s", messages(findings))
	}
}

// TestAStaleExemptionIsReported — an exemption for a pattern nobody mounts
// silently re-permits the path the day somebody re-adds it.
func TestAStaleExemptionIsReported(t *testing.T) {
	path := routesFile(t, `	mux.Handle("GET /v1/reports/{id}", guard(a, b, h.Get))`)

	findings, err := Check(path, map[string]string{
		"GET /v1/gone": "removed two phases ago",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !strings.Contains(messages(findings), "stale exemption") {
		t.Errorf("a stale exemption was not reported:\n%s", messages(findings))
	}
}

// TestAFileWithNoRoutesIsAnError.
//
// ⚠ A PARSER THAT FINDS NOTHING PROVES NOTHING. The most likely way this guard
// dies is a refactor that moves the route table, leaving a check that reads an
// empty file and reports success forever.
func TestAFileWithNoRoutesIsAnError(t *testing.T) {
	path := routesFile(t, `	_ = mux`)

	if _, err := Check(path, nil); err == nil {
		t.Fatal("a routes file with no routes was accepted")
	}
}

// TestCustomAuthWrappers lets a service name its own, without loosening the
// default for everyone else.
func TestCustomAuthWrappers(t *testing.T) {
	path := routesFile(t, `	mux.Handle("GET /v1/x", mustBeAdmin(h.X))`)

	if findings, err := Check(path, nil); err != nil {
		t.Fatalf("check: %v", err)
	} else if len(findings) == 0 {
		t.Fatal("an unknown wrapper was accepted by the default set")
	}

	findings, err := CheckWith(path, nil, []string{"mustBeAdmin"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a declared wrapper was still rejected:\n%s", messages(findings))
	}
}
