package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/libs/go-shared/routeguard"
)

// TestEveryRouteIsGuardedOrDeliberatelyPublic parses routes.go and fails on any
// route that carries no middleware and is not a listed public exemption.
//
// The logic lives in libs/go-shared/routeguard so all eight services share one
// implementation; the publicRoutes map stays HERE, next to the routes it
// describes, because the exemptions are a per-service security decision.
//
// See that package's doc for why this reads source rather than the mux.
func TestEveryRouteIsGuardedOrDeliberatelyPublic(t *testing.T) {
	findings, err := routeguard.Check("routes.go", publicRoutes)
	if err != nil {
		t.Fatalf("route guard: %v", err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// The catch-all in main.go answers unmatched paths with the canonical error
// shape. Without it ServeMux emits its own text/plain 404, which gives routing
// 404s a different shape from cross-tenant 404s — and that difference is an
// oracle telling an attacker which resource ids exist.
func TestUnmatchedRoutesUseTheCanonicalErrorShape(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpx.NotFound)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/does-not-exist", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
