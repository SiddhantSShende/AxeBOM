package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/libs/go-shared/routeguard"
	"github.com/axebom/axebom/services/aibom/internal/handler"
)

// TestEveryRouteIsGuardedOrDeliberatelyPublic parses routes.go and fails on any
// route that carries no middleware and is not a listed public exemption.
//
// The logic lives in libs/go-shared/routeguard so every service shares one
// implementation; the publicRoutes map stays HERE, next to the routes it
// describes, because the exemptions are a per-service security decision.
func TestEveryRouteIsGuardedOrDeliberatelyPublic(t *testing.T) {
	findings, err := routeguard.Check("routes.go", publicRoutes)
	if err != nil {
		t.Fatalf("route guard: %v", err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestEveryRoutePatternRegistersWithoutConflict.
//
// ⚠ THE TEXT PARSER ABOVE CANNOT SEE A PATTERN CONFLICT, AND ServeMux PANICS ON
// ONE. Go 1.22's mux refuses two overlapping patterns where neither is more
// specific — which would make this a startup crash in the container rather than
// a failing build. This service is exactly the shape that hits it:
// `/v1/aibom/{projectId}/models` and `/v1/aibom/{projectId}/form` share a
// prefix, and `/v1/aibom/{projectId}/models/{modelKey}/fields` sits under one
// of them.
//
// A zero-value handler and Guard are enough: registerRoutes only closes over
// them, and the mux registration is the only thing under test.
func TestEveryRoutePatternRegistersWithoutConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registering this service's routes panics, so the service "+
				"would not start:\n%v", r)
		}
	}()

	registerRoutes(http.NewServeMux(), &deps{
		handler:  &handler.Handler{},
		identity: &oidcauth.Guard{},
	})
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
