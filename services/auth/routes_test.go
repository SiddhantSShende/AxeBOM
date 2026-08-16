package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
)

// ---------------------------------------------------------------------------
// THE ROUTE GUARD TEST.
//
// "Somebody forgot to wrap one handler" is the single most common way an
// authenticated API leaks. It produces no compile error, no runtime error and
// no failing test — the endpoint simply works, for everyone.
//
// So this test reads routes.go as a SYNTAX TREE and checks the mounting call
// used for each route. Reading the source rather than the mux is deliberate:
// http.ServeMux does not expose its patterns or the handler chain, so a
// runtime check cannot tell a wrapped handler from an unwrapped one.
//
// The consequence is that a new route is denied by default: it fails this test
// until it is either wrapped in Authenticate or explicitly listed in
// publicRoutes with a reason.
// ---------------------------------------------------------------------------

// routeMount is one route as it is mounted in the source.
type routeMount struct {
	pattern string
	// viaHandle is true for mux.Handle(...) — the form that takes a wrapped
	// http.Handler. mux.HandleFunc takes a bare function and therefore cannot
	// be carrying middleware.
	viaHandle bool
	line      int
}

func parseRouteMounts(t *testing.T) []routeMount {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "routes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse routes.go: %v", err)
	}

	var mounts []routeMount
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "mux" {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}

		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}

		mounts = append(mounts, routeMount{
			pattern:   pattern,
			viaHandle: sel.Sel.Name == "Handle",
			line:      fset.Position(call.Pos()).Line,
		})
		return true
	})

	if len(mounts) == 0 {
		t.Fatal("no routes were found in routes.go — the parser is broken, " +
			"and a broken parser here means this test proves nothing")
	}
	return mounts
}

// TestEveryRouteIsGuardedOrDeliberatelyPublic is the acceptance test.
func TestEveryRouteIsGuardedOrDeliberatelyPublic(t *testing.T) {
	for _, m := range parseRouteMounts(t) {
		_, isPublic := publicRoutes[m.pattern]

		switch {
		case isPublic && m.viaHandle:
			// Not an error, but worth flagging: a public route mounted through
			// Handle is probably wrapped in something, which contradicts the
			// list.
			t.Errorf("routes.go:%d: %q is listed as public but is mounted via "+
				"mux.Handle — either drop it from publicRoutes or use HandleFunc",
				m.line, m.pattern)

		case isPublic:
			// Deliberate exception with a stated reason. Fine.

		case !m.viaHandle:
			t.Errorf("routes.go:%d: %q is mounted with mux.HandleFunc, so it "+
				"carries NO middleware and is reachable without a token.\n"+
				"    Either wrap it: mux.Handle(%q, authenticated(http.HandlerFunc(h.X)))\n"+
				"    or add it to publicRoutes with the reason it must be public.",
				m.line, m.pattern, m.pattern)
		}
	}
}

// Every entry in publicRoutes must correspond to a route that exists, or the
// list becomes a graveyard of stale exemptions that quietly re-permit a path
// somebody later re-adds.
func TestPublicRouteListHasNoStaleEntries(t *testing.T) {
	mounted := map[string]bool{}
	for _, m := range parseRouteMounts(t) {
		mounted[m.pattern] = true
	}
	for pattern := range publicRoutes {
		if !mounted[pattern] {
			t.Errorf("publicRoutes lists %q, which is not mounted in routes.go — "+
				"remove the stale exemption", pattern)
		}
	}
}

// Each exemption must carry a reason. An empty string is how a list like this
// decays into a rubber stamp.
func TestEveryPublicRouteStatesWhy(t *testing.T) {
	for pattern, reason := range publicRoutes {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%q is exempted from authentication with no stated reason", pattern)
		}
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
