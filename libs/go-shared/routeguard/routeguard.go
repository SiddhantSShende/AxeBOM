// Package routeguard asserts that every HTTP route is authenticated.
//
// WHY THIS EXISTS: "somebody forgot to wrap one handler" is the single most
// common way an authenticated API leaks. It produces no compile error, no
// runtime error and no failing test — the endpoint simply works, for everyone.
//
// WHY IT READS SOURCE RATHER THAN THE MUX: http.ServeMux exposes neither its
// patterns nor the handler chain, so a runtime check cannot tell a wrapped
// handler from an unwrapped one. Parsing the route table is the only way to see
// the difference.
//
// WHY IT IS A LIBRARY: every service needs the same check, and eight copies of
// a 150-line test drift. Each service keeps a ten-line test that calls Assert
// with its own publicRoutes map, so the exemptions stay next to the routes they
// describe while the logic has one home.
//
// The effect is that a NEW ROUTE IS DENIED BY DEFAULT: it fails the check until
// it is either wrapped in authentication or explicitly listed as public with a
// stated reason.
package routeguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// Mount is one route as it appears in the source.
type Mount struct {
	// Pattern is the route pattern, e.g. "GET /v1/projects/{id}".
	Pattern string
	// ViaHandle is true for mux.Handle(...), the form that takes a wrapped
	// http.Handler. mux.HandleFunc takes a bare function and therefore cannot
	// be carrying middleware.
	ViaHandle bool
	// Wrapper is the name of the function the handler is passed through, e.g.
	// "guard" or "authenticated". Empty when the handler is not a call.
	//
	// ⚠ WITHOUT THIS, "WRAPPED" WAS TAKEN TO MEAN "AUTHENTICATED". A route
	// mounted as mux.Handle(p, rateLimiter(h)) is wrapped and completely
	// unauthenticated, and the earlier check passed it silently. The report
	// service's rate-limited share-link route is exactly that shape and is what
	// found the hole.
	Wrapper string
	// Line is the 1-based line of the mounting call.
	Line int
}

// Finding is one problem with a route table.
type Finding struct {
	Pattern string
	Line    int
	Message string
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("routes.go:%d: %s", f.Line, f.Message)
	}
	return f.Message
}

// ParseMounts extracts every mux.Handle / mux.HandleFunc call from a file.
func ParseMounts(path string) ([]Mount, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var mounts []Mount
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

		m := Mount{
			Pattern:   pattern,
			ViaHandle: sel.Sel.Name == "Handle",
			Line:      fset.Position(call.Pos()).Line,
		}
		if len(call.Args) > 1 {
			m.Wrapper = wrapperName(call.Args[1])
		}
		mounts = append(mounts, m)
		return true
	})
	return mounts, nil
}

// wrapperName returns the name of the outermost function applied to a handler.
//
// Only the OUTERMOST call is inspected, and that is the right level:
// authentication must be outside everything else, or a request reaches the
// inner middleware before its identity is established.
func wrapperName(arg ast.Expr) string {
	call, ok := arg.(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		// e.g. d.sharedLimiter(...). The receiver is irrelevant; the NAME is
		// what says whether this establishes an identity.
		return fn.Sel.Name
	default:
		return ""
	}
}

// DefaultAuthWrappers are the function names that establish an identity.
//
// `guard` composes authentication with one authorization matrix cell;
// `authenticated` is authentication alone, for routes whose permission is
// checked inside the handler. Any OTHER wrapper — a rate limiter, a
// content-type check, a logger — leaves the route unauthenticated, however
// wrapped it looks.
var DefaultAuthWrappers = []string{"guard", "authenticated"}

// Check validates a route table against its public-route exemptions.
//
// publicRoutes maps a route pattern to the REASON it may be reached without a
// token. An empty reason is itself a finding: a list of exemptions with no
// reasons decays into a rubber stamp.
func Check(path string, publicRoutes map[string]string) ([]Finding, error) {
	return CheckWith(path, publicRoutes, DefaultAuthWrappers)
}

// CheckWith is Check with a service-specific set of authenticating wrappers.
func CheckWith(path string, publicRoutes map[string]string, authWrappers []string) ([]Finding, error) {
	authenticating := make(map[string]bool, len(authWrappers))
	for _, w := range authWrappers {
		authenticating[w] = true
	}

	mounts, err := ParseMounts(path)
	if err != nil {
		return nil, err
	}
	if len(mounts) == 0 {
		return nil, fmt.Errorf(
			"no routes found in %s — a parser that finds nothing proves nothing", path)
	}

	var findings []Finding

	for _, m := range mounts {
		reason, isPublic := publicRoutes[m.Pattern]

		// ⚠ THE QUESTION IS "IS IT AUTHENTICATED", NOT "IS IT WRAPPED".
		//
		// mux.HandleFunc can carry nothing. mux.Handle carries whatever it was
		// given — which may be a rate limiter, and a rate limiter establishes no
		// identity. Treating any Handle mount as guarded is how an
		// unauthenticated route passes this check while looking protected.
		guarded := m.ViaHandle && authenticating[m.Wrapper]

		switch {
		case isPublic && guarded:
			findings = append(findings, Finding{
				Pattern: m.Pattern, Line: m.Line,
				Message: fmt.Sprintf("%q is listed as public but is wrapped in %s(), "+
					"which authenticates — either drop it from publicRoutes or stop "+
					"authenticating it", m.Pattern, m.Wrapper),
			})

		case isPublic && strings.TrimSpace(reason) == "":
			findings = append(findings, Finding{
				Pattern: m.Pattern, Line: m.Line,
				Message: fmt.Sprintf("%q is exempted from authentication with no stated reason", m.Pattern),
			})

		case isPublic:
			// A deliberate exception with a reason. Fine — and it may still be
			// wrapped in non-authenticating middleware such as a rate limiter,
			// which is exactly what an unauthenticated route ought to have.

		case !guarded:
			how := "is mounted with mux.HandleFunc, so it carries NO middleware"
			if m.ViaHandle {
				how = fmt.Sprintf("is wrapped in %s(), which is not one of the "+
					"authenticating wrappers (%s)", m.Wrapper, strings.Join(authWrappers, ", "))
			}
			findings = append(findings, Finding{
				Pattern: m.Pattern, Line: m.Line,
				Message: fmt.Sprintf(
					"%q %s, so it is reachable without a token.\n"+
						"    Either authenticate it:  mux.Handle(%q, guard(resource, action, h.X))\n"+
						"    or add it to publicRoutes with the reason it must be public.",
					m.Pattern, how, m.Pattern),
			})
		}
	}

	// A stale exemption silently re-permits a path somebody later re-adds under
	// the same pattern.
	mounted := make(map[string]bool, len(mounts))
	for _, m := range mounts {
		mounted[m.Pattern] = true
	}
	stale := make([]string, 0)
	for pattern := range publicRoutes {
		if !mounted[pattern] {
			stale = append(stale, pattern)
		}
	}
	sort.Strings(stale) // deterministic output; map order would vary per run
	for _, pattern := range stale {
		findings = append(findings, Finding{
			Pattern: pattern,
			Message: fmt.Sprintf(
				"publicRoutes lists %q, which is not mounted in %s — remove the stale exemption",
				pattern, path),
		})
	}

	return findings, nil
}
