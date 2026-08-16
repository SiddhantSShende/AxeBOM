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

		mounts = append(mounts, Mount{
			Pattern:   pattern,
			ViaHandle: sel.Sel.Name == "Handle",
			Line:      fset.Position(call.Pos()).Line,
		})
		return true
	})
	return mounts, nil
}

// Check validates a route table against its public-route exemptions.
//
// publicRoutes maps a route pattern to the REASON it may be reached without a
// token. An empty reason is itself a finding: a list of exemptions with no
// reasons decays into a rubber stamp.
func Check(path string, publicRoutes map[string]string) ([]Finding, error) {
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

		switch {
		case isPublic && m.ViaHandle:
			findings = append(findings, Finding{
				Pattern: m.Pattern, Line: m.Line,
				Message: fmt.Sprintf("%q is listed as public but is mounted via mux.Handle — "+
					"either drop it from publicRoutes or use HandleFunc", m.Pattern),
			})

		case isPublic && strings.TrimSpace(reason) == "":
			findings = append(findings, Finding{
				Pattern: m.Pattern, Line: m.Line,
				Message: fmt.Sprintf("%q is exempted from authentication with no stated reason", m.Pattern),
			})

		case isPublic:
			// A deliberate exception with a reason. Fine.

		case !m.ViaHandle:
			findings = append(findings, Finding{
				Pattern: m.Pattern, Line: m.Line,
				Message: fmt.Sprintf(
					"%q is mounted with mux.HandleFunc, so it carries NO middleware "+
						"and is reachable without a token.\n"+
						"    Either wrap it:  mux.Handle(%q, authenticated(http.HandlerFunc(h.X)))\n"+
						"    or add it to publicRoutes with the reason it must be public.",
					m.Pattern, m.Pattern),
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
