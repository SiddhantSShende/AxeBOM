package main

import (
	"net/http"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/authz"
)

// registerRoutes mounts this service's HTTP surface.
//
// GENERATED SCAFFOLD, then hand-edited. The generator writes this file only if
// it does not already exist, so your routes survive a re-run.
//
// Route patterns use Go 1.22+ method-and-pattern syntax ("GET /projects/{id}").
// The pattern — not the concrete path — is what reaches metrics as a label;
// a concrete path would produce unbounded cardinality.
//
// This service's surface is defined in docs/02-CONTRACTS.md §8. Add routes as
// the owning phase implements them; do not invent endpoints here.
//
// ---------------------------------------------------------------------------
// EVERY ROUTE HERE IS AUTHENTICATED. publicRoutes is empty and should stay
// that way: unlike auth, this service has no chicken-and-egg problem — a
// project only exists inside a tenant, so there is no operation that can
// legitimately precede having one.
//
// TestEveryRouteIsGuardedOrDeliberatelyPublic parses this file and fails on any
// route mounted with mux.HandleFunc, which carries no middleware.
// ---------------------------------------------------------------------------

// publicRoutes are reachable WITHOUT a token. Adding an entry is a security
// decision; keep the reason with it.
var publicRoutes = map[string]string{}

func registerRoutes(mux *http.ServeMux, d *deps) {
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	h := d.handler
	authenticated := auth.Authenticate(d.issuer, nil)

	// guard composes authentication and one matrix cell, so a route's
	// permission is declared next to the handler it protects rather than
	// inferred from a chain somebody has to remember to read.
	guard := func(res authz.Resource, act authz.Action, fn http.HandlerFunc) http.Handler {
		return authenticated(auth.Authorize(res, act)(fn))
	}

	// --- Projects -----------------------------------------------------------
	mux.Handle("POST /v1/projects",
		guard(authz.ResourceProject, authz.ActionCreate, h.Create))
	mux.Handle("GET /v1/projects",
		guard(authz.ResourceProject, authz.ActionList, h.List))

	// Mounted before the {id} pattern would matter — Go's ServeMux prefers the
	// more specific literal, but declaring it first keeps the intent obvious to
	// a reader who does not know that rule.
	mux.Handle("GET /v1/projects/options",
		guard(authz.ResourceProject, authz.ActionList, h.Options))

	mux.Handle("GET /v1/projects/{id}",
		guard(authz.ResourceProject, authz.ActionRead, h.Get))
	mux.Handle("PUT /v1/projects/{id}",
		guard(authz.ResourceProject, authz.ActionUpdate, h.Update))
	mux.Handle("DELETE /v1/projects/{id}",
		guard(authz.ResourceProject, authz.ActionDelete, h.Delete))

	// --- Practices ----------------------------------------------------------
	// A distinct resource in the matrix, not folded into project:update. These
	// are a CERT-In minimum element, and who may change a compliance
	// declaration is a different question from who may rename a project.
	mux.Handle("GET /v1/projects/{id}/practices",
		guard(authz.ResourcePractices, authz.ActionRead, h.GetPractices))
	mux.Handle("PUT /v1/projects/{id}/practices",
		guard(authz.ResourcePractices, authz.ActionUpdate, h.SetPractices))

	// --- Repository connections --------------------------------------------
	mux.Handle("POST /v1/projects/{id}/connections",
		guard(authz.ResourceRepoConn, authz.ActionCreate, h.Connect))
	// SERVICE PRINCIPALS ONLY — see handler.Source. RequireService sits inside
	// Authenticate and alongside Authorize: it narrows WHO may call, it does
	// not replace the permission check.
	mux.Handle("GET /v1/projects/{id}/source",
		authenticated(auth.RequireService(
			auth.Authorize(authz.ResourceProject, authz.ActionRead)(http.HandlerFunc(h.Source)))))

	mux.Handle("GET /v1/projects/{id}/connections",
		guard(authz.ResourceRepoConn, authz.ActionRead, h.ListConnections))
	mux.Handle("GET /v1/github/repos",
		guard(authz.ResourceRepoConn, authz.ActionList, h.ListRepos))

	// --- Uploads ------------------------------------------------------------
	mux.Handle("POST /v1/projects/{id}/uploads",
		guard(authz.ResourceUpload, authz.ActionCreate, h.Upload))
	mux.Handle("GET /v1/projects/{id}/uploads",
		guard(authz.ResourceUpload, authz.ActionRead, h.ListUploads))
}
