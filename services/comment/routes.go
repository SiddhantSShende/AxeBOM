package main

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
)

// registerRoutes mounts this service's HTTP surface.
//
// This service's surface is defined in docs/02-CONTRACTS.md §8.
//
// ---------------------------------------------------------------------------
// EVERY ROUTE HERE IS AUTHENTICATED. publicRoutes is empty and should stay
// that way: a comment only ever exists attached to a report inside a tenant,
// so there is no operation that can legitimately precede having an identity.
//
// TestEveryRouteIsGuardedOrDeliberatelyPublic parses this file and fails on
// any route mounted with mux.HandleFunc, which carries no middleware.
// ---------------------------------------------------------------------------

// publicRoutes are reachable WITHOUT a token. Adding an entry is a security
// decision; keep the reason with it.
var publicRoutes = map[string]string{}

func registerRoutes(mux *http.ServeMux, d *deps) {
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	h := d.handler
	authenticated := d.identity.Authenticate()

	// guard composes authentication and one matrix cell, so a route's
	// permission is declared next to the handler it protects rather than
	// inferred from a chain somebody has to remember to read.
	guard := func(res authz.Resource, act authz.Action, fn http.HandlerFunc) http.Handler {
		return authenticated(auth.Authorize(res, act)(fn))
	}

	// ⚠ create/update/delete ALL RESOLVE TO ActionCreate/Update/Delete AT THE
	// SAME RoleViewer MINIMUM (libs/go-shared/authz/matrix.go): any tenant
	// member may comment, and may edit or delete their OWN comment. The matrix
	// cannot express "own" — it has no notion of row ownership — so update and
	// delete additionally check authorship inside the handler/store
	// (internal/store.Store.Update / .Delete), which is what actually refuses
	// a Viewer editing someone else's comment, with PERM_COMMENT_NOT_OWNER.
	mux.Handle("GET /v1/comments",
		guard(authz.ResourceComment, authz.ActionRead, h.List))
	mux.Handle("POST /v1/comments",
		guard(authz.ResourceComment, authz.ActionCreate, h.Create))
	mux.Handle("PUT /v1/comments/{id}",
		guard(authz.ResourceComment, authz.ActionUpdate, h.Update))
	mux.Handle("DELETE /v1/comments/{id}",
		guard(authz.ResourceComment, authz.ActionDelete, h.Delete))
}
