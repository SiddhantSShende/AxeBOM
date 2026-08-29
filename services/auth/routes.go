package main

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
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
// THE ROUTE TABLE IS THE SECURITY BOUNDARY.
//
// Every route is EITHER in publicRoutes — a deliberate, listed exception —
// OR wrapped in Authenticate. There is no third case, and TestEveryRouteIsGuarded
// enumerates this file to prove it. That test exists because "forgot to wrap
// one handler" is the single most common way an authenticated API leaks: it
// produces no error, no log line, and no failing test unless something counts
// the routes.
// ---------------------------------------------------------------------------

// publicRoutes are reachable WITHOUT a token, each for a stated reason.
//
// Adding to this list is a security decision. Keep the reason with the entry so
// the next reader does not have to reconstruct it.
var publicRoutes = map[string]string{
	"POST /v1/auth/register":                "creating the first account cannot require an account",
	"POST /v1/auth/login":                   "the endpoint that issues tokens cannot demand one",
	"POST /v1/auth/refresh":                 "authenticates with the refresh cookie, not a bearer token",
	"GET /v1/auth/github/authorize":         "starts sign-in; no identity exists yet",
	"GET /v1/auth/github/callback":          "authenticated by the OAuth state cookie + code",
	"GET /v1/auth/github/connect/authorize": "a browser redirect cannot carry a bearer token; the OAuth state cookie is this flow's CSRF defense, same as login, and it mints no AxeBOM session",
	"GET /v1/auth/github/connect/callback":  "same reason as connect/authorize — the redirect back from github.com carries no bearer token either",
	"POST /v1/auth/invitations/accept":      "the invitee has no account yet; the invite token is the credential",
}

func registerRoutes(mux *http.ServeMux, d *deps) {
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	h, issuer := d.handler, d.issuer

	// --- Public -------------------------------------------------------------
	mux.HandleFunc("POST /v1/auth/register", h.Register)
	mux.HandleFunc("POST /v1/auth/login", h.Login)
	mux.HandleFunc("POST /v1/auth/refresh", h.Refresh)
	mux.HandleFunc("GET /v1/auth/github/authorize", h.GitHubAuthorize)
	mux.HandleFunc("GET /v1/auth/github/callback", h.GitHubCallback)
	mux.HandleFunc("GET /v1/auth/github/connect/authorize", h.GitHubConnectAuthorize)
	mux.HandleFunc("GET /v1/auth/github/connect/callback", h.GitHubConnectCallback)
	mux.HandleFunc("POST /v1/auth/invitations/accept", h.AcceptInvite)

	// --- Authenticated ------------------------------------------------------
	authenticated := auth.Authenticate(issuer, nil)

	// Logout and /me need identity but no permission: every authenticated
	// caller may end their own session and read their own claims.
	mux.Handle("POST /v1/auth/logout", authenticated(http.HandlerFunc(h.Logout)))
	mux.Handle("GET /v1/auth/me", authenticated(http.HandlerFunc(h.Me)))

	// Inviting is a member:create action. The handler additionally refuses to
	// invite ABOVE the actor's own role — the matrix says "may invite", it
	// cannot say "may invite to which role".
	mux.Handle("POST /v1/auth/invitations", authenticated(
		auth.Authorize(authz.ResourceMember, authz.ActionCreate)(
			http.HandlerFunc(h.CreateInvite))))

	// --- API keys (Phase 16) ---
	//
	// ⚠ ZITADEL-AUTHENTICATED, NOT `authenticated` ABOVE. A person managing
	// their tenant's keys today signs in through ZITADEL like every other
	// screen in the product; the local `issuer` above backs only this
	// service's own pre-ZITADEL routes. See deps.go's identity field.
	zitadel := d.identity.Authenticate()
	mux.Handle("POST /v1/api-keys", zitadel(
		auth.Authorize(authz.ResourceAPIKey, authz.ActionCreate)(
			http.HandlerFunc(h.CreateAPIKey))))
	mux.Handle("GET /v1/api-keys", zitadel(
		auth.Authorize(authz.ResourceAPIKey, authz.ActionList)(
			http.HandlerFunc(h.ListAPIKeys))))
	mux.Handle("DELETE /v1/api-keys/{id}", zitadel(
		auth.Authorize(authz.ResourceAPIKey, authz.ActionDelete)(
			http.HandlerFunc(h.RevokeAPIKey))))

	// --- audit log export (Phase 16) ---
	mux.Handle("GET /v1/audit-log/export", zitadel(
		auth.Authorize(authz.ResourceAuditLog, authz.ActionList)(
			http.HandlerFunc(h.ExportAuditLog))))
}
