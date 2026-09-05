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
	"GET /v1/auth/github/connect/authorize": "a browser redirect cannot carry a bearer token; the OAuth state cookie is this flow's CSRF defense, and it mints no AxeBOM session",
	"GET /v1/auth/github/connect/callback":  "same reason as connect/authorize — the redirect back from github.com carries no bearer token either",
}

func registerRoutes(mux *http.ServeMux, d *deps) {
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	h := d.handler

	// --- Public: the GitHub REPOSITORY-CONNECT flow, and nothing else --------
	//
	// ⚠ THIS SECTION USED TO MOUNT THE WHOLE LOCAL-JWT AUTH SURFACE, AND IT WAS
	// STILL UNAUTHENTICATED AND STILL PROXIED BY THE GATEWAY.
	//
	// register / login / refresh / logout / me / invitations / invitations
	// -accept / github-authorize / github-callback were the pre-ZITADEL
	// identity system. Every product service now verifies ZITADEL tokens
	// (see each service's deps.go), so the tokens these minted opened nothing
	// — but that is not the same as being harmless:
	//
	//   * `POST /v1/auth/register` was an UNAUTHENTICATED account-creation and
	//     user-enumeration surface, running in parallel to the sanctioned
	//     `POST /v1/auth/signup` on the gateway, which creates the organisation
	//     and its Owner grant properly. Two ways to make an account, one of
	//     which produced accounts that could not sign in.
	//   * logout / me / invitations were wrapped in `auth.Authenticate(issuer)`
	//     — the LOCAL issuer — so no ZITADEL-authenticated browser could ever
	//     reach them. Permanently 401, for every real user.
	//
	// CLAUDE.md's standing rule is that the hand-rolled auth is deleted once the
	// frontend is on ZITADEL. It is (docs/STATE.md, 2026-08-23 (k) and 08-24).
	// The ROUTES go here; the handlers and the issuer stay for now because the
	// api-keys path below still shares this service's plumbing.
	//
	// What is genuinely still used is the repo-connect pair: a browser redirect
	// to github.com cannot carry a bearer token, and these mint no AxeBOM
	// session — they hand a repo-scoped token straight to Vault.
	mux.HandleFunc("GET /v1/auth/github/connect/authorize", h.GitHubConnectAuthorize)
	mux.HandleFunc("GET /v1/auth/github/connect/callback", h.GitHubConnectCallback)

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
