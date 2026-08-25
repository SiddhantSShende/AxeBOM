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
// ⚠ THIS SERVICE HAS THE ONLY UNAUTHENTICATED DATA ROUTE IN THE PRODUCT.
//
// `/shared/{token}` serves tenant data to whoever holds a link. It is listed in
// publicRoutes with its reason, and TestEveryRouteIsGuardedOrDeliberatelyPublic
// parses this file and fails on any OTHER route mounted with mux.HandleFunc —
// which carries no middleware.
//
// Everything that makes that route safe is in the handler and the database, not
// in a middleware chain: shape-checked token, atomic claim against the download
// cap, audited attempt, `attachment` + `nosniff` + `no-store`, and rate
// limiting by IP applied below.
// ---------------------------------------------------------------------------

// publicRoutes are reachable WITHOUT a token. Adding an entry is a security
// decision; keep the reason with it.
var publicRoutes = map[string]string{
	"GET /shared/{token}": "the share link IS the credential. There is no " +
		"identity to authenticate: minting the link is the authorization step " +
		"(share_link:share requires Analyst), the token carries 256 bits of " +
		"entropy, every access is audited, and the download cap and expiry are " +
		"enforced atomically in Postgres.",
}

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

	// --- Reports ------------------------------------------------------------
	mux.Handle("POST /v1/reports",
		guard(authz.ResourceReport, authz.ActionCreate, h.Create))
	mux.Handle("GET /v1/reports",
		guard(authz.ResourceReport, authz.ActionList, h.List))
	mux.Handle("GET /v1/reports/{id}",
		guard(authz.ResourceReport, authz.ActionRead, h.Get))

	// ⚠ The matrix cell here is only HALF the check. Every role from Viewer up
	// holds (report, download); whether THIS report may be downloaded depends
	// on its visibility, which is a property of the row. The handler calls
	// authz.CanDownloadReport once it has read it (CERT-In §5.3.2).
	mux.Handle("GET /v1/reports/{id}/download",
		guard(authz.ResourceReport, authz.ActionDownload, h.Download))

	// The detached signature is metadata about a report, not the report — a
	// Viewer who may not download a private artifact may still see that it was
	// signed and by which key.
	mux.Handle("GET /v1/reports/{id}/signature",
		guard(authz.ResourceReport, authz.ActionRead, h.Signature))

	// --- Share links --------------------------------------------------------
	// A distinct resource in the matrix, not folded into report:read. Minting a
	// link exposes data OUTSIDE the tenant, which is a different question from
	// who may read a report inside it.
	mux.Handle("POST /v1/reports/{id}/shares",
		guard(authz.ResourceShareLink, authz.ActionShare, h.Share))
	mux.Handle("GET /v1/reports/{id}/shares",
		guard(authz.ResourceShareLink, authz.ActionRead, h.ListShares))
	mux.Handle("DELETE /v1/shares/{share_id}",
		guard(authz.ResourceShareLink, authz.ActionDelete, h.Revoke))
	mux.Handle("GET /v1/shares/{share_id}/accesses",
		guard(authz.ResourceShareLink, authz.ActionRead, h.ShareAccessLog))

	// --- CSAF advisories ------------------------------------------------------
	// Project-scoped, not report-scoped — like the VEX statements they
	// publish (services/scan-orchestrator/routes.go's own comment on why),
	// an advisory is a fact about a project's vulnerability landscape, not
	// tied to one rendered report.
	mux.Handle("POST /v1/csaf/{projectId}/advisories",
		guard(authz.ResourceCSAF, authz.ActionCreate, h.GenerateCSAFAdvisory))
	mux.Handle("GET /v1/csaf/{projectId}/advisories",
		guard(authz.ResourceCSAF, authz.ActionRead, h.ListCSAFAdvisories))

	// --- The anonymous download ---------------------------------------------
	//
	// ⚠ RATE LIMITED BY IP, AND THAT IS NOT OPTIONAL HERE.
	//
	// Every other route is bounded by a token that had to be issued. This one
	// is reachable by anyone, so without a limit it is a free oracle: an
	// attacker can probe tokens as fast as the network allows. The limit does
	// not make a 256-bit token guessable — nothing does — but it stops the
	// endpoint from being a convenient amplifier and bounds the audit-log write
	// volume a stranger can force.
	mux.Handle("GET /shared/{token}", d.sharedLimiter(http.HandlerFunc(h.Shared)))
}
