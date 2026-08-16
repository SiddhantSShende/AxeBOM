package main

import (
	"context"
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
// Every route is authenticated. TestEveryRouteIsGuardedOrDeliberatelyPublic
// parses this file and fails on any mounted with mux.HandleFunc, which carries
// no middleware.

// publicRoutes are reachable WITHOUT a token. Adding an entry is a security
// decision; keep the reason with it.
var publicRoutes = map[string]string{}

func registerRoutes(mux *http.ServeMux, d *deps) {
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	//
	// The reaper is started here because registerRoutes is a PRESERVED hook
	// that runs once at startup; main.go is regenerated and must not carry
	// hand-written wiring.
	d.StartBackground(context.Background())

	h := d.handler
	authenticated := auth.Authenticate(d.issuer, nil)

	guard := func(res authz.Resource, act authz.Action, fn http.HandlerFunc) http.Handler {
		return authenticated(auth.Authorize(res, act)(fn))
	}

	// Running a scan is an Analyst action: it consumes real compute and
	// produces a compliance artifact.
	mux.Handle("POST /v1/scans",
		guard(authz.ResourceScan, authz.ActionRun, h.Create))

	// Before the {id} pattern, so "engines" is not read as a scan id.
	mux.Handle("GET /v1/scans/engines",
		guard(authz.ResourceScan, authz.ActionList, h.Engines))

	mux.Handle("GET /v1/scans/{id}",
		guard(authz.ResourceScan, authz.ActionRead, h.Get))

	// Engine Coverage — the honest denominator. Readable by anyone who can see
	// the scan, because it belongs in every report they can read.
	mux.Handle("GET /v1/scans/{id}/engine-runs",
		guard(authz.ResourceScan, authz.ActionRead, h.EngineRuns))

	mux.Handle("POST /v1/scans/{id}/cancel",
		guard(authz.ResourceScan, authz.ActionCancel, h.Cancel))

	// The WebSocket authenticates like any other route: the upgrade happens
	// only after Authorize has passed, so a cross-tenant scan is a 404 on the
	// HTTP response rather than an accepted socket that then closes.
	mux.Handle("GET /v1/scans/{id}/progress",
		guard(authz.ResourceScan, authz.ActionRead, h.Progress))
}
