package main

import (
	"net/http"
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
func registerRoutes(mux *http.ServeMux, d *deps) {
	// Phase 14 adds this service's real routes.
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	_, _ = mux, d
}
