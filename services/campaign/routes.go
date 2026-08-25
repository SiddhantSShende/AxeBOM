package main

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
)

// registerRoutes mounts this service's HTTP surface.
//
// This service's surface is defined in docs/02-CONTRACTS.md §8. Add routes as
// the owning phase implements them; do not invent endpoints here.
//
// ⚠ THIS SERVICE HAS NO PUBLIC ROUTES, AND SHOULD NOT ACQUIRE ANY. A campaign
// is a standing instruction to scan somebody's source on a schedule; an
// unauthenticated caller who could create or trigger one would have a way to
// make the platform fetch a repository of their choosing, repeatedly, on our
// egress. TestThisServiceHasNoPublicRoutes fails if this map gains an entry.
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

	mux.Handle("POST /v1/campaigns",
		guard(authz.ResourceCampaign, authz.ActionCreate, h.Create))
	mux.Handle("GET /v1/campaigns",
		guard(authz.ResourceCampaign, authz.ActionList, h.List))
	mux.Handle("GET /v1/campaigns/{id}",
		guard(authz.ResourceCampaign, authz.ActionRead, h.Get))
	mux.Handle("PUT /v1/campaigns/{id}",
		guard(authz.ResourceCampaign, authz.ActionUpdate, h.Update))
	mux.Handle("DELETE /v1/campaigns/{id}",
		guard(authz.ResourceCampaign, authz.ActionDelete, h.Delete))

	// ⚠ ENABLING IS `update`, TRIGGERING IS `run`, AND THEY ARE DIFFERENT
	// PERMISSIONS. Turning a campaign on schedules work indefinitely; running
	// it once consumes scan capacity now. A role that may edit a definition is
	// not automatically a role that may spend the platform's compute.
	mux.Handle("POST /v1/campaigns/{id}/enabled",
		guard(authz.ResourceCampaign, authz.ActionUpdate, h.SetEnabled))
	mux.Handle("POST /v1/campaigns/{id}/run",
		guard(authz.ResourceCampaign, authz.ActionRun, h.RunNow))

	mux.Handle("GET /v1/campaigns/{id}/runs",
		guard(authz.ResourceCampaign, authz.ActionRead, h.Runs))
}
