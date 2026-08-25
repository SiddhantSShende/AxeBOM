package main

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
)

// registerRoutes mounts this service's HTTP surface.
//
// This service's surface is defined in docs/02-CONTRACTS.md §11.
//
// ⚠ NO PUBLIC ROUTES, AND NO INBOUND WEBHOOK ENDPOINT EITHER.
//
// This service SENDS webhooks; it does not receive them. An inbound callback
// route is the shape that usually ends up unauthenticated ("the signature is
// the auth"), and there is nothing here for one to do.
var publicRoutes = map[string]string{}

func registerRoutes(mux *http.ServeMux, d *deps) {
	// Health endpoints (/healthz, /readyz) are mounted separately in main.go.
	h := d.handler
	authenticated := d.identity.Authenticate()

	guard := func(res authz.Resource, act authz.Action, fn http.HandlerFunc) http.Handler {
		return authenticated(auth.Authorize(res, act)(fn))
	}

	// ⚠ SUBSCRIPTIONS ARE A TENANT-LEVEL SETTING, NOT A PROJECT ONE, so they
	// are guarded against `tenant` rather than a resource a project member
	// holds. Creating one directs where this tenant's activity is reported —
	// a decision at the level of the organisation, not of one repository.
	mux.Handle("POST /v1/notifications/subscriptions",
		guard(authz.ResourceTenant, authz.ActionUpdate, h.Create))
	mux.Handle("GET /v1/notifications/subscriptions",
		guard(authz.ResourceTenant, authz.ActionRead, h.List))
	mux.Handle("POST /v1/notifications/subscriptions/{id}/enabled",
		guard(authz.ResourceTenant, authz.ActionUpdate, h.SetEnabled))
	mux.Handle("DELETE /v1/notifications/subscriptions/{id}",
		guard(authz.ResourceTenant, authz.ActionUpdate, h.Delete))

	// The delivery log is how an operator answers "why was I not told?".
	mux.Handle("GET /v1/notifications/subscriptions/{id}/deliveries",
		guard(authz.ResourceTenant, authz.ActionRead, h.Deliveries))

	// The UI renders its event checkboxes from this rather than a hardcoded
	// list, so adding an event to the product adds it to the settings screen.
	mux.Handle("GET /v1/notifications/events",
		guard(authz.ResourceTenant, authz.ActionRead, h.Events))
}
