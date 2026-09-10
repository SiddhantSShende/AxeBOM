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
// EVERY ROUTE HERE IS AUTHENTICATED. publicRoutes is empty and should stay that
// way: every one of these is a statement about a project inside a tenant, so
// there is no operation that can legitimately precede having an identity.
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
	authenticated := d.identity.Authenticate()

	// guard composes authentication and one matrix cell, so a route's
	// permission is declared next to the handler it protects rather than
	// inferred from a chain somebody has to remember to read.
	guard := func(res authz.Resource, act authz.Action, fn http.HandlerFunc) http.Handler {
		return authenticated(auth.Authorize(res, act)(fn))
	}

	// --- The inventory, and the half of it a person supplies ----------------
	//
	// ⚠ `/v1/aibom/{projectId}/form` KEEPS ITS PATH AND CHANGES ITS UPSTREAM.
	// The browser already called it; it reached services/project only because
	// that is where the first handler was written. The gateway now routes the
	// whole `/v1/aibom` prefix here, and a prefix claimed by two upstreams is
	// refused at construction — so the move could not have been half-done.
	mux.Handle("GET /v1/aibom/{projectId}/form",
		guard(authz.ResourceAIModel, authz.ActionRead, h.Form))
	mux.Handle("GET /v1/aibom/{projectId}/models",
		guard(authz.ResourceAIModel, authz.ActionList, h.Inventory))
	// ⚠ KEYED BY model_key, NOT BY A ROW ID. Every re-normalization writes new
	// rows (invariant 10), so a row id is valid for one document only and an
	// answer attached to one would be orphaned by the next scan.
	mux.Handle("PUT /v1/aibom/{projectId}/models/{modelKey}/fields",
		guard(authz.ResourceAIModel, authz.ActionUpdate, h.SaveUserFields))

	// --- Consent: the two switches that send code to a third party ----------
	//
	// ⚠ ActionUpdate ON ResourceAIPolicy IS Admin, not Analyst. Editing what a
	// model is for changes one row of a document; consenting to LLM enrichment
	// ships the customer's source to a third party on every future scan.
	mux.Handle("GET /v1/aibom/{projectId}/policy",
		guard(authz.ResourceAIPolicy, authz.ActionRead, h.GetPolicy))
	mux.Handle("PUT /v1/aibom/{projectId}/policy",
		guard(authz.ResourceAIPolicy, authz.ActionUpdate, h.SetPolicy))

	// --- Compliance tagging -------------------------------------------------
	mux.Handle("GET /v1/aibom/{projectId}/tags",
		guard(authz.ResourceAITag, authz.ActionList, h.ListTags))
	mux.Handle("PUT /v1/aibom/{projectId}/tags",
		guard(authz.ResourceAITag, authz.ActionUpdate, h.SaveTag))

	// --- Attestation verification records -----------------------------------
	mux.Handle("GET /v1/aibom/{projectId}/attestations",
		guard(authz.ResourceAIAttestation, authz.ActionList, h.ListAttestations))
	mux.Handle("POST /v1/aibom/{projectId}/attestations",
		guard(authz.ResourceAIAttestation, authz.ActionCreate, h.RecordAttestation))
}
