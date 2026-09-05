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
	authenticated := d.identity.Authenticate()

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

	// --- Web sources ----------------------------------------------------------
	mux.Handle("POST /v1/projects/{id}/web-sources",
		guard(authz.ResourceWebSource, authz.ActionCreate, h.CreateWebSource))
	mux.Handle("GET /v1/projects/{id}/web-sources",
		guard(authz.ResourceWebSource, authz.ActionRead, h.ListWebSources))

	// --- Dependencies and findings -------------------------------------------
	// normalize.components and normalize.findings, read cross-schema — see
	// internal/store/dependencies.go and internal/store/findings.go.
	mux.Handle("GET /v1/projects/{id}/dependencies",
		guard(authz.ResourceDependency, authz.ActionList, h.ListDependencies))
	mux.Handle("GET /v1/projects/{id}/dependencies/{key}",
		guard(authz.ResourceDependency, authz.ActionRead, h.GetComponentDetail))
	mux.Handle("GET /v1/projects/{id}/crypto-assets",
		guard(authz.ResourceCryptoAsset, authz.ActionList, h.ListCryptoAssets))
	mux.Handle("GET /v1/projects/{id}/findings",
		guard(authz.ResourceFinding, authz.ActionList, h.ListFindings))

	// --- Hardware BOM (HBOM) -------------------------------------------------
	// Import plus structured entry — never a scan. See internal/hbom's
	// package doc and frontend/src/lib/hbom.ts's own header comment.
	//
	// Mounted before the {projectId} pattern would matter, same reasoning as
	// /v1/projects/options above: /v1/hbom/preview, /v1/hbom/lookup and
	// /v1/hbom/provider are not scoped to a project and Go's ServeMux would
	// resolve them correctly either way, but declaring them first keeps that
	// obvious to a reader.
	mux.Handle("POST /v1/hbom/preview",
		guard(authz.ResourceHardware, authz.ActionCreate, h.PreviewHBOMImport))
	mux.Handle("POST /v1/hbom/lookup",
		guard(authz.ResourceHardware, authz.ActionCreate, h.LookupParts))
	mux.Handle("GET /v1/hbom/provider",
		guard(authz.ResourceHardware, authz.ActionRead, h.PartProvider))

	mux.Handle("GET /v1/hbom/{projectId}",
		guard(authz.ResourceHardware, authz.ActionRead, h.GetHardwareTree))
	mux.Handle("POST /v1/hbom/{projectId}/components",
		guard(authz.ResourceHardware, authz.ActionCreate, h.SaveHardwareComponent))
	mux.Handle("POST /v1/hbom/{projectId}/import",
		guard(authz.ResourceHardware, authz.ActionCreate, h.ConfirmHBOMImport))
	// ⚠ THE THREE-SEGMENT FORM, BECAUSE THE FRONTEND HAS ALWAYS CALLED IT AND
	// IT HAS ALWAYS 404'd.
	//
	// frontend/src/lib/hbom.ts's useConfirmImport posts to `/v1/hbom/import`
	// with `project_id` in the multipart body. No ServeMux pattern matched
	// three segments, so confirm-import failed for every customer who ever
	// reached the last step of the import wizard — with a 404, which reads as
	// "the feature is not deployed" rather than "you found a bug".
	//
	// Both forms are mounted rather than one being deleted: the path-scoped
	// form is the better shape (the project id is part of the resource, and
	// the route guard can see it), and breaking a client to prove a point is
	// not worth a release. ConfirmHBOMImport already reads `project_id` from
	// the body when the path carries none — see its own comment on which wins.
	mux.Handle("POST /v1/hbom/import",
		guard(authz.ResourceHardware, authz.ActionCreate, h.ConfirmHBOMImport))

	// --- Registered devices --------------------------------------------------
	//
	// ⚠ PROJECT-SCOPED, AND THE OBVIOUS ALTERNATIVE PANICS AT STARTUP.
	//
	// `/v1/hbom/{projectId}/devices` for the list plus
	// `/v1/hbom/devices/{deviceId}` for one device is REFUSED by ServeMux: both
	// match "/v1/hbom/devices/devices" and neither is more specific, so
	// registration panics and the service never starts.
	// TestEveryRoutePatternRegistersWithoutConflict exists because nothing else
	// in this repo builds the mux — the route-guard test parses this file as
	// text and would have passed while the container crash-looped.
	//
	// Scoping every device route under its project is the better shape anyway:
	// the guard sees the project id, and the store scopes on it too, so a device
	// id from another project 404s instead of quietly returning a row the URL
	// says belongs somewhere else.
	mux.Handle("GET /v1/hbom/{projectId}/devices",
		guard(authz.ResourceHardware, authz.ActionRead, h.ListDevices))
	mux.Handle("POST /v1/hbom/{projectId}/devices",
		guard(authz.ResourceHardware, authz.ActionCreate, h.CreateDevice))
	mux.Handle("GET /v1/hbom/{projectId}/devices/{deviceId}",
		guard(authz.ResourceHardware, authz.ActionRead, h.GetDevice))
	mux.Handle("PUT /v1/hbom/{projectId}/devices/{deviceId}",
		guard(authz.ResourceHardware, authz.ActionUpdate, h.UpdateDevice))
	// Retiring a device is Admin — see the authz matrix's note on why the soft
	// delete is gated higher than every edit on the same row.
	mux.Handle("DELETE /v1/hbom/{projectId}/devices/{deviceId}",
		guard(authz.ResourceHardware, authz.ActionDelete, h.DeleteDevice))

	// --- Quantum BOM (QBOM) device metadata ----------------------------------
	// Captured by form, never scanned — CERT-In Table 8 has no open-source
	// discovery tool. See internal/qbom's package doc. Mounted the same
	// shape as hardware BOM above: a form-definition route, a read, and a
	// save that always creates a new normalization version.
	mux.Handle("GET /v1/qbom/{projectId}/form",
		guard(authz.ResourceQuantumDevice, authz.ActionRead, h.GetQBOMForm))
	mux.Handle("GET /v1/qbom/{projectId}",
		guard(authz.ResourceQuantumDevice, authz.ActionRead, h.GetQuantumDevice))
	mux.Handle("POST /v1/qbom/{projectId}/device",
		guard(authz.ResourceQuantumDevice, authz.ActionCreate, h.SaveQuantumDevice))

	// --- AI models (AIBOM) ---------------------------------------------------
	// Discovered by workers/aibom/normalize/pipeline.py, read cross-schema —
	// see internal/store/ai_models.go. Table 10's four user-supplied elements
	// (security requirements, intended usage, out-of-scope usage,
	// attestation) are this service's one write path onto an otherwise
	// Python-normalized row; see internal/aibom's package doc.
	mux.Handle("GET /v1/projects/{id}/ai-models",
		guard(authz.ResourceAIModel, authz.ActionList, h.ListAIModels))
	mux.Handle("GET /v1/aibom/{projectId}/form",
		guard(authz.ResourceAIModel, authz.ActionRead, h.GetAIModelForm))
	mux.Handle("POST /v1/projects/{id}/ai-models/{modelId}/fields",
		guard(authz.ResourceAIModel, authz.ActionUpdate, h.UpdateAIModelUserFields))
}
