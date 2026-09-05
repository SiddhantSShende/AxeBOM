// Package handler is the scan orchestrator's HTTP surface.
//
// Two things here are worth reading before changing anything:
//
//  1. An invalid engine/source combination is a 422 listing EVERY offending
//     pair. The service layer produces that list; this package must not collapse
//     it to a single message.
//
//  2. The WebSocket sends a SNAPSHOT ON CONNECT, then streams. That snapshot is
//     what makes a lossy event stream acceptable — a client that reconnects
//     mid-scan is immediately correct rather than waiting for the next event to
//     tell it something it can already read from the database.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/policy"

	"github.com/nats-io/nats.go/jetstream"
)

// Handler serves the scan endpoints.
type Handler struct {
	orch        *orchestr.Orchestrator
	store       *orchestr.Store
	bus         *bus.Bus
	registry    *policy.Registry
	policyStore *policy.Store

	// originHost is the public origin the browser actually connects from,
	// parsed once from FrontendURL. See Progress's own comment for why the
	// WebSocket upgrade needs it explicitly rather than trusting r.Host.
	originHost string
}

// New builds a Handler. frontendURL is the same FRONTEND_URL config value
// already threaded into orchestr.Config for notification links (deps.go) —
// reused here, not duplicated, as the one source of truth for "what origin
// does the browser actually use."
func New(
	orch *orchestr.Orchestrator, store *orchestr.Store, b *bus.Bus,
	reg *policy.Registry, policyStore *policy.Store, frontendURL string,
) *Handler {
	h := &Handler{orch: orch, store: store, bus: b, registry: reg, policyStore: policyStore}

	if frontendURL == "" {
		slog.Warn("FRONTEND_URL is empty; the scan progress WebSocket will refuse every " +
			"real browser connection (Origin will never match the proxy-rewritten Host) " +
			"until it is set")
		return h
	}
	u, err := url.Parse(frontendURL)
	if err != nil || u.Host == "" {
		slog.Warn("FRONTEND_URL could not be parsed; the scan progress WebSocket will "+
			"refuse every real browser connection until it is fixed",
			"frontend_url", frontendURL, "error", err)
		return h
	}
	h.originHost = u.Host
	return h
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type createScanRequest struct {
	ProjectID  string   `json:"project_id"`
	SourceKind string   `json:"source_kind"`
	Families   []string `json:"families"`
	Engines    []string `json:"engines,omitempty"`
	// TriggeredBy and TriggerRef are honoured ONLY from a service principal —
	// see triggerFields. The campaign service sends them and they used to be
	// dropped on the floor, because this struct had no field for either.
	TriggeredBy string `json:"triggered_by,omitempty"`
	TriggerRef  string `json:"trigger_ref,omitempty"`
}

type engineRunDTO struct {
	Engine  string `json:"engine"`
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Attempt int    `json:"attempt"`
	Weight  int    `json:"weight"`

	EcosystemsCovered []string `json:"ecosystems_covered"`
	EngineVersion     string   `json:"engine_version,omitempty"`
	// EngineDBVersion is surfaced because a finding that cannot be dated is not
	// defensible — a reader must be able to see "matched against data as of X".
	EngineDBVersion string `json:"engine_db_version,omitempty"`

	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`

	ErrorCode   string              `json:"error_code,omitempty"`
	ErrorDetail string              `json:"error_message,omitempty"`
	Diagnostics []events.Diagnostic `json:"diagnostics,omitempty"`

	// Summary is what this engine counted. Every field is nullable, and null
	// is NOT zero: it means the engine does not measure that dimension. syft
	// catalogues components and matches no vulnerabilities, so rendering
	// "syft: 0 vulnerabilities" would answer a question syft was never asked.
	//
	// Never omitempty — a client must be able to tell "not measured" from a
	// field this server did not send.
	Summary events.Summary `json:"summary"`
}

type scanDTO struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Status    string `json:"status"`

	SourceKind string `json:"source_kind"`
	CommitSHA  string `json:"commit_sha,omitempty"`

	Families []string `json:"families"`
	// EnginesRequested is what was ASKED for, which can differ from what ran.
	// An engine that went unavailable must still appear in Engine Coverage.
	EnginesRequested []string `json:"engines_requested"`

	Progress   int            `json:"progress_pct"`
	EngineRuns []engineRunDTO `json:"engine_runs"`

	// CoverageGaps are ecosystems detected with NO available engine.
	//
	// Surfaced at the top level, not buried: an SBOM that silently omits an
	// ecosystem converts an unknown into a false negative the customer trusts.
	CoverageGaps []string `json:"coverage_gaps"`

	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// scanListItemDTO is scanDTO minus CoverageGaps.
//
// ⚠ THE FIELD IS ABSENT, NOT AN EMPTY ARRAY. CoverageGaps reads
// scan.ecosystems_detected, and computing it for every row of a page would put
// the N+1 straight back that loadRunsFor exists to remove. Sending
// `"coverage_gaps": []` instead would silently claim "no gaps" for a value that
// was never computed — exactly the false negative invariant 12 exists to
// prevent. Leaving the key out is honest about what a list row does not know;
// GET /v1/scans/{id}/engine-runs is where the real answer lives.
type scanListItemDTO struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Status    string `json:"status"`

	SourceKind string `json:"source_kind"`
	CommitSHA  string `json:"commit_sha,omitempty"`

	Families         []string `json:"families"`
	EnginesRequested []string `json:"engines_requested"`

	Progress   int            `json:"progress_pct"`
	EngineRuns []engineRunDTO `json:"engine_runs"`

	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// severityCountsDTO mirrors orchestr.SeverityCounts. See that type for why
// None, Unknown and NotProvided are three separate fields rather than one
// "unknown-ish" bucket.
type severityCountsDTO struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
	Unknown  int `json:"unknown"`
	// json tag matches the vocabulary CLAUDE.md invariant 3 uses everywhere
	// else in this product for "stored explicitly, asserts nothing" — this is
	// that same state applied to a finding's severity.
	NotProvided int `json:"not-provided"`
}

type findingsSummaryDTO struct {
	ScanID string `json:"scan_id"`
	// BOMDocumentID is omitted, not "", when nothing has been normalized yet
	// — the same reasoning scanListItemDTO applies to CoverageGaps: a client
	// must be able to tell "no document" from "a document with an empty id".
	BOMDocumentID string            `json:"bom_document_id,omitempty"`
	Severities    severityCountsDTO `json:"severities"`
	// Always present, even when empty — see EngineRuns.
	CoverageGaps []string `json:"coverage_gaps"`
}

func toFindingsSummaryDTO(s orchestr.FindingsSummary, gaps []string) findingsSummaryDTO {
	return findingsSummaryDTO{
		ScanID:        s.ScanID,
		BOMDocumentID: s.BOMDocumentID,
		Severities: severityCountsDTO{
			Critical:    s.Severities.Critical,
			High:        s.Severities.High,
			Medium:      s.Severities.Medium,
			Low:         s.Severities.Low,
			None:        s.Severities.None,
			Unknown:     s.Severities.Unknown,
			NotProvided: s.Severities.NotProvided,
		},
		CoverageGaps: orEmpty(gaps),
	}
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

// triggerFields classifies ctxkey.UserID's subject into the (triggered_by,
// trigger_ref) pair scan.scans actually stores. trigger_ref is a UUID
// column holding "the user or campaign id behind the scan" (store.go) — it
// has no column that could hold oidcauth's "apikey:<id>"/"service:<name>"
// subject strings, so a non-human principal must leave it empty rather than
// feed that string to the uuid cast, which fails the insert outright. This
// is the CI/scripting path `axebom apikey mint` exists for (and the service
// principal path internal callers use), so both must actually work, not
// only interactive sign-in.
// isServicePrincipal reports whether the caller is another AxeBOM service,
// as opposed to an API key or a signed-in person.
func isServicePrincipal(subject string) bool {
	return strings.HasPrefix(subject, oidcauth.ServiceSubjectPrefix)
}

func triggerFields(subject string) (triggeredBy, requestedBy string) {
	switch {
	case strings.HasPrefix(subject, oidcauth.APIKeySubjectPrefix),
		strings.HasPrefix(subject, oidcauth.ServiceSubjectPrefix):
		return "api", ""
	default:
		return "user", subject
	}
}

// Create handles POST /v1/scans.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req createScanRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	families := make([]events.Family, 0, len(req.Families))
	for _, f := range req.Families {
		families = append(families, events.Family(f))
	}

	// ⚠ LOADED HERE, NOT INSIDE Orchestrator.CreateScan. The orchestrator's
	// job is resolving families into engines; deciding what a tenant has
	// customised is a persistence concern the handler owns, the same
	// separation ListScans/GetScan already draw between this package and
	// orchestr. An explicit per-request `req.Engines` still wins — it is
	// validated in full against the source kind below, and a caller who named
	// engines explicitly asked for exactly those, not this tenant's default.
	overrides, err := h.policyStore.OverridesForTenant(r.Context(), tenantID)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	triggeredBy, requestedBy := triggerFields(ctxkey.UserID(r.Context()))

	// ⚠ A SERVICE PRINCIPAL MAY NAME ITSELF; A BROWSER MAY NOT.
	//
	// The campaign service sends triggered_by=campaign and trigger_ref=<id> so
	// a scan answers "why does this exist?" without a join — and this handler
	// had no field for either, so both were dropped and every scheduled scan
	// would have been recorded as a plain `api` call with no campaign at all.
	//
	// Honoured only for a service principal, whose identity the middleware has
	// already verified. Letting a signed-in user assert `campaign` would let
	// anybody attribute their own scan to an automation that never ran — the
	// same reason triggerFields derives the value rather than reading it.
	if triggeredBy == "api" && isServicePrincipal(ctxkey.UserID(r.Context())) {
		if claimed := strings.TrimSpace(req.TriggeredBy); claimed != "" {
			triggeredBy = claimed
			requestedBy = strings.TrimSpace(req.TriggerRef)
		}
	}

	scan, err := h.orch.CreateScan(r.Context(), tenantID, orchestr.CreateScanInput{
		ProjectID:        req.ProjectID,
		SourceKind:       events.SourceKind(req.SourceKind),
		Families:         families,
		EngineOverrides:  overrides,
		RequestedEngines: req.Engines,
		RequestedBy:      requestedBy,
		TriggeredBy:      triggeredBy,
	})
	if err != nil {
		// The 422 with every offending pair travels through unchanged — the
		// details ARE the value, and flattening them would make the user
		// resubmit once per error.
		errs.Write(w, r, err)
		return
	}

	errs.WriteJSON(w, http.StatusAccepted, h.toDTO(r.Context(), tenantID, scan, nil))
}

// List handles GET /v1/scans.
//
// Keyset on id DESC, mirroring project.Handler.List exactly: the same cursor
// idiom (last id seen, never an offset), the same effectiveLimit clamp, the
// same {resource-plural, next_cursor} envelope. project_id and status are
// optional filters — see orchestr.Store.ListScans for why an absent filter
// matches everything rather than nothing.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	scans, runsByScan, err := h.store.ListScans(r.Context(), tenantID, limit,
		r.URL.Query().Get("cursor"),
		r.URL.Query().Get("project_id"),
		r.URL.Query().Get("status"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	items := make([]scanListItemDTO, 0, len(scans))
	for _, sc := range scans {
		items = append(items, toListItemDTO(sc, runsByScan[sc.ID]))
	}

	// The cursor is the LAST id, because ids are UUIDv7 and therefore ordered.
	// Offset pagination would skip or repeat rows whenever a scan finishes
	// mid-listing — which, unlike a project list, happens constantly here.
	var next string
	if len(scans) > 0 && len(scans) == effectiveLimit(limit) {
		next = scans[len(scans)-1].ID
	}

	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"scans":       items,
		"next_cursor": next,
	})
}

func effectiveLimit(requested int) int {
	if requested <= 0 || requested > 200 {
		return 50
	}
	return requested
}

// Get handles GET /v1/scans/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	scan, runs, err := h.store.GetScan(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapStoreError(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, h.toDTO(r.Context(), tenantID, scan, runs))
}

// EngineRuns handles GET /v1/scans/{id}/engine-runs.
//
// A separate endpoint because this is the Engine Coverage data, and a client
// rendering that section should not have to fetch and discard a whole scan.
func (h *Handler) EngineRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	_, runs, err := h.store.GetScan(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapStoreError(err))
		return
	}

	gaps, _ := h.store.CoverageGaps(r.Context(), tenantID, r.PathValue("id"))
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"engine_runs": toRunDTOs(runs),
		// Always present, even when empty: a client must be able to tell
		// "no gaps" from "the field is missing".
		"coverage_gaps": orEmpty(gaps),
		"note": "Engine Coverage lists every requested engine and every ecosystem " +
			"detected with no available engine. An omitted ecosystem would be a " +
			"false negative rather than an unknown.",
	})
}

// FindingsSummary handles GET /v1/scans/{id}/findings-summary.
//
// ⚠ TWO SCHEMAS, STITCHED HERE, NOT ONE SQL JOIN — see orchestr/findings.go.
//
// GetScan runs FIRST and its result is otherwise discarded: it is the only
// thing that can tell a cross-tenant scan id apart from one with nothing
// normalized yet, both of which look like zero rows from inside normalize.*
// alone. Skipping it would turn a cross-tenant id into 200 with an all-zero
// summary — an oracle for probing which scans exist — instead of the 404
// every other scan endpoint gives that id.
func (h *Handler) FindingsSummary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	scanID := r.PathValue("id")

	if _, _, err := h.store.GetScan(r.Context(), tenantID, scanID); err != nil {
		errs.Write(w, r, mapStoreError(err))
		return
	}

	summary, err := h.store.FindingsSummary(r.Context(), tenantID, scanID)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	// CoverageGaps does not depend on normalization having run — it reads
	// scan.ecosystems_detected, populated as engines report — so it is
	// available even for a scan whose SBOM is not normalized yet, and it
	// answers a different question than the severity counts: zero findings
	// and "no engine covered this ecosystem" are different facts, and a
	// client rendering one number needs to be able to show the other.
	gaps, _ := h.store.CoverageGaps(r.Context(), tenantID, scanID)

	errs.WriteJSON(w, http.StatusOK, toFindingsSummaryDTO(summary, gaps))
}

// Cancel handles POST /v1/scans/{id}/cancel.
func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	scanID := r.PathValue("id")

	// Read first, so a cross-tenant cancel is a 404 rather than a silent no-op
	// that returns 204 and tells the caller the id exists.
	scan, _, err := h.store.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		errs.Write(w, r, mapStoreError(err))
		return
	}
	if scan.Status == events.ScanCompleted || scan.Status == events.ScanFailed ||
		scan.Status == events.ScanCompletedWithErrors {
		errs.Write(w, r, errs.Newf(errs.ValidationFieldInvalid,
			"this scan already finished with status %q", scan.Status))
		return
	}

	if err := h.store.UpdateScanStatus(r.Context(), tenantID, scanID, events.ScanCancelled); err != nil {
		errs.Write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Engines handles GET /v1/scans/engines.
//
// Serves the registry so the UI can show what will run, including the honest
// labels — HBOM is import-only, QBOM is derived — as data rather than as
// frontend copy that can drift.
//
// ⚠ `?project_id=` IS OPTIONAL AND ADDITIVE. Without it, this is the same
// static registry it always was. With it, each engine also carries
// `last_run` — that project's most recent invocation of this engine, however
// long ago — so the Engine Coverage panel can show "never run" as an honest,
// distinct state from "ran and failed" rather than collapsing both into
// silence (CLAUDE.md invariant #12).
func (h *Handler) Engines(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var latest map[string]orchestr.EngineRun
	if projectID := r.URL.Query().Get("project_id"); projectID != "" {
		latest, err = h.store.LatestEngineRunsForProject(r.Context(), tenantID, projectID)
		if err != nil {
			errs.Write(w, r, err)
			return
		}
	}

	out := make([]map[string]any, 0)
	for _, id := range h.registry.IDs() {
		e, _ := h.registry.Get(id)

		// ⚠ SCAFFOLDS ARE NOT PART OF THE PRODUCT AND MUST NOT BE LISTED.
		// Marking `mock-engine` as a scaffold stopped it being DISPATCHED, but
		// this endpoint enumerates the whole registry by id — so Settings →
		// Engines kept showing customers a fake scanner they could read
		// ecosystems and weights for, and a tenant could "enable" it. Excluding
		// it from dispatch and listing it in the UI is the same drift in two
		// directions.
		if e.Scaffold {
			continue
		}

		row := map[string]any{
			"engine_id":       e.ID,
			"mode":            e.Mode,
			"families":        e.Families,
			"source_kinds":    e.SourceKinds,
			"ecosystems":      e.Ecosystems,
			"produces":        e.Produces,
			"db_backed":       e.DBBacked,
			"default_weight":  e.DefaultWeight,
			"requires_import": e.RequiresImport,
			"is_derived":      e.Derived,
		}
		if e.OperatorAction != "" {
			// What a person must DO for this engine to have anything to read.
			// Absent for engines that just run, so the UI can show an
			// instruction only where one exists.
			row["operator_action"] = e.OperatorAction
		}
		if run, ok := latest[e.ID]; ok {
			row["last_run"] = map[string]any{
				"scan_id":     run.ScanID,
				"status":      run.Status,
				"started_at":  run.StartedAt,
				"finished_at": run.FinishedAt,
				"error_code":  run.ErrorCode,
			}
		}
		out = append(out, row)
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"engines": out})
}

// ---------------------------------------------------------------------------
// Engine policy — configurable tool management
// ---------------------------------------------------------------------------

// configurableFamilies are the families a tenant may customise. Deliberately
// excludes "fetch" (not a BOM family a tenant reasons about) but INCLUDES
// hbom and qbom — a row for either is harmless (rejectNonScannableFamilies
// still refuses to ever schedule a job for them) and future-proofs the store
// against a family that later grows a real engine.
var configurableFamilies = map[string]bool{
	"sbom": true, "cbom": true, "qbom": true, "aibom": true, "hbom": true,
}

type enginePolicyDTO struct {
	Family    string         `json:"family"`
	EngineIDs []string       `json:"engine_ids"`
	Weights   map[string]int `json:"weights"`
	Enabled   bool           `json:"enabled"`
	Note      string         `json:"note,omitempty"`
}

func toEnginePolicyDTO(p policy.EnginePolicy) enginePolicyDTO {
	return enginePolicyDTO{
		Family: string(p.Family), EngineIDs: p.EngineIDs,
		Weights: p.Weights, Enabled: p.Enabled, Note: p.Note,
	}
}

// EnginePolicyList handles GET /v1/scans/engine-policy.
//
// Returns only the families this tenant has customised — an absent family
// means "use the built-in default", the same convention the migration
// documents. The UI renders all five BOM types regardless; this is the
// overlay, not the whole picture (h.Engines is the whole picture).
func (h *Handler) EnginePolicyList(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	rows, err := h.policyStore.ListForTenant(r.Context(), tenantID)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	out := make([]enginePolicyDTO, 0, len(rows))
	for _, p := range rows {
		out = append(out, toEnginePolicyDTO(p))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"engine_policies": out})
}

type enginePolicyUpsertRequest struct {
	EngineIDs []string       `json:"engine_ids"`
	Weights   map[string]int `json:"weights"`
	Enabled   *bool          `json:"enabled"`
	Note      string         `json:"note"`
}

// EnginePolicyUpsert handles PUT /v1/scans/engine-policy/{family}.
//
// ⚠ EVERY engine_id IS VALIDATED AGAINST THE REGISTRY AND ITS FAMILY, HERE —
// NOT LEFT FOR THE NEXT SCAN TO DISCOVER. Storing an unknown or wrong-family
// engine id would silently drop it from every future scan's fan-out
// (Registry.Resolve skips ids it cannot find), which is the same
// discover-it-at-worker-time failure CreateScan's own validation exists to
// avoid — just moved from scan time to configuration time.
func (h *Handler) EnginePolicyUpsert(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	family := r.PathValue("family")
	if !configurableFamilies[family] {
		errs.Write(w, r, errs.Newf(errs.ValidationFieldInvalid,
			"family must be one of sbom, cbom, qbom, aibom, hbom (got %q)", family))
		return
	}

	var req enginePolicyUpsertRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	var unknown []string
	for _, id := range req.EngineIDs {
		e, ok := h.registry.Get(id)
		if !ok || !e.InFamily(events.Family(family)) {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		engErr := errs.Newf(errs.ValidationFieldInvalid,
			"%d engine id(s) are not valid for family %q: %s",
			len(unknown), family, strings.Join(unknown, ", "))
		for _, id := range unknown {
			engErr = engErr.WithDetail(errs.Detail{"engine": id, "family": family})
		}
		errs.Write(w, r, engErr)
		return
	}

	// Enabled defaults to true — an operator setting only engine_ids to pin a
	// smaller set should not have to also remember to pass enabled:true.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	p, err := h.policyStore.Upsert(r.Context(), tenantID, events.Family(family),
		req.EngineIDs, req.Weights, enabled, req.Note)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toEnginePolicyDTO(p))
}

// EnginePolicyDelete handles DELETE /v1/scans/engine-policy/{family}. Reverts
// the family to the built-in default by removing the tenant's override row.
func (h *Handler) EnginePolicyDelete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	family := r.PathValue("family")
	if !configurableFamilies[family] {
		errs.Write(w, r, errs.Newf(errs.ValidationFieldInvalid,
			"family must be one of sbom, cbom, qbom, aibom, hbom (got %q)", family))
		return
	}
	if err := h.policyStore.Delete(r.Context(), tenantID, events.Family(family)); err != nil {
		errs.Write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// WebSocket progress
// ---------------------------------------------------------------------------

// wsMessage is what the socket sends.
type wsMessage struct {
	// Type is "snapshot" or "event". A client must be able to tell the
	// authoritative state from an advisory update without inspecting shape.
	Type     string              `json:"type"`
	Snapshot *scanDTO            `json:"snapshot,omitempty"`
	Event    *events.ScanEventV1 `json:"event,omitempty"`
}

// Progress handles GET /v1/scans/{id}/progress as a WebSocket.
//
// ⚠ THE SNAPSHOT ON CONNECT IS WHAT MAKES A LOSSY STREAM ACCEPTABLE.
//
// Events are advisory and the database is the source of truth. A client that
// connects mid-scan, or reconnects after a drop, gets the FULL CURRENT STATE
// first and is immediately correct — it never has to reconstruct state by
// replaying a stream it may have missed part of.
//
// Without the snapshot, a reconnecting client shows a scan at 0% until the next
// event arrives, which for a slow engine could be minutes.
func (h *Handler) Progress(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	scanID := r.PathValue("id")

	// Authorize BEFORE upgrading. A cross-tenant scan must be a 404 on the HTTP
	// response, not an accepted socket that then closes — the latter tells the
	// caller the id exists.
	scan, runs, err := h.store.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		errs.Write(w, r, mapStoreError(err))
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// ⚠ InsecureSkipVerify STAYS false — the browser's same-origin policy
		// is a real control here. OriginPatterns is NOT a weakening of it: it
		// is what makes the check actually work behind this deployment's
		// reverse proxy.
		//
		// coder/websocket's own same-origin check (accept.go's
		// authenticateOrigin) auto-authorizes only when the request's Host
		// equals the Origin header's host — "the request host is always
		// authorized" — which assumes Host still reflects the browser's real,
		// public-facing address. It does not here: gateway's reverse proxy
		// deliberately rewrites Host to the upstream's own address before
		// this handler ever sees the request (services/gateway/internal/
		// proxy/proxy.go's Rewrite — correct and necessary for ordinary HTTP
		// routing across every OTHER route). Left as InsecureSkipVerify:false
		// with no OriginPatterns, EVERY real browser handshake here got a
		// pre-101 403 — Origin said the public host, Host said
		// "scan-orchestrator:8093", and neither matched — while curl (which
		// sends no Origin header at all) sailed through untouched, masking
		// the bug from every curl-based check performed while diagnosing it.
		// originHost is the one value that actually reflects the browser's
		// real origin in this topology; see New's doc comment.
		InsecureSkipVerify: false,
		OriginPatterns:     []string{h.originHost},
		// ⚠ THIS IS NOT DECORATION. The browser cannot put an Authorization
		// header on a handshake, so the SPA offers its access token as a second
		// subprotocol (oidcauth.WSBearerPrefix) alongside this one. RFC 6455
		// says a server that selects NONE of the offered protocols makes the
		// client fail the connection — so omitting this list would reject every
		// authenticated browser socket while leaving curl working perfectly.
		Subprotocols: []string{oidcauth.WSSubprotocol},
	})
	if err != nil {
		return // Accept already answered
	}
	defer func() { _ = conn.CloseNow() }()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()

	// 1. THE SNAPSHOT, FIRST, ALWAYS.
	snapshot := h.toDTO(ctx, tenantID, scan, runs)
	if err := wsjson.Write(ctx, conn, wsMessage{Type: "snapshot", Snapshot: &snapshot}); err != nil {
		return
	}

	// A terminal scan needs no stream. Sending the snapshot and closing is the
	// whole correct answer.
	if isTerminal(scan.Status) {
		_ = conn.Close(websocket.StatusNormalClosure, "scan already finished")
		return
	}

	// 2. Then the advisory stream.
	h.streamEvents(ctx, conn, scanID)
}

// streamEvents forwards advisory events until the context ends.
func (h *Handler) streamEvents(ctx context.Context, conn *websocket.Conn, scanID string) {
	subject := "scan.event." + scanID

	// An EPHEMERAL consumer: this subscription belongs to one browser tab, and
	// a durable would accumulate one consumer per page load forever.
	consumer, err := h.bus.JetStream().CreateConsumer(ctx, bus.StreamEvents, jetstream.ConsumerConfig{
		FilterSubject: subject,
		AckPolicy:     jetstream.AckNonePolicy, // advisory; nothing to ack
		// Only what arrives from now on. The snapshot already covered history,
		// and replaying it would double-count in the client.
		DeliverPolicy:     jetstream.DeliverNewPolicy,
		InactiveThreshold: 5 * time.Minute,
	})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "could not subscribe")
		return
	}

	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		var e events.ScanEventV1
		if err := events.Decode(msg.Data(), &e); err != nil {
			return
		}
		// Best effort. A slow client that cannot keep up is disconnected by the
		// write error, and it will reconnect and get a fresh snapshot — which
		// is exactly the design working.
		_ = wsjson.Write(ctx, conn, wsMessage{Type: "event", Event: &e})
	})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "could not consume")
		return
	}
	defer cc.Stop()

	// Block until the client goes away or the context expires.
	<-ctx.Done()
	_ = conn.Close(websocket.StatusNormalClosure, "")
}

func isTerminal(s events.ScanStatus) bool {
	switch s {
	case events.ScanCompleted, events.ScanCompletedWithErrors,
		events.ScanFailed, events.ScanCancelled:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

func (h *Handler) toDTO(ctx context.Context, tenantID string, scan orchestr.Scan, runs []orchestr.EngineRun) scanDTO {
	if runs == nil {
		if _, loaded, err := h.store.GetScan(ctx, tenantID, scan.ID); err == nil {
			runs = loaded
		}
	}
	gaps, _ := h.store.CoverageGaps(ctx, tenantID, scan.ID)

	return scanDTO{
		ID: scan.ID, ProjectID: scan.ProjectID,
		Status:           string(scan.Status),
		SourceKind:       string(scan.SourceKind),
		CommitSHA:        scan.CommitSHA,
		Families:         orEmpty(scan.Families),
		EnginesRequested: orEmpty(scan.EnginesRequested),
		// Computed SERVER-SIDE from engine weights. A client cannot know that
		// dependency-check is worth less than syft.
		Progress:     orchestr.Progress(runs),
		EngineRuns:   toRunDTOs(runs),
		CoverageGaps: orEmpty(gaps),
		CreatedAt:    scan.CreatedAt.UTC(),
		StartedAt:    scan.StartedAt,
		FinishedAt:   scan.FinishedAt,
	}
}

// toListItemDTO is toDTO without the two per-row queries List cannot afford:
// runs come from the page's single batched load, and CoverageGaps is not
// computed at all — see scanListItemDTO.
func toListItemDTO(scan orchestr.Scan, runs []orchestr.EngineRun) scanListItemDTO {
	return scanListItemDTO{
		ID: scan.ID, ProjectID: scan.ProjectID,
		Status:           string(scan.Status),
		SourceKind:       string(scan.SourceKind),
		CommitSHA:        scan.CommitSHA,
		Families:         orEmpty(scan.Families),
		EnginesRequested: orEmpty(scan.EnginesRequested),
		Progress:         orchestr.Progress(runs),
		EngineRuns:       toRunDTOs(runs),
		CreatedAt:        scan.CreatedAt.UTC(),
		StartedAt:        scan.StartedAt,
		FinishedAt:       scan.FinishedAt,
	}
}

func toRunDTOs(runs []orchestr.EngineRun) []engineRunDTO {
	out := make([]engineRunDTO, 0, len(runs))
	for _, r := range runs {
		out = append(out, engineRunDTO{
			Engine: r.EngineID, JobID: r.JobID, Status: string(r.Status),
			Attempt: r.Attempt, Weight: r.Weight,
			EcosystemsCovered: orEmpty(r.EcosystemsCovered),
			EngineVersion:     r.EngineVersion,
			EngineDBVersion:   r.EngineDBVersion,
			StartedAt:         r.StartedAt,
			FinishedAt:        r.FinishedAt,
			ErrorCode:         r.ErrorCode,
			ErrorDetail:       r.ErrorMessage,
			Diagnostics:       r.Diagnostics,
			Summary:           r.Summary,
		})
	}
	return out
}

// orEmpty renders a nil slice as [] rather than null, so a client can length-
// check without a null guard on every field.
func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func mapStoreError(err error) error {
	if errors.Is(err, orchestr.ErrNotFound) {
		// 404, never 403: a 403 confirms the id exists.
		return errs.New(errs.NotFoundScan, "no such scan")
	}
	return err
}

const maxBodyBytes = 1 << 20

func decode(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()

	if err := dec.Decode(into); err != nil {
		if errors.Is(err, io.EOF) {
			return errs.New(errs.ValidationBodyMalformed, "request body is empty")
		}
		return errs.Wrap(err, errs.ValidationBodyMalformed, "request body is not valid JSON")
	}
	return nil
}
