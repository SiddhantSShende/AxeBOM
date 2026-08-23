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
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/bus"
	"github.com/encorebom/encorebom/libs/go-shared/events"
	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/orchestr"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/policy"

	"github.com/nats-io/nats.go/jetstream"
)

// Handler serves the scan endpoints.
type Handler struct {
	orch     *orchestr.Orchestrator
	store    *orchestr.Store
	bus      *bus.Bus
	registry *policy.Registry
}

func New(orch *orchestr.Orchestrator, store *orchestr.Store, b *bus.Bus, reg *policy.Registry) *Handler {
	return &Handler{orch: orch, store: store, bus: b, registry: reg}
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type createScanRequest struct {
	ProjectID  string   `json:"project_id"`
	SourceKind string   `json:"source_kind"`
	Families   []string `json:"families"`
	Engines    []string `json:"engines,omitempty"`
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

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

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

	scan, err := h.orch.CreateScan(r.Context(), tenantID, orchestr.CreateScanInput{
		ProjectID:        req.ProjectID,
		SourceKind:       events.SourceKind(req.SourceKind),
		Families:         families,
		RequestedEngines: req.Engines,
		RequestedBy:      ctxkey.UserID(r.Context()),
		TriggeredBy:      "user",
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
func (h *Handler) Engines(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]map[string]any, 0)
	for _, id := range h.registry.IDs() {
		e, _ := h.registry.Get(id)
		out = append(out, map[string]any{
			"engine_id":       e.ID,
			"families":        e.Families,
			"source_kinds":    e.SourceKinds,
			"ecosystems":      e.Ecosystems,
			"produces":        e.Produces,
			"db_backed":       e.DBBacked,
			"default_weight":  e.DefaultWeight,
			"requires_import": e.RequiresImport,
			"is_derived":      e.Derived,
		})
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"engines": out})
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
		// No cross-origin upgrades: the browser's same-origin policy is a real
		// control here, and OriginPatterns would weaken it.
		InsecureSkipVerify: false,
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
