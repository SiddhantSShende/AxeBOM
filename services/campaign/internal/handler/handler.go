// Package handler is the campaign service's HTTP surface.
//
// The tenant comes from auth.RequireTenant — the VERIFIED token in the context
// and nothing else. A campaign id in a path is never enough to identify a
// resource; it is always (tenant, id), and a cross-tenant read returns 404
// because RLS filtered the row out and "no such campaign" is the honest answer.
//
// ⚠ THE SCHEDULE IS VALIDATED AT WRITE TIME, NOT AT FIRE TIME.
//
// An unparseable cron or a timezone this host's database does not know is a
// 400 naming the field, here, while somebody is looking at the form. Accepting
// it and discovering the problem in a background tick means the failure surfaces
// at 02:30 on a Tuesday, in a log nobody reads, as a campaign that simply never
// runs — and "never ran" is the one failure a compliance customer finds at
// audit rather than in the product.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/campaign/internal/store"
)

const maxRequestBody = 1 << 20

// Store is the persistence this handler needs.
type Store interface {
	Create(ctx context.Context, tenantID string, c store.Campaign) (store.Campaign, error)
	Get(ctx context.Context, tenantID, id string) (store.Campaign, error)
	List(ctx context.Context, tenantID string, limit int) ([]store.Campaign, error)
	Update(ctx context.Context, tenantID, id string, c store.Campaign, now time.Time) (store.Campaign, error)
	SetEnabled(ctx context.Context, tenantID, id string, enabled bool, now time.Time) (store.Campaign, error)
	Delete(ctx context.Context, tenantID, id string) error
	ListRuns(ctx context.Context, tenantID, campaignID string, limit int) ([]store.Run, error)
}

// RunNow triggers a campaign immediately.
type RunNow interface {
	RunNow(ctx context.Context, tenantID, campaignID string, at time.Time) (runID string, scanIDs []string, err error)
}

// Handler serves the campaign endpoints.
type Handler struct {
	store  Store
	runNow RunNow
	now    func() time.Time
}

// New builds a handler. A nil clock uses time.Now.
func New(s Store, runNow RunNow, now func() time.Time) *Handler {
	if now == nil {
		now = time.Now
	}
	return &Handler{store: s, runNow: runNow, now: now}
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type campaignResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	ProjectIDs []string `json:"project_ids"`

	CronExpr string `json:"cron_expr"`
	Timezone string `json:"timezone"`

	BOMTypes     []string `json:"bom_types"`
	ReportLevels []string `json:"report_levels"`
	Standards    []string `json:"standards"`
	Formats      []string `json:"formats"`

	Enabled   bool   `json:"enabled"`
	NextRunAt string `json:"next_run_at,omitempty"`
	LastRunAt string `json:"last_run_at,omitempty"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toResponse(c store.Campaign) campaignResponse {
	out := campaignResponse{
		ID: c.ID, Name: c.Name,
		ProjectIDs: nonNil(c.ProjectIDs),
		CronExpr:   c.CronExpr, Timezone: c.Timezone,
		BOMTypes:     nonNil(c.BOMTypes),
		ReportLevels: nonNil(c.ReportLevels),
		Standards:    nonNil(c.Standards),
		Formats:      nonNil(c.Formats),
		Enabled:      c.Enabled,
		CreatedAt:    c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:    c.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if c.NextRunAt != nil {
		out.NextRunAt = c.NextRunAt.UTC().Format(time.RFC3339)
	}
	if c.LastRunAt != nil {
		out.LastRunAt = c.LastRunAt.UTC().Format(time.RFC3339)
	}
	return out
}

type runResponse struct {
	ID           string   `json:"id"`
	CampaignID   string   `json:"campaign_id"`
	ScheduledFor string   `json:"scheduled_for"`
	StartedAt    string   `json:"started_at,omitempty"`
	FinishedAt   string   `json:"finished_at,omitempty"`
	Status       string   `json:"status"`
	SkipReason   string   `json:"skip_reason,omitempty"`
	ScanIDs      []string `json:"scan_ids"`
	Error        string   `json:"error,omitempty"`
}

func toRunResponse(r store.Run) runResponse {
	out := runResponse{
		ID: r.ID, CampaignID: r.CampaignID,
		ScheduledFor: r.ScheduledFor.UTC().Format(time.RFC3339),
		Status:       r.Status,
		// ⚠ SKIPPED RUNS CARRY THEIR REASON TO THE CLIENT. The run-history UI
		// showing a gap with no explanation is barely better than no row at
		// all; the point of recording a missed occurrence is that somebody can
		// see WHY it was missed.
		SkipReason: r.SkipReason,
		ScanIDs:    nonNil(r.ScanIDs),
		Error:      r.Error,
	}
	if r.StartedAt != nil {
		out.StartedAt = r.StartedAt.UTC().Format(time.RFC3339)
	}
	if r.FinishedAt != nil {
		out.FinishedAt = r.FinishedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// nonNil turns a nil slice into an empty one.
//
// A JSON `null` where the client expects a list is a class of frontend crash
// that only appears for the empty case — which is every newly created campaign.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

type campaignRequest struct {
	Name         string   `json:"name"`
	ProjectIDs   []string `json:"project_ids"`
	CronExpr     string   `json:"cron_expr"`
	Timezone     string   `json:"timezone"`
	BOMTypes     []string `json:"bom_types"`
	ReportLevels []string `json:"report_levels"`
	Standards    []string `json:"standards"`
	Formats      []string `json:"formats"`
	Enabled      bool     `json:"enabled"`
}

// validate checks a campaign request and returns the first occurrence.
func (req campaignRequest) validate(now time.Time) (time.Time, error) {
	if req.Name == "" {
		return time.Time{}, errs.New(errs.ValidationFieldRequired, "name is required")
	}
	if len(req.ProjectIDs) == 0 {
		return time.Time{}, errs.New(errs.ValidationFieldRequired,
			"a campaign needs at least one project")
	}
	if len(req.BOMTypes) == 0 {
		return time.Time{}, errs.New(errs.ValidationFieldRequired,
			"a campaign needs at least one BOM type")
	}
	if len(req.Formats) == 0 {
		return time.Time{}, errs.New(errs.ValidationFieldRequired,
			"a campaign needs at least one report format")
	}

	// ⚠ THIS IS THE WRITE-TIME SCHEDULE CHECK. store.FirstOccurrence parses the
	// cron AND loads the timezone, so both failures become a 400 here instead
	// of a campaign that silently never fires.
	next, err := store.FirstOccurrence(req.CronExpr, req.Timezone, now)
	if err != nil {
		return time.Time{}, errs.Wrap(err, errs.ValidationFieldInvalid, err.Error())
	}
	return next, nil
}

func (req campaignRequest) toStore() store.Campaign {
	return store.Campaign{
		Name:       req.Name,
		ProjectIDs: req.ProjectIDs,
		CronExpr:   req.CronExpr,
		Timezone:   req.Timezone,
		BOMTypes:   req.BOMTypes, ReportLevels: req.ReportLevels,
		Standards: req.Standards, Formats: req.Formats,
		Enabled: req.Enabled,
	}
}

// Create registers a campaign.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	userID := ctxkey.UserID(r.Context())

	var req campaignRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	next, err := req.validate(h.now())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	c := req.toStore()
	c.CreatedBy = userID
	if req.Enabled {
		c.NextRunAt = &next
	}

	created, err := h.store.Create(r.Context(), tenantID, c)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toResponse(created))
}

// Get returns one campaign.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	c, err := h.store.Get(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, toResponse(c))
}

// List returns a tenant's campaigns.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	campaigns, err := h.store.List(r.Context(), tenantID, limit)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]campaignResponse, 0, len(campaigns))
	for _, c := range campaigns {
		out = append(out, toResponse(c))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"campaigns": out})
}

// Update changes a campaign's definition.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req campaignRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}
	if _, err := req.validate(h.now()); err != nil {
		errs.Write(w, r, err)
		return
	}

	updated, err := h.store.Update(r.Context(), tenantID, r.PathValue("id"), req.toStore(), h.now())
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, toResponse(updated))
}

// SetEnabled turns a campaign on or off.
func (h *Handler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	updated, err := h.store.SetEnabled(r.Context(), tenantID, r.PathValue("id"), req.Enabled, h.now())
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, toResponse(updated))
}

// Delete removes a campaign.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	if err := h.store.Delete(r.Context(), tenantID, r.PathValue("id")); err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Runs returns a campaign's history.
func (h *Handler) Runs(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	// The campaign is read first so a cross-tenant id 404s on the campaign
	// rather than returning an empty run list, which would be an existence
	// oracle by omission.
	campaignID := r.PathValue("id")
	if _, err := h.store.Get(r.Context(), tenantID, campaignID); err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := h.store.ListRuns(r.Context(), tenantID, campaignID, limit)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]runResponse, 0, len(runs))
	for _, run := range runs {
		out = append(out, toRunResponse(run))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"runs": out})
}

// RunNow triggers a campaign immediately.
//
// ⚠ IT GOES THROUGH THE SAME CLAIM PATH AS A SCHEDULED RUN, so a manual trigger
// and a tick landing on the same second produce one run rather than two. The
// occurrence it claims is the current instant, which cannot collide with a cron
// slot at second-zero granularity — but the constraint is what guarantees it,
// not the arithmetic.
func (h *Handler) RunNow(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	if h.runNow == nil {
		errs.Write(w, r, errs.New(errs.NotFoundResource, "manual triggering is not configured"))
		return
	}

	campaignID := r.PathValue("id")
	if _, err := h.store.Get(r.Context(), tenantID, campaignID); err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	runID, scanIDs, err := h.runNow.RunNow(r.Context(), tenantID, campaignID, h.now())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	errs.WriteJSON(w, http.StatusAccepted, map[string]any{
		"run_id":   runID,
		"scan_ids": nonNil(scanIDs),
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	// Strict: a typo'd field in a user's request is a mistake worth reporting.
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errs.Newf(errs.ValidationFieldInvalid, "malformed request body: %v", err)
	}
	return nil
}

// mapNotFound turns a store miss into the 404 taxonomy code.
//
// Cross-tenant reads land here: RLS filtered the row out, the store saw
// nothing, and "no such campaign" is the honest answer. A 403 would confirm the
// id exists in somebody else's tenant.
func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errs.New(errs.NotFoundCampaign, "no such campaign")
	}
	return err
}
