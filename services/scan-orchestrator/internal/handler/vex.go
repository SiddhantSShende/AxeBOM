package handler

import (
	"net/http"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/vex"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// ---------------------------------------------------------------------------
// VEX statements
//
// ⚠ THIS IS THE WRITE AUTHORITY. libs/go-shared/vex's pure logic is shared
// with services/report (which only ever READS normalize.vex_statements
// directly, to resolve effective status at render time — see that
// service's bomsource.go); every CREATE goes through this handler and
// orchestr.Store, never a direct write from elsewhere.
// ---------------------------------------------------------------------------

// vexStatementDTO mirrors one vex.Statement for the wire.
type vexStatementDTO struct {
	ID            string `json:"id"`
	ComponentKey  string `json:"component_key,omitempty"`
	ClusterID     string `json:"cluster_id"`
	Status        string `json:"status"`
	Scope         string `json:"scope"`
	Justification string `json:"justification,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	Workarounds   string `json:"workarounds,omitempty"`
	Downtime      string `json:"downtime,omitempty"`
	Version       int    `json:"version"`
	SupersededBy  string `json:"superseded_by,omitempty"`
	AuthorUserID  string `json:"author_user_id,omitempty"`
	CreatedAt     string `json:"created_at"`
}

func toVEXStatementDTO(s vex.Statement) vexStatementDTO {
	return vexStatementDTO{
		ID:            s.ID,
		ComponentKey:  s.ComponentKey,
		ClusterID:     s.ClusterID,
		Status:        string(s.Status),
		Scope:         string(s.Scope),
		Justification: s.Justification,
		Remediation:   s.Remediation,
		Workarounds:   s.Workarounds,
		Downtime:      s.Downtime,
		Version:       s.Version,
		SupersededBy:  s.SupersededBy,
		AuthorUserID:  s.AuthorUserID,
		CreatedAt:     s.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// createVEXStatementDTO is the POST body — everything a caller supplies for
// a triage decision. AuthorUserID and CreatedAt are never accepted from a
// client: the author comes from the authenticated request, the timestamp
// from Postgres (ADR-0003 — a client-supplied clock is never trustworthy for
// an audit trail).
type createVEXStatementDTO struct {
	ComponentKey  string `json:"component_key"`
	ClusterID     string `json:"cluster_id"`
	Status        string `json:"status"`
	Scope         string `json:"scope"`
	Justification string `json:"justification"`
	Remediation   string `json:"remediation"`
	Workarounds   string `json:"workarounds"`
	Downtime      string `json:"downtime"`
}

// CreateVEXStatement handles POST /v1/vex/{projectId}/statements.
func (h *Handler) CreateVEXStatement(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var dto createVEXStatementDTO
	if err := decode(r, &dto); err != nil {
		errs.Write(w, r, err)
		return
	}

	scope := vex.Scope(dto.Scope)
	if scope == "" {
		// The migration's own DEFAULT — matched here so a client that omits
		// scope entirely gets the guideline's least-surprising default
		// (applies everywhere) rather than a rejected request.
		scope = vex.ScopeProject
	}

	stmt, err := h.store.CreateVEXStatement(r.Context(), tenantID, orchestr.VEXStatementInput{
		ProjectID:     r.PathValue("projectId"),
		ComponentKey:  dto.ComponentKey,
		ClusterID:     dto.ClusterID,
		Status:        vex.Status(dto.Status),
		Scope:         scope,
		Justification: dto.Justification,
		Remediation:   dto.Remediation,
		Workarounds:   dto.Workarounds,
		Downtime:      dto.Downtime,
		AuthorUserID:  ctxkey.UserID(r.Context()),
	})
	if err != nil {
		// ⚠ EVERY FAILURE HERE IS A CLIENT ERROR, NOT A SERVER ONE.
		// CreateVEXStatement's only failure modes are vex.Validate/vex.Supersede
		// rejecting the input (bad status, missing justification, a successor
		// at the wrong scope) or a genuine database error — the latter would
		// already be a non-nil, non-validation error surfacing through
		// errs.Write's own fallback, so wrapping unconditionally here is safe:
		// nothing about this store method can fail for a reason that ISN'T
		// something the caller sent wrong.
		errs.Write(w, r, errs.Newf(errs.ValidationFieldInvalid, "%s", err))
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toVEXStatementDTO(*stmt))
}

// ListVEXHistory handles
// GET /v1/vex/{projectId}/statements?cluster_id=X&component_key=Y.
//
// ⚠ component_key MAY BE EMPTY. A project-scoped statement has none — see
// vex.Statement's own doc comment — so an empty query parameter is a real,
// valid request, not a missing one.
func (h *Handler) ListVEXHistory(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired, "cluster_id is required"))
		return
	}
	componentKey := r.URL.Query().Get("component_key")

	history, err := h.store.GetVEXHistory(r.Context(), tenantID, r.PathValue("projectId"), clusterID, componentKey)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]vexStatementDTO, 0, len(history))
	for _, s := range history {
		out = append(out, toVEXStatementDTO(s))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"statements": out})
}
