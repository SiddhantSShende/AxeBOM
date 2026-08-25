package handler

import (
	"encoding/json"
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/report/internal/store"
)

// ---------------------------------------------------------------------------
// CSAF advisories — GET/POST /v1/csaf/{projectId}/advisories.
//
// ⚠ CSAF FOLLOWS VEX. A generate request names an EXISTING vex_statement_id;
// this handler never accepts a status/justification/scope directly — those
// came from scan-orchestrator's VEX write path already, and re-typing them
// here would let a client publish an advisory that disagrees with the VEX
// record behind it.
// ---------------------------------------------------------------------------

type csafAdvisoryDTO struct {
	ID             string          `json:"id"`
	VEXStatementID string          `json:"vex_statement_id"`
	TrackingID     string          `json:"tracking_id"`
	Description    string          `json:"description,omitempty"`
	Severity       string          `json:"severity,omitempty"`
	MitigationStep string          `json:"mitigation_steps,omitempty"`
	PublishedAt    string          `json:"published_at,omitempty"`
	Document       json.RawMessage `json:"document"`
	CreatedAt      string          `json:"created_at"`
}

func toCSAFAdvisoryDTO(a store.CSAFAdvisory) csafAdvisoryDTO {
	return csafAdvisoryDTO{
		ID: a.ID, VEXStatementID: a.VEXStatementID, TrackingID: a.TrackingID,
		Description: a.Description, Severity: a.Severity, MitigationStep: a.MitigationStep,
		PublishedAt: a.PublishedAt, Document: a.Document, CreatedAt: a.CreatedAt,
	}
}

type generateCSAFAdvisoryDTO struct {
	VEXStatementID   string   `json:"vex_statement_id"`
	ClusterDisplayID string   `json:"cluster_display_id"`
	ClusterAliases   []string `json:"cluster_aliases"`
	ComponentName    string   `json:"component_name"`
	ComponentPURL    string   `json:"component_purl"`
}

// GenerateCSAFAdvisory handles POST /v1/csaf/{projectId}/advisories.
func (h *Handler) GenerateCSAFAdvisory(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var dto generateCSAFAdvisoryDTO
	if err := decode(r, &dto); err != nil {
		errs.Write(w, r, err)
		return
	}
	if dto.VEXStatementID == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired, "vex_statement_id is required"))
		return
	}

	advisory, err := h.svc.GenerateCSAFAdvisory(r.Context(), tenantID, r.PathValue("projectId"),
		store.GenerateCSAFAdvisoryInput{
			VEXStatementID:   dto.VEXStatementID,
			ClusterDisplayID: dto.ClusterDisplayID,
			ClusterAliases:   dto.ClusterAliases,
			ComponentName:    dto.ComponentName,
			ComponentPURL:    dto.ComponentPURL,
		}, h.now().UTC())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toCSAFAdvisoryDTO(*advisory))
}

// ListCSAFAdvisories handles GET /v1/csaf/{projectId}/advisories.
func (h *Handler) ListCSAFAdvisories(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	advisories, err := h.svc.ListCSAFAdvisories(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]csafAdvisoryDTO, 0, len(advisories))
	for _, a := range advisories {
		out = append(out, toCSAFAdvisoryDTO(a))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"advisories": out})
}
