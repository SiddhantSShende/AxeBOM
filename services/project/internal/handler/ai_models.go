package handler

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/aibom"
)

// ---------------------------------------------------------------------------
// AI models (AIBOM)
//
// ⚠ ListAIModels HAS NO SEPARATE DTO — store.AIModel ALREADY CARRIES ITS OWN
// `json` TAGS, same reasoning as ListCryptoAssets in dependencies.go: the
// wire shape and the store shape are the same shape, and a DTO here would be
// a field-for-field copy with no logic in it.
// ---------------------------------------------------------------------------

// ListAIModels handles GET /v1/projects/{id}/ai-models.
func (h *Handler) ListAIModels(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	models, err := h.svc.ListAIModels(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"ai_models": models})
}

// aiModelFormFieldDTO mirrors one entry of aibom.UserSuppliedFormFields().
type aiModelFormFieldDTO struct {
	FieldID       string `json:"field_id"`
	Name          string `json:"name"`
	CanonicalPath string `json:"canonical_path"`
	SourcePage    int    `json:"source_page"`
}

// GetAIModelForm handles GET /v1/aibom/{projectId}/form.
//
// The four field definitions do not depend on projectId — Table 10 is the
// same form for every project — but the route carries the id anyway for the
// same forward-compatibility reason GetQBOMForm's own comment gives.
func (h *Handler) GetAIModelForm(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	form := h.svc.GetAIModelForm()
	out := make([]aiModelFormFieldDTO, 0, len(form.Fields))
	for _, f := range form.Fields {
		out = append(out, aiModelFormFieldDTO{
			FieldID:       f.FieldID,
			Name:          f.Name,
			CanonicalPath: f.CanonicalPath,
			SourcePage:    f.SourcePage,
		})
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"fields": out})
}

// aiModelUserFieldsDTO is the POST body for UpdateAIModelUserFields — Table
// 10 elements 12, 15, 16 and 19, the only four a client can submit. Every
// other element is discovered, never accepted from a request body.
type aiModelUserFieldsDTO struct {
	SecurityRequirements string `json:"security_requirements"`
	IntendedUsage        string `json:"intended_usage"`
	OutOfScopeUsage      string `json:"out_of_scope_usage"`
	AttestationSignature string `json:"attestation_signature"`
}

func (dto aiModelUserFieldsDTO) toFields() aibom.UserFields {
	return aibom.UserFields{
		SecurityRequirements: dto.SecurityRequirements,
		IntendedUsage:        dto.IntendedUsage,
		OutOfScopeUsage:      dto.OutOfScopeUsage,
		AttestationSignature: dto.AttestationSignature,
	}
}

// UpdateAIModelUserFields handles
// POST /v1/projects/{id}/ai-models/{modelId}/fields.
func (h *Handler) UpdateAIModelUserFields(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var dto aiModelUserFieldsDTO
	if err := decode(r, &dto); err != nil {
		errs.Write(w, r, err)
		return
	}

	model, err := h.svc.UpdateAIModelUserFields(
		r.Context(), tenantID, r.PathValue("id"), r.PathValue("modelId"), dto.toFields(),
	)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"ai_model": model})
}
