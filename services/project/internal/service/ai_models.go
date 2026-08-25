package service

import (
	"context"
	"errors"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/aibom"
	"github.com/axebom/axebom/services/project/internal/store"
)

// ---------------------------------------------------------------------------
// AI models (AIBOM)
//
// ⚠ MOSTLY A THIN PASS-THROUGH TO store/ai_models.go, UNLIKE QBOM'S SERVICE
// LAYER. Sixteen of Table 10's nineteen elements are discovered and
// normalized by workers/aibom/normalize/pipeline.py; this service only ever
// reads them back or updates the four user-supplied ones. See
// services/project/internal/aibom's package doc.
// ---------------------------------------------------------------------------

// AIModelForm is the payload GET /v1/aibom/{projectId}/form returns.
type AIModelForm struct {
	Fields []aibom.FormField
}

// GetAIModelForm returns the four user-suppliable Table 10 field
// definitions, generated from the profile (CLAUDE.md invariant 2).
func (s *Service) GetAIModelForm() AIModelForm {
	return AIModelForm{Fields: aibom.UserSuppliedFormFields()}
}

// ListAIModels returns a project's current AIBOM model inventory.
func (s *Service) ListAIModels(ctx context.Context, tenantID, projectID string) ([]store.AIModel, error) {
	models, err := s.store.ListAIModels(ctx, tenantID, projectID)
	return models, mapStoreError(err)
}

// UpdateAIModelUserFields records a customer's answer for the four
// user-supplied Table 10 elements on one AI model.
//
// ⚠ NOT mapStoreError — a bare store.ErrNotFound here means "no such model
// in this project's current AIBOM", not "no such project" (mapStoreError's
// only ErrNotFound mapping), the same reason GetComponentDetail
// (dependencies.go) writes its own check rather than reusing it.
func (s *Service) UpdateAIModelUserFields(
	ctx context.Context, tenantID, projectID, modelID string, fields aibom.UserFields,
) (*store.AIModel, error) {
	model, err := s.store.UpdateAIModelUserFields(ctx, tenantID, projectID, modelID, fields)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errs.New(errs.NotFoundResource, "no such AI model")
		}
		return nil, err
	}
	return model, nil
}
