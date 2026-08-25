package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/aibom"
	"github.com/axebom/axebom/services/project/internal/store"
)

// seedAIModels inserts one AIBOM bom_document with one model, one dataset
// and one dependency — enough to exercise the join across all three tables
// without duplicating workers/aibom/normalize/test_pipeline.py's coverage of
// the normalizer itself.
func seedAIModels(t *testing.T, pool *db.Pool, tenantID, projectID string) (docID, modelID string) {
	t.Helper()
	err := pool.WithTenant(t.Context(), tenantID, func(ctx context.Context, tx db.Tx) error {
		var scanID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO scan.scans (tenant_id, project_id, triggered_by, source_kind)
			VALUES ($1, $2, 'user', 'git') RETURNING id`, tenantID, projectID).Scan(&scanID); err != nil {
			return err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version, generated_at)
			VALUES ($1, $2, 'AIBOM', 1, 'test-1', app.uuid_v7(), '', now())
			RETURNING id`, tenantID, scanID).Scan(&docID); err != nil {
			return err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.ai_models
				(tenant_id, bom_document_id, model_name, model_developer, licensing,
				 risk_score, owasp_llm_top10, field_status)
			VALUES ($1, $2, 'Llama-3-8B', 'Meta', 'llama3',
			        7.5, ARRAY['LLM01','LLM06'], '{"certin.aibom.01.model_name":"provided"}'::jsonb)
			RETURNING id`, tenantID, docID).Scan(&modelID); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.ai_datasets (tenant_id, ai_model_id, name, format, license)
			VALUES ($1, $2, 'the-pile', 'text', 'MIT')`, tenantID, modelID); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO normalize.ai_model_dependencies (tenant_id, ai_model_id, component_key)
			VALUES ($1, $2, 'purl:pkg:pypi/langchain@0.3.7')`, tenantID, modelID)
		return err
	})
	if err != nil {
		t.Fatalf("seed AIBOM: %v", err)
	}
	return docID, modelID
}

func TestListAIModelsJoinsDatasetsAndDependencies(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedAIModels(t, pool, tenantA, projectID)

	models, err := st.ListAIModels(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListAIModels: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("models = %d, want 1", len(models))
	}

	m := models[0]
	if m.ModelName != "Llama-3-8B" || m.ModelDeveloper != "Meta" {
		t.Errorf("model = %+v", m)
	}
	if m.RiskScore == nil || *m.RiskScore != 7.5 {
		t.Errorf("RiskScore = %v, want 7.5", m.RiskScore)
	}
	if len(m.OwaspLLMTop10) != 2 {
		t.Errorf("OwaspLLMTop10 = %v, want 2 entries", m.OwaspLLMTop10)
	}
	if len(m.Datasets) != 1 || m.Datasets[0].Name != "the-pile" {
		t.Errorf("Datasets = %+v, want one row named the-pile", m.Datasets)
	}
	if len(m.Dependencies) != 1 || m.Dependencies[0] != "purl:pkg:pypi/langchain@0.3.7" {
		t.Errorf("Dependencies = %+v", m.Dependencies)
	}
}

func TestListAIModelsIsEmptyBeforeAnyAIBOM(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)

	models, err := st.ListAIModels(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListAIModels: %v", err)
	}
	if len(models) != 0 {
		t.Errorf("models = %d, want 0 before any AIBOM scan", len(models))
	}
}

// TestListAIModelsIsTenantScoped mirrors
// TestListCryptoAssetsIsTenantScoped's identical assertion: a cross-tenant
// fetch is ErrNotFound, never an empty list.
func TestListAIModelsIsTenantScoped(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedAIModels(t, pool, tenantA, projectID)

	_, err := st.ListAIModels(t.Context(), tenantB, projectID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ListAIModels cross-tenant error = %v, want ErrNotFound", err)
	}
}

func TestUpdateAIModelUserFieldsPatchesOnlyThoseFourColumns(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	_, modelID := seedAIModels(t, pool, tenantA, projectID)

	updated, err := st.UpdateAIModelUserFields(t.Context(), tenantA, projectID, modelID, aibom.UserFields{
		IntendedUsage:        "internal chat assistant",
		AttestationSignature: "not-provided",
	})
	if err != nil {
		t.Fatalf("UpdateAIModelUserFields: %v", err)
	}

	if updated.IntendedUsage != "internal chat assistant" {
		t.Errorf("IntendedUsage = %q", updated.IntendedUsage)
	}
	// ⚠ AN EMPTY SUBMISSION STORES THE EXPLICIT SENTINEL, NEVER NULL.
	// SecurityRequirements and OutOfScopeUsage were left as Go zero values in
	// this call's UserFields — the raw column must read back the literal
	// string "not-provided", not "" (which COALESCE would also produce for a
	// genuinely NULL column, making the two indistinguishable to a reader).
	if updated.SecurityRequirements != aibom.NotProvided {
		t.Errorf("SecurityRequirements = %q, want the explicit not-provided sentinel", updated.SecurityRequirements)
	}
	if updated.OutOfScopeUsage != aibom.NotProvided {
		t.Errorf("OutOfScopeUsage = %q, want the explicit not-provided sentinel", updated.OutOfScopeUsage)
	}
	// ⚠ FIELDS NEVER TOUCHED BY THIS CALL ARE PRESERVED — the discovery-owned
	// columns (ModelName, ModelDeveloper, ...) and the field_status entries
	// the normalizer already computed for them must survive a user-field
	// edit untouched.
	if updated.ModelName != "Llama-3-8B" || updated.ModelDeveloper != "Meta" {
		t.Errorf("discovery-owned columns changed: %+v", updated)
	}
	if updated.FieldStatus["certin.aibom.01.model_name"] != "provided" {
		t.Errorf("pre-existing field_status entry lost: %+v", updated.FieldStatus)
	}
	if updated.FieldStatus["certin.aibom.15.intended_usage"] != "provided" {
		t.Errorf("intended_usage field_status = %q, want provided", updated.FieldStatus["certin.aibom.15.intended_usage"])
	}
	// ⚠ A USER WHO TYPES "not-provided" HAS DECLARED THE GAP, AND IT STILL
	// SCORES ZERO — CLAUDE.md invariant 3, mirrored from
	// workers/aibom/normalize/ai.py's _is_substantive().
	if updated.FieldStatus["certin.aibom.19.attestations"] != aibom.NotProvided {
		t.Errorf("attestations field_status = %q, want not-provided", updated.FieldStatus["certin.aibom.19.attestations"])
	}
	if len(updated.Datasets) != 1 || len(updated.Dependencies) != 1 {
		t.Errorf("children lost after update: datasets=%v dependencies=%v", updated.Datasets, updated.Dependencies)
	}
}

func TestUpdateAIModelUserFieldsRejectsAModelFromAnotherProject(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectA := createTestProject(t, st, tenantA)
	projectB := createTestProject(t, st, tenantA)
	_, modelID := seedAIModels(t, pool, tenantA, projectA)

	_, err := st.UpdateAIModelUserFields(t.Context(), tenantA, projectB, modelID, aibom.UserFields{
		IntendedUsage: "should not apply",
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-project update error = %v, want ErrNotFound", err)
	}
}
