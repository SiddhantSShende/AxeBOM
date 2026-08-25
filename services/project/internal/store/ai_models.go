package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/aibom"
)

// ---------------------------------------------------------------------------
// AI models — normalize.ai_models/ai_datasets/ai_model_dependencies, read
// cross-schema.
//
// ⚠ SAME PATTERN AS ListCryptoAssets (crypto.go): this service owns
// project.* only, not normalize.*. One query per table, no cross-schema SQL
// JOIN (CLAUDE.md invariant 11), scoped by the project's current AIBOM
// bom_document via resolveCurrentBOMDocument.
//
// ⚠ ROWS ARE WRITTEN BY workers/aibom/normalize/pipeline.py, NOT THIS
// SERVICE — unlike QBOM/HBOM (qbom.go, hbom.go), which are 100% Go-owned
// because their CERT-In tables have no scanner at all. Table 10 elements 12,
// 15, 16 and 19 (security_requirements, intended_usage, out_of_scope_usage,
// attestations) are the exception: no tool reports intent or policy, so
// UpdateAIModelUserFields below is this service's one write path onto an
// otherwise Python-normalized row — see its own doc comment for why that is
// a targeted UPDATE rather than a new normalization version.
// ---------------------------------------------------------------------------

// AIDataset is one normalize.ai_datasets row.
type AIDataset struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Format      string `json:"format,omitempty"`
	Limitations string `json:"limitations,omitempty"`
	License     string `json:"license,omitempty"`
	Source      string `json:"source,omitempty"`
}

// AIModel is one row of the AI model inventory screen
// (frontend/src/routes/boms/AIModelInventory.tsx).
//
// ⚠ risk_score AND owasp_llm_top10 ARE AXEBOM EXTENSIONS FROM TRUSERA
// ai-bom — NOT CERT-In Table 10 fields, excluded from both coverage numbers
// (migrations/normalize/0003_specialized_boms.sql's own column comment;
// workers/aibom/normalize/ai.py's module docstring). Rendered in the UI
// clearly labelled as such, never folded into a CERT-In field.
type AIModel struct {
	ID                   string            `json:"id"`
	ModelName            string            `json:"model_name"`
	ModelVersion         string            `json:"model_version,omitempty"`
	ModelType            string            `json:"model_type,omitempty"`
	ModelDeveloper       string            `json:"model_developer,omitempty"`
	Licensing            string            `json:"licensing,omitempty"`
	MLModelsAlgorithms   []string          `json:"ml_models_algorithms,omitempty"`
	PerformanceMetrics   json.RawMessage   `json:"performance_metrics,omitempty"`
	DataSource           string            `json:"data_source,omitempty"`
	Hardware             string            `json:"hardware,omitempty"`
	SecurityRequirements string            `json:"security_requirements,omitempty"`
	Input                string            `json:"input,omitempty"`
	Output               string            `json:"output,omitempty"`
	IntendedUsage        string            `json:"intended_usage,omitempty"`
	OutOfScopeUsage      string            `json:"out_of_scope_usage,omitempty"`
	EnvironmentalImpact  string            `json:"environmental_impact,omitempty"`
	AttestationSignature string            `json:"attestation_signature,omitempty"`
	RiskScore            *float64          `json:"risk_score,omitempty"`
	OwaspLLMTop10        []string          `json:"owasp_llm_top10,omitempty"`
	FieldStatus          map[string]string `json:"field_status"`
	Datasets             []AIDataset       `json:"datasets"`
	Dependencies         []string          `json:"dependencies"`
}

// ListAIModels returns the project's current AIBOM model inventory.
func (s *Store) ListAIModels(ctx context.Context, tenantID, projectID string) ([]AIModel, error) {
	out := []AIModel{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "AIBOM")
		if err != nil {
			return err
		}
		if docID == "" {
			return nil // no AIBOM normalized yet — an honest empty list
		}

		models, err := listAIModelRows(ctx, tx, docID)
		if err != nil {
			return err
		}

		for i := range models {
			datasets, err := listAIDatasets(ctx, tx, models[i].ID)
			if err != nil {
				return err
			}
			models[i].Datasets = datasets

			deps, err := listAIModelDependencies(ctx, tx, models[i].ID)
			if err != nil {
				return err
			}
			models[i].Dependencies = deps
		}

		out = models
		return nil
	})
	return out, err
}

func listAIModelRows(ctx context.Context, tx db.Tx, docID string) ([]AIModel, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, model_name, COALESCE(model_version,''), COALESCE(model_type,''),
		       COALESCE(model_developer,''), COALESCE(licensing,''),
		       ml_models_algorithms, performance_metrics, COALESCE(data_source,''),
		       COALESCE(hardware,''), COALESCE(security_requirements,''),
		       COALESCE(input,''), COALESCE(output,''), COALESCE(intended_usage,''),
		       COALESCE(out_of_scope_usage,''), COALESCE(environmental_impact,''),
		       COALESCE(attestation_signature,''), risk_score, owasp_llm_top10, field_status
		  FROM normalize.ai_models
		 WHERE bom_document_id = $1
		 ORDER BY model_name`, docID)
	if err != nil {
		return nil, fmt.Errorf("list ai models: %w", err)
	}
	defer rows.Close()

	var out []AIModel
	for rows.Next() {
		var (
			m           AIModel
			metricsJSON []byte
			statusJSON  []byte
		)
		if err := rows.Scan(
			&m.ID, &m.ModelName, &m.ModelVersion, &m.ModelType,
			&m.ModelDeveloper, &m.Licensing,
			&m.MLModelsAlgorithms, &metricsJSON, &m.DataSource,
			&m.Hardware, &m.SecurityRequirements,
			&m.Input, &m.Output, &m.IntendedUsage,
			&m.OutOfScopeUsage, &m.EnvironmentalImpact,
			&m.AttestationSignature, &m.RiskScore, &m.OwaspLLMTop10, &statusJSON,
		); err != nil {
			return nil, fmt.Errorf("scan ai model: %w", err)
		}
		if len(metricsJSON) > 0 {
			m.PerformanceMetrics = metricsJSON
		}
		m.FieldStatus = map[string]string{}
		if len(statusJSON) > 0 {
			if err := json.Unmarshal(statusJSON, &m.FieldStatus); err != nil {
				return nil, fmt.Errorf("unmarshal ai model field_status: %w", err)
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func listAIDatasets(ctx context.Context, tx db.Tx, aiModelID string) ([]AIDataset, error) {
	rows, err := tx.Query(ctx, `
		SELECT name, COALESCE(version,''), COALESCE(format,''),
		       COALESCE(limitations,''), COALESCE(license,''), COALESCE(source,'')
		  FROM normalize.ai_datasets
		 WHERE ai_model_id = $1
		 ORDER BY name`, aiModelID)
	if err != nil {
		return nil, fmt.Errorf("list ai datasets: %w", err)
	}
	defer rows.Close()

	datasets := []AIDataset{}
	for rows.Next() {
		var d AIDataset
		if err := rows.Scan(&d.Name, &d.Version, &d.Format, &d.Limitations, &d.License, &d.Source); err != nil {
			return nil, fmt.Errorf("scan ai dataset: %w", err)
		}
		datasets = append(datasets, d)
	}
	return datasets, rows.Err()
}

// listAIModelDependencies returns the SBOM component keys this model
// depends on.
//
// ⚠ component_key IS A PLAIN TEXT COLUMN, NOT A FOREIGN KEY — see
// docs/01-DATA-MODEL.md's ai_model_dependencies entry. The referenced SBOM
// component usually lives in a DIFFERENT bom_document_id (a different
// bom_type entirely) than this AIBOM, so there is nothing to JOIN against
// here; a caller wanting the component's own details resolves it separately
// via GET /v1/projects/{id}/dependencies/{key}.
func listAIModelDependencies(ctx context.Context, tx db.Tx, aiModelID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT component_key FROM normalize.ai_model_dependencies
		 WHERE ai_model_id = $1
		 ORDER BY component_key`, aiModelID)
	if err != nil {
		return nil, fmt.Errorf("list ai model dependencies: %w", err)
	}
	defer rows.Close()

	deps := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan ai model dependency: %w", err)
		}
		deps = append(deps, key)
	}
	return deps, rows.Err()
}

// UpdateAIModelUserFields records a customer's answer for the four
// user-supplied Table 10 elements on one already-discovered AI model.
//
// ⚠ A TARGETED UPDATE, NOT A NEW NORMALIZATION VERSION — DELIBERATELY
// DIFFERENT FROM QBOM'S SaveQuantumDevice. QBOM's entire document is
// Go-owned (qbom.go's own doc comment), so a save can safely mint a whole
// new normalize.bom_documents version with nothing else to carry forward. An
// AI model's row is mostly Python-owned — sixteen of its columns, every
// dataset row and every dependency row come from workers/aibom/normalize
// /pipeline.py — so treating a four-field edit the same way would mean
// cloning an entire model plus its children to touch four columns, and nothing
// else in this codebase does that for a Python-normalized row. This is a
// deliberate, narrower scope than CLAUDE.md invariant 10's versioning
// discipline for RE-NORMALIZATION; it is accepted here because these four
// fields are never derived from a raw artifact in the first place — there is
// no "wrong output" of a scanner to make replayable, only a customer's
// answer to record. See docs/STATE.md for the trade-off this leaves open.
//
// Returns ErrNotFound if modelID does not belong to the project's current
// AIBOM document — cross-tenant/cross-project safety, same 404-not-403 rule
// as every other lookup in this package.
func (s *Store) UpdateAIModelUserFields(
	ctx context.Context, tenantID, projectID, modelID string, fields aibom.UserFields,
) (*AIModel, error) {
	var out *AIModel
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "AIBOM")
		if err != nil {
			return err
		}
		if docID == "" {
			return ErrNotFound
		}

		var statusJSON []byte
		err = tx.QueryRow(ctx, `
			SELECT field_status FROM normalize.ai_models
			 WHERE id = $1 AND bom_document_id = $2`, modelID, docID).Scan(&statusJSON)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("load ai model field_status: %w", err)
		}

		status := map[string]string{}
		if len(statusJSON) > 0 {
			if err := json.Unmarshal(statusJSON, &status); err != nil {
				return fmt.Errorf("unmarshal ai model field_status: %w", err)
			}
		}
		aibom.ApplyUserFields(status, fields)

		newStatusJSON, err := json.Marshal(status)
		if err != nil {
			return fmt.Errorf("marshal ai model field_status: %w", err)
		}

		// ⚠ aibom.OrNotProvided, NOT nullIfEmpty — see that function's own
		// doc comment. An empty submission stores the explicit sentinel, the
		// same value normalize_model() would have written, never NULL.
		if _, err := tx.Exec(ctx, `
			UPDATE normalize.ai_models
			   SET security_requirements = $1, intended_usage = $2,
			       out_of_scope_usage = $3, attestation_signature = $4,
			       field_status = $5
			 WHERE id = $6 AND bom_document_id = $7`,
			aibom.OrNotProvided(fields.SecurityRequirements), aibom.OrNotProvided(fields.IntendedUsage),
			aibom.OrNotProvided(fields.OutOfScopeUsage), aibom.OrNotProvided(fields.AttestationSignature),
			newStatusJSON, modelID, docID,
		); err != nil {
			return fmt.Errorf("update ai model user fields: %w", err)
		}

		models, err := listAIModelRows(ctx, tx, docID)
		if err != nil {
			return err
		}
		for i := range models {
			if models[i].ID != modelID {
				continue
			}
			datasets, err := listAIDatasets(ctx, tx, modelID)
			if err != nil {
				return err
			}
			deps, err := listAIModelDependencies(ctx, tx, modelID)
			if err != nil {
				return err
			}
			models[i].Datasets = datasets
			models[i].Dependencies = deps
			out = &models[i]
			return nil
		}
		return ErrNotFound
	})
	return out, err
}
