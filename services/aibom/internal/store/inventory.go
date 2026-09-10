package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// ---------------------------------------------------------------------------
// The discovered AI inventory — READ from `normalize.*`, never written.
//
// ⚠ ONE QUERY PER TABLE, JOINED IN Go. `normalize` belongs to the normalizer
// and `scan` to the orchestrator; CLAUDE.md invariant 11 forbids a cross-schema
// SQL JOIN, which is what keeps a service extractable. The cost is a handful of
// round trips on a page load; the alternative is a query that cannot be moved.
//
// ⚠ AND `model_key` IS SELECTED NOW, WHICH IT WAS NOT BEFORE. The operator's
// answers are keyed by it (`aibom.model_user_values`), because a row id is
// valid for exactly one normalization and the key is stable across all of them.
// A UI that could not see the key could not address the model it was editing.
// ---------------------------------------------------------------------------

// ErrNotFound is returned for a project this tenant cannot see.
//
// ⚠ NOT FOUND, NOT FORBIDDEN. A 403 confirms the resource exists, which is
// exactly what a cross-tenant probe is looking for (CLAUDE.md invariant 6).
var ErrNotFound = errors.New("not found")

// AIDataset is one normalize.ai_datasets row.
type AIDataset struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Format      string `json:"format,omitempty"`
	Limitations string `json:"limitations,omitempty"`
	License     string `json:"license,omitempty"`
	Source      string `json:"source,omitempty"`
}

// AIAsset is one prompt, vector store, RAG pipeline or inference endpoint.
//
// ⚠ NO CERT-In TABLE 10 ELEMENT COVERS ANY OF THESE, and they are still
// reported: `airom` and `cdxgen-ai` find them with file:line evidence, and a
// screen that showed the models and silently dropped the rest would be the
// omission invariant 12 exists to prevent. Scored into neither coverage number.
type AIAsset struct {
	Type        string          `json:"asset_type"`
	Key         string          `json:"asset_key"`
	Name        string          `json:"name"`
	Provider    string          `json:"provider,omitempty"`
	Evidence    []string        `json:"evidence"`
	ServesModel string          `json:"serves_model_key,omitempty"`
	Attributes  json.RawMessage `json:"attributes,omitempty"`
}

// AIModel is one row of the AI model inventory screen.
//
// ⚠ `risk_score` AND `owasp_llm_top10` ARE AxeBOM EXTENSIONS from Trusera
// ai-bom — not CERT-In Table 10 fields, excluded from both coverage numbers.
// Rendered clearly labelled as such, never folded into a CERT-In field.
type AIModel struct {
	ID       string `json:"id"`
	ModelKey string `json:"model_key"`
	// How the key was established, and how much that is worth. A `name:` key at
	// low confidence and a `purl:pkg:huggingface/…` key at high confidence are
	// different degrees of evidence, and a reviewer should be able to see which.
	IdentityRule       string `json:"identity_rule,omitempty"`
	IdentityConfidence string `json:"identity_confidence,omitempty"`
	// Which engines reported this model. One or three is the most useful single
	// fact on the row — see normalize.ai_model_provenance.
	FoundBy  []string `json:"found_by"`
	Evidence []string `json:"evidence"`
	// True only when an engine confirmed the model resolves upstream. Never
	// defaults to true: a model nobody could confirm is not a model somebody
	// confirmed.
	Verified bool `json:"verified"`

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

// Inventory is everything the AI screens render for one project.
type Inventory struct {
	Models []AIModel `json:"ai_models"`
	Assets []AIAsset `json:"ai_assets"`
}

// GetInventory returns the project's current AIBOM.
//
// ⚠ AN EMPTY INVENTORY IS NOT AN ERROR. A project with no AIBOM scan yet has
// genuinely recorded nothing, and the screen renders that as an empty state.
func (s *Store) GetInventory(ctx context.Context, tenantID, projectID string) (Inventory, error) {
	out := Inventory{Models: []AIModel{}, Assets: []AIAsset{}}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}
		docID, err := currentAIBOMDocument(ctx, tx, projectID)
		if err != nil || docID == "" {
			return err
		}

		models, err := listAIModelRows(ctx, tx, docID)
		if err != nil {
			return err
		}
		if err := attachModelChildren(ctx, tx, models); err != nil {
			return err
		}
		out.Models = models

		if out.Assets, err = listAIAssets(ctx, tx, docID); err != nil {
			return err
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return Inventory{}, errs.New(errs.NotFoundProject, "project not found")
	}
	return out, err
}

// requireAIBOMClassified refuses a write against a project that is not
// classified for AIBOM.
//
// ⚠ WITHOUT THIS, DATA IS STORED AGAINST A PROJECT WHOSE REPORTS CAN NEVER
// CONTAIN IT. A person fills in what a model is for, on a project classified
// SBOM only; the answer is saved, the screen says saved, and no AIBOM is ever
// generated to render it. The failure is silent and the customer finds it at
// report time.
//
// ⚠ ITS OWN QUERY, NOT services/project's `bommodule.RequireClassified`. That
// registry lives under `services/project/internal`, which depguard forbids
// another service from importing (invariant 11) — and rightly: a shared helper
// reached across a service boundary is the first step in making the boundary
// notional. Reading `project.project_classifications` cross-schema is the
// sanctioned form; a cross-schema SQL JOIN is not, and there is none here.
func requireAIBOMClassified(ctx context.Context, tx db.Tx, projectID string) error {
	if err := projectExists(ctx, tx, projectID); err != nil {
		return err
	}
	var classified bool
	err := tx.QueryRow(ctx, `
		SELECT true FROM project.project_classifications
		 WHERE project_id = $1 AND bom_type = 'AIBOM'`, projectID).Scan(&classified)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.New(errs.ProjectNotClassified,
			"this project is not classified for AIBOM, so an AI model record "+
				"saved against it would never appear in a report")
	}
	return err
}

func projectExists(ctx context.Context, tx db.Tx, projectID string) error {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT true FROM project.projects WHERE id = $1 AND deleted_at IS NULL`,
		projectID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// currentAIBOMDocument resolves the newest AIBOM document for a project.
//
// ⚠ NEWEST SCAN, THEN HIGHEST NORMALIZATION VERSION WITHIN IT. Re-normalizing
// writes a NEW document rather than updating the old one (invariant 10), so
// "the current AIBOM" is the highest version of the newest scan that produced
// one — not simply the newest row.
func currentAIBOMDocument(ctx context.Context, tx db.Tx, projectID string) (string, error) {
	// Capped rather than every scan a project ever ran: a project with
	// thousands of historical scans should not turn a page load into an
	// unbounded IN-list. UUIDv7 ids are time-ordered, so DESC is newest first.
	const scanWindow = 200

	rows, err := tx.Query(ctx, `
		SELECT id FROM scan.scans
		 WHERE project_id = $1
		 ORDER BY id DESC
		 LIMIT $2`, projectID, scanWindow)
	if err != nil {
		return "", fmt.Errorf("list project scans: %w", err)
	}
	scanIDs := make([]string, 0, scanWindow)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return "", err
		}
		scanIDs = append(scanIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(scanIDs) == 0 {
		return "", nil
	}

	var docID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE scan_id = ANY($1) AND bom_type = 'AIBOM'
		 ORDER BY scan_id DESC, normalization_version DESC
		 LIMIT 1`, scanIDs).Scan(&docID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve aibom document: %w", err)
	}
	return docID, nil
}

func listAIModelRows(ctx context.Context, tx db.Tx, docID string) ([]AIModel, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, COALESCE(model_key,''), COALESCE(identity_rule,''),
		       COALESCE(identity_confidence,''), evidence, verified,
		       model_name, COALESCE(model_version,''), COALESCE(model_type,''),
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

	out := []AIModel{}
	for rows.Next() {
		var (
			m                                     AIModel
			evidenceJSON, metricsJSON, statusJSON []byte
		)
		if err := rows.Scan(
			&m.ID, &m.ModelKey, &m.IdentityRule, &m.IdentityConfidence,
			&evidenceJSON, &m.Verified,
			&m.ModelName, &m.ModelVersion, &m.ModelType,
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
		m.Evidence = []string{}
		// Malformed JSON costs that one field, never the row: a model with an
		// unreadable evidence list is still a model that was found.
		_ = json.Unmarshal(evidenceJSON, &m.Evidence)
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

// attachModelChildren fills every model's datasets, dependencies and
// provenance in a fixed number of queries.
//
// ⚠ THIS WAS ONE QUERY PER MODEL PER CHILD TABLE, AND THAT DOES NOT SURVIVE A
// REAL REPOSITORY. Three models cost eleven round trips and nobody notices; a
// monorepo with two hundred model references costs six hundred, in one HTTP
// request, holding a pooled connection inside a tenant transaction for all of
// them. The page does not fail — it gets slower in proportion to how much the
// customer found, which is the worst shape for a scaling problem to have,
// because the customers who hit it are the ones with the most data.
//
// Three queries now, whatever the model count. Ordering is preserved inside
// each list (the SQL still sorts), and `models` keeps the order
// `listAIModelRows` returned.
//
// ⚠ EVERY MODEL GETS AN EMPTY SLICE, NEVER A NIL ONE. `datasets: null` in the
// JSON makes a browser null-check per call site, and the one that gets missed
// is a blank screen for the customer with the most models.
func attachModelChildren(ctx context.Context, tx db.Tx, models []AIModel) error {
	for i := range models {
		models[i].Datasets = []AIDataset{}
		models[i].Dependencies = []string{}
		models[i].FoundBy = []string{}
	}
	if len(models) == 0 {
		return nil
	}

	ids := make([]string, len(models))
	index := make(map[string]int, len(models))
	for i, m := range models {
		ids[i] = m.ID
		index[m.ID] = i
	}

	datasets, err := tx.Query(ctx, `
		SELECT ai_model_id::text, name, COALESCE(version,''), COALESCE(format,''),
		       COALESCE(limitations,''), COALESCE(license,''), COALESCE(source,'')
		  FROM normalize.ai_datasets
		 WHERE ai_model_id = ANY($1)
		 ORDER BY name`, ids)
	if err != nil {
		return fmt.Errorf("list ai datasets: %w", err)
	}
	for datasets.Next() {
		var modelID string
		var d AIDataset
		if err := datasets.Scan(&modelID, &d.Name, &d.Version, &d.Format,
			&d.Limitations, &d.License, &d.Source); err != nil {
			datasets.Close()
			return fmt.Errorf("scan ai dataset: %w", err)
		}
		// A child row whose parent is not in this document cannot happen —
		// the ids came from the document. Skipping rather than indexing blind
		// is what keeps that true if it ever stops being.
		if i, ok := index[modelID]; ok {
			models[i].Datasets = append(models[i].Datasets, d)
		}
	}
	datasets.Close()
	if err := datasets.Err(); err != nil {
		return fmt.Errorf("list ai datasets: %w", err)
	}

	// ⚠ `component_key` IS A PLAIN TEXT COLUMN, NOT A FOREIGN KEY — the
	// referenced component usually lives in a different `bom_document_id` (a
	// different BOM type entirely), so there is nothing to join against. A
	// caller wanting the component's own details resolves it through the SBOM's
	// own endpoint.
	deps, err := tx.Query(ctx, `
		SELECT ai_model_id::text, component_key
		  FROM normalize.ai_model_dependencies
		 WHERE ai_model_id = ANY($1)
		 ORDER BY component_key`, ids)
	if err != nil {
		return fmt.Errorf("list ai model dependencies: %w", err)
	}
	for deps.Next() {
		var modelID, key string
		if err := deps.Scan(&modelID, &key); err != nil {
			deps.Close()
			return fmt.Errorf("scan ai model dependency: %w", err)
		}
		if i, ok := index[modelID]; ok {
			models[i].Dependencies = append(models[i].Dependencies, key)
		}
	}
	deps.Close()
	if err := deps.Err(); err != nil {
		return fmt.Errorf("list ai model dependencies: %w", err)
	}

	prov, err := tx.Query(ctx, `
		SELECT ai_model_id::text, engine_id
		  FROM normalize.ai_model_provenance
		 WHERE ai_model_id = ANY($1)
		 ORDER BY engine_id`, ids)
	if err != nil {
		return fmt.Errorf("list ai model provenance: %w", err)
	}
	for prov.Next() {
		var modelID, engineID string
		if err := prov.Scan(&modelID, &engineID); err != nil {
			prov.Close()
			return fmt.Errorf("scan ai model provenance: %w", err)
		}
		if i, ok := index[modelID]; ok {
			models[i].FoundBy = append(models[i].FoundBy, engineID)
		}
	}
	prov.Close()
	return prov.Err()
}

func listAIAssets(ctx context.Context, tx db.Tx, docID string) ([]AIAsset, error) {
	rows, err := tx.Query(ctx, `
		SELECT asset_type, asset_key, name, COALESCE(provider,''),
		       evidence, COALESCE(serves_model_key,''), attributes
		  FROM normalize.ai_assets
		 WHERE bom_document_id = $1
		 ORDER BY asset_type, name`, docID)
	if err != nil {
		return nil, fmt.Errorf("list ai assets: %w", err)
	}
	defer rows.Close()

	out := []AIAsset{}
	for rows.Next() {
		var a AIAsset
		var evidenceJSON []byte
		if err := rows.Scan(&a.Type, &a.Key, &a.Name, &a.Provider,
			&evidenceJSON, &a.ServesModel, &a.Attributes); err != nil {
			return nil, fmt.Errorf("scan ai asset: %w", err)
		}
		a.Evidence = []string{}
		_ = json.Unmarshal(evidenceJSON, &a.Evidence)
		out = append(out, a)
	}
	return out, rows.Err()
}
