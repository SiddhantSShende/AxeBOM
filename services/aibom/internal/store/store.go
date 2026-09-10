// Package store is services/aibom's Postgres access.
//
// ⚠ THIS SERVICE OWNS `aibom.*` AND READS `normalize.*`. Two different things,
// and the difference is the whole reason the service exists.
//
//	aibom.*      operator input and verification records. WRITTEN here.
//	normalize.*  the discovered AI inventory. READ here, never written.
//
// `services/project` used to do the second half AND write into `normalize`
// with a targeted UPDATE — a mutation of normalized data, which CLAUDE.md
// invariant 10 says never happens. The read stays (cross-schema reads are
// fine; cross-schema SQL JOINs are not — invariant 11, so this is one query
// per table joined in Go); the write is gone.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Store reads and writes this service's data.
type Store struct{ pool *db.Pool }

// NewStore constructs a Store.
func NewStore(pool *db.Pool) *Store { return &Store{pool: pool} }

// ---------------------------------------------------------------------------
// Operator-supplied Table 10 elements
// ---------------------------------------------------------------------------

// UserFields is what a person supplies for the Table 10 elements no tool ever
// reports.
//
// ⚠ THE FIELD SET IS DECLARED IN THE PROFILE, NOT HERE. `user_supplied: true`
// in `docs/reference/certin-v2.0.yaml` is what says which elements these are,
// and both languages generate from it — this struct is a transport shape that
// `aibom.UserSuppliedFormFields()` is checked against, never the definition.
type UserFields struct {
	SecurityRequirements string `json:"security_requirements"`
	IntendedUsage        string `json:"intended_usage"`
	OutOfScopeUsage      string `json:"out_of_scope_usage"`
	EnvironmentalImpact  string `json:"environmental_impact"`
	AttestationSignature string `json:"attestation_signature"`
}

// ModelUserValues is one stored answer, with who last touched it.
type ModelUserValues struct {
	ModelKey string `json:"model_key"`
	UserFields
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
}

// SaveUserFields records one model's operator-supplied elements.
//
// ⚠ AN UPSERT ON `(tenant, project, model_key)`, NOT AN INSERT-PER-SCAN.
// These are answers about a MODEL, not about a scan of it: re-scanning must not
// ask the operator again, and a second answer replaces the first rather than
// accumulating a history nobody reads. The row carries `updated_by` so a
// changed answer is still attributable.
//
// ⚠ EMPTY MEANS EMPTY HERE, AND `not-provided` IS APPLIED AT RENDER. The
// sentinel belongs to the normalized document (invariant 3), where every
// element always carries a value; storing it in the operator's own table would
// make "they cleared the field" and "they typed the word" indistinguishable.
func (s *Store) SaveUserFields(
	ctx context.Context, tenantID, projectID, modelKey, userID string, f UserFields,
) error {
	if modelKey == "" {
		return errs.New(errs.ValidationFieldRequired, "model_key is required")
	}
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := requireAIBOMClassified(ctx, tx, projectID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO aibom.model_user_values
				(tenant_id, project_id, model_key, security_requirements,
				 intended_usage, out_of_scope_usage, environmental_impact,
				 attestation_signature, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (tenant_id, project_id, model_key) DO UPDATE SET
				security_requirements = EXCLUDED.security_requirements,
				intended_usage        = EXCLUDED.intended_usage,
				out_of_scope_usage    = EXCLUDED.out_of_scope_usage,
				environmental_impact  = EXCLUDED.environmental_impact,
				attestation_signature = EXCLUDED.attestation_signature,
				updated_by            = EXCLUDED.updated_by`,
			tenantID, projectID, modelKey,
			nullIfEmpty(f.SecurityRequirements), nullIfEmpty(f.IntendedUsage),
			nullIfEmpty(f.OutOfScopeUsage), nullIfEmpty(f.EnvironmentalImpact),
			nullIfEmpty(f.AttestationSignature), userID,
		)
		if err != nil {
			return fmt.Errorf("save ai model user fields: %w", err)
		}
		return nil
	})
}

// ListUserFields returns every stored answer for one project, keyed by model.
func (s *Store) ListUserFields(
	ctx context.Context, tenantID, projectID string,
) (map[string]ModelUserValues, error) {
	out := map[string]ModelUserValues{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT model_key, COALESCE(security_requirements,''),
			       COALESCE(intended_usage,''), COALESCE(out_of_scope_usage,''),
			       COALESCE(environmental_impact,''), COALESCE(attestation_signature,''),
			       updated_by::text, updated_at
			  FROM aibom.model_user_values
			 WHERE project_id = $1
			 ORDER BY model_key`, projectID)
		if err != nil {
			return fmt.Errorf("list ai model user fields: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v ModelUserValues
			var updatedAt time.Time
			if err := rows.Scan(
				&v.ModelKey, &v.SecurityRequirements, &v.IntendedUsage,
				&v.OutOfScopeUsage, &v.EnvironmentalImpact, &v.AttestationSignature,
				&v.UpdatedBy, &updatedAt,
			); err != nil {
				return fmt.Errorf("scan ai model user fields: %w", err)
			}
			v.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
			out[v.ModelKey] = v
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Per-project AI policy
// ---------------------------------------------------------------------------

// Policy is the two consent switches, and who recorded them.
type Policy struct {
	LLMEnrichEnabled bool   `json:"llm_enrich_enabled"`
	CiscoEnabled     bool   `json:"cisco_enabled"`
	ConsentBy        string `json:"consent_recorded_by,omitempty"`
	ConsentAt        string `json:"consent_recorded_at,omitempty"`
	// ⚠ A STATEMENT ABOUT THE PLATFORM, NOT ABOUT THE SWITCH. Both engines need
	// network egress the sandbox does not have, so consent alone changes
	// nothing today. Surfaced so the UI cannot imply that flipping a toggle
	// turned an engine on.
	Effective bool   `json:"effective"`
	Blocker   string `json:"blocker,omitempty"`
}

// NoEgressProxy is why consent is recorded but not yet acted on.
const NoEgressProxy = "no egress allowlist exists yet, so scan engines still " +
	"run with no network; consent is recorded and the engines remain off"

// GetPolicy returns a project's AI policy, defaulting to both switches off.
//
// ⚠ AN ABSENT ROW IS "BOTH OFF", NOT AN ERROR. A project nobody has visited is
// a project that has consented to nothing, which is the safe reading and the
// true one.
func (s *Store) GetPolicy(ctx context.Context, tenantID, projectID string) (Policy, error) {
	var p Policy
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var by *string
		var at *time.Time
		err := tx.QueryRow(ctx, `
			SELECT llm_enrich_enabled, cisco_enabled,
			       consent_recorded_by::text, consent_recorded_at
			  FROM aibom.project_policy
			 WHERE project_id = $1`, projectID,
		).Scan(&p.LLMEnrichEnabled, &p.CiscoEnabled, &by, &at)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get ai policy: %w", err)
		}
		if by != nil {
			p.ConsentBy = *by
		}
		if at != nil {
			p.ConsentAt = at.UTC().Format(time.RFC3339)
		}
		return nil
	})
	if p.LLMEnrichEnabled || p.CiscoEnabled {
		p.Blocker = NoEgressProxy
	}
	return p, err
}

// SetPolicy records consent, with who and when.
//
// ⚠ `consent_recorded_by` IS SET ONLY WHEN SOMETHING IS TURNED ON. Turning both
// switches off is a withdrawal, and attributing a withdrawal as a consent would
// leave a record saying the opposite of what happened.
func (s *Store) SetPolicy(
	ctx context.Context, tenantID, projectID, userID string, llmEnrich, cisco bool,
) (Policy, error) {
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := requireAIBOMClassified(ctx, tx, projectID); err != nil {
			return err
		}
		// ⚠ NULL WHEN NOTHING IS BEING TURNED ON. Turning both switches off is a
		// WITHDRAWAL, and attributing that as a consent would leave a record
		// saying the opposite of what happened. The COALESCE below then keeps
		// the original consent's attribution rather than erasing it.
		var consentBy any
		if llmEnrich || cisco {
			consentBy = userID
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO aibom.project_policy
				(tenant_id, project_id, llm_enrich_enabled, cisco_enabled,
				 consent_recorded_by, consent_recorded_at)
			VALUES ($1,$2,$3,$4,$5, CASE WHEN $5::uuid IS NULL THEN NULL ELSE now() END)
			ON CONFLICT (tenant_id, project_id) DO UPDATE SET
				llm_enrich_enabled  = EXCLUDED.llm_enrich_enabled,
				cisco_enabled       = EXCLUDED.cisco_enabled,
				consent_recorded_by = COALESCE(EXCLUDED.consent_recorded_by,
				                               aibom.project_policy.consent_recorded_by),
				consent_recorded_at = COALESCE(EXCLUDED.consent_recorded_at,
				                               aibom.project_policy.consent_recorded_at)`,
			tenantID, projectID, llmEnrich, cisco, consentBy)
		if err != nil {
			return fmt.Errorf("set ai policy: %w", err)
		}
		return nil
	})
	if err != nil {
		return Policy{}, err
	}
	return s.GetPolicy(ctx, tenantID, projectID)
}

// ---------------------------------------------------------------------------
// Compliance tagging
// ---------------------------------------------------------------------------

// ComplianceTag is one operator classification.
//
// ⚠ THE OPERATOR'S, NEVER AxeBOM's. Whether a system is high-risk under the EU
// AI Act depends on what it is USED FOR — none of which is visible in a
// repository. `DeclaredBy` is on the record because a classification nobody
// signed is a classification nobody can be asked about.
type ComplianceTag struct {
	ModelKey    string   `json:"model_key"`
	EUAIActTier string   `json:"eu_ai_act_tier,omitempty"`
	NISTAIRMF   []string `json:"nist_ai_rmf"`
	ISO42001    []string `json:"iso_42001"`
	Rationale   string   `json:"rationale,omitempty"`
	DeclaredBy  string   `json:"declared_by"`
	UpdatedAt   string   `json:"updated_at"`
}

// ListTags returns every classification recorded for a project.
func (s *Store) ListTags(ctx context.Context, tenantID, projectID string) ([]ComplianceTag, error) {
	out := []ComplianceTag{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT model_key, COALESCE(eu_ai_act_tier,''), nist_ai_rmf, iso_42001,
			       COALESCE(rationale,''), declared_by::text, updated_at
			  FROM aibom.compliance_tags
			 WHERE project_id = $1
			 ORDER BY model_key`, projectID)
		if err != nil {
			return fmt.Errorf("list compliance tags: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var t ComplianceTag
			var updatedAt time.Time
			if err := rows.Scan(&t.ModelKey, &t.EUAIActTier, &t.NISTAIRMF, &t.ISO42001,
				&t.Rationale, &t.DeclaredBy, &updatedAt); err != nil {
				return fmt.Errorf("scan compliance tag: %w", err)
			}
			t.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// SaveTag upserts one classification. An empty model key tags the project.
func (s *Store) SaveTag(
	ctx context.Context, tenantID, projectID, userID string, t ComplianceTag,
) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := requireAIBOMClassified(ctx, tx, projectID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO aibom.compliance_tags
				(tenant_id, project_id, model_key, eu_ai_act_tier,
				 nist_ai_rmf, iso_42001, rationale, declared_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (tenant_id, project_id, model_key) DO UPDATE SET
				eu_ai_act_tier = EXCLUDED.eu_ai_act_tier,
				nist_ai_rmf    = EXCLUDED.nist_ai_rmf,
				iso_42001      = EXCLUDED.iso_42001,
				rationale      = EXCLUDED.rationale,
				declared_by    = EXCLUDED.declared_by`,
			tenantID, projectID, t.ModelKey, nullIfEmpty(t.EUAIActTier),
			t.NISTAIRMF, t.ISO42001, nullIfEmpty(t.Rationale), userID)
		if err != nil {
			return fmt.Errorf("save compliance tag: %w", err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Attestation verification records
// ---------------------------------------------------------------------------

// Attestation is one verification RESULT — never a signature.
type Attestation struct {
	ModelKey       string          `json:"model_key"`
	Verified       bool            `json:"verified"`
	Method         string          `json:"method"`
	SignerIdentity string          `json:"signer_identity,omitempty"`
	SignerIssuer   string          `json:"signer_issuer,omitempty"`
	Digest         string          `json:"digest,omitempty"`
	FailureReason  string          `json:"failure_reason,omitempty"`
	Raw            json.RawMessage `json:"raw,omitempty"`
	VerifiedAt     string          `json:"verified_at"`
	RecordedBy     string          `json:"recorded_by"`
}

// RecordAttestation appends a verification record.
//
// ⚠ APPENDS. Verification is a statement about a MOMENT — the same reasoning
// campaigns exist for — so re-verifying adds a row and the newest one is the
// current answer. Overwriting would erase the history that makes a CHANGED
// answer legible, which is the only interesting case.
func (s *Store) RecordAttestation(
	ctx context.Context, tenantID, projectID, userID string, a Attestation,
) error {
	raw := a.Raw
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := requireAIBOMClassified(ctx, tx, projectID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO aibom.attestations
				(tenant_id, project_id, model_key, verified, method,
				 signer_identity, signer_issuer, digest, failure_reason, raw, recorded_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			tenantID, projectID, a.ModelKey, a.Verified, a.Method,
			nullIfEmpty(a.SignerIdentity), nullIfEmpty(a.SignerIssuer),
			nullIfEmpty(a.Digest), nullIfEmpty(a.FailureReason), raw, userID)
		if err != nil {
			return fmt.Errorf("record attestation: %w", err)
		}
		return nil
	})
}

// ListAttestations returns a project's verification records, newest first.
func (s *Store) ListAttestations(
	ctx context.Context, tenantID, projectID string,
) ([]Attestation, error) {
	out := []Attestation{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT model_key, verified, method, COALESCE(signer_identity,''),
			       COALESCE(signer_issuer,''), COALESCE(digest,''),
			       COALESCE(failure_reason,''), raw, verified_at, recorded_by::text
			  FROM aibom.attestations
			 WHERE project_id = $1
			 ORDER BY created_at DESC`, projectID)
		if err != nil {
			return fmt.Errorf("list attestations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a Attestation
			var verifiedAt time.Time
			if err := rows.Scan(&a.ModelKey, &a.Verified, &a.Method, &a.SignerIdentity,
				&a.SignerIssuer, &a.Digest, &a.FailureReason, &a.Raw,
				&verifiedAt, &a.RecordedBy); err != nil {
				return fmt.Errorf("scan attestation: %w", err)
			}
			a.VerifiedAt = verifiedAt.UTC().Format(time.RFC3339)
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
