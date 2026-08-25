package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// EnginePolicy mirrors scan.engine_policy — one tenant's override of which
// engines run for one family.
type EnginePolicy struct {
	ID       string
	TenantID string
	Family   events.Family
	// EngineIDs replaces the DEFAULT set for Family. An empty, non-nil slice
	// is meaningful: "run nothing for this family" (a tenant disabling a BOM
	// type without touching every project's classification).
	EngineIDs []string
	// Weights overrides an engine's DefaultWeight for progress calculation.
	// Absent keys use the registry's default.
	Weights map[string]int
	Enabled bool
	Note    string
}

// Store is scan.engine_policy's persistence layer.
//
// ⚠ TENANT-SCOPED ROWS ONLY, NEVER THE GLOBAL (tenant_id IS NULL) DEFAULT.
//
// The migration's own comment describes a tenant reading "the global row and
// its own", but `enable_tenant_rls_nullable`'s actual USING clause
// (migrations/bootstrap/0002_pin_helper_search_path.sql) is strictly
// `tenant_id = current_tenant` — WITH CHECK is the only clause that adds
// `OR tenant_id IS NULL`, and that only permits an operator connecting
// without a tenant context to WRITE a global row, not a tenant to read one.
// This is the identical shape `auth.audit_log` already documents as
// deliberate: a global row is write-only to every tenant-scoped connection,
// and reading it back is a platform-admin surface out of scope before Phase
// 16. So "no row for this tenant" already means "use the built-in default" —
// there is nothing to additionally fall back to today.
type Store struct{ pool *db.Pool }

func NewStore(pool *db.Pool) *Store { return &Store{pool: pool} }

// Get returns this tenant's override for one family, if it has customised
// one. ok is false when there is no row — "use the built-in default", not an
// error.
func (s *Store) Get(ctx context.Context, tenantID string, family events.Family) (EnginePolicy, bool, error) {
	var out EnginePolicy
	found := false
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT id, tenant_id, family, engine_ids, weights, enabled, COALESCE(note, '')
			  FROM scan.engine_policy
			 WHERE family = $1`, string(family))
		p, err := scanEnginePolicyRow(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		out, found = p, true
		return nil
	})
	if err != nil {
		return EnginePolicy{}, false, err
	}
	return out, found, nil
}

// ListForTenant returns every family this tenant has customised — the shape
// a settings screen needs to show all five BOM types in one call rather than
// five.
func (s *Store) ListForTenant(ctx context.Context, tenantID string) ([]EnginePolicy, error) {
	var out []EnginePolicy
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, family, engine_ids, weights, enabled, COALESCE(note, '')
			  FROM scan.engine_policy
			 ORDER BY family`)
		if err != nil {
			return fmt.Errorf("list engine policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanEnginePolicyRow(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// Upsert replaces this tenant's override for one family.
//
// ⚠ NEVER TARGETS THE GLOBAL ROW. tenantID always binds the row's tenant_id;
// there is no code path here that can write tenant_id IS NULL, so a
// tenant-facing API built on this can never touch the system-wide default —
// exactly the boundary CLAUDE.md invariant 6 exists to enforce for every
// other table.
func (s *Store) Upsert(ctx context.Context, tenantID string, family events.Family,
	engineIDs []string, weights map[string]int, enabled bool, note string,
) (EnginePolicy, error) {
	if engineIDs == nil {
		engineIDs = []string{}
	}
	if weights == nil {
		weights = map[string]int{}
	}
	weightsJSON, err := json.Marshal(weights)
	if err != nil {
		return EnginePolicy{}, errs.Newf(errs.ValidationFieldInvalid, "weights: %v", err)
	}

	var out EnginePolicy
	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO scan.engine_policy (tenant_id, family, engine_ids, weights, enabled, note)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))
			ON CONFLICT (tenant_id, family) DO UPDATE SET
				engine_ids = EXCLUDED.engine_ids,
				weights    = EXCLUDED.weights,
				enabled    = EXCLUDED.enabled,
				note       = EXCLUDED.note
			RETURNING id, tenant_id, family, engine_ids, weights, enabled, COALESCE(note, '')`,
			tenantID, string(family), engineIDs, weightsJSON, enabled, note)
		p, err := scanEnginePolicyRow(row)
		if err != nil {
			return err
		}
		out = p
		return nil
	})
	if err != nil {
		return EnginePolicy{}, err
	}
	return out, nil
}

// Delete removes this tenant's override for one family, reverting it to the
// built-in default.
func (s *Store) Delete(ctx context.Context, tenantID string, family events.Family) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			DELETE FROM scan.engine_policy WHERE family = $1`, string(family))
		return err
	})
}

// OverridesForTenant returns this tenant's customisations in the shape
// Registry.Resolve already accepts — engine_ids per family, for every family
// that has a row and is enabled.
//
// ⚠ A DISABLED ROW MEANS "RUN NOTHING", NOT "USE THE DEFAULT". Both are
// expressed as this family being present in the returned map; the caller
// (Orchestrator.CreateScan, via resolveEngines) must not special-case an
// empty slice as "no override" — Resolve() already treats overrides[f] = []
// as replacing the default set with nothing, which is exactly right here.
func (s *Store) OverridesForTenant(ctx context.Context, tenantID string) (map[events.Family][]string, error) {
	rows, err := s.ListForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[events.Family][]string, len(rows))
	for _, p := range rows {
		if !p.Enabled {
			out[p.Family] = []string{}
			continue
		}
		out[p.Family] = p.EngineIDs
	}
	return out, nil
}

func scanEnginePolicyRow(row pgx.Row) (EnginePolicy, error) {
	var p EnginePolicy
	var family, note string
	var weightsJSON []byte
	if err := row.Scan(&p.ID, &p.TenantID, &family, &p.EngineIDs, &weightsJSON, &p.Enabled, &note); err != nil {
		return EnginePolicy{}, err
	}
	p.Family = events.Family(family)
	p.Note = note
	if len(weightsJSON) > 0 {
		if err := json.Unmarshal(weightsJSON, &p.Weights); err != nil {
			return EnginePolicy{}, fmt.Errorf("unmarshal engine_policy.weights: %w", err)
		}
	}
	return p, nil
}
