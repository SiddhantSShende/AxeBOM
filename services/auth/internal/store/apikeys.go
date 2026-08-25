package store

import (
	"context"
	"fmt"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// ⚠ THESE ARE ALL TENANT-SCOPED, UNLIKE THE REST OF THIS FILE'S PRE-TENANT
// FUNCTIONS. Minting, listing and revoking a key all happen from an
// authenticated session that already knows its tenant — the pre-tenant
// lookup a REQUEST presenting a key needs lives in
// libs/go-shared/oidcauth, which authenticates every service's traffic, not
// this one's key-management screen.

// CreateAPIKeyInput is what a caller asks to mint.
type CreateAPIKeyInput struct {
	Name      string
	Scopes    []auth.Scope
	TTL       time.Duration
	CreatedBy string
}

// CreateAPIKey mints a key and stores it.
func (s *Store) CreateAPIKey(ctx context.Context, tenantID string, in CreateAPIKeyInput, now time.Time) (auth.Minted, error) {
	minted, err := auth.Mint(tenantID, in.Name, in.CreatedBy, in.Scopes, in.TTL, now)
	if err != nil {
		return auth.Minted{}, err
	}

	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO auth.api_keys
				(tenant_id, name, key_id, hash, scopes, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, created_at`,
			tenantID, minted.Record.Name, minted.Record.KeyID, minted.Record.Hash,
			auth.ScopeStrings(minted.Record.Scopes), in.CreatedBy, minted.Record.ExpiresAt,
		).Scan(&minted.Record.ID, &minted.Record.CreatedAt)
	})
	if err != nil {
		return auth.Minted{}, fmt.Errorf("create api key: %w", err)
	}
	minted.Record.TenantID = tenantID
	minted.Record.CreatedBy = in.CreatedBy
	return minted, nil
}

// ListAPIKeys returns a tenant's keys, newest first.
//
// ⚠ NEVER SELECTS hash. A listing screen has no business touching the one
// column that lets a presented key be verified — dropping it from the SELECT
// means a bug in the response mapping cannot leak it either.
func (s *Store) ListAPIKeys(ctx context.Context, tenantID string) ([]auth.APIKey, error) {
	var out []auth.APIKey
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, name, key_id, scopes, created_by, created_at,
			       expires_at, last_used_at, revoked_at
			  FROM auth.api_keys
			 ORDER BY created_at DESC`)
		if err != nil {
			return fmt.Errorf("list api keys: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				k         auth.APIKey
				scopesRaw []string
				lastUsed  *time.Time
				revokedAt *time.Time
			)
			if err := rows.Scan(&k.ID, &k.TenantID, &k.Name, &k.KeyID, &scopesRaw,
				&k.CreatedBy, &k.CreatedAt, &k.ExpiresAt, &lastUsed, &revokedAt); err != nil {
				return fmt.Errorf("scan api key: %w", err)
			}
			k.Scopes = make([]auth.Scope, len(scopesRaw))
			for i, sc := range scopesRaw {
				k.Scopes[i] = auth.Scope(sc)
			}
			k.LastUsed = lastUsed
			k.RevokedAt = revokedAt
			out = append(out, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeAPIKey withdraws a key.
//
// ⚠ IDEMPOTENT, LIKE A SHARE-LINK REVOKE. The caller wants the key withdrawn;
// re-stamping revoked_at on an already-revoked key still leaves it revoked,
// so a repeated call succeeds rather than erroring on a state that is already
// safe.
func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, id string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE auth.api_keys SET revoked_at = now() WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("revoke api key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}
