package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// authenticateAPIKey verifies a presented AxeBOM API key and returns a
// context carrying the same values a session would.
//
// ⚠ ROLE IS FIXED AT RoleAnalyst, MATCHING apikey.go's OWN ASSUMPTION.
// AuthorizeKey's matrix check already assumes a key's ceiling is Analyst
// ("nothing that manages tenants, members, roles... is reachable with an API
// key"); setting it here is what makes that assumption true rather than
// aspirational, and mirrors the identical precedent this package's own
// service-token branch already established a few lines above.
func authenticateAPIKey(ctx context.Context, pool *db.Pool, presented string) (context.Context, error) {
	if pool == nil {
		return nil, errs.New(errs.InternalUnexpected,
			"this service cannot verify API keys: no database pool was configured")
	}

	keyID, err := auth.ParseKeyID(presented)
	if err != nil {
		return nil, err
	}

	record, err := lookupAPIKey(ctx, pool, keyID)
	if err != nil {
		return nil, err
	}

	if err := auth.Verify(presented, record, time.Now()); err != nil {
		return nil, err
	}

	ctx = ctxkey.WithTenantID(ctx, record.TenantID)
	ctx = ctxkey.WithUserID(ctx, APIKeySubjectPrefix+record.KeyID)
	ctx = ctxkey.WithRole(ctx, string(authz.RoleAnalyst))
	ctx = ctxkey.WithAPIKeyScopes(ctx, auth.ScopeStrings(record.Scopes))

	// ⚠ BEST EFFORT, NEVER FATAL. The key already verified; a telemetry write
	// failing must not turn a valid credential into a rejected request. Same
	// trade report/internal/service.ClaimShared's audit write already makes.
	touchAPIKeyLastUsed(ctx, pool, record)

	return ctx, nil
}

// lookupAPIKey is the pre-tenant read, by the plaintext id segment.
//
// ⚠ pool.Raw(), NOT WithTenant. The tenant is what this call is trying to
// discover — same shape as auth.memberships_for_user and every other
// pre-tenant lookup in migrations/auth/0002.
func lookupAPIKey(ctx context.Context, pool *db.Pool, keyID string) (auth.APIKey, error) {
	var (
		rec       auth.APIKey
		scopesRaw []string
		revokedAt *time.Time
	)

	err := pool.Raw().QueryRow(ctx, `
		SELECT id, tenant_id, name, key_id, hash, scopes, expires_at, revoked_at
		  FROM auth.api_key_by_key_id($1)`, keyID).
		Scan(&rec.ID, &rec.TenantID, &rec.Name, &rec.KeyID, &rec.Hash,
			&scopesRaw, &rec.ExpiresAt, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ⚠ SAME ANSWER AS A WRONG HASH, DELIBERATELY. Unlike a share
			// link's granted/expired/revoked/exhausted distinction — made for
			// a holder who already has a real token and gains nothing from
			// the extra detail — an unknown API key id and a tampered one are
			// indistinguishable here, matching how a malformed JWT is also
			// just "invalid" rather than diagnosed.
			return auth.APIKey{}, errs.New(errs.AuthTokenInvalid, "API key is not valid")
		}
		return auth.APIKey{}, fmt.Errorf("lookup api key: %w", err)
	}

	rec.RevokedAt = revokedAt
	rec.Scopes = make([]auth.Scope, len(scopesRaw))
	for i, s := range scopesRaw {
		rec.Scopes[i] = auth.Scope(s)
	}
	return rec, nil
}

// touchAPIKeyLastUsed records when a key was last presented.
//
// A normal tenant-scoped write, not another SECURITY DEFINER function: by
// this point the key has verified and its tenant is known, so RLS applies
// exactly as it should for any other write this tenant makes.
func touchAPIKeyLastUsed(ctx context.Context, pool *db.Pool, rec auth.APIKey) {
	err := pool.WithTenant(ctx, rec.TenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE auth.api_keys SET last_used_at = now() WHERE id = $1`, rec.ID)
		return err
	})
	if err != nil {
		slog.Default().Warn("could not record API key last-used timestamp",
			"key_id", rec.KeyID, "error", err)
	}
}
