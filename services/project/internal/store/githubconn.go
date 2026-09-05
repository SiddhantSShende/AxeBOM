package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// GitHubConnection is a tenant's one GitHub authorisation.
//
// ⚠ IT CARRIES NO TOKEN AND MUST NOT LEARN TO. CredentialRef is a Vault path,
// the same discipline project.repository_connections already follows: the
// secret lives in exactly one place, and a struct that could hold it is a
// struct that will eventually be logged.
type GitHubConnection struct {
	TenantID      string
	CredentialRef string
	GitHubLogin   string
	ConnectedBy   string
	ConnectedAt   string
}

// UpsertGitHubConnection records — or replaces — a tenant's GitHub connection.
//
// ⚠ UPSERT, NOT INSERT. Reconnecting is the normal way to repair an expired or
// revoked authorisation, and it must not fail on the primary key. The
// credential_ref is deterministic (it is derived from the tenant id), so the
// replacement overwrites the same Vault path rather than orphaning a secret.
func (s *Store) UpsertGitHubConnection(ctx context.Context, c GitHubConnection) (GitHubConnection, error) {
	var out GitHubConnection
	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO project.github_connections
				(tenant_id, credential_ref, github_login, connected_by)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id) DO UPDATE
			   SET credential_ref = EXCLUDED.credential_ref,
			       github_login   = EXCLUDED.github_login,
			       connected_by   = EXCLUDED.connected_by
			RETURNING tenant_id, credential_ref, github_login, connected_by,
			          to_char(connected_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
			c.TenantID, c.CredentialRef, c.GitHubLogin, c.ConnectedBy).
			Scan(&out.TenantID, &out.CredentialRef, &out.GitHubLogin,
				&out.ConnectedBy, &out.ConnectedAt)
	})
	if err != nil {
		return GitHubConnection{}, fmt.Errorf("upsert github connection: %w", err)
	}
	return out, nil
}

// GetGitHubConnection returns the tenant's connection, or ErrNotFound.
func (s *Store) GetGitHubConnection(ctx context.Context, tenantID string) (GitHubConnection, error) {
	var out GitHubConnection
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id, credential_ref, github_login, connected_by,
			       to_char(connected_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			  FROM project.github_connections`).
			Scan(&out.TenantID, &out.CredentialRef, &out.GitHubLogin,
				&out.ConnectedBy, &out.ConnectedAt)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return GitHubConnection{}, ErrNotFound
	case err != nil:
		return GitHubConnection{}, fmt.Errorf("get github connection: %w", err)
	}
	return out, nil
}

// DeleteGitHubConnection removes the row. The caller deletes the secret.
//
// ⚠ THE ROW GOES FIRST AND THE SECRET SECOND, WHICH IS THE SAFE ORDER. If the
// second step fails, a secret outlives its row — unreachable, because every
// read path goes through this table. The reverse order would leave a row
// pointing at a Vault path that no longer resolves, and every repo search would
// fail with an internal error instead of "not connected".
func (s *Store) DeleteGitHubConnection(ctx context.Context, tenantID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM project.github_connections`)
		return err
	})
}
