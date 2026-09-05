package service

import (
	"context"
	"errors"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/project/internal/store"
)

// GitHubConnectionStatus is what the UI is told about a tenant's connection.
//
// ⚠ NO TOKEN, AND NO CREDENTIAL REF EITHER. The Vault path is not a secret, but
// publishing it hands an attacker who reaches the API the exact location to
// aim at — and no screen has any use for it.
type GitHubConnectionStatus struct {
	Connected   bool
	GitHubLogin string
	ConnectedAt string
}

// ConnectGitHub stores a tenant-wide GitHub authorisation.
//
// ⚠ THIS IS "CONNECT ONCE", AND IT REPLACES A PER-PROJECT POPUP. Every project
// registration used to run its own OAuth round trip: useGitHubConnect opened a
// popup, took a repo-scoped token by postMessage, and passed it through the
// browser to the repo picker and then to the connection endpoint, where it was
// written to Vault against that ONE project. Nothing kept it, so three projects
// meant three authorisations — and every repo search sent the token back out
// through the browser again.
//
// The token now goes to Vault once and stays server-side. The browser sends it
// exactly once, on this call.
func (s *Service) ConnectGitHub(ctx context.Context, tenantID, userID, token, login string) (GitHubConnectionStatus, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return GitHubConnectionStatus{}, errs.New(errs.ValidationFieldRequired,
			"a GitHub token is required to connect")
	}

	// ⚠ THE REF IS DERIVED FROM THE TENANT, NOT RANDOM, so reconnecting
	// overwrites the same path instead of leaving the previous token in Vault
	// with nothing pointing at it. One tenant, one provider secret.
	ref := vault.Ref{TenantID: tenantID, Kind: vault.KindProviderToken, ID: "github"}
	path, err := s.vault.Put(ctx, ref, map[string]string{"token": token})
	if err != nil {
		return GitHubConnectionStatus{}, errs.Wrap(err, errs.InternalDependency,
			"could not store the GitHub credential securely; the connection was not saved")
	}

	// ⚠ SECRET FIRST, ROW SECOND. A row written before the secret would point
	// at a path that does not resolve, and every repo search would fail with an
	// internal error rather than the honest "not connected".
	conn, err := s.store.UpsertGitHubConnection(ctx, store.GitHubConnection{
		TenantID:      tenantID,
		CredentialRef: path,
		GitHubLogin:   strings.TrimSpace(login),
		ConnectedBy:   userID,
	})
	if err != nil {
		return GitHubConnectionStatus{}, mapStoreError(err)
	}

	return GitHubConnectionStatus{
		Connected:   true,
		GitHubLogin: conn.GitHubLogin,
		ConnectedAt: conn.ConnectedAt,
	}, nil
}

// GitHubConnection reports whether this tenant has connected GitHub.
//
// Not connected is a normal answer, not an error: it is the state every tenant
// starts in and the state the registration screen must render a button for.
func (s *Service) GitHubConnection(ctx context.Context, tenantID string) (GitHubConnectionStatus, error) {
	conn, err := s.store.GetGitHubConnection(ctx, tenantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return GitHubConnectionStatus{Connected: false}, nil
	case err != nil:
		return GitHubConnectionStatus{}, mapStoreError(err)
	}
	return GitHubConnectionStatus{
		Connected:   true,
		GitHubLogin: conn.GitHubLogin,
		ConnectedAt: conn.ConnectedAt,
	}, nil
}

// DisconnectGitHub removes the tenant's authorisation and its secret.
func (s *Service) DisconnectGitHub(ctx context.Context, tenantID string) error {
	// Read first: Delete needs the STORED path, which vault.checkOwnership uses
	// to prove the ref belongs to this tenant. Deleting the row first would
	// discard the only pointer to the secret.
	conn, err := s.store.GetGitHubConnection(ctx, tenantID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // already disconnected; saying so twice is not an error
	}
	if err != nil {
		return mapStoreError(err)
	}

	if err := s.store.DeleteGitHubConnection(ctx, tenantID); err != nil {
		return mapStoreError(err)
	}

	// ⚠ BEST EFFORT, AND DELIBERATELY NOT FATAL. The row is gone, so nothing
	// can reach the secret any more — every read path goes through the table.
	// Failing the request here would tell the customer their disconnect did not
	// work when it did, and the retry would delete a row that no longer exists.
	ref := vault.Ref{TenantID: tenantID, Kind: vault.KindProviderToken, ID: "github"}
	_ = s.vault.Delete(ctx, ref, conn.CredentialRef)
	return nil
}

// GitHubToken returns the tenant's stored token for a server-side GitHub call.
//
// ⚠ INTERNAL, AND IT MUST NEVER REACH A RESPONSE BODY. This exists so the repo
// search can run without the browser holding a token at all; the moment it is
// returned to a caller outside this service, "connect once" becomes "hand the
// token out on every request", which is worse than what it replaced.
func (s *Service) GitHubToken(ctx context.Context, tenantID string) (string, error) {
	conn, err := s.store.GetGitHubConnection(ctx, tenantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", errs.New(errs.ValidationFieldRequired,
			"GitHub is not connected for this organisation. Connect it once, and "+
				"every project can pick a repository without authorising again.")
	case err != nil:
		return "", mapStoreError(err)
	}

	ref := vault.Ref{TenantID: tenantID, Kind: vault.KindProviderToken, ID: "github"}
	secret, err := s.vault.Get(ctx, ref, conn.CredentialRef)
	if err != nil {
		return "", errs.Wrap(err, errs.InternalDependency,
			"the stored GitHub credential could not be read; reconnect GitHub")
	}
	token := secret["token"]
	if token == "" {
		return "", errs.New(errs.InternalDependency,
			"the stored GitHub credential is empty; reconnect GitHub")
	}
	return token, nil
}
