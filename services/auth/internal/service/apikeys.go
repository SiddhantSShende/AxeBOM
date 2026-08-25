package service

import (
	"context"
	"errors"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/auth/internal/store"
)

// CreateAPIKeyRequest is what a caller asks to mint.
type CreateAPIKeyRequest struct {
	Name      string
	Scopes    []string
	TTLDays   int
	CreatedBy string
}

// CreateAPIKey validates and mints a key.
//
// ⚠ SCOPE VALIDATION HAPPENS HERE, NOT IN THE HANDLER. "%q is not a scope
// this build issues" is a business rule about what AxeBOM can enforce, not an
// HTTP concern — the same reason Queue validates a report's level and format
// before a row exists rather than in the worker.
func (s *Service) CreateAPIKey(ctx context.Context, tenantID string, req CreateAPIKeyRequest) (auth.Minted, error) {
	scopes, err := auth.ParseScopes(req.Scopes)
	if err != nil {
		return auth.Minted{}, err
	}

	var ttl time.Duration
	if req.TTLDays > 0 {
		ttl = time.Duration(req.TTLDays) * 24 * time.Hour
	}

	return s.store.CreateAPIKey(ctx, tenantID, store.CreateAPIKeyInput{
		Name:      req.Name,
		Scopes:    scopes,
		TTL:       ttl,
		CreatedBy: req.CreatedBy,
	}, s.now())
}

// ListAPIKeys returns a tenant's keys.
func (s *Service) ListAPIKeys(ctx context.Context, tenantID string) ([]auth.APIKey, error) {
	return s.store.ListAPIKeys(ctx, tenantID)
}

// RevokeAPIKey withdraws a key.
func (s *Service) RevokeAPIKey(ctx context.Context, tenantID, id string) error {
	err := s.store.RevokeAPIKey(ctx, tenantID, id)
	if err != nil && errors.Is(err, store.ErrNotFound) {
		return errs.New(errs.NotFoundResource, "no such API key")
	}
	return err
}
