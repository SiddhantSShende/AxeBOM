package service

import (
	"context"
	"errors"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/store"
)

// ---------------------------------------------------------------------------
// Dependencies and findings
//
// Thin pass-throughs: the cross-schema read discipline (project owns none of
// normalize.*, and never joins across a schema boundary in SQL) lives in
// store/dependencies.go and store/findings.go, matching
// services/scan-orchestrator/internal/orchestr/findings.go and
// services/report/internal/store/bomsource.go.
// ---------------------------------------------------------------------------

// ListDependencies returns a project's current SBOM component inventory.
func (s *Service) ListDependencies(ctx context.Context, tenantID, projectID string) ([]store.DependencyRow, error) {
	rows, err := s.store.ListDependencies(ctx, tenantID, projectID)
	return rows, mapStoreError(err)
}

// GetComponentDetail returns one component's full drawer payload.
func (s *Service) GetComponentDetail(ctx context.Context, tenantID, projectID, componentKey string) (store.ComponentDetail, error) {
	detail, err := s.store.GetComponentDetail(ctx, tenantID, projectID, componentKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ComponentDetail{}, errs.New(errs.NotFoundResource, "no such component")
		}
		return store.ComponentDetail{}, err
	}
	return detail, nil
}

// ListFindings returns a project's findings, one row per deduplicated
// vulnerability cluster.
func (s *Service) ListFindings(ctx context.Context, tenantID, projectID string) ([]store.Finding, error) {
	findings, err := s.store.ListFindings(ctx, tenantID, projectID)
	return findings, mapStoreError(err)
}

// ListCryptoAssets returns a project's current CBOM crypto-asset inventory.
func (s *Service) ListCryptoAssets(ctx context.Context, tenantID, projectID string) ([]store.CryptoAsset, error) {
	assets, err := s.store.ListCryptoAssets(ctx, tenantID, projectID)
	return assets, mapStoreError(err)
}
