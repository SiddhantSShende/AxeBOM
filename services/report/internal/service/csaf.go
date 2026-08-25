package service

import (
	"context"
	"errors"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/report/internal/store"
)

// ---------------------------------------------------------------------------
// CSAF advisories
//
// ⚠ THIN, DELIBERATELY. All the real work — generation (csafgen.Generate),
// idempotency, and the vex_statement/tenant lookups — lives in
// internal/store/csaf.go, which already has everything it needs (the pool)
// to do that in one transaction. A service-layer method that split those
// steps across two round trips would open a window for a duplicate advisory
// between "check if one exists" and "insert".
// ---------------------------------------------------------------------------

// GenerateCSAFAdvisory publishes the CSAF form of an existing VEX statement.
//
// ⚠ now IS THE CALLER'S CLOCK, NEVER time.Now() READ HERE — matches every
// other timestamped write in this service (see Handler's own h.now()), so a
// re-generation of an identical decision is reproducible rather than dated
// by whichever instant this happened to run (ADR-0003).
func (s *Service) GenerateCSAFAdvisory(
	ctx context.Context, tenantID, projectID string, in store.GenerateCSAFAdvisoryInput, now time.Time,
) (*store.CSAFAdvisory, error) {
	advisory, err := s.store.GenerateAndStoreCSAFAdvisory(ctx, tenantID, projectID, in, now)
	if err != nil {
		if errors.Is(err, store.ErrVEXStatementNotFound) {
			return nil, errs.New(errs.NotFoundResource, "no such VEX statement")
		}
		return nil, err
	}
	return advisory, nil
}

// ListCSAFAdvisories returns every CSAF advisory published for a project.
func (s *Service) ListCSAFAdvisories(ctx context.Context, tenantID, projectID string) ([]store.CSAFAdvisory, error) {
	return s.store.ListCSAFAdvisories(ctx, tenantID, projectID)
}
