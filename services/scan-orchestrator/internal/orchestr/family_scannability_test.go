package orchestr_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// ---------------------------------------------------------------------------
// HBOM and QBOM cannot be requested as a scan family
// ---------------------------------------------------------------------------
//
// ⚠ NEITHER FAMILY HAS A WORKER, BY DESIGN.
//
// workers/hbom and workers/qbom deliberately have no runner: HBOM is a
// CSV/form import, and QBOM is derived from CBOM discovery with
// quantum-vulnerability rules applied (CLAUDE.md honest labels). Before this
// check existed, `families: ["hbom"]` or `["qbom"]` resolved cleanly through
// policy.Registry.Resolve (which only consults Supports(kind), not the
// Derived/RequiresImport flags) and CreateScan went on to publish a
// scan.job.hbom / scan.job.qbom job that nothing ever consumes — the scan sat
// unconsumed until it timed out (docs/STATE.md, session 2026-08-23 (c)).
//
// This is refused HERE, before anything is persisted or published, exactly
// as CreateScan's own doc comment demands.

// TestFamilyNotDirectlyScannable is the table: HBOM/QBOM alone are rejected,
// a mix with a real scannable family is rejected but names ONLY the
// offender, and SBOM/CBOM/AIBOM remain accepted and unaffected.
func TestFamilyNotDirectlyScannable(t *testing.T) {
	tests := []struct {
		name         string
		families     []events.Family
		wantRejected bool
		// wantNamed are families that MUST appear among the offending
		// families in the error details.
		wantNamed []string
		// wantNotNamed are families that MUST NOT appear — a scannable family
		// swept up into the rejection would block a legitimate request.
		wantNotNamed []string
	}{
		{
			name:         "hbom alone is rejected",
			families:     []events.Family{events.FamilyHBOM},
			wantRejected: true,
			wantNamed:    []string{"hbom"},
		},
		{
			name:         "qbom alone is rejected",
			families:     []events.Family{events.FamilyQBOM},
			wantRejected: true,
			wantNamed:    []string{"qbom"},
		},
		{
			// ⚠ THE MIXED CASE: a real scannable family requested ALONGSIDE an
			// import/derived one must still name the true offender, not the
			// whole request, and must not reject sbom along with it.
			name:         "sbom mixed with hbom is rejected and names hbom specifically",
			families:     []events.Family{events.FamilySBOM, events.FamilyHBOM},
			wantRejected: true,
			wantNamed:    []string{"hbom"},
			wantNotNamed: []string{"sbom"},
		},
		{
			name:     "sbom alone remains accepted",
			families: []events.Family{events.FamilySBOM},
		},
		{
			name:     "cbom alone remains accepted",
			families: []events.Family{events.FamilyCBOM},
		},
		{
			name:     "aibom alone remains accepted",
			families: []events.Family{events.FamilyAIBOM},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			scan, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
				ProjectID: projectA, SourceKind: events.SourceGit,
				Families: tt.families, RequestedBy: userA,
			})

			if !tt.wantRejected {
				if err != nil {
					t.Fatalf("families %v were rejected, want accepted: %v", tt.families, err)
				}
				cleanupScan(t, f, tenantA, scan.ID)
				return
			}

			if err == nil {
				t.Fatalf("families %v were accepted; want SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE", tt.families)
			}
			if !errs.Is(err, errs.ScanFamilyNotDirectlyScannable) {
				t.Fatalf("code = %v, want SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE", err)
			}

			var e *errs.Error
			if !errors.As(err, &e) {
				t.Fatalf("not a structured error: %v", err)
			}
			if e.HTTPStatus() != 422 {
				t.Errorf("status = %d, want 422", e.HTTPStatus())
			}

			named := map[string]bool{}
			for _, d := range e.Details {
				fam, ok := d["family"].(string)
				if !ok {
					continue
				}
				named[fam] = true
				if reason, ok := d["reason"].(string); !ok || reason == "" {
					t.Errorf("offending family %s carries no reason", fam)
				}
			}
			for _, want := range tt.wantNamed {
				if !named[want] {
					t.Errorf("%s is not named among the offending families: %v", want, e.Details)
				}
			}
			for _, notWant := range tt.wantNotNamed {
				if named[notWant] {
					t.Errorf("%s was named as offending, but it is directly scannable", notWant)
				}
			}
		})
	}
}

// HBOM's redirect must point at the import endpoints, not merely say "no".
// An actionable 422 names the alternative, not just the refusal.
func TestHBOMRejectionNamesTheImportEndpoint(t *testing.T) {
	f := newFixture(t)
	_, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceUpload,
		Families: []events.Family{events.FamilyHBOM}, RequestedBy: userA,
	})
	var e *errs.Error
	if !errors.As(err, &e) {
		t.Fatalf("not a structured error: %v", err)
	}
	if !containsSubstring(e, "/v1/hbom/") {
		t.Errorf("HBOM rejection does not name the /v1/hbom/* import endpoints: %+v", e.Details)
	}
}

// QBOM's redirect must explain that it becomes available once CBOM exists —
// not merely refuse it, or a user has no idea how to ever get a QBOM report.
func TestQBOMRejectionExplainsTheCBOMDependency(t *testing.T) {
	f := newFixture(t)
	_, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceGit,
		Families: []events.Family{events.FamilyQBOM}, RequestedBy: userA,
	})
	var e *errs.Error
	if !errors.As(err, &e) {
		t.Fatalf("not a structured error: %v", err)
	}
	if !containsSubstring(e, "CBOM") {
		t.Errorf("QBOM rejection does not explain the CBOM dependency: %+v", e.Details)
	}
}

func containsSubstring(e *errs.Error, needle string) bool {
	for _, d := range e.Details {
		if reason, ok := d["reason"].(string); ok && strings.Contains(reason, needle) {
			return true
		}
	}
	return strings.Contains(e.Message, needle)
}

// ---------------------------------------------------------------------------
// An explicit RequestedEngines entry naming a metadata-only engine directly
// ---------------------------------------------------------------------------

// A caller who bypasses family selection and names hbom-csv / qbom-derive
// directly in RequestedEngines must be refused exactly the same way — the
// family-level check alone would miss this path, since RequestedEngines
// resolves verbatim (resolveEngines) rather than through Registry.Resolve.
func TestExplicitMetadataOnlyEngineRequestIsRejected(t *testing.T) {
	tests := []struct {
		name       string
		engine     string
		family     events.Family
		sourceKind events.SourceKind
	}{
		{"hbom-csv requested directly", "hbom-csv", events.FamilyHBOM, events.SourceUpload},
		{"qbom-derive requested directly", "qbom-derive", events.FamilyQBOM, events.SourceGit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			_, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
				ProjectID: projectA, SourceKind: tt.sourceKind,
				Families:         []events.Family{tt.family},
				RequestedEngines: []string{tt.engine},
			})
			if err == nil {
				t.Fatalf("an explicit request for the metadata-only engine %s was accepted", tt.engine)
			}
			if !errs.Is(err, errs.ScanFamilyNotDirectlyScannable) {
				t.Fatalf("code = %v, want SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE", err)
			}

			var e *errs.Error
			if !errors.As(err, &e) {
				t.Fatalf("not a structured error: %v", err)
			}
			named := map[string]bool{}
			for _, d := range e.Details {
				if engine, ok := d["engine"].(string); ok {
					named[engine] = true
				}
			}
			if !named[tt.engine] {
				t.Errorf("%s is not named among the offending engines: %v", tt.engine, e.Details)
			}
		})
	}
}
