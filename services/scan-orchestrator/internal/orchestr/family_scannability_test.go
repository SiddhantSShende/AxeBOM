package orchestr_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// ---------------------------------------------------------------------------
// QBOM cannot be requested as a scan family. HBOM now can.
// ---------------------------------------------------------------------------
//
// ⚠ HBOM MOVED, AND THAT MOVE IS WHAT THESE TESTS PIN.
//
// It used to be refused alongside QBOM, because every registered HBOM engine
// was an import (hbom-csv). `hbom-ecad` is not: it parses the customer's own
// KiCad/Altium/OrCAD design files out of an upload or a connected repository —
// the same kind of act as parsing package-lock.json for an SBOM, and nothing
// like inspecting a device. So the family became directly scannable.
//
// ⚠ IT BECAME SCANNABLE WITH NO EDIT TO rejectNonScannableFamilies. That
// function walks the registry's Derived/RequiresImport flags rather than
// naming families, so adding one non-import engine was the whole change. These
// tests exist to keep that property true in both directions.
//
// QBOM is unchanged: it is derived from CBOM discovery with
// quantum-vulnerability rules applied (CLAUDE.md honest labels), has no runner
// by design, and is still refused HERE — before anything is persisted or
// published — because a published scan.job.qbom is a job nothing consumes,
// and the scan then sits until it times out (docs/STATE.md, 2026-08-23 (c)).

// TestFamilyNotDirectlyScannable is the table: QBOM alone is rejected, a mix
// with a real scannable family is rejected but names ONLY the offender, and
// SBOM/CBOM/AIBOM/HBOM are accepted and unaffected.
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
			// ⚠ THE INVERTED CASE. This asserted rejection until hbom-ecad
			// existed. A design-file parse is a real scan, so refusing it
			// would now be the bug.
			name:     "hbom alone is accepted, because hbom-ecad parses design files",
			families: []events.Family{events.FamilyHBOM},
		},
		{
			name:         "qbom alone is rejected",
			families:     []events.Family{events.FamilyQBOM},
			wantRejected: true,
			wantNamed:    []string{"qbom"},
		},
		{
			// ⚠ THE MIXED CASE: a real scannable family requested ALONGSIDE a
			// derived one must still name the true offender, not the whole
			// request, and must not reject sbom along with it.
			name:         "sbom mixed with qbom is rejected and names qbom specifically",
			families:     []events.Family{events.FamilySBOM, events.FamilyQBOM},
			wantRejected: true,
			wantNamed:    []string{"qbom"},
			wantNotNamed: []string{"sbom"},
		},
		{
			name:     "sbom mixed with hbom is accepted — both are scannable now",
			families: []events.Family{events.FamilySBOM, events.FamilyHBOM},
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

// TestHBOMIsScannableFromAnUploadAndFromARepository is the positive case that
// replaced TestHBOMRejectionNamesTheImportEndpoint.
//
// ⚠ IT CHECKS THE RESOLVED ENGINE SET, NOT MERELY THAT NO ERROR CAME BACK.
// An HBOM scan that was accepted but resolved to zero engines would pass a
// bare error check while doing nothing at all — and "the scan completed and
// wrote nothing" is precisely the silent-failure shape this codebase keeps
// finding. hbom-ecad must actually be queued.
func TestHBOMIsScannableFromAnUploadAndFromARepository(t *testing.T) {
	for _, kind := range []events.SourceKind{events.SourceUpload, events.SourceGit} {
		t.Run(string(kind), func(t *testing.T) {
			f := newFixture(t)
			scan, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
				ProjectID: projectA, SourceKind: kind,
				Families: []events.Family{events.FamilyHBOM}, RequestedBy: userA,
			})
			if err != nil {
				t.Fatalf("an hbom scan from a %s source was refused: %v", kind, err)
			}
			defer cleanupScan(t, f, tenantA, scan.ID)

			var queued []string
			queued = append(queued, scan.EnginesRequested...)
			if !slices.Contains(queued, "hbom-ecad") {
				t.Errorf("hbom-ecad was not queued for a %s source; engines = %v", kind, queued)
			}
			// ⚠ hbom-csv NAMES THE REST IMPORT PATH, NOT A JOB. It declares no
			// source kind precisely so fan-out cannot select it; a job for it
			// would sit unconsumed and leave a permanent skipped row in the
			// Engine Coverage section.
			if slices.Contains(queued, "hbom-csv") {
				t.Errorf("hbom-csv was dispatched as a scan engine; it has no worker "+
					"and names the /v1/hbom/* import path instead. engines = %v", queued)
			}
		})
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

// A caller who bypasses family selection and names an UNDISPATCHABLE engine
// directly in RequestedEngines must be refused — the family-level check alone
// would miss this path, since RequestedEngines resolves verbatim
// (resolveEngines) rather than through Registry.Resolve.
//
// ⚠ "UNDISPATCHABLE" IS Derived OR NO SOURCE KINDS — NOT RequiresImport.
// That flag is an honest label about where data came from, and
// github-dependency-graph-sbom has carried it while being dispatched on every
// git SBOM scan since it was added. Using it as the predicate looked correct
// only because nothing ever named that engine explicitly. See
// TestAnImportLabelledEngineWithASourceKindIsStillRequestable below, which is
// the other half of this rule and the reason it was changed.
func TestExplicitMetadataOnlyEngineRequestIsRejected(t *testing.T) {
	tests := []struct {
		name       string
		engine     string
		family     events.Family
		sourceKind events.SourceKind
		// ⚠ TWO DIFFERENT CODES, AND WHICH ONE FIRES IS NOT ARBITRARY.
		//
		// ValidateCombination runs FIRST and catches an engine that cannot read
		// the requested source kind — which is how an empty SourceKinds
		// presents. rejectNonScannableFamilies runs after and catches a Derived
		// engine, which reads every source kind and is undispatchable for a
		// different reason. Both are 422s naming the engine with an actionable
		// reason; asserting the specific code keeps the two paths distinct
		// rather than letting one quietly start covering the other.
		wantCode errs.Code
	}{
		{
			"hbom-csv requested directly", "hbom-csv", events.FamilyHBOM, events.SourceUpload,
			errs.ScanEngineCombinationInvalid,
		},
		{
			"qbom-derive requested directly", "qbom-derive", events.FamilyQBOM, events.SourceGit,
			errs.ScanFamilyNotDirectlyScannable,
		},
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
			if !errs.Is(err, tt.wantCode) {
				t.Fatalf("code = %v, want %s", err, tt.wantCode)
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
				if engine, ok := d["engine"].(string); ok {
					named[engine] = true
					// An error that names the engine but not why is only half
					// actionable — the caller still has to guess what to change.
					if reason, ok := d["reason"].(string); !ok || reason == "" {
						t.Errorf("offending engine %s carries no reason", engine)
					}
				}
			}
			if !named[tt.engine] {
				t.Errorf("%s is not named among the offending engines: %v", tt.engine, e.Details)
			}
		})
	}
}

// TestAnImportLabelledEngineWithASourceKindIsStillRequestable pins the half of
// the rule that the old RequiresImport predicate got wrong.
//
// hbom-cdxgen-host is RequiresImport — it ingests a CycloneDX host inventory
// the CUSTOMER produced by running cdxgen on their own device, and AxeBOM
// never touches that device. That is an honest label about provenance. It says
// nothing about whether a job can be published, and the job runs fine.
//
// Under the old predicate this request was a 422. Under the new one it is
// accepted, exactly as github-dependency-graph-sbom's identical label has
// always been in practice.
func TestAnImportLabelledEngineWithASourceKindIsStillRequestable(t *testing.T) {
	f := newFixture(t)
	scan, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceUpload,
		Families:         []events.Family{events.FamilyHBOM},
		RequestedEngines: []string{"hbom-cdxgen-host"},
		RequestedBy:      userA,
	})
	if err != nil {
		t.Fatalf("hbom-cdxgen-host was refused for carrying an honest import label: %v", err)
	}
	cleanupScan(t, f, tenantA, scan.ID)
}
