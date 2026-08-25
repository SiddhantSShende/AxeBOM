package orchestr_test

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// latestEngineRunsProject is DEDICATED to this file, never shared with
// projectA/projectB — LatestEngineRunsForProject answers "the MOST RECENT
// scan of each engine for this project", and a project id every other test
// in this package also writes to would make that answer ambiguous.
const latestEngineRunsProject = "01900000-0000-7000-8000-0000000000fe"

func createScanForLatestEngineRunsTests(t *testing.T, f *fixture, tenantID string, engines ...string) orchestr.Scan {
	t.Helper()
	in := orchestr.CreateScanInput{
		ProjectID: latestEngineRunsProject, SourceKind: events.SourceGit,
		Families: []events.Family{events.FamilySBOM}, RequestedBy: userA,
	}
	if len(engines) > 0 {
		in.RequestedEngines = engines
	}
	scan, err := f.orch.CreateScan(t.Context(), tenantID, in)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	return scan
}

// TestLatestEngineRunsForProject exercises the Engine Coverage panel's data
// source: one row per engine this project has ever invoked, from its most
// recent scan of that engine — not merely its most recent scan.
func TestLatestEngineRunsForProject(t *testing.T) {
	f := newFixture(t)

	scan := createScanForLatestEngineRunsTests(t, f, tenantA, "syft")
	cleanupScan(t, f, tenantA, scan.ID)

	latest, err := f.store.LatestEngineRunsForProject(t.Context(), tenantA, latestEngineRunsProject)
	if err != nil {
		t.Fatalf("LatestEngineRunsForProject: %v", err)
	}

	run, ok := latest["syft"]
	if !ok {
		t.Fatalf("expected a syft run, got %v", latest)
	}
	if run.ScanID != scan.ID {
		t.Errorf("scan id = %q, want %q", run.ScanID, scan.ID)
	}
	// ⚠ NOT PINNED TO "queued". This environment runs its DB-backed tests
	// against the SAME live NATS/Postgres a real `task dev` stack's
	// sbom-worker container also consumes from (docs/08-OPERATIONS.md — these
	// tests need a running stack, and nothing here is a private, hermetic
	// broker). `CreateScan` publishes a genuine `scan.job.sbom`, and a live
	// worker can pick it up and advance its status before this assertion
	// runs — status = "queued" flaked under `go test -race` for exactly that
	// reason. Any status the column's own CHECK constraint accepts proves the
	// row is real and correctly associated with this scan, which is the
	// actual property under test — the transient value it happened to hold
	// at query time is not.
	switch run.Status {
	case "queued", "running", "succeeded", "partial", "failed", "timeout", "unavailable", "skipped":
	default:
		t.Errorf("status = %q, not a recognized engine status", run.Status)
	}
}

// TestLatestEngineRunsForProjectIsTenantScoped asserts RLS, not application
// logic, is what keeps one tenant's engine history out of another's — the
// same property every other store method in this package is tested against.
func TestLatestEngineRunsForProjectIsTenantScoped(t *testing.T) {
	f := newFixture(t)

	scan := createScanForLatestEngineRunsTests(t, f, tenantA, "syft")
	cleanupScan(t, f, tenantA, scan.ID)

	latest, err := f.store.LatestEngineRunsForProject(t.Context(), tenantB, latestEngineRunsProject)
	if err != nil {
		t.Fatalf("LatestEngineRunsForProject: %v", err)
	}
	if len(latest) != 0 {
		t.Errorf("tenantB saw %d of tenantA's engine runs, want 0", len(latest))
	}
}

// TestLatestEngineRunsForProjectIsEmptyForAnUnknownProject asserts a project
// with no scan history yet is a genuinely empty map, not an error — "never
// run" is a state the Engine Coverage panel must render, not fail on.
func TestLatestEngineRunsForProjectIsEmptyForAnUnknownProject(t *testing.T) {
	f := newFixture(t)

	latest, err := f.store.LatestEngineRunsForProject(t.Context(), tenantA, "01900000-0000-7000-8000-0000000000ff")
	if err != nil {
		t.Fatalf("LatestEngineRunsForProject: %v", err)
	}
	if len(latest) != 0 {
		t.Errorf("got %d runs for a project with none, want 0", len(latest))
	}
}
