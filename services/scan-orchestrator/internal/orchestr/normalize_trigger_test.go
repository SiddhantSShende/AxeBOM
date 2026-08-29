package orchestr_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// MarkNormalizeTriggered is the write-once guard the whole mechanism rests
// on: a redelivered ScanResultV1 reaching maybeTriggerNormalize after
// normalization has already fired must not fire it a second time.
func TestMarkNormalizeTriggeredFiresOnlyOnce(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	offered := uuid.NewString()
	first, fired, err := f.store.MarkNormalizeTriggered(t.Context(), tenantA, scan.ID, events.FamilySBOM, offered)
	if err != nil {
		t.Fatalf("first mark: %v", err)
	}
	if !fired {
		t.Fatal("first call did not fire; want fired=true")
	}
	if first != offered {
		t.Errorf("persisted id = %q, want the offered id %q", first, offered)
	}

	// A second call offering a DIFFERENT id must not fire, and must not
	// displace the id the first call actually persisted — the caller
	// publishes under its own offered id BEFORE claiming (see
	// maybeTriggerNormalize), so the persisted id is whichever call won,
	// not necessarily this call's own.
	second, fired, err := f.store.MarkNormalizeTriggered(t.Context(), tenantA, scan.ID, events.FamilySBOM, uuid.NewString())
	if err != nil {
		t.Fatalf("second mark: %v", err)
	}
	if fired {
		t.Error("second call fired again; the guard is not write-once")
	}
	if second != first {
		t.Errorf("trigger id changed across calls: %q then %q; a stable identity must survive redelivery", first, second)
	}

	// A different family for the same scan is a DIFFERENT trigger — the
	// primary key is (scan_id, family), not scan_id alone.
	thirdOffered := uuid.NewString()
	third, fired, err := f.store.MarkNormalizeTriggered(t.Context(), tenantA, scan.ID, events.FamilyCBOM, thirdOffered)
	if err != nil {
		t.Fatalf("cbom mark: %v", err)
	}
	if !fired {
		t.Error("cbom family did not fire even though sbom already had; the guard is scoped too broadly")
	}
	if third == first {
		t.Error("sbom and cbom triggers share an id; they must be independent rows")
	}
	if third != thirdOffered {
		t.Errorf("cbom persisted id = %q, want the offered id %q", third, thirdOffered)
	}
}

// NormalizeTriggerID must observe state without changing it — it exists
// specifically so a caller (this test, or an operator) can check whether a
// trigger fired without accidentally claiming the write-once slot the way a
// naive call to MarkNormalizeTriggered as a "just checking" probe would.
func TestNormalizeTriggerIDDoesNotClaimTheSlot(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	if id, err := f.store.NormalizeTriggerID(t.Context(), tenantA, scan.ID, events.FamilySBOM); err != nil {
		t.Fatalf("first check: %v", err)
	} else if id != "" {
		t.Fatalf("NormalizeTriggerID = %q before anything triggered, want empty", id)
	}

	// A read that returned "not fired" must not itself have fired it.
	if id, err := f.store.NormalizeTriggerID(t.Context(), tenantA, scan.ID, events.FamilySBOM); err != nil {
		t.Fatalf("second check: %v", err)
	} else if id != "" {
		t.Fatal("NormalizeTriggerID claimed the slot on read — a query must never have this side effect")
	}

	marked, fired, err := f.store.MarkNormalizeTriggered(t.Context(), tenantA, scan.ID, events.FamilySBOM, uuid.NewString())
	if err != nil || !fired {
		t.Fatalf("mark: id=%q fired=%v err=%v", marked, fired, err)
	}

	if id, err := f.store.NormalizeTriggerID(t.Context(), tenantA, scan.ID, events.FamilySBOM); err != nil {
		t.Fatalf("third check: %v", err)
	} else if id != marked {
		t.Errorf("NormalizeTriggerID = %q after marking, want %q", id, marked)
	}
}

// The end-to-end path: a normalize trigger fires exactly once, only after
// EVERY sbom engine actually dispatched for this scan reaches a terminal
// state — not after the first, and not more than once.
//
// syft and mock-engine are chosen because neither has a ConsumesOutputOf
// relationship (unlike grype, which FanOut deliberately holds back until
// syft reports) — this test is about family-readiness, not the producer/
// consumer ordering dependent_test.go already covers.
func TestNormalizeTriggerFiresOnlyAfterEveryFamilyEngineIsTerminal(t *testing.T) {
	f := newFixture(t)
	// This test publishes real jobs to scan.job.sbom and drives their
	// results by hand. A running worker (the Python sbom-worker, or the Go
	// mock engine consumer bus.go's docstring on `durable_name` describes as
	// mutually exclusive with it) would consume them and report on its own
	// timeline, racing this test's own HandleResult calls. See requireExclusive
	// in pipeline_test.go and its use throughout dependent_test.go.
	requireExclusive(t.Context(), t, f.bus, bus.StreamJobs, "scan.job.sbom", "",
		"docker compose stop sbom-worker")

	scan := createScan(t, f, tenantA, "syft", "mock-engine")

	if _, err := f.store.SetSourceOnce(t.Context(), tenantA, scan.ID,
		"a1b2c3", "s3://b/src.tar.zst", "sha-src"); err != nil {
		t.Fatalf("pinning source: %v", err)
	}
	if _, err := f.orch.FanOut(t.Context(), tenantA, scan.ID); err != nil {
		t.Fatalf("fan out: %v", err)
	}

	_, runs, _ := f.store.GetScan(t.Context(), tenantA, scan.ID)
	jobFor := map[string]string{}
	for _, r := range runs {
		jobFor[r.EngineID] = r.JobID
	}

	// syft reports first. Only one of two sbom engines is terminal — no
	// trigger yet.
	if err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         jobFor["syft"],
		ScanID:        scan.ID, TenantID: tenantA,
		Engine: "syft", EngineVersion: "1.51.0",
		Status: events.StatusSucceeded,
		Artifacts: []events.Artifact{{
			Role: "native_output", URI: "s3://b/syft.json",
			MediaType: "application/vnd.cyclonedx+json", SHA256: "syft-sha",
		}},
	}); err != nil {
		t.Fatalf("handle syft result: %v", err)
	}

	if id, err := f.store.NormalizeTriggerID(t.Context(), tenantA, scan.ID, events.FamilySBOM); err != nil {
		t.Fatalf("check trigger after syft only: %v", err)
	} else if id != "" {
		t.Errorf("normalize triggered (id=%s) after only one of two sbom engines reported", id)
	}

	// mock-engine reports. Now both are terminal — the orchestrator's own
	// HandleResult call fires the trigger.
	if err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         jobFor["mock-engine"],
		ScanID:        scan.ID, TenantID: tenantA,
		Engine: "mock-engine", EngineVersion: "dev",
		Status: events.StatusSucceeded,
		Artifacts: []events.Artifact{{
			Role: "native_output", URI: "s3://b/mock.json",
			MediaType: "application/vnd.cyclonedx+json", SHA256: "mock-sha",
		}},
	}); err != nil {
		t.Fatalf("handle mock-engine result: %v", err)
	}

	triggerID, err := f.store.NormalizeTriggerID(t.Context(), tenantA, scan.ID, events.FamilySBOM)
	if err != nil {
		t.Fatalf("check trigger after both reported: %v", err)
	}
	if triggerID == "" {
		t.Fatal("no trigger was recorded after every sbom engine reached a terminal state")
	}

	// The raw artifacts HandleResult recorded along the way are exactly what
	// the fired trigger's envelope would have carried — this is the same
	// query buildNormalizeTrigger uses to assemble it.
	artifacts, err := f.store.LoadRawArtifactsForEngines(t.Context(), tenantA, scan.ID, []string{"syft", "mock-engine"})
	if err != nil {
		t.Fatalf("load raw artifacts: %v", err)
	}
	if len(artifacts["syft"]) != 1 || artifacts["syft"][0].SHA256 != "syft-sha" {
		t.Errorf("syft raw artifacts = %+v, want one artifact with sha256=syft-sha", artifacts["syft"])
	}
	if len(artifacts["mock-engine"]) != 1 || artifacts["mock-engine"][0].SHA256 != "mock-sha" {
		t.Errorf("mock-engine raw artifacts = %+v, want one artifact with sha256=mock-sha", artifacts["mock-engine"])
	}
}

// A result from an engine outside the sbom family must never trigger
// normalization — maybeTriggerNormalize's family guard is checked before
// anything else.
//
// ⚠ BUILT VIA f.store.CreateScan DIRECTLY, NOT the createScan() helper.
// createScan() goes through Orchestrator.CreateScan, which publishes a real
// fetch job — and this shared dev stack has a live fetcher and a live
// scan-orchestrator SERVICE (a separate running process, not this test
// binary) that would race to process it, exactly the class of interference
// requireExclusive exists to catch on the JOB side. There is no equivalent
// guard for "nothing downstream of a published fetch job ever completes
// before this assertion runs", so the only reliable way to test a single
// HandleResult call in isolation is to never publish anything real in the
// first place: insert the scan/engine-run rows straight through the store,
// call HandleResult in-process, and check nothing else could plausibly have
// touched this scan.
//
// cbomkit-theia is used (not a made-up id) so this exercises the actual
// family guard (`family != events.FamilySBOM`), not registry.Get's ok=false
// path.
func TestNormalizeTriggerIgnoresNonSbomResults(t *testing.T) {
	f := newFixture(t)

	scan, err := f.store.CreateScan(t.Context(), orchestr.Scan{
		TenantID: tenantA, ProjectID: projectA, SourceKind: events.SourceGit,
		Families: []string{"cbom"}, EnginesRequested: []string{"cbomkit-theia"},
		TriggeredBy: "user", TriggerRef: userA,
	}, nil) // no engine_runs rows — this test upserts its own via HandleResult
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	cleanupScan(t, f, tenantA, scan.ID)

	if err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         uuid.NewString(),
		ScanID:        scan.ID, TenantID: tenantA,
		Engine: "cbomkit-theia", EngineVersion: "1.1.2",
		Status: events.StatusSucceeded,
	}); err != nil {
		t.Fatalf("handle cbom result: %v", err)
	}

	if id, err := f.store.NormalizeTriggerID(t.Context(), tenantA, scan.ID, events.FamilySBOM); err != nil {
		t.Fatalf("check sbom trigger: %v", err)
	} else if id != "" {
		t.Errorf("an sbom normalize trigger (id=%s) exists after only a cbom engine reported", id)
	}
}
