package orchestr_test

import (
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/bus"

	"github.com/encorebom/encorebom/libs/go-shared/events"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/orchestr"
)

// grype reads syft's SBOM, so its job must not be published until syft reports.
//
// The fan-out used to publish all six engine jobs at once, so grype was
// routinely delivered before syft had produced the document it matches against
// and reported ENGINE_INPUT_MISSING on every real scan. The registry now models
// the dependency and FanOut holds the consumer back.
func TestAConsumingEngineIsNotPublishedUntilItsProducerReports(t *testing.T) {
	f := newFixture(t)
	// These tests publish real jobs to scan.job.sbom. A running worker would
	// consume them, scan a workspace that does not exist, and report — and the
	// live orchestrator would then release or skip grype before the assertion
	// ran. See requireExclusive in pipeline_test.go.
	requireExclusive(t.Context(), t, f.bus, bus.StreamJobs, "scan.job.sbom", "",
		"docker compose stop sbom-worker")

	scan := createScan(t, f, tenantA, "syft", "grype")

	if _, err := f.store.SetSourceOnce(t.Context(), tenantA, scan.ID,
		"a1b2c3", "s3://b/src.tar.zst", "sha-src"); err != nil {
		t.Fatalf("pinning source: %v", err)
	}

	published, err := f.orch.FanOut(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("fan out: %v", err)
	}

	// syft only. grype is held.
	if published != 1 {
		t.Errorf("fan-out published %d jobs, want 1 — grype must wait for syft", published)
	}

	_, runs, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	for _, r := range runs {
		if r.EngineID == "grype" && r.Status != "queued" {
			t.Errorf("grype is %q before syft reported; it should still be queued", r.Status)
		}
	}
}

// A producer that produced nothing must not leave its consumer queued forever.
//
// Left queued, the scan never reaches a terminal state and the reaper reports a
// timeout half an hour later — a misleading cause for a straightforward one.
func TestAConsumerIsSkippedWhenItsProducerFails(t *testing.T) {
	f := newFixture(t)
	// These tests publish real jobs to scan.job.sbom. A running worker would
	// consume them, scan a workspace that does not exist, and report — and the
	// live orchestrator would then release or skip grype before the assertion
	// ran. See requireExclusive in pipeline_test.go.
	requireExclusive(t.Context(), t, f.bus, bus.StreamJobs, "scan.job.sbom", "",
		"docker compose stop sbom-worker")

	scan := createScan(t, f, tenantA, "syft", "grype")

	if _, err := f.store.SetSourceOnce(t.Context(), tenantA, scan.ID,
		"a1b2c3", "s3://b/src.tar.zst", "sha-src"); err != nil {
		t.Fatalf("pinning source: %v", err)
	}
	if _, err := f.orch.FanOut(t.Context(), tenantA, scan.ID); err != nil {
		t.Fatalf("fan out: %v", err)
	}

	_, runs, _ := f.store.GetScan(t.Context(), tenantA, scan.ID)
	var syftJob string
	for _, r := range runs {
		if r.EngineID == "syft" {
			syftJob = r.JobID
		}
	}
	if syftJob == "" {
		t.Fatal("no syft run was created")
	}

	if err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         syftJob,
		ScanID:        scan.ID,
		TenantID:      tenantA,
		Engine:        "syft",
		EngineVersion: "1.51.0",
		Status:        events.StatusFailed,
		// Validate refuses a failed result with no error: a failure that cannot
		// say why is not a usable record.
		Error: &events.ResultError{
			Code:    "ENGINE_NONZERO_EXIT",
			Message: "syft exited 1",
		},
	}); err != nil {
		t.Fatalf("handle result: %v", err)
	}

	_, runs, _ = f.store.GetScan(t.Context(), tenantA, scan.ID)
	var grype orchestr.EngineRun
	for _, r := range runs {
		if r.EngineID == "grype" {
			grype = r
		}
	}

	if grype.Status != events.StatusSkipped {
		t.Errorf("grype is %q after syft failed, want skipped — a consumer whose "+
			"producer produced nothing must reach a terminal state now, not via "+
			"the reaper in half an hour", grype.Status)
	}
	if grype.ErrorCode != "ENGINE_INPUT_MISSING" {
		t.Errorf("grype error code = %q, want ENGINE_INPUT_MISSING", grype.ErrorCode)
	}
	if grype.ErrorMessage == "" {
		t.Error("grype was skipped with no stated reason; Engine Coverage would not say why")
	}
}

// The successful path: syft reports, grype's job is published.
func TestAConsumerIsReleasedWhenItsProducerSucceeds(t *testing.T) {
	f := newFixture(t)
	// These tests publish real jobs to scan.job.sbom. A running worker would
	// consume them, scan a workspace that does not exist, and report — and the
	// live orchestrator would then release or skip grype before the assertion
	// ran. See requireExclusive in pipeline_test.go.
	requireExclusive(t.Context(), t, f.bus, bus.StreamJobs, "scan.job.sbom", "",
		"docker compose stop sbom-worker")

	scan := createScan(t, f, tenantA, "syft", "grype")

	if _, err := f.store.SetSourceOnce(t.Context(), tenantA, scan.ID,
		"a1b2c3", "s3://b/src.tar.zst", "sha-src"); err != nil {
		t.Fatalf("pinning source: %v", err)
	}
	if _, err := f.orch.FanOut(t.Context(), tenantA, scan.ID); err != nil {
		t.Fatalf("fan out: %v", err)
	}

	_, runs, _ := f.store.GetScan(t.Context(), tenantA, scan.ID)
	var syftJob string
	for _, r := range runs {
		if r.EngineID == "syft" {
			syftJob = r.JobID
		}
	}

	if err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         syftJob,
		ScanID:        scan.ID,
		TenantID:      tenantA,
		Engine:        "syft",
		EngineVersion: "1.51.0",
		Status:        events.StatusSucceeded,
	}); err != nil {
		t.Fatalf("handle result: %v", err)
	}

	_, runs, _ = f.store.GetScan(t.Context(), tenantA, scan.ID)
	for _, r := range runs {
		if r.EngineID == "grype" && r.Status == events.StatusSkipped {
			t.Errorf("grype was skipped even though syft succeeded: %s", r.ErrorMessage)
		}
	}
}
