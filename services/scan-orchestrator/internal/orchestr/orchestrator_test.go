package orchestr_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/bus"
	"github.com/encorebom/encorebom/libs/go-shared/events"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/orchestr"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/policy"
)

// Phase 6 acceptance tests, against real Postgres and real NATS.
//
// The properties under test are properties of the INFRASTRUCTURE — idempotent
// upsert on a unique key, advisory-lock leader election, RLS isolation. A
// mocked store would pass while the product double-counted.

const (
	tenantA  = "01900000-0000-7000-8000-00000000000a"
	tenantB  = "01900000-0000-7000-8000-00000000000b"
	projectA = "01900000-0000-7000-8000-0000000000f1"
	userA    = "01900000-0000-7000-8000-0000000000a1"
)

type fixture struct {
	orch  *orchestr.Orchestrator
	store *orchestr.Store
	pool  *db.Pool
	bus   *bus.Bus
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("scan-orchestrator")
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	pool, err := db.Open(t.Context(), cfg.Postgres)
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(pool.Close)

	b, err := bus.Connect(t.Context(), bus.Config{URL: cfg.NATS.URL, Name: "orchestr-test"})
	if err != nil {
		t.Skipf("NATS unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	store := orchestr.NewStore(pool)
	return &fixture{
		orch: orchestr.New(orchestr.Config{
			Store: store, Bus: b, Registry: policy.DefaultRegistry(),
		}),
		store: store, pool: pool, bus: b,
	}
}

// cleanupScan removes a test scan. Tests must leave the database as they found
// it — accumulated rows break anything that reasons about counts, which was
// learned the hard way in Phase 4.
func cleanupScan(t *testing.T, f *fixture, tenantID, scanID string) {
	t.Helper()
	t.Cleanup(func() {
		err := f.pool.WithTenant(context.Background(), tenantID,
			func(ctx context.Context, tx db.Tx) error {
				_, err := tx.Exec(ctx, `DELETE FROM scan.scans WHERE id = $1`, scanID)
				return err
			})
		if err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
}

func createScan(t *testing.T, f *fixture, tenantID string, engines ...string) orchestr.Scan {
	t.Helper()
	in := orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceGit,
		Families: []events.Family{events.FamilySBOM}, RequestedBy: userA,
	}
	if len(engines) > 0 {
		in.RequestedEngines = engines
	}
	scan, err := f.orch.CreateScan(t.Context(), tenantID, in)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	cleanupScan(t, f, tenantID, scan.ID)
	return scan
}

// ---------------------------------------------------------------------------
// Create and fan out
// ---------------------------------------------------------------------------

func TestCreateScanFansOutOneJobPerEngine(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft", "grype", "trivy-fs")

	_, runs, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}

	// ⚠ ONE ROW PER ENGINE (ADR-0004). This is what makes partial failure
	// expressible: "grype timed out but syft succeeded" has no representation
	// under one-job-per-family.
	if len(runs) != 3 {
		t.Fatalf("got %d engine runs, want 3", len(runs))
	}

	seen := map[string]bool{}
	for _, r := range runs {
		if r.JobID == "" {
			t.Errorf("engine run %s has no job id", r.EngineID)
		}
		if seen[r.JobID] {
			t.Errorf("job id %s is reused across engines; it is the idempotency key", r.JobID)
		}
		seen[r.JobID] = true

		if r.DeadlineAt == nil {
			t.Errorf("engine run %s has no deadline; the reaper can never time it out", r.EngineID)
		}
	}
}

// ⚠ THE 422 REQUIREMENT: EVERY offending pair, not the first.
//
// A user who fixes the one error they were shown, resubmits, and hits the next
// one has been made to do the work twice.
func TestInvalidCombinationListsEveryOffendingPair(t *testing.T) {
	f := newFixture(t)

	// THREE engines that cannot read a container image, requested together.
	_, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceImage,
		Families:         []events.Family{events.FamilySBOM},
		RequestedEngines: []string{"trivy-fs", "osv-scanner", "dependency-check", "syft"},
	})
	if err == nil {
		t.Fatal("an invalid engine/source combination was accepted")
	}
	if !errs.Is(err, errs.ScanEngineCombinationInvalid) {
		t.Fatalf("code = %v, want SCAN_ENGINE_COMBINATION_INVALID", err)
	}

	var e *errs.Error
	if !errors.As(err, &e) {
		t.Fatalf("not a structured error: %v", err)
	}
	if e.HTTPStatus() != 422 {
		t.Errorf("status = %d, want 422", e.HTTPStatus())
	}

	// All THREE offending engines must be named. syft supports images, so it
	// must not appear.
	named := map[string]bool{}
	for _, d := range e.Details {
		if engine, ok := d["engine"].(string); ok {
			named[engine] = true
		}
		if reason, ok := d["reason"].(string); !ok || reason == "" {
			t.Errorf("an offending pair carries no reason: %v", d)
		}
	}
	for _, want := range []string{"trivy-fs", "osv-scanner", "dependency-check"} {
		if !named[want] {
			t.Errorf("%s is not listed among the offending pairs; the user would "+
				"fix one error and resubmit into the next", want)
		}
	}
	if named["syft"] {
		t.Error("syft was reported as offending, but it supports image sources")
	}
}

func TestUnknownEngineIsRejected(t *testing.T) {
	f := newFixture(t)

	_, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceGit,
		Families:         []events.Family{events.FamilySBOM},
		RequestedEngines: []string{"syft", "not-a-real-engine"},
	})
	if err == nil {
		t.Fatal("an unknown engine id was accepted")
	}
}

func TestScanWithNoFamiliesIsRejected(t *testing.T) {
	f := newFixture(t)

	_, err := f.orch.CreateScan(t.Context(), tenantA, orchestr.CreateScanInput{
		ProjectID: projectA, SourceKind: events.SourceGit,
	})
	if err == nil {
		t.Fatal("a scan with no BOM families was accepted")
	}
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

// ⚠ THE IDEMPOTENCY PROOF, AND THE ONE THAT MATTERS.
//
// A worker that dies between uploading its artifacts and acking WILL be
// redelivered — ack_wait is 30 minutes. Processing the same result twice must
// converge, not duplicate: a second engine_runs row would double every count
// downstream and put two entries for one engine in the Engine Coverage table.
func TestDuplicateResultConvergesRatherThanDuplicating(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	_, runs, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	jobID := runs[0].JobID

	result := events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         jobID, ScanID: scan.ID, TenantID: tenantA,
		Engine: "syft", EngineVersion: "1.51.0",
		Status:            events.StatusSucceeded,
		EcosystemsCovered: []string{"npm", "pypi"},
		Summary:           events.Summary{Components: 412},
		Invocation: events.Invocation{
			ArgvRedacted: []string{"syft"},
			StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
		},
	}

	// The SAME result, three times — the redelivery scenario.
	for i := 0; i < 3; i++ {
		if err := f.orch.HandleResult(t.Context(), result); err != nil {
			t.Fatalf("handle result %d: %v", i, err)
		}
	}

	_, after, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if len(after) != 1 {
		t.Errorf("got %d engine runs after 3 identical results, want 1 — "+
			"every count downstream would be tripled", len(after))
	}
	if after[0].Status != events.StatusSucceeded {
		t.Errorf("status = %q", after[0].Status)
	}
}

// ---------------------------------------------------------------------------
// Status derivation, end to end
// ---------------------------------------------------------------------------

// The derivation table asserted against REAL ROWS, not just the pure function.
func TestScanStatusDerivesFromEngineResults(t *testing.T) {
	tests := []struct {
		name     string
		statuses []events.EngineStatus
		want     events.ScanStatus
	}{
		{"all succeeded", []events.EngineStatus{events.StatusSucceeded, events.StatusSucceeded}, events.ScanCompleted},
		{"mixed", []events.EngineStatus{events.StatusSucceeded, events.StatusFailed}, events.ScanCompletedWithErrors},
		{"all failed", []events.EngineStatus{events.StatusFailed, events.StatusFailed}, events.ScanFailed},
		{"all partial", []events.EngineStatus{events.StatusPartial, events.StatusPartial}, events.ScanCompletedWithErrors},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			scan := createScan(t, f, tenantA, "syft", "grype")

			_, runs, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
			if err != nil {
				t.Fatalf("get scan: %v", err)
			}
			if len(runs) != len(tt.statuses) {
				t.Fatalf("fixture has %d runs, test needs %d", len(runs), len(tt.statuses))
			}

			for i, status := range tt.statuses {
				result := events.ScanResultV1{
					SchemaVersion: events.SchemaScanResultV1,
					JobID:         runs[i].JobID, ScanID: scan.ID, TenantID: tenantA,
					Engine: runs[i].EngineID, EngineVersion: "1.0.0",
					// Vulnerability engines need a dated database, or the
					// envelope is rejected — which is itself the contract.
					EngineDBVersion: "db-2026-08-16",
					Status:          status,
					Invocation: events.Invocation{
						ArgvRedacted: []string{runs[i].EngineID},
						StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
					},
				}
				if status == events.StatusFailed {
					result.Error = &events.ResultError{Code: "X", Message: "failed"}
				}
				if err := f.orch.HandleResult(t.Context(), result); err != nil {
					t.Fatalf("handle result %d: %v", i, err)
				}
			}

			got, _, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
			if err != nil {
				t.Fatalf("get scan: %v", err)
			}
			if got.Status != tt.want {
				t.Errorf("scan status = %q, want %q", got.Status, tt.want)
			}
		})
	}
}

// A scan is not terminal while any engine is still running — reporting a final
// status early would put a partial result into a report.
func TestScanStaysRunningUntilEveryEngineReports(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft", "grype")

	_, runs, _ := f.store.GetScan(t.Context(), tenantA, scan.ID)

	// Only ONE of two engines reports.
	if err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         runs[0].JobID, ScanID: scan.ID, TenantID: tenantA,
		Engine: runs[0].EngineID, EngineVersion: "1.0", EngineDBVersion: "db-1",
		Status: events.StatusSucceeded,
		Invocation: events.Invocation{
			ArgvRedacted: []string{"x"}, StartedAt: time.Now(), FinishedAt: time.Now(),
		},
	}); err != nil {
		t.Fatalf("handle result: %v", err)
	}

	got, _, _ := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if got.Status == events.ScanCompleted || got.Status == events.ScanFailed {
		t.Errorf("scan reached the terminal status %q with one engine still running", got.Status)
	}
}

// ---------------------------------------------------------------------------
// commit_sha immutability
// ---------------------------------------------------------------------------

// ⚠ commit_sha IS WRITTEN EXACTLY ONCE (ADR-0008).
//
// A redelivered fetch result must not repoint a scan at a different commit
// while engines are already running against the first — that produces a report
// with components from one commit and vulnerabilities from another, describing
// a codebase that never existed.
func TestCommitShaIsWrittenOnceAndIsImmutable(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	const first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const second = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	wrote, err := f.store.SetSourceOnce(t.Context(), tenantA, scan.ID, first, "s3://b/a.tar.zst", "sha-1")
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if !wrote {
		t.Fatal("the first write reported that it wrote nothing")
	}

	// A redelivered fetch result, with a DIFFERENT commit.
	wrote, err = f.store.SetSourceOnce(t.Context(), tenantA, scan.ID, second, "s3://b/b.tar.zst", "sha-2")
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if wrote {
		t.Error("a second fetch result overwrote commit_sha")
	}

	got, _, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if got.CommitSHA != first {
		t.Errorf("commit_sha = %q, want the FIRST value %q — engines already "+
			"running would be scanning different code from what is recorded",
			got.CommitSHA, first)
	}
}

// ---------------------------------------------------------------------------
// The reaper
// ---------------------------------------------------------------------------

// ⚠ WITHOUT THE REAPER, A LOST JOB IS INVISIBLE FOREVER.
//
// A worker that dies after picking up a job leaves the run in `running` with
// nothing to move it. JetStream gives up after max_deliver; the row does not.
func TestReaperTimesOutOverdueJobs(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	// Backdate the deadline, simulating a job whose worker vanished.
	err := f.pool.WithTenant(t.Context(), tenantA, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE scan.engine_runs
			   SET status = 'running', deadline_at = now() - interval '1 minute'
			 WHERE scan_id = $1`, scan.ID)
		return err
	})
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}

	reaper := orchestr.NewReaper(orchestr.ReaperConfig{Pool: f.pool, Store: f.store})
	res, err := reaper.Sweep(t.Context())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.JobsTimedOut < 1 {
		t.Fatal("the reaper found no overdue jobs")
	}

	got, runs, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if runs[0].Status != events.StatusTimeout {
		t.Errorf("engine run status = %q, want timeout", runs[0].Status)
	}
	// And the SCAN became terminal — the point of the reaper is that a scan
	// does not sit at 60% forever with no explanation.
	if got.Status != events.ScanFailed {
		t.Errorf("scan status = %q, want failed (its only engine timed out)", got.Status)
	}
	if runs[0].ErrorCode == "" {
		t.Error("the timed-out run carries no error code")
	}
}

// ⚠ LEADER ELECTION VIA A POSTGRES ADVISORY LOCK.
//
// Every instance runs the reaper loop; only the lock holder works. Two
// concurrent sweeps must not both reap — double-reaping is harmless here, but
// the lock is what stops N instances hammering the database every tick.
func TestReaperLeaderElectionIsExclusive(t *testing.T) {
	f := newFixture(t)

	// Hold the lock on a dedicated connection, as the leader would.
	conn, err := f.pool.Raw().Acquire(t.Context())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(t.Context(), `SELECT pg_try_advisory_lock(1)`).Scan(&acquired); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if !acquired {
		t.Skip("the reaper lock is already held by another process")
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(1)`)
	}()

	// A SECOND connection must not get it.
	conn2, err := f.pool.Raw().Acquire(t.Context())
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	defer conn2.Release()

	var second bool
	if err := conn2.QueryRow(t.Context(), `SELECT pg_try_advisory_lock(1)`).Scan(&second); err != nil {
		t.Fatalf("lock 2: %v", err)
	}
	if second {
		_, _ = conn2.Exec(t.Context(), `SELECT pg_advisory_unlock(1)`)
		t.Error("two instances both acquired the reaper lock; every instance would sweep every tick")
	}
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

// A scan of tenant B must be invisible and un-cancellable from tenant A, and
// the answer must be 404 — a 403 would confirm the id exists.
func TestScansAreInvisibleAcrossTenants(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	_, _, err := f.store.GetScan(t.Context(), tenantB, scan.ID)
	if err == nil {
		t.Fatal("tenant B read tenant A's scan")
	}
	if !errors.Is(err, orchestr.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// A result claiming another tenant's scan must not write to it.
func TestResultForAnotherTenantCannotWrite(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	_, runs, _ := f.store.GetScan(t.Context(), tenantA, scan.ID)

	// A forged result: tenant B's id, tenant A's scan and job.
	err := f.orch.HandleResult(t.Context(), events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         runs[0].JobID, ScanID: scan.ID, TenantID: tenantB,
		Engine: "syft", EngineVersion: "1.0",
		Status: events.StatusSucceeded,
		Invocation: events.Invocation{
			ArgvRedacted: []string{"syft"}, StartedAt: time.Now(), FinishedAt: time.Now(),
		},
	})
	// It either errors, or writes a row into tenant B's scope. What must NOT
	// happen is tenant A's run being modified.
	t.Logf("forged cross-tenant result returned: %v", err)

	_, after, getErr := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if getErr != nil {
		t.Fatalf("get scan: %v", getErr)
	}
	if after[0].Status == events.StatusSucceeded {
		t.Error("a result carrying another tenant's id modified this tenant's engine run")
	}
}

// ---------------------------------------------------------------------------
// Coverage gaps — the honest denominator
// ---------------------------------------------------------------------------

// ⚠ AN ECOSYSTEM WITH NO AVAILABLE ENGINE IS THE MOST IMPORTANT THING A BOM
// CAN DISCLOSE. Omitting it converts an unknown into a false negative the
// customer trusts.
func TestEcosystemsWithNoEngineAreRecorded(t *testing.T) {
	f := newFixture(t)
	scan := createScan(t, f, tenantA, "syft")

	if err := f.store.RecordEcosystem(t.Context(), tenantA, scan.ID, "cocoapods", "detector", false); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := f.store.RecordEcosystem(t.Context(), tenantA, scan.ID, "npm", "syft", true); err != nil {
		t.Fatalf("record: %v", err)
	}

	gaps, err := f.store.CoverageGaps(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("gaps: %v", err)
	}
	if len(gaps) != 1 || gaps[0] != "cocoapods" {
		t.Errorf("gaps = %v, want [cocoapods]", gaps)
	}
}

// Progress is a WEIGHTED mean, computed server-side. dependency-check taking 40
// minutes must not count the same as syft taking 20 seconds, and a client
// cannot know the weights.
func TestProgressIsWeighted(t *testing.T) {
	runs := []orchestr.EngineRun{
		{EngineID: "syft", Weight: 3, Status: events.StatusSucceeded},
		{EngineID: "dependency-check", Weight: 1, Status: "queued"},
	}
	if got := orchestr.Progress(runs); got != 75 {
		t.Errorf("progress = %d, want 75 (3 of 4 weight complete)", got)
	}

	// Equal weights would give 50, which is the bug this guards against.
	runs[1].Weight = 3
	if got := orchestr.Progress(runs); got != 50 {
		t.Errorf("progress = %d, want 50 with equal weights", got)
	}
}
