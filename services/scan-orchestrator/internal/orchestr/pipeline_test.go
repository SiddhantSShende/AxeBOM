package orchestr_test

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/encorebom/encorebom/libs/go-shared/bus"
	"github.com/encorebom/encorebom/libs/go-shared/events"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/orchestr"
)

// The whole pipeline, end to end, against real Postgres and real NATS.
//
//	create scan -> fetch result -> FAN OUT -> engine consumes -> result ->
//	status derived mechanically
//
// This is the phase's manual acceptance check written as a test, so it runs
// every time rather than once when somebody remembers.

// fakeWorker consumes engine jobs and publishes results.
//
// It implements the REAL worker contract, including the manifest idempotency
// check, so the machinery is exercised the way a real engine will exercise it.
// requireExclusiveSbomSubject skips unless this test can own scan.job.sbom.
//
// ⚠ CALLED FROM THE TEST BODY, NOT FROM THE WORKER GOROUTINE. t.Skipf outside
// the test's own goroutine does not skip anything — the test carries on and
// fails later for an unrelated-looking reason. That is exactly what happened:
// the check lived inside fakeWorker.run and the test still reported
// `scan status = "failed", want completed`.
//
// A WorkQueue stream allows ONE consumer per filter subject, so this test
// stands in for the real SBOM worker and needs the subject to itself. It used
// to take it with ReleaseFilterSubject, which claims a subject by DELETING
// whatever consumer is already there — on a machine with the stack running,
// that silently drops a live worker's in-flight deliveries, and the two then
// compete anyway.
//
// The durable fix is an isolated broker per test run; recorded in docs/STATE.md.
func requireExclusiveSbomSubject(ctx context.Context, t *testing.T, b *bus.Bus, durable string) {
	t.Helper()
	requireExclusive(ctx, t, b, bus.StreamJobs, "scan.job.sbom", durable,
		"docker compose stop sbom-worker")
}

// requireExclusiveResults skips unless this test owns the fetch-result stream.
//
// The orchestrator's own durable is `orchestrator-fetch`, and a test that calls
// ConsumeResults creates a consumer with THAT SAME NAME. On a WorkQueue stream
// that is not a conflict — it is a consumer GROUP, so NATS load-balances
// between the test and the running orchestrator, and roughly half the test's
// messages are handled by a process the test cannot observe.
//
// The symptom is a 45-second timeout waiting for a status the other consumer
// already applied, which reads as a product defect rather than a shared broker.
func requireExclusiveResults(ctx context.Context, t *testing.T, b *bus.Bus, family string) {
	t.Helper()
	requireExclusive(ctx, t, b, bus.StreamResults, "scan.result."+family, "",
		"docker compose stop scan-orchestrator")
}

func requireExclusive(ctx context.Context, t *testing.T, b *bus.Bus,
	stream, subject, ownDurable, remedy string,
) {
	t.Helper()

	existing, err := b.ConsumersOn(ctx, stream, subject)
	if err != nil {
		t.Fatalf("listing consumers on %s: %v", subject, err)
	}
	for _, name := range existing {
		if name != ownDurable {
			t.Skipf("a live consumer %q already holds %s; this test needs the subject "+
				"to itself. Stop it (%s) or run against an isolated NATS.",
				name, subject, remedy)
		}
	}
}

type fakeWorker struct {
	bus      *bus.Bus
	t        *testing.T
	status   events.EngineStatus
	consumed atomic.Int32

	// seen records job ids, so a redelivery can be detected rather than
	// assumed absent.
	seen sync.Map
}

func (w *fakeWorker) run(ctx context.Context, durable string) {
	consumer, err := w.bus.EnsureConsumer(ctx, bus.ConsumerConfig{
		Stream: bus.StreamJobs, Durable: durable, FilterSubject: "scan.job.sbom",
	})
	if err != nil {
		w.t.Errorf("worker consumer: %v", err)
		return
	}

	_ = w.bus.Consume(ctx, consumer, "scan.dlq.sbom", func(ctx context.Context, msg jetstream.Msg) error {
		var job events.ScanJobV1
		if err := events.Decode(msg.Data(), &job); err != nil {
			return err
		}
		w.consumed.Add(1)

		// THE IDEMPOTENCY CHECK, as a real worker does it: already done means
		// re-emit rather than re-run.
		if _, already := w.seen.LoadOrStore(job.JobID, true); already {
			w.t.Logf("job %s redelivered; re-emitting rather than re-running", job.JobID)
		}

		result := events.ScanResultV1{
			SchemaVersion: events.SchemaScanResultV1,
			JobID:         job.JobID, ScanID: job.ScanID, TenantID: job.TenantID,
			Engine: job.Engine, EngineVersion: "0.0.1-test",
			Status:            w.status,
			EcosystemsCovered: []string{"npm"},
			Summary:           events.Summary{Components: events.Count(7)},
			Invocation: events.Invocation{
				ArgvRedacted: []string{job.Engine},
				StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
			},
		}
		if w.status == events.StatusFailed {
			result.Error = &events.ResultError{
				Code: "ENGINE_TEST_FAILURE", Message: "deliberate", Retryable: false,
			}
		}

		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		return w.bus.Publish(ctx, "scan.result.sbom", job.JobID, payload)
	})
}

// ⚠ THE FULL PIPELINE.
//
// Every step is one the product depends on and none of them is observable from
// a unit test: the fan-out happens in a consumer, the status derivation happens
// in another, and the two only meet through NATS and Postgres.
func TestFullPipelineCreateFetchFanOutResultStatus(t *testing.T) {
	f := newFixture(t)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	// The orchestrator's own result loop — the thing under test.
	requireExclusiveResults(ctx, t, f.bus, "fetch")
	go func() { _ = f.orch.ConsumeResults(ctx) }()

	requireExclusiveSbomSubject(ctx, t, f.bus, "pipeline-test-worker")

	worker := &fakeWorker{bus: f.bus, t: t, status: events.StatusSucceeded}
	go worker.run(ctx, "pipeline-test-worker")
	t.Cleanup(func() {
		_ = f.bus.DeleteConsumer(context.Background(), bus.StreamJobs, "pipeline-test-worker")
	})

	scan := createScan(t, f, tenantA, "mock-engine")

	// The fetch completes: this is what pins the commit and triggers fan-out.
	const commitSHA = "1234567890abcdef1234567890abcdef12345678"
	if err := f.orch.PublishFetchResult(ctx, scan.ID, tenantA,
		commitSHA, "s3://encorebom/workspaces/test/source.tar.zst", "sha-abc"); err != nil {
		t.Fatalf("publish fetch result: %v", err)
	}

	// Wait for the scan to reach a terminal status.
	final := waitForTerminal(t, f, tenantA, scan.ID, 60*time.Second)

	if final.Status != events.ScanCompleted {
		t.Errorf("scan status = %q, want completed", final.Status)
	}
	// ⚠ THE COMMIT MUST BE PINNED BEFORE ENGINES RAN. A report that cannot name
	// the commit it describes is not evidence of anything.
	if final.CommitSHA != commitSHA {
		t.Errorf("commit_sha = %q, want %q", final.CommitSHA, commitSHA)
	}
	if worker.consumed.Load() < 1 {
		t.Error("the worker never received a job; fan-out did not happen")
	}
	t.Logf("pipeline completed: status=%s commit=%s jobs_consumed=%d",
		final.Status, final.CommitSHA[:8], worker.consumed.Load())
}

// A failing engine must produce `failed` for a single-engine scan, mechanically
// — not a hand-set status, and not a silent success.
func TestFullPipelineWithAFailingEngine(t *testing.T) {
	f := newFixture(t)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	requireExclusiveResults(ctx, t, f.bus, "fetch")
	go func() { _ = f.orch.ConsumeResults(ctx) }()

	requireExclusiveSbomSubject(ctx, t, f.bus, "pipeline-test-worker-fail")

	worker := &fakeWorker{bus: f.bus, t: t, status: events.StatusFailed}
	go worker.run(ctx, "pipeline-test-worker-fail")
	t.Cleanup(func() {
		_ = f.bus.DeleteConsumer(context.Background(), bus.StreamJobs, "pipeline-test-worker-fail")
	})

	scan := createScan(t, f, tenantA, "mock-engine")

	if err := f.orch.PublishFetchResult(ctx, scan.ID, tenantA,
		"abcdef1234567890abcdef1234567890abcdef12",
		"s3://encorebom/workspaces/test/source.tar.zst", "sha-abc"); err != nil {
		t.Fatalf("publish fetch result: %v", err)
	}

	final := waitForTerminal(t, f, tenantA, scan.ID, 60*time.Second)
	if final.Status != events.ScanFailed {
		t.Errorf("scan status = %q, want failed (its only engine failed)", final.Status)
	}
}

// A failed FETCH must fail the scan promptly, with the real cause — not leave
// every engine queued for the reaper to time out half an hour later.
func TestFailedFetchFailsTheScanImmediately(t *testing.T) {
	f := newFixture(t)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	requireExclusiveResults(ctx, t, f.bus, "fetch")
	go func() { _ = f.orch.ConsumeResults(ctx) }()

	scan := createScan(t, f, tenantA, "mock-engine")

	failed := events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         "fetch-fail-" + scan.ID,
		ScanID:        scan.ID, TenantID: tenantA,
		Engine: "fetcher", EngineVersion: "internal",
		Status: events.StatusFailed,
		Error: &events.ResultError{
			Code: "FETCH_AUTH_FAILED", Message: "the repository could not be read",
		},
		Invocation: events.Invocation{
			ArgvRedacted: []string{"fetcher"},
			StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
		},
	}
	payload, _ := json.Marshal(failed)
	if err := f.bus.Publish(ctx, "scan.result.fetch", failed.JobID, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	final := waitForTerminal(t, f, tenantA, scan.ID, 45*time.Second)
	if final.Status != events.ScanFailed {
		t.Errorf("scan status = %q, want failed", final.Status)
	}

	// The engine run carries the REAL cause, not a generic timeout half an hour
	// later.
	_, runs, err := f.store.GetScan(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if len(runs) > 0 && runs[0].ErrorCode != "FETCH_AUTH_FAILED" {
		t.Errorf("error_code = %q, want the fetch's real cause", runs[0].ErrorCode)
	}
}

// waitForTerminal polls until the scan finishes or the timeout expires.
//
// POLLS THE DATABASE, not the event stream — the database is the source of
// truth, and a test that waited on events would be asserting the advisory path
// is reliable, which is exactly what the design does not promise.
func waitForTerminal(t *testing.T, f *fixture, tenantID, scanID string, timeout time.Duration) orchestr.Scan {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last orchestr.Scan
	for time.Now().Before(deadline) {
		scan, _, err := f.store.GetScan(context.Background(), tenantID, scanID)
		if err != nil {
			t.Fatalf("get scan: %v", err)
		}
		last = scan
		switch scan.Status {
		case events.ScanCompleted, events.ScanCompletedWithErrors,
			events.ScanFailed, events.ScanCancelled:
			return scan
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("scan %s did not reach a terminal status within %v (last: %q)",
		scanID, timeout, last.Status)
	return last
}
