// Command mock-engine is a fake scanner that exercises the orchestration
// machinery before any real adapter exists.
//
// ⚠ IT IS NOT A STUB THAT RETURNS A CONSTANT.
//
// It implements the real worker contract — the idempotency check, progress
// events, the result envelope — so the machinery is proven against the same
// code path a real engine will take. A mock that skipped the manifest HEAD
// would leave the single most important property in Phase 6 untested.
//
// Behaviour is controlled by MOCK_BEHAVIOUR, so one binary exercises success,
// partial, failure, timeout and crash paths:
//
//	succeed  (default) emit progress, return components
//	partial            succeed with an ecosystem gap and a diagnostic
//	fail               a permanent, non-retryable failure
//	flaky              fail on attempt 1, succeed after
//	hang               never finish, so the wall clock and reaper are exercised
//	crash              exit without publishing anything, so redelivery is
//	                   exercised — the "kill a worker mid-job" case
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/obs"

	"github.com/nats-io/nats.go/jetstream"
)

const engineID = "mock-engine"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mock-engine: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadService("scan-orchestrator")
	if err != nil {
		return err
	}
	obs.InitLogger(obs.LogConfig{Service: "mock-engine", Level: cfg.LogLevel, Format: cfg.LogFormat})
	log := slog.Default()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	b, err := bus.Connect(ctx, bus.Config{URL: cfg.NATS.URL, Name: "mock-engine"})
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()

	consumer, err := b.EnsureConsumer(ctx, bus.ConsumerConfig{
		Stream:        bus.StreamJobs,
		Durable:       "mock-engine",
		FilterSubject: "scan.job.sbom",
		MaxAckPending: 4,
	})
	if err != nil {
		return err
	}

	w := &worker{bus: b, log: log, behaviour: behaviourFromEnv()}
	log.Info("mock engine started", "behaviour", w.behaviour)

	return b.Consume(ctx, consumer, "scan.dlq.sbom", w.handle)
}

type behaviour string

const (
	behaveSucceed behaviour = "succeed"
	behavePartial behaviour = "partial"
	behaveFail    behaviour = "fail"
	behaveFlaky   behaviour = "flaky"
	behaveHang    behaviour = "hang"
	behaveCrash   behaviour = "crash"
)

func behaviourFromEnv() behaviour {
	b := behaviour(os.Getenv("MOCK_BEHAVIOUR"))
	switch b {
	case behaveSucceed, behavePartial, behaveFail, behaveFlaky, behaveHang, behaveCrash:
		return b
	default:
		return behaveSucceed
	}
}

type worker struct {
	bus       *bus.Bus
	log       *slog.Logger
	behaviour behaviour
}

// handle processes one job.
func (w *worker) handle(ctx context.Context, msg jetstream.Msg) error {
	var job events.ScanJobV1
	if err := events.Decode(msg.Data(), &job); err != nil {
		// A payload we cannot parse will not parse on retry either. Returning
		// a non-ErrRetry error terminates it to the DLQ rather than burning
		// four delivery attempts on it.
		return fmt.Errorf("undecodable job: %w", err)
	}
	if job.Engine != engineID {
		// Not ours. Ack so it does not redeliver forever — the filter subject
		// should have prevented this, and quietly looping would hide the
		// misconfiguration.
		w.log.Warn("received a job for another engine", "engine", job.Engine)
		return nil
	}

	// ⚠ THE FIRST ACTION IS THE IDEMPOTENCY CHECK.
	//
	// A worker that dies after uploading its artifacts but before acking WILL
	// be redelivered — ack_wait is 30 minutes. Re-running would produce a
	// second set of artifacts under the same prefix and double-count
	// everything downstream.
	if done, prior := w.alreadyComplete(job); done {
		w.log.Info("job already complete; re-emitting the stored result",
			"job_id", job.JobID)
		return w.publishResult(ctx, job, prior)
	}

	attempt := 1
	if meta, err := msg.Metadata(); err == nil {
		attempt = int(meta.NumDelivered)
	}

	switch w.behaviour {
	case behaveCrash:
		// Exit WITHOUT acking, so JetStream redelivers. This is the "kill a
		// worker mid-job" case, and the point is that the redelivery produces
		// no duplicate artifacts.
		w.log.Warn("MOCK_BEHAVIOUR=crash: exiting without acking", "job_id", job.JobID)
		os.Exit(1)

	case behaveHang:
		w.emit(ctx, job, events.PhaseRunning, 50, "hanging deliberately")
		<-ctx.Done()
		return ctx.Err()
	}

	w.emit(ctx, job, events.PhasePreparing, 10, "preparing workspace")
	time.Sleep(200 * time.Millisecond)
	w.emit(ctx, job, events.PhaseRunning, 50, "cataloguing packages")
	time.Sleep(200 * time.Millisecond)

	result := w.buildResult(job, attempt)

	w.emit(ctx, job, events.PhaseUploading, 90, "uploading result")
	if err := w.writeManifest(job, result); err != nil {
		return fmt.Errorf("%w: writing manifest: %w", bus.ErrRetry, err)
	}

	terminal := events.PhaseDone
	if result.Status == events.StatusFailed {
		terminal = events.PhaseFailed
	}
	w.emit(ctx, job, terminal, 100, "finished")

	return w.publishResult(ctx, job, result)
}

// buildResult produces the result envelope for the configured behaviour.
func (w *worker) buildResult(job events.ScanJobV1, attempt int) events.ScanResultV1 {
	now := time.Now().UTC()
	result := events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         job.JobID, ScanID: job.ScanID, TenantID: job.TenantID,
		Engine: engineID, EngineVersion: "0.0.1-mock",
		Invocation: events.Invocation{
			ArgvRedacted: []string{"mock-engine", "--workspace", "/workspace"},
			StartedAt:    now.Add(-400 * time.Millisecond), FinishedAt: now,
			DurationMS: 400, ExitCode: 0,
		},
		Status:            events.StatusSucceeded,
		EcosystemsCovered: []string{"npm", "pypi"},
		Summary:           events.Summary{Components: events.Count(42), Licenses: events.Count(7)},
	}

	switch w.behaviour {
	case behavePartial:
		// A first-class status: real output PLUS a known gap, and both must
		// reach the report.
		result.Status = events.StatusPartial
		result.EcosystemsCovered = []string{"npm"}
		result.Summary.Components = events.Count(21)
		result.Diagnostics = []events.Diagnostic{{
			Severity: "warn", Code: "ENGINE_PARTIAL_ECOSYSTEM", Ecosystem: "pypi",
			Message: "requirements.txt failed to parse",
			Hint:    "malformed line 12",
		}}

	case behaveFail:
		result.Status = events.StatusFailed
		result.Invocation.ExitCode = 2
		result.Summary = events.Summary{}
		result.EcosystemsCovered = nil
		result.Error = &events.ResultError{
			Code:    "ENGINE_MOCK_FAILURE",
			Message: "MOCK_BEHAVIOUR=fail",
			// Permanent: a retry produces the same failure, and naking would
			// burn four attempts and ten minutes of backoff to learn nothing.
			Retryable: false,
		}

	case behaveFlaky:
		if attempt <= 1 {
			result.Status = events.StatusFailed
			result.Summary = events.Summary{}
			result.Error = &events.ResultError{
				Code: "ENGINE_MOCK_TRANSIENT", Message: "transient failure on the first attempt",
				Retryable: true,
			}
		}
	}

	return result
}

// alreadyComplete checks for a stored manifest.
//
// The real worker HEADs object storage. The mock uses the local filesystem so
// the machinery can be exercised without MinIO, and the SHAPE of the check —
// first action, before any work — is what matters.
func (w *worker) alreadyComplete(job events.ScanJobV1) (bool, events.ScanResultV1) {
	path := w.manifestPath(job)
	data, err := os.ReadFile(path) //nolint:gosec // path derived from job_id, not user input
	if err != nil {
		return false, events.ScanResultV1{}
	}
	var prior events.ScanResultV1
	if err := json.Unmarshal(data, &prior); err != nil {
		// A corrupt manifest is worse than none: re-run rather than re-emit
		// something we cannot read.
		return false, events.ScanResultV1{}
	}
	return true, prior
}

func (w *worker) writeManifest(job events.ScanJobV1, result events.ScanResultV1) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	path := w.manifestPath(job)
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// manifestPath derives the local manifest location from job_id.
func (w *worker) manifestPath(job events.ScanJobV1) string {
	root := os.Getenv("MOCK_ARTIFACT_DIR")
	if root == "" {
		root = os.TempDir() + "/axebom-mock"
	}
	return root + "/" + job.JobID + "/manifest.json"
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

func (w *worker) publishResult(ctx context.Context, job events.ScanJobV1, result events.ScanResultV1) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	// job_id as the dedup key, so a re-emitted result does not create a second
	// message.
	subject := "scan.result." + string(job.Family)
	if err := w.bus.Publish(ctx, subject, job.JobID, payload); err != nil {
		return fmt.Errorf("%w: publishing result: %w", bus.ErrRetry, err)
	}
	return nil
}

// emit publishes an advisory progress event. Failures are ignored: the database
// is the source of truth, and a scan must not fail because a progress message
// did not send.
func (w *worker) emit(ctx context.Context, job events.ScanJobV1, phase events.Phase, pct int, msg string) {
	e := events.ScanEventV1{
		SchemaVersion: events.SchemaScanEventV1,
		ScanID:        job.ScanID, JobID: job.JobID, TenantID: job.TenantID,
		Engine: engineID, TS: time.Now().UTC(),
		Phase: phase, Pct: pct, Message: msg,
	}
	e.Sanitize()

	payload, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = w.bus.PublishAdvisory(ctx, e.Subject(), payload)
}
