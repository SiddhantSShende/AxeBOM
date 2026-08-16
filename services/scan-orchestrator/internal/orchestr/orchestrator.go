package orchestr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/encorebom/encorebom/libs/go-shared/bus"
	"github.com/encorebom/encorebom/libs/go-shared/events"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/policy"
)

// Orchestrator creates scans, fans out jobs, and aggregates results.
type Orchestrator struct {
	store    *Store
	bus      *bus.Bus
	registry *policy.Registry
	log      *slog.Logger

	artifactPrefix string
	now            func() time.Time

	// seq numbers events PER PROCESS. Consumers reorder by (job_id, seq) and
	// tolerate gaps, so a restart resetting this is survivable — which is the
	// whole reason events are advisory.
	seq atomic.Int64
}

// Config configures the orchestrator.
type Config struct {
	Store    *Store
	Bus      *bus.Bus
	Registry *policy.Registry
	Logger   *slog.Logger
	// ArtifactPrefix is the object-storage root, e.g. s3://encorebom.
	ArtifactPrefix string
	Now            func() time.Time
}

func New(cfg Config) *Orchestrator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ArtifactPrefix == "" {
		cfg.ArtifactPrefix = "s3://encorebom"
	}
	if cfg.Registry == nil {
		cfg.Registry = policy.DefaultRegistry()
	}
	return &Orchestrator{
		store: cfg.Store, bus: cfg.Bus, registry: cfg.Registry,
		log: cfg.Logger, artifactPrefix: cfg.ArtifactPrefix, now: cfg.Now,
	}
}

// CreateScanInput is the request to start a scan.
type CreateScanInput struct {
	ProjectID  string
	SourceKind events.SourceKind
	Families   []events.Family
	// EngineOverrides pins specific engines per family, replacing the defaults.
	EngineOverrides map[events.Family][]string
	// RequestedEngines is an explicit engine list. When set it is validated
	// against the source kind and used verbatim.
	RequestedEngines []string
	// RequestedBy is the user or campaign id behind the scan.
	RequestedBy string
	// TriggeredBy is user | campaign | api | webhook. Defaults to `user`.
	TriggeredBy string
}

// triggerOrDefault normalizes the trigger source.
func triggerOrDefault(s string) string {
	switch s {
	case "user", "campaign", "api", "webhook":
		return s
	default:
		return "user"
	}
}

// CreateScan validates, persists, and publishes the fetch job.
//
// ⚠ VALIDATION HAPPENS HERE, BEFORE ANYTHING IS PERSISTED OR PUBLISHED.
//
// An invalid engine/source combination is a 422 listing EVERY offending pair.
// Discovering at worker time that an engine cannot read this source — after a
// fetch, a container start and twenty minutes — is a design failure
// (docs/02-CONTRACTS.md §7).
func (o *Orchestrator) CreateScan(ctx context.Context, tenantID string, in CreateScanInput) (Scan, error) {
	if in.ProjectID == "" {
		return Scan{}, errs.New(errs.ValidationFieldRequired, "project_id is required")
	}
	if len(in.Families) == 0 {
		return Scan{}, errs.New(errs.ValidationFieldRequired,
			"select at least one BOM family; a scan with none produces nothing")
	}
	switch in.SourceKind {
	case events.SourceGit, events.SourceUpload, events.SourceImage:
	default:
		return Scan{}, errs.Newf(errs.ValidationFieldInvalid,
			"source_kind must be git, upload or image (got %q)", in.SourceKind)
	}

	// An explicit engine list is validated in full — every offending pair, so
	// one correction fixes all of them.
	if len(in.RequestedEngines) > 0 {
		if err := o.registry.ValidateCombination(in.RequestedEngines, in.SourceKind, in.Families); err != nil {
			return Scan{}, err
		}
	}

	resolution := o.resolveEngines(in)
	if len(resolution.Engines) == 0 {
		// Nothing can scan this source. A clear refusal now beats a scan that
		// completes in ten seconds having done nothing.
		err := errs.Newf(errs.ScanNoEnginesAvailable,
			"no engine can scan a %s source for the requested BOM types", in.SourceKind)
		for _, p := range resolution.SkippedForSource {
			err = err.WithDetail(errs.Detail{"engine": p.Engine, "reason": p.Reason})
		}
		return Scan{}, err
	}

	families := make([]string, 0, len(in.Families))
	for _, f := range in.Families {
		families = append(families, string(f))
	}

	runs := make([]EngineRun, 0, len(resolution.Engines))
	for _, e := range resolution.Engines {
		deadline := o.now().Add(defaultJobDeadline)
		runs = append(runs, EngineRun{
			// job_id is a UUIDv4, not v7: it is an IDEMPOTENCY KEY, and a
			// time-ordered key would leak scheduling information into the
			// object-storage paths it appears in.
			JobID:      uuid.NewString(),
			EngineID:   e.ID,
			Family:     familyOf(e),
			Attempt:    1,
			Weight:     e.DefaultWeight,
			DeadlineAt: &deadline,
		})
	}

	engineIDs := make([]string, 0, len(resolution.Engines))
	for _, e := range resolution.Engines {
		engineIDs = append(engineIDs, e.ID)
	}

	scan, err := o.store.CreateScan(ctx, Scan{
		TenantID: tenantID, ProjectID: in.ProjectID,
		SourceKind: in.SourceKind, Families: families,
		EnginesRequested: engineIDs,
		TriggeredBy:      triggerOrDefault(in.TriggeredBy),
		TriggerRef:       in.RequestedBy,
	}, runs)
	if err != nil {
		return Scan{}, err
	}

	// Engines skipped because they cannot read this source are RECORDED, not
	// discarded. They belong in the Engine Coverage section: a user who asked
	// for SBOM on a container image should see that trivy-fs was excluded, not
	// silently get fewer engines.
	for _, p := range resolution.SkippedForSource {
		if e, ok := o.registry.Get(p.Engine); ok {
			for _, eco := range e.Ecosystems {
				_ = o.store.RecordEcosystem(ctx, tenantID, scan.ID, eco, p.Engine, false)
			}
		}
	}

	if err := o.publishFetchJob(ctx, scan); err != nil {
		// The scan row exists and is queued. Failing here leaves it for the
		// reaper rather than losing it: a scan recorded but not dispatched is
		// visible and times out, whereas rolling back would lose the record of
		// what the user asked for.
		o.log.Error("scan created but the fetch job could not be published",
			"scan_id", scan.ID, "cause", err.Error())
		return scan, errs.Wrap(err, errs.InternalDependency,
			"the scan was created but could not be queued; it will time out and can be retried")
	}

	return scan, nil
}

// defaultJobDeadline matches the sandbox wall-clock ceiling plus scheduling
// slack. The reaper marks anything past it as `timeout`.
const defaultJobDeadline = 30 * time.Minute

// resolveEngines turns the request into an engine set.
func (o *Orchestrator) resolveEngines(in CreateScanInput) policy.Resolution {
	if len(in.RequestedEngines) > 0 {
		var res policy.Resolution
		for _, id := range in.RequestedEngines {
			if e, ok := o.registry.Get(id); ok {
				res.Engines = append(res.Engines, e)
			}
		}
		return res
	}
	return o.registry.Resolve(in.Families, in.SourceKind, in.EngineOverrides)
}

func familyOf(e policy.Engine) string {
	if len(e.Families) == 0 {
		return string(events.FamilySBOM)
	}
	return string(e.Families[0])
}

// ---------------------------------------------------------------------------
// Fan-out
// ---------------------------------------------------------------------------

// publishFetchJob queues the single fetch that materializes source once.
func (o *Orchestrator) publishFetchJob(ctx context.Context, scan Scan) error {
	jobID := uuid.NewString()
	job := events.ScanJobV1{
		SchemaVersion: events.SchemaScanJobV1,
		JobID:         jobID,
		ScanID:        scan.ID,
		TenantID:      scan.TenantID,
		ProjectID:     scan.ProjectID,
		Family:        events.FamilyFetch,
		Engine:        "fetcher",
		Attempt:       1,
		IssuedAt:      o.now().UTC(),
		DeadlineAt:    o.now().Add(defaultJobDeadline).UTC(),
		SourceMeta:    events.SourceMeta{Kind: scan.SourceKind},
		Limits:        defaultJobLimits(),
		Output:        events.OutputRef{Prefix: o.outputPrefix(scan.ID, "fetcher", jobID)},
	}

	if err := job.Validate(); err != nil {
		return err
	}
	return o.publishJob(ctx, job)
}

// FanOut queues one job per engine, all pointing at the same archive.
//
// ⚠ EVERY ENGINE READS THE SAME BYTES (ADR-0008).
//
// Six engines cloning independently can land on six different commits in one
// report, describing a codebase that never existed. The fetch already happened;
// this hands every engine the identical content-addressed archive.
func (o *Orchestrator) FanOut(ctx context.Context, tenantID, scanID string) (int, error) {
	scan, runs, err := o.store.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return 0, err
	}
	if scan.ArchiveRef == "" {
		return 0, fmt.Errorf("cannot fan out scan %s: no source archive recorded", scanID)
	}

	var published int
	for _, run := range runs {
		// Only queued runs. A redelivered fetch result must not re-publish
		// jobs for engines that already started.
		if run.Status != statusQueued {
			continue
		}

		// The family is DERIVED from the registry, not stored on the row.
		//
		// engine_runs has no family column — the engine id determines it, and a
		// second copy would be a second thing to keep in sync. Getting this
		// wrong is silent: an empty family fails job validation, the job is
		// skipped, and the scan sits at `running` until the reaper times it out
		// half an hour later. That is exactly what happened the first time.
		family := events.FamilySBOM
		if e, ok := o.registry.Get(run.EngineID); ok && len(e.Families) > 0 {
			family = e.Families[0]
		}

		job := events.ScanJobV1{
			SchemaVersion: events.SchemaScanJobV1,
			JobID:         run.JobID,
			ScanID:        scan.ID,
			TenantID:      scan.TenantID,
			ProjectID:     scan.ProjectID,
			Family:        family,
			Engine:        run.EngineID,
			Attempt:       run.Attempt,
			IssuedAt:      o.now().UTC(),
			DeadlineAt:    o.now().Add(defaultJobDeadline).UTC(),
			Workspace: events.Workspace{
				ArtifactURI: scan.ArchiveRef,
				SHA256:      scan.ArchiveSHA256,
			},
			SourceMeta: events.SourceMeta{
				Kind:      scan.SourceKind,
				CommitSHA: scan.CommitSHA,
			},
			Limits: defaultJobLimits(),
			Output: events.OutputRef{Prefix: o.outputPrefix(scan.ID, run.EngineID, run.JobID)},
		}

		if err := job.Validate(); err != nil {
			// A skipped job leaves its engine run queued forever, so this is an
			// ERROR with the cause attached — not a debug line. The scan will
			// sit at `running` until the reaper times it out, and the log is
			// the only place that explains why.
			o.log.Error("REFUSING TO PUBLISH AN INVALID JOB; its engine run will "+
				"stay queued until the reaper times it out",
				"scan_id", scanID, "engine", run.EngineID, "cause", err.Error())
			continue
		}
		if err := o.publishJob(ctx, job); err != nil {
			// One engine failing to queue must not abandon the rest. It stays
			// `queued` and the reaper will time it out, which is visible.
			o.log.Error("could not publish an engine job",
				"scan_id", scanID, "engine", run.EngineID, "cause", err.Error())
			continue
		}
		published++
	}

	return published, nil
}

// publishJob marshals and publishes, keyed for deduplication.
func (o *Orchestrator) publishJob(ctx context.Context, job events.ScanJobV1) error {
	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}
	// job_id as the dedup key: an orchestrator that crashes after publishing
	// but before recording it republishes the same id, and JetStream drops the
	// duplicate rather than running the job twice.
	return o.bus.Publish(ctx, job.Subject(), job.JobID, payload)
}

// outputPrefix builds the artifact path.
//
// ⚠ job_id IS IN THE PATH, so a retry writes somewhere new and can never
// overwrite a prior attempt's artifacts. Those artifacts are compliance
// evidence — an overwritten one is evidence destroyed.
func (o *Orchestrator) outputPrefix(scanID, engine, jobID string) string {
	return fmt.Sprintf("%s/scans/%s/raw/%s/%s/", o.artifactPrefix, scanID, engine, jobID)
}

func defaultJobLimits() events.JobLimits {
	return events.JobLimits{
		WallClockSec: 900, CPUMillis: 2000, MemoryMB: 4096,
		DiskMB: 20480, PIDsMax: 512, MaxOutputBytes: 256 << 20,
	}
}

// ---------------------------------------------------------------------------
// Result handling
// ---------------------------------------------------------------------------

// HandleResult records an engine result and recomputes the scan status.
//
// Idempotent: the upsert converges on job_id, and the status derivation is a
// pure function of the rows. Processing the same result twice produces the same
// state, which is what makes redelivery safe.
func (o *Orchestrator) HandleResult(ctx context.Context, result events.ScanResultV1) error {
	if err := result.Validate(); err != nil {
		// A malformed result is PERMANENT — retrying will not fix the payload.
		// Returning a non-ErrRetry error terminates it to the DLQ.
		return fmt.Errorf("invalid result for job %s: %w", result.JobID, err)
	}

	run := EngineRun{
		ScanID: result.ScanID, TenantID: result.TenantID, JobID: result.JobID,
		EngineID: result.Engine, Status: result.Status, Attempt: 1,
		EcosystemsCovered: result.EcosystemsCovered,
		EngineVersion:     result.EngineVersion,
		EngineDBVersion:   result.EngineDBVersion,
		Diagnostics:       result.Diagnostics,
		// Provenance: what actually ran. This is what makes a report
		// defensible six months later.
		ArgvRedacted: result.Invocation.ArgvRedacted,
		Summary:      result.Summary,
	}
	exitCode := result.Invocation.ExitCode
	run.ExitCode = &exitCode
	if result.Invocation.DurationMS > 0 {
		d := int(result.Invocation.DurationMS)
		run.DurationMS = &d
	}
	if !result.Invocation.StartedAt.IsZero() {
		t := result.Invocation.StartedAt
		run.StartedAt = &t
	}
	if !result.Invocation.FinishedAt.IsZero() {
		t := result.Invocation.FinishedAt
		run.FinishedAt = &t
	}
	if result.Error != nil {
		run.ErrorCode = result.Error.Code
		run.ErrorMessage = result.Error.Message
	}
	if run.Family == "" {
		if e, ok := o.registry.Get(result.Engine); ok {
			run.Family = familyOf(e)
		}
	}

	if err := o.store.UpsertEngineRun(ctx, run); err != nil {
		return fmt.Errorf("%w: recording engine run: %w", bus.ErrRetry, err)
	}

	// Every ecosystem the engine covered is recorded as covered. The gaps were
	// recorded at create time; together they are the Engine Coverage denominator.
	for _, eco := range result.EcosystemsCovered {
		_ = o.store.RecordEcosystem(ctx, result.TenantID, result.ScanID, eco, result.Engine, true)
	}

	return o.RecomputeScanStatus(ctx, result.TenantID, result.ScanID)
}

// RecomputeScanStatus derives and writes the scan's status.
//
// ⚠ MECHANICAL. There is no path that sets a scan to `completed` by hand — a
// hand-set status is how a scan with a failed engine comes to report success.
func (o *Orchestrator) RecomputeScanStatus(ctx context.Context, tenantID, scanID string) error {
	done, err := o.store.AllRunsTerminal(ctx, tenantID, scanID)
	if err != nil {
		return fmt.Errorf("%w: checking run states: %w", bus.ErrRetry, err)
	}
	if !done {
		// Still running. Not an error, and not a status change.
		return nil
	}

	statuses, err := o.store.TerminalStatuses(ctx, tenantID, scanID)
	if err != nil {
		return fmt.Errorf("%w: reading terminal statuses: %w", bus.ErrRetry, err)
	}

	derived := events.DeriveScanStatus(statuses)
	if err := o.store.UpdateScanStatus(ctx, tenantID, scanID, derived); err != nil {
		return fmt.Errorf("%w: writing scan status: %w", bus.ErrRetry, err)
	}

	o.log.Info("scan status derived",
		"scan_id", scanID, "status", derived, "engine_runs", len(statuses))
	return nil
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// PublishEvent emits an advisory progress event.
//
// Errors are logged, not returned: an event is advisory, and failing a scan
// because a progress message could not be published would invert the priority.
func (o *Orchestrator) PublishEvent(ctx context.Context, e events.ScanEventV1) {
	e.SchemaVersion = events.SchemaScanEventV1
	if e.EventID == "" {
		e.EventID = uuid.NewString()
	}
	if e.TS.IsZero() {
		e.TS = o.now().UTC()
	}
	if e.Seq == 0 {
		e.Seq = o.seq.Add(1)
	}
	e.Sanitize()

	if err := e.Validate(); err != nil {
		o.log.Warn("refusing to publish an invalid event", "cause", err.Error())
		return
	}

	payload, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := o.bus.PublishAdvisory(ctx, e.Subject(), payload); err != nil {
		o.log.Debug("advisory event not published; the database remains authoritative",
			"scan_id", e.ScanID, "cause", err.Error())
	}
}

// Progress computes a scan's completion percentage.
//
// ⚠ A WEIGHTED MEAN OVER ENGINES, computed HERE and not by the client
// (docs/02-CONTRACTS.md §5). dependency-check taking 40 minutes and syft taking
// 20 seconds must not contribute equally, and a client cannot know the weights.
func Progress(runs []EngineRun) int {
	var totalWeight, done int
	for _, r := range runs {
		w := r.Weight
		if w <= 0 {
			w = 1
		}
		totalWeight += w
		if r.Status != statusQueued && r.Status != "running" {
			done += w
		}
	}
	if totalWeight == 0 {
		return 0
	}
	return done * 100 / totalWeight
}
