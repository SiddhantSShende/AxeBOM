package orchestr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/policy"
)

// Orchestrator creates scans, fans out jobs, and aggregates results.
type Orchestrator struct {
	store    *Store
	bus      *bus.Bus
	registry *policy.Registry
	log      *slog.Logger

	artifactPrefix string
	// frontendURL builds a notify event's URL. Empty means the scan.completed
	// notification is skipped entirely rather than published with a broken
	// link — see RecomputeScanStatus.
	frontendURL string
	now         func() time.Time

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
	// ArtifactPrefix is the object-storage root, e.g. s3://axebom.
	ArtifactPrefix string
	// FrontendURL builds a notify event's URL. Empty disables that
	// notification rather than publishing a broken link.
	FrontendURL string
	Now         func() time.Time
}

func New(cfg Config) *Orchestrator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ArtifactPrefix == "" {
		cfg.ArtifactPrefix = "s3://axebom"
	}
	if cfg.Registry == nil {
		cfg.Registry = policy.DefaultRegistry()
	}
	return &Orchestrator{
		store: cfg.Store, bus: cfg.Bus, registry: cfg.Registry,
		log: cfg.Logger, artifactPrefix: cfg.ArtifactPrefix,
		frontendURL: cfg.FrontendURL, now: cfg.Now,
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
	case events.SourceGit, events.SourceUpload, events.SourceImage, events.SourceURL:
	default:
		return Scan{}, errs.Newf(errs.ValidationFieldInvalid,
			"source_kind must be git, upload, image or url (got %q)", in.SourceKind)
	}

	// An explicit engine list is validated in full — every offending pair, so
	// one correction fixes all of them.
	if len(in.RequestedEngines) > 0 {
		if err := o.registry.ValidateCombination(in.RequestedEngines, in.SourceKind, in.Families); err != nil {
			return Scan{}, err
		}
	}

	// HBOM and QBOM have no worker: workers/hbom and workers/qbom deliberately
	// have no runner, because neither is a scan (CLAUDE.md honest labels — HBOM
	// is a CSV/form import, QBOM is derived from CBOM discovery). Resolving
	// either into `resolution.Engines` below would publish a scan.job.hbom /
	// scan.job.qbom job that nothing ever consumes, and the scan would sit
	// unconsumed until the reaper times it out. Reject before anything is
	// persisted or published — never discover this at worker time.
	if err := o.rejectNonScannableFamilies(in); err != nil {
		return Scan{}, err
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

	// ⚠ WHICH PRODUCER RUNS FIRST DEPENDS ON THE SOURCE, NOT THE FAMILIES
	// REQUESTED. A url source has no repository to clone and no upload to
	// extract — services/webrecon is what materializes ITS input (subdomain
	// discovery + JS fingerprinting), publishing scan.job.webrecon instead of
	// scan.job.fetch. Every other source kind is unchanged.
	publishProducer := o.publishFetchJob
	producerName := "fetch"
	if scan.SourceKind == events.SourceURL {
		publishProducer = o.publishWebreconJob
		producerName = "webrecon"
	}
	if err := publishProducer(ctx, scan); err != nil {
		// The scan row exists and is queued. Failing here leaves it for the
		// reaper rather than losing it: a scan recorded but not dispatched is
		// visible and times out, whereas rolling back would lose the record of
		// what the user asked for.
		o.log.Error("scan created but the "+producerName+" job could not be published",
			"scan_id", scan.ID, "cause", err.Error())
		return scan, errs.Wrap(err, errs.InternalDependency,
			"the scan was created but could not be queued; it will time out and can be retried")
	}

	return scan, nil
}

// defaultJobDeadline matches the sandbox wall-clock ceiling plus scheduling
// slack. The reaper marks anything past it as `timeout`.
const defaultJobDeadline = 30 * time.Minute

// familyRedirect names the concrete alternative for a family whose every
// registered engine is metadata-only (policy.Engine.Derived or
// .RequiresImport) — i.e. it exists in the registry for UI/tenant-override
// purposes but has no engine that can be dispatched as a scan job.
//
// A family not listed here still gets rejected by rejectNonScannableFamilies
// — the registry's flags are the source of truth, not this map — but with a
// generic message instead of a specific redirect. Add an entry here whenever
// a new metadata-only family is registered, so the 422 stays actionable.
var familyRedirect = map[events.Family]string{
	events.FamilyHBOM: "HBOM has no scanner; import hardware inventory via the " +
		"/v1/hbom/* endpoints instead of requesting a scan.",
	events.FamilyQBOM: "QBOM is derived from CBOM discovery, not scanned directly; " +
		"it becomes available automatically once a CBOM report exists for this project.",
}

// rejectNonScannableFamilies refuses any requested family for which EVERY
// registered engine is metadata-only, plus any RequestedEngines entry that
// names such an engine directly.
//
// ⚠ GENERIC OFF THE REGISTRY FLAGS, NOT HARDCODED FAMILY NAMES.
//
// Today that is exactly HBOM (hbom-csv, RequiresImport) and QBOM
// (qbom-derive, Derived) — see policy.DefaultRegistry — but this walks
// Engine.Derived / Engine.RequiresImport rather than switching on family
// name, so it stays correct if the registry changes without a second edit
// here.
//
// Lists EVERY offending family and engine in one error, matching this
// package's stated philosophy (see the doc comment on CreateScan): a user who
// fixes the one thing they were shown and resubmits into the next has been
// made to do the work twice.
func (o *Orchestrator) rejectNonScannableFamilies(in CreateScanInput) error {
	var offendingFamilies []events.Family
	for _, f := range in.Families {
		candidates := o.registry.ForFamily(f)
		if len(candidates) == 0 {
			// No registered engine at all for this family is a DIFFERENT
			// problem (ScanNoEnginesAvailable, raised after resolution below) —
			// not this check's concern.
			continue
		}
		allMetadataOnly := true
		for _, e := range candidates {
			if !e.Derived && !e.RequiresImport {
				allMetadataOnly = false
				break
			}
		}
		if allMetadataOnly {
			offendingFamilies = append(offendingFamilies, f)
		}
	}

	var offendingEngines []string
	for _, id := range in.RequestedEngines {
		if e, ok := o.registry.Get(id); ok && (e.Derived || e.RequiresImport) {
			offendingEngines = append(offendingEngines, id)
		}
	}

	if len(offendingFamilies) == 0 && len(offendingEngines) == 0 {
		return nil
	}

	err := errs.New(errs.ScanFamilyNotDirectlyScannable,
		buildNonScannableMessage(offendingFamilies, offendingEngines))

	for _, f := range offendingFamilies {
		reason, ok := familyRedirect[f]
		if !ok {
			reason = fmt.Sprintf(
				"%s has no directly-invokable engine; every registered engine for "+
					"it is derived from another BOM type's output or is an import, "+
					"never a scan", f)
		}
		err = err.WithDetail(errs.Detail{"family": string(f), "reason": reason})
	}
	for _, id := range offendingEngines {
		err = err.WithDetail(errs.Detail{
			"engine": id,
			"reason": fmt.Sprintf("%s is a metadata-only engine (derived or import-only) "+
				"and cannot be requested directly as a scan engine", id),
		})
	}
	return err
}

// buildNonScannableMessage mirrors policy.buildCombinationMessage's shape:
// every offender named in the message AND in the details, so the error is
// legible without a client that renders `details`.
func buildNonScannableMessage(families []events.Family, engines []string) string {
	var parts []string
	if len(families) > 0 {
		names := make([]string, len(families))
		for i, f := range families {
			names[i] = string(f)
		}
		parts = append(parts, fmt.Sprintf("%d BOM family(s) cannot be requested as a scan: %s",
			len(families), strings.Join(names, ", ")))
	}
	if len(engines) > 0 {
		parts = append(parts, fmt.Sprintf("%d engine(s) are metadata-only and cannot be requested directly: %s",
			len(engines), strings.Join(engines, ", ")))
	}
	return strings.Join(parts, "; ") +
		". Every offending family and engine is listed in the error details, so one correction fixes all of them."
}

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

// publishWebreconJob queues the single webrecon job that discovers and
// fingerprints a url source. publishFetchJob's sibling, invoked instead of
// it when scan.SourceKind == events.SourceURL — see CreateScan.
func (o *Orchestrator) publishWebreconJob(ctx context.Context, scan Scan) error {
	jobID := uuid.NewString()
	job := events.ScanJobV1{
		SchemaVersion: events.SchemaScanJobV1,
		JobID:         jobID,
		ScanID:        scan.ID,
		TenantID:      scan.TenantID,
		ProjectID:     scan.ProjectID,
		Family:        events.FamilyWebrecon,
		Engine:        "webrecon",
		Attempt:       1,
		IssuedAt:      o.now().UTC(),
		DeadlineAt:    o.now().Add(defaultJobDeadline).UTC(),
		SourceMeta:    events.SourceMeta{Kind: scan.SourceKind},
		Limits:        defaultJobLimits(),
		Output:        events.OutputRef{Prefix: o.outputPrefix(scan.ID, "webrecon", jobID)},
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

	// Loaded once per FanOut call, used only by engines that consume it
	// (github-dependency-graph-sbom, webrecon-fingerprint) — see
	// policy.Engine.ConsumesNativeSBOM. A no-op query for every scan that
	// never staged one: LoadRawArtifactsForEngines returns an empty slice,
	// not an error, when neither producer recorded anything under role
	// "native_output".
	nativeSBOMRef := o.nativeSBOMRefFor(ctx, tenantID, scanID)

	// ⚠ TWO WAYS A SCAN CAN HAVE SOMETHING TO FAN OUT WITH, NOT ONE.
	//
	// A git/upload-sourced scan has a real content-addressed source archive
	// (ArchiveRef). A url-sourced scan never does — services/webrecon
	// produces a native discovery document instead, never a source archive —
	// so ArchiveRef being empty is the EXPECTED, honest state for it, not a
	// missing-data bug. Refusing to fan out only when BOTH are empty is what
	// makes this guard correct for both source shapes.
	if scan.ArchiveRef == "" && nativeSBOMRef == "" {
		return 0, fmt.Errorf("cannot fan out scan %s: no source archive or native document recorded", scanID)
	}

	var published int
	for _, run := range runs {
		// Only queued runs. A redelivered fetch result must not re-publish
		// jobs for engines that already started.
		if run.Status != statusQueued {
			continue
		}

		// ⚠ AN ENGINE THAT READS ANOTHER'S OUTPUT IS HELD BACK.
		//
		// Publishing all six jobs at once meant grype was routinely delivered
		// before syft had produced the SBOM it matches against, so it reported
		// `skipped` on every real scan for an input that was still being
		// produced. Its run stays `queued` here and is published by
		// releaseDependents when its producer reports.
		if e, ok := o.registry.Get(run.EngineID); ok && e.ConsumesOutputOf != "" {
			o.log.Info("holding an engine job until its producer reports",
				"scan_id", scanID, "engine", run.EngineID, "waits_for", e.ConsumesOutputOf)
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

		if e, ok := o.registry.Get(run.EngineID); ok && e.ConsumesNativeSBOM {
			job.Workspace.NativeSBOMRef = nativeSBOMRef
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

// nativeSBOMProducers are the components that can stage a native document —
// never a policy.Engine, never given a scan.engine_runs row, so their
// artifacts are looked up by producer id rather than engine id. See
// RecordProducerArtifacts and migrations/scan/0009.
var nativeSBOMProducers = []string{"fetcher", "webrecon"}

// nativeSBOMRefFor looks up a staged native document, if one of
// nativeSBOMProducers staged one — see fetchDependencyGraphSBOM in
// services/fetcher/internal/work/work.go, services/webrecon's worker, and
// Workspace.NativeSBOMRef's own doc comment.
//
// Errors are logged and swallowed, not returned: a lookup failure here must
// never block the rest of FanOut, and every engine that cares
// (github-dependency-graph-sbom, webrecon-fingerprint) already treats an
// empty ref as an honest ENGINE_INPUT_MISSING rather than a hard failure.
func (o *Orchestrator) nativeSBOMRefFor(ctx context.Context, tenantID, scanID string) string {
	artifacts, err := o.store.LoadRawArtifactsForEngines(ctx, tenantID, scanID, nativeSBOMProducers)
	if err != nil {
		o.log.Warn("could not check for a staged native document; proceeding without one",
			"scan_id", scanID, "cause", err.Error())
		return ""
	}
	for _, producer := range nativeSBOMProducers {
		for _, a := range artifacts[producer] {
			if a.Role == "native_output" {
				return a.URI
			}
		}
	}
	return ""
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

	engineRunID, err := o.store.UpsertEngineRun(ctx, run)
	if err != nil {
		return fmt.Errorf("%w: recording engine run: %w", bus.ErrRetry, err)
	}

	// ⚠ THE ONE WRITE PATH FOR scan.raw_artifacts. Before this, an engine's
	// artifact URIs/checksums were read off ScanResultV1 and then discarded
	// the moment this function returned — nothing durable ever recorded
	// where a raw result lives. This is what makes both the normalize
	// trigger's envelope (below) and future re-normalization possible.
	// Best-effort: a failure here must not fail engine-run bookkeeping, which
	// has already committed above.
	if err := o.store.RecordRawArtifacts(ctx, result.TenantID, result.ScanID, engineRunID, result.Artifacts); err != nil {
		o.log.Error("could not record raw artifacts", "scan_id", result.ScanID,
			"engine", result.Engine, "cause", err.Error())
	}

	// Every ecosystem the engine covered is recorded as covered. The gaps were
	// recorded at create time; together they are the Engine Coverage denominator.
	for _, eco := range result.EcosystemsCovered {
		_ = o.store.RecordEcosystem(ctx, result.TenantID, result.ScanID, eco, result.Engine, true)
	}

	// ⚠ BEFORE RecomputeScanStatus, NOT AFTER.
	//
	// Recompute asks whether every run is terminal. A dependent run that is
	// still `queued` keeps the scan `running`, which is correct — but if this
	// ran afterwards, a producer arriving last would recompute against a run
	// that had not yet been published and the scan would sit at `running`
	// until the reaper, with nothing in flight.
	if err := o.releaseDependents(ctx, result); err != nil {
		return err
	}

	if err := o.RecomputeScanStatus(ctx, result.TenantID, result.ScanID); err != nil {
		return err
	}

	// ⚠ AFTER RecomputeScanStatus, same reasoning as releaseDependents runs
	// BEFORE it: this reads the scan's engine runs fresh, so it must see
	// this result's row (already written above) and any dependent job
	// releaseDependents just queued or skipped. Best-effort, matching
	// publishScanCompleted's discipline: a failed trigger-publish must not
	// turn a correctly-derived scan status into a retried one.
	o.maybeTriggerNormalize(ctx, result)
	return nil
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

	// ⚠ AFTER THE STATUS WRITE, NEVER BEFORE — same rule report's render
	// worker follows for report.ready. Best effort: a notification failing
	// must not turn a correctly-derived scan status into a retried one
	// (docs/02-CONTRACTS.md §2, "events are advisory").
	o.publishScanCompleted(ctx, tenantID, scanID, derived)
	return nil
}

// publishScanCompleted sends the notify.> event for a scan reaching a
// terminal status, whatever that status is — webhook.EventScanCompleted's
// own doc comment: "fires once per scan, whatever its terminal status."
//
// ⚠ NO COMPONENT/FINDING COUNTS. Those live in `normalize.*`, which this
// service does not otherwise read (ADR-0001, CLAUDE.md invariant 11) — and
// whether normalization has even finished by the moment every engine run
// reaches terminal is a real, unanswered timing question, not something to
// guess at here. A future session wiring real counts needs to answer that
// first; until then this event carries ids, status and a URL only, which is
// still the complete story a webhook receiver or an email needs to know
// something happened and where to look for detail.
func (o *Orchestrator) publishScanCompleted(ctx context.Context, tenantID, scanID string, status events.ScanStatus) {
	if o.bus == nil || o.frontendURL == "" {
		return
	}

	scan, _, err := o.store.GetScan(ctx, tenantID, scanID)
	if err != nil {
		o.log.Warn("could not load the scan for its completion notification",
			"scan_id", scanID, "error", err)
		return
	}

	evt := events.NotifyEventV1{
		Schema:     events.NotifyEventSchema,
		Event:      events.NotifyEventScanCompleted,
		TenantID:   tenantID,
		ProjectID:  scan.ProjectID,
		ScanID:     scanID,
		Status:     string(status),
		URL:        o.frontendURL + "/scans/" + scanID,
		OccurredAt: o.now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(evt)
	if err != nil {
		o.log.Warn("could not encode the scan.completed notification", "scan_id", scanID, "error", err)
		return
	}
	// Dedup key: the scan id. RecomputeScanStatus only reaches here once a
	// scan's status is genuinely terminal, and a crash-retry of the same
	// terminal recomputation must not fan the same notification out twice.
	if err := o.bus.Publish(ctx, evt.Subject(), scanID, body); err != nil {
		o.log.Warn("could not publish the scan.completed notification", "scan_id", scanID, "error", err)
	}
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
