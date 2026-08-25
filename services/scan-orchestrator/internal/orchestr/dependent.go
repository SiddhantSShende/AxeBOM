package orchestr

import (
	"context"
	"fmt"
	"time"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
)

// releaseDependents publishes engine jobs that were waiting on this result.
//
// # Why an engine waits at all
//
// grype matches against OUR syft SBOM rather than cataloguing the tree itself.
// Re-scanning would produce a second, subtly different component inventory to
// reconcile, which is exactly the work the normalizer exists to avoid. So the
// two jobs are ordered, and the ordering has to be enforced by whoever publishes
// them — the worker cannot wait for an input that may never come without burning
// its retry budget against a thirty-minute ack window.
//
// # ⚠ A PRODUCER THAT DID NOT PRODUCE MUST NOT LEAVE ITS CONSUMER QUEUED
//
// If syft fails, grype can never run. Leaving its run `queued` means the scan
// never reaches a terminal state and the reaper reports a timeout half an hour
// later — a misleading cause for a straightforward one. The dependent is marked
// `skipped` immediately, naming the producer, so Engine Coverage says why.
func (o *Orchestrator) releaseDependents(ctx context.Context, result events.ScanResultV1) error {
	scan, runs, err := o.store.GetScan(ctx, result.TenantID, result.ScanID)
	if err != nil {
		return fmt.Errorf("%w: loading scan to release dependents: %w", bus.ErrRetry, err)
	}

	producedUsableOutput := result.Status == events.StatusSucceeded ||
		result.Status == events.StatusPartial

	for _, run := range runs {
		if run.Status != statusQueued {
			continue
		}
		engine, ok := o.registry.Get(run.EngineID)
		if !ok || engine.ConsumesOutputOf != result.Engine {
			continue
		}

		if !producedUsableOutput {
			o.skipDependent(ctx, run, result)
			continue
		}

		family := events.FamilySBOM
		if len(engine.Families) > 0 {
			family = engine.Families[0]
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
			o.log.Error("REFUSING TO PUBLISH AN INVALID DEPENDENT JOB; its engine run "+
				"will stay queued until the reaper times it out",
				"scan_id", scan.ID, "engine", run.EngineID, "cause", err.Error())
			continue
		}
		if err := o.publishJob(ctx, job); err != nil {
			// Its run stays queued and the reaper will time it out, which is
			// visible. One engine failing to queue must not abandon the rest.
			o.log.Error("could not publish a dependent engine job",
				"scan_id", scan.ID, "engine", run.EngineID, "cause", err.Error())
			continue
		}

		o.log.Info("released a dependent engine job",
			"scan_id", scan.ID, "engine", run.EngineID, "after", result.Engine)
	}

	return nil
}

// skipDependent records that a consumer can never run because its producer did
// not produce.
func (o *Orchestrator) skipDependent(ctx context.Context, run EngineRun, result events.ScanResultV1) {
	now := time.Now().UTC()
	run.Status = events.StatusSkipped
	run.FinishedAt = &now
	run.ErrorCode = "ENGINE_INPUT_MISSING"
	run.ErrorMessage = fmt.Sprintf(
		"%s reads %s's output, and %s reported %s",
		run.EngineID, result.Engine, result.Engine, result.Status)

	if err := o.store.UpsertEngineRun(ctx, run); err != nil {
		// Not fatal: the reaper will time the run out. Logged because a
		// silently stuck run is the thing this function exists to prevent.
		o.log.Error("could not mark a dependent engine as skipped",
			"scan_id", run.ScanID, "engine", run.EngineID, "cause", err.Error())
		return
	}

	o.log.Info("skipped a dependent engine; its producer produced nothing",
		"scan_id", run.ScanID, "engine", run.EngineID,
		"producer", result.Engine, "producer_status", result.Status)
}
