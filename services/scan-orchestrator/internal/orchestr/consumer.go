package orchestr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
)

// The result consumer: the loop that turns worker output into scan state.
//
// TWO KINDS OF RESULT ARRIVE HERE, and they do different things:
//
//	FETCH   pins commit_sha and the archive, then FANS OUT one job per engine.
//	        Every engine then reads the same bytes (ADR-0008).
//	ENGINE  upserts one engine_runs row and recomputes the scan status
//	        mechanically.
//
// Both are IDEMPOTENT, because both will be redelivered: ack_wait is 30 minutes
// and a worker can die at any point.

// ConsumeResults runs the result loop until the context is cancelled.
func (o *Orchestrator) ConsumeResults(ctx context.Context) error {
	for _, family := range events.AllFamilies() {
		consumer, err := o.bus.EnsureConsumer(ctx, bus.ConsumerConfig{
			Stream: bus.StreamResults,
			// One durable per family, matching the one-consumer-per-filter
			// constraint on a WorkQueue stream. Every orchestrator instance
			// shares it, and NATS distributes between them.
			Durable:       "orchestrator-" + string(family),
			FilterSubject: "scan.result." + string(family),
			MaxAckPending: 16,
		})
		if err != nil {
			return fmt.Errorf("result consumer for %s: %w", family, err)
		}

		fam := family
		go func() {
			dlq := "scan.dlq." + string(fam)
			if err := o.bus.Consume(ctx, consumer, dlq, o.handleResultMessage); err != nil {
				o.log.Error("result consumer stopped", "family", fam, "cause", err.Error())
			}
		}()
	}

	<-ctx.Done()
	return nil
}

// handleResultMessage routes one result.
func (o *Orchestrator) handleResultMessage(ctx context.Context, msg jetstream.Msg) error {
	var result events.ScanResultV1
	if err := events.Decode(msg.Data(), &result); err != nil {
		// Undecodable now, undecodable on retry. A permanent error terminates
		// to the DLQ rather than burning four delivery attempts.
		return fmt.Errorf("undecodable result: %w", err)
	}

	if result.Engine == "fetcher" {
		return o.handleFetchResult(ctx, result)
	}
	if result.Engine == "webrecon" {
		return o.handleWebreconResult(ctx, result)
	}
	return o.HandleResult(ctx, result)
}

// handleFetchResult pins the source and fans out.
//
// ⚠ THE ORDER MATTERS AND IS NOT INTERCHANGEABLE.
//
// commit_sha is recorded FIRST, and only then are engine jobs published. A
// fan-out before the pin would hand engines a job whose source_meta.commit_sha
// is empty — and a report that cannot name the commit it describes is not
// evidence of anything.
func (o *Orchestrator) handleFetchResult(ctx context.Context, result events.ScanResultV1) error {
	// ⚠ AN UNKNOWN SCAN IS PERMANENT, NOT TRANSIENT.
	//
	// A result naming a scan that does not exist for this tenant will never
	// become processable: the row is not coming back. Returning a plain error
	// terminates the message to the DLQ; returning ErrRetry would nak it, and
	// that is not a theoretical distinction.
	//
	// Observed on this stack: results left behind by a test run saturated the
	// consumer — "Outstanding Acks: 16 out of maximum 16, Unprocessed: 42" —
	// because every one of them naked, waited out the backoff, and naked again.
	// A single class of poison message stalled every real scan behind it, and
	// the only symptom was scans sitting at `queued`.
	if _, _, err := o.store.GetScan(ctx, result.TenantID, result.ScanID); err != nil {
		if errors.Is(err, ErrNotFound) {
			o.log.Warn("fetch result for an unknown scan; discarding",
				"scan_id", result.ScanID, "job_id", result.JobID)
			return fmt.Errorf("no such scan %s for this tenant", result.ScanID)
		}
		// A real database problem IS transient.
		return fmt.Errorf("%w: loading scan: %w", bus.ErrRetry, err)
	}

	if result.Status == events.StatusFailed || result.Status == events.StatusTimeout {
		// Nothing to scan. Mark every engine run and the scan itself failed:
		// leaving them queued would make the reaper report a timeout in half an
		// hour rather than the real cause now.
		o.log.Error("fetch failed; the scan cannot proceed",
			"scan_id", result.ScanID, "status", result.Status)

		if err := o.failAllRuns(ctx, result); err != nil {
			return fmt.Errorf("%w: failing runs after a failed fetch: %w", bus.ErrRetry, err)
		}
		return o.RecomputeScanStatus(ctx, result.TenantID, result.ScanID)
	}

	archiveRef, archiveSHA := archiveFrom(result)
	if archiveRef == "" {
		return fmt.Errorf("fetch result for scan %s carries no source archive", result.ScanID)
	}

	// Idempotent by construction: a redelivered fetch result writes nothing and
	// reports that it wrote nothing, which is success rather than a conflict.
	wrote, err := o.store.SetSourceOnce(ctx, result.TenantID, result.ScanID,
		commitSHAFrom(result), archiveRef, archiveSHA)
	if err != nil {
		return fmt.Errorf("%w: pinning source: %w", bus.ErrRetry, err)
	}
	if !wrote {
		o.log.Info("fetch result redelivered; source already pinned",
			"scan_id", result.ScanID)
	}

	// Records EVERY artifact the fetcher staged — the source archive again
	// (redundant with source_archive_ref on the scan row, but raw_artifacts is
	// meant to be the complete evidence ledger) and, when present, the
	// GitHub Dependency Graph native_output document nativeSBOMRefFor reads
	// back. See RecordProducerArtifacts's own doc comment for why this call
	// was MISSING until now, despite Milestone 3 believing it worked.
	if err := o.store.RecordProducerArtifacts(ctx, result.TenantID, result.ScanID,
		"fetcher", result.Artifacts); err != nil {
		return fmt.Errorf("%w: recording fetcher artifacts: %w", bus.ErrRetry, err)
	}

	published, err := o.FanOut(ctx, result.TenantID, result.ScanID)
	if err != nil {
		return fmt.Errorf("%w: fanning out: %w", bus.ErrRetry, err)
	}
	o.log.Info("fanned out engine jobs", "scan_id", result.ScanID, "jobs", published)
	return nil
}

// handleWebreconResult records a url source's discovery + fingerprint
// document and fans out.
//
// publishFetchJob's counterpart for a url-sourced scan — handleFetchResult's
// sibling. The two differ in exactly what a producer PRODUCES: fetch pins a
// commit and a source archive every SBOM engine reads identically; webrecon
// has neither (there is no commit, and no traditional source archive — see
// events.ScanJobV1.Validate) and instead stages one native_output document
// that only webrecon-fingerprint (policy.Engine.ConsumesNativeSBOM) consumes.
func (o *Orchestrator) handleWebreconResult(ctx context.Context, result events.ScanResultV1) error {
	// Same reasoning as handleFetchResult's identical check: a result naming a
	// scan that no longer exists for this tenant will never become
	// processable, so this is permanent, not a retry candidate.
	if _, _, err := o.store.GetScan(ctx, result.TenantID, result.ScanID); err != nil {
		if errors.Is(err, ErrNotFound) {
			o.log.Warn("webrecon result for an unknown scan; discarding",
				"scan_id", result.ScanID, "job_id", result.JobID)
			return fmt.Errorf("no such scan %s for this tenant", result.ScanID)
		}
		return fmt.Errorf("%w: loading scan: %w", bus.ErrRetry, err)
	}

	if result.Status == events.StatusFailed || result.Status == events.StatusTimeout {
		o.log.Error("webrecon failed; the scan cannot proceed",
			"scan_id", result.ScanID, "status", result.Status)
		if err := o.failAllRuns(ctx, result); err != nil {
			return fmt.Errorf("%w: failing runs after a failed webrecon: %w", bus.ErrRetry, err)
		}
		return o.RecomputeScanStatus(ctx, result.TenantID, result.ScanID)
	}

	// ⚠ EMPTY COMMIT, EMPTY ARCHIVE — DELIBERATELY, NOT A GAP.
	//
	// A url source has no commit to pin and no traditional source archive;
	// SetSourceOnce is still called, for its OTHER two effects: the
	// write-once idempotency guard (WHERE source_commit_sha IS NULL, so a
	// redelivered result is a harmless no-op) and flipping the scan to
	// `running`. Recording empty strings for a source with nothing to name is
	// the SAME choice an upload-sourced scan already makes for commit_sha —
	// see CommitSHA's own `omitempty` doc comment in fetch.go — not a new
	// pattern invented here.
	wrote, err := o.store.SetSourceOnce(ctx, result.TenantID, result.ScanID, "", "", "")
	if err != nil {
		return fmt.Errorf("%w: marking the scan running: %w", bus.ErrRetry, err)
	}
	if !wrote {
		o.log.Info("webrecon result redelivered; scan already marked running",
			"scan_id", result.ScanID)
	}

	if err := o.store.RecordProducerArtifacts(ctx, result.TenantID, result.ScanID,
		"webrecon", result.Artifacts); err != nil {
		return fmt.Errorf("%w: recording webrecon artifacts: %w", bus.ErrRetry, err)
	}

	published, err := o.FanOut(ctx, result.TenantID, result.ScanID)
	if err != nil {
		return fmt.Errorf("%w: fanning out: %w", bus.ErrRetry, err)
	}
	o.log.Info("fanned out engine jobs", "scan_id", result.ScanID, "jobs", published)
	return nil
}

// commitSHAFrom reads the commit the fetcher pinned.
//
// ⚠ THIS USED TO READ EngineDBVersion, AND THAT WAS A LIE IN BOTH DIRECTIONS.
//
// ScanResultV1 had no home for a commit sha, so the fetch path borrowed the
// vulnerability-database vintage field. A fetch result therefore claimed a
// database version it had never consulted, and the commit sha — which appears
// in every report and is the thing that stops a scan describing a codebase that
// never existed — lived in a field nobody would think to look in.
//
// SourceMeta now carries it. The fallback stays because a fetcher deployed
// before that field existed is still correct, and losing the commit sha would
// silently produce reports that cannot name what they describe.
func commitSHAFrom(result events.ScanResultV1) string {
	if result.SourceMeta != nil && result.SourceMeta.CommitSHA != "" {
		return result.SourceMeta.CommitSHA
	}
	return result.EngineDBVersion
}

// archiveFrom extracts the source archive from a fetch result.
func archiveFrom(result events.ScanResultV1) (uri, sha string) {
	for _, a := range result.Artifacts {
		if a.Role == "source_archive" {
			return a.URI, a.SHA256
		}
	}
	// Fall back to the first artifact: a fetcher that produced exactly one
	// thing produced the archive.
	if len(result.Artifacts) == 1 {
		return result.Artifacts[0].URI, result.Artifacts[0].SHA256
	}
	return "", ""
}

// failAllRuns marks every queued run failed after an unrecoverable fetch.
func (o *Orchestrator) failAllRuns(ctx context.Context, result events.ScanResultV1) error {
	_, runs, err := o.store.GetScan(ctx, result.TenantID, result.ScanID)
	if err != nil {
		return err
	}

	code, message := "SCAN_SOURCE_UNREACHABLE", "the source could not be fetched"
	if result.Error != nil {
		code, message = result.Error.Code, result.Error.Message
	}

	now := time.Now().UTC()
	for _, run := range runs {
		if run.Status != statusQueued {
			continue
		}
		run.Status = events.StatusFailed
		run.FinishedAt = &now
		run.ErrorCode = code
		run.ErrorMessage = message
		if _, err := o.store.UpsertEngineRun(ctx, run); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test and operational helper
// ---------------------------------------------------------------------------

// PublishFetchResult publishes a fetch result.
//
// Used by the mock fetcher and by the end-to-end check. The real fetcher
// publishes the same envelope from inside the sandbox — this exists so the
// orchestration can be exercised without one, NOT as a second code path for
// production.
func (o *Orchestrator) PublishFetchResult(ctx context.Context, scanID, tenantID,
	commitSHA, archiveURI, archiveSHA string,
) error {
	result := events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         "fetch-" + scanID,
		ScanID:        scanID, TenantID: tenantID,
		Engine: "fetcher", EngineVersion: "internal",
		// The fetcher reports the pinned commit here; it is the one piece of
		// provenance every engine job inherits.
		EngineDBVersion: commitSHA,
		Status:          events.StatusSucceeded,
		Artifacts: []events.Artifact{{
			Role: "source_archive", URI: archiveURI,
			MediaType: "application/zstd", SHA256: archiveSHA,
		}},
		Invocation: events.Invocation{
			ArgvRedacted: []string{"fetcher"},
			StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
		},
	}

	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return o.bus.Publish(ctx, "scan.result.fetch", result.JobID, payload)
}

// PublishWebreconResult publishes a webrecon result. PublishFetchResult's
// sibling for a url-sourced scan, and used the same way — to exercise
// orchestration without a real services/webrecon instance, never as a second
// production code path.
func (o *Orchestrator) PublishWebreconResult(ctx context.Context, scanID, tenantID,
	artifactURI, artifactSHA string,
) error {
	result := events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         "webrecon-" + scanID,
		ScanID:        scanID, TenantID: tenantID,
		Engine: "webrecon", EngineVersion: "internal",
		Status: events.StatusSucceeded,
		Artifacts: []events.Artifact{{
			Role: "native_output", URI: artifactURI,
			MediaType: "application/json", SHA256: artifactSHA,
		}},
		Invocation: events.Invocation{
			ArgvRedacted: []string{"webrecon"},
			StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
		},
	}

	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return o.bus.Publish(ctx, "scan.result.webrecon", result.JobID, payload)
}
