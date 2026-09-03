package orchestr

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/policy"
)

// maybeTriggerNormalize fires exactly one NormalizeTriggerV1 the moment
// every engine dispatched for one family reaches a terminal state.
//
// ⚠ SBOM ONLY, FOR NOW — an explicit, trivially-removable guard. The
// mechanism below is family-generic (readiness is derived from the registry,
// not a hardcoded engine list), but CBOM/AIBOM are deliberately not wired
// yet: the normalize consumer this publishes to only exists for SBOM today.
//
// ⚠ BEST EFFORT, AND PUBLISH-THEN-CLAIM, DELIBERATELY IN THAT ORDER.
//
// Every error here is logged, never returned — matching publishScanCompleted's
// discipline. By the time this runs, HandleResult has already committed the
// engine-run row and recomputed the scan's status; a failed trigger-publish
// must not turn either of those into a retried operation.
//
// The write-once row in scan.normalize_triggers is claimed ONLY AFTER a
// successful publish, not before. Claiming first (the original design) meant
// a transient failure in ANY of build/validate/marshal/publish after the
// claim permanently lost that scan's normalization: the row already existed,
// so every future redelivery's own claim attempt would see "already fired"
// and return without ever retrying — silent, permanent loss from one NATS
// hiccup. Publishing first means the worst a transient failure can do is
// leave nothing claimed, so the NEXT terminal result (a redelivery, or any
// other engine's result racing to the same terminal check) tries again from
// scratch. The cost is a narrow, accepted race: two calls can both pass the
// cheap NormalizeTriggerID pre-check below concurrently, both publish under
// DIFFERENT trigger ids, and only one wins the claim — a harmless duplicate
// trigger, since the consumer's own idempotency (pre-check by scan_id/
// bom_type/normalization_version, backed by a UNIQUE constraint) absorbs a
// duplicate the way it already absorbs a redelivered one.
// normalizedFamilies are the families whose NormalizeTriggerV1 has a consumer
// on the other end.
//
// ⚠ AN ALLOWLIST, NOT A REMOVED GUARD, AND THE DIFFERENCE IS A SILENT FAILURE.
//
// NORMALIZE_JOBS is a WorkQueue stream. Publishing scan.normalize.cbom with no
// consumer attached leaves a message nobody acks: it sits until MaxAge and
// that scan simply never normalizes, with no error raised anywhere and a
// completed scan showing zero results. That is the exact shape of failure this
// codebase keeps finding, so the gate stays and the list grows by one entry
// when a family's consumer is actually deployed.
//
// The entry and the compose service are two halves of one fact. Adding either
// without the other is the bug.
//
// QBOM is the one family that will never be here: it is DERIVED from CBOM
// crypto assets rather than scanned, so it has no scan.job of its own and
// therefore no result to trigger on.
var normalizedFamilies = map[events.Family]bool{
	events.FamilySBOM:  true,
	events.FamilyHBOM:  true,
	events.FamilyCBOM:  true,
	events.FamilyAIBOM: true,
}

func (o *Orchestrator) maybeTriggerNormalize(ctx context.Context, result events.ScanResultV1) {
	e, ok := o.registry.Get(result.Engine)
	if !ok {
		return
	}
	family := events.Family(familyOf(e))
	if !normalizedFamilies[family] {
		return
	}

	scan, runs, err := o.store.GetScan(ctx, result.TenantID, result.ScanID)
	if err != nil {
		o.log.Warn("could not load the scan to check normalize readiness",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	}

	latest := latestRunsByEngine(runs)
	if !familyTerminal(latest, o.registry, family) {
		return
	}

	// Cheap, READ-ONLY early exit for the common case: this scan already
	// normalized, and most terminal results reaching this point are a
	// redelivery of one that already fired it. NormalizeTriggerID must never
	// claim on its own — see its doc comment — or this stops being a safe
	// probe.
	if existing, err := o.store.NormalizeTriggerID(ctx, result.TenantID, result.ScanID, family); err != nil {
		o.log.Warn("could not check whether normalize already fired",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	} else if existing != "" {
		return
	}

	newID, err := uuid.NewV7()
	if err != nil {
		o.log.Error("could not generate a normalize trigger id",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	}

	trigger, err := o.buildNormalizeTrigger(ctx, scan, latest, newID.String(), family)
	if err != nil {
		o.log.Error("could not assemble the normalize trigger",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	}
	if err := trigger.Validate(); err != nil {
		o.log.Error("refusing to publish an invalid normalize trigger",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	}

	payload, err := json.Marshal(trigger)
	if err != nil {
		o.log.Error("could not encode the normalize trigger",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	}
	// trigger_id as the dedup key: a crash or redelivery between here and the
	// claim below republishes the same id, and JetStream drops the duplicate.
	if err := o.bus.Publish(ctx, trigger.Subject(), trigger.TriggerID, payload); err != nil {
		o.log.Error("could not publish the normalize trigger; a future terminal "+
			"result for this scan will retry from scratch",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	}

	if _, fired, err := o.store.MarkNormalizeTriggered(
		ctx, result.TenantID, result.ScanID, family, trigger.TriggerID,
	); err != nil {
		o.log.Error("published the normalize trigger but could not record the claim; "+
			"a future terminal result will publish a harmless duplicate",
			"scan_id", result.ScanID, "cause", err.Error())
		return
	} else if !fired {
		o.log.Info("a concurrent call already claimed this trigger; the publish "+
			"just performed is a harmless duplicate",
			"scan_id", result.ScanID)
		return
	}

	o.log.Info("published a normalize trigger",
		"scan_id", result.ScanID, "family", family, "engines", len(trigger.Engines))
}

// familyTerminal reports whether every engine the registry places in family
// has reached a terminal state, among a scan's LATEST attempt per engine.
//
// ⚠ SCOPED TO ENGINES ACTUALLY DISPATCHED FOR THIS FAMILY, not a hardcoded
// count — a scan requesting both sbom and cbom must not wait on cbom engines
// before normalizing sbom, and a git source never dispatches trivy-image at
// all, so there is nothing to wait on for it. Returns false if the family has
// no matching engine at all (nothing to normalize is not "ready").
func familyTerminal(latest map[string]EngineRun, registry *policy.Registry, family events.Family) bool {
	found := false
	for _, r := range latest {
		e, ok := registry.Get(r.EngineID)
		if !ok || !e.InFamily(family) {
			continue
		}
		found = true
		if r.Status == statusQueued || r.Status == "running" {
			return false
		}
	}
	return found
}

// latestRunsByEngine reduces a scan's engine runs — which may include
// several retry attempts per engine — to the one attempt that represents
// each engine, mirroring TerminalStatuses' SQL ordering exactly: prefer a
// non-failed attempt, then the highest attempt number
// (docs/02-CONTRACTS.md §4: "a retry that succeeds must not be outvoted by
// the attempt that failed before it"). Applied to rows already loaded by
// GetScan rather than a second query.
func latestRunsByEngine(runs []EngineRun) map[string]EngineRun {
	best := map[string]EngineRun{}
	for _, r := range runs {
		current, ok := best[r.EngineID]
		if !ok || betterAttempt(r, current) {
			best[r.EngineID] = r
		}
	}
	return best
}

func betterAttempt(candidate, current EngineRun) bool {
	candidateFailed := candidate.Status == events.StatusFailed
	currentFailed := current.Status == events.StatusFailed
	if candidateFailed != currentFailed {
		return !candidateFailed
	}
	return candidate.Attempt > current.Attempt
}

// buildNormalizeTrigger assembles the self-contained envelope described in
// docs/02-CONTRACTS.md §6a — every artifact URI and engine status the
// consumer needs, so it never has to query scan.* itself.
func (o *Orchestrator) buildNormalizeTrigger(
	ctx context.Context, scan Scan, latest map[string]EngineRun, triggerID string, family events.Family,
) (events.NormalizeTriggerV1, error) {
	var engineIDs []string
	for id := range latest {
		if e, ok := o.registry.Get(id); ok && e.InFamily(family) {
			engineIDs = append(engineIDs, id)
		}
	}
	// Sorted for a deterministic envelope — latest is a map, and iteration
	// order would otherwise leak into the published trigger's engines list.
	sort.Strings(engineIDs)

	artifactsByEngine, err := o.store.LoadRawArtifactsForEngines(ctx, scan.TenantID, scan.ID, engineIDs)
	if err != nil {
		return events.NormalizeTriggerV1{}, fmt.Errorf("loading raw artifacts: %w", err)
	}

	gaps, err := o.store.CoverageGaps(ctx, scan.TenantID, scan.ID)
	if err != nil {
		return events.NormalizeTriggerV1{}, fmt.Errorf("loading coverage gaps: %w", err)
	}

	engines := make([]events.NormalizeEngineArtifact, 0, len(engineIDs))
	for _, id := range engineIDs {
		r := latest[id]
		engines = append(engines, events.NormalizeEngineArtifact{
			EngineID:          r.EngineID,
			EngineVersion:     r.EngineVersion,
			EngineDBVersion:   r.EngineDBVersion,
			Status:            r.Status,
			Artifacts:         artifactsByEngine[r.EngineID],
			EcosystemsCovered: r.EcosystemsCovered,
		})
	}

	return events.NormalizeTriggerV1{
		SchemaVersion:           events.SchemaNormalizeTriggerV1,
		TriggerID:               triggerID,
		ScanID:                  scan.ID,
		TenantID:                scan.TenantID,
		ProjectID:               scan.ProjectID,
		Family:                  family,
		NormalizationVersion:    1,
		SourceCommitSHA:         scan.CommitSHA,
		WorkspaceArchiveSHA256:  scan.ArchiveSHA256,
		EcosystemsWithoutEngine: gaps,
		IssuedAt:                o.now().UTC(),
		Engines:                 engines,
	}, nil
}
