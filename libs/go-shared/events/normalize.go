package events

import (
	"fmt"
	"strings"
	"time"
)

// SchemaNormalizeTriggerV1 identifies the envelope below. See
// docs/02-CONTRACTS.md §6a, which is the SSOT.
const SchemaNormalizeTriggerV1 = "scan.normalize/v1"

// NormalizeTriggerV1 fires once every engine dispatched for one (scan,
// family) reaches a terminal state.
//
// ⚠ NOT A ScanJobV1 IN DISGUISE. There is no engine to run here — only a
// normalization pass to trigger — so this is a genuinely separate envelope
// on its own subject and its own stream (NORMALIZE_JOBS, not SCAN_JOBS),
// rather than a job with an empty Engine field.
//
// ⚠ SELF-CONTAINED, DELIBERATELY. Every artifact URI and engine status the
// consumer needs travels in this envelope, so the normalize consumer never
// queries scan.* — the one credential it holds is scoped to the normalize
// schema only (docs/02-CONTRACTS.md §6a).
type NormalizeTriggerV1 struct {
	SchemaVersion string `json:"schema_version"`

	// TriggerID is the scan.normalize_triggers row's id, and also the
	// Nats-Msg-Id dedup key — a redelivered publish of the same trigger must
	// not cause a second normalization attempt to even be considered.
	TriggerID string `json:"trigger_id"`
	ScanID    string `json:"scan_id"`
	TenantID  string `json:"tenant_id"`
	ProjectID string `json:"project_id"`

	Family                 Family `json:"family"`
	NormalizationVersion   int    `json:"normalization_version"`
	SourceCommitSHA        string `json:"source_commit_sha,omitempty"`
	WorkspaceArchiveSHA256 string `json:"workspace_archive_sha256,omitempty"`

	// EcosystemsWithoutEngine is CoverageGaps' output at trigger time — the
	// honest denominator (CLAUDE.md invariant 12), carried through so the
	// normalize consumer's provenance manifest matches what the orchestrator
	// already knew rather than re-deriving it from a query it does not have
	// the credential to make.
	EcosystemsWithoutEngine []string `json:"ecosystems_without_engine,omitempty"`

	IssuedAt time.Time `json:"issued_at"`

	Engines []NormalizeEngineArtifact `json:"engines"`
}

// NormalizeEngineArtifact is one engine's contribution to the trigger — just
// enough for the consumer to load its raw artifact and record its status in
// the provenance manifest, without a second query back to scan.*.
type NormalizeEngineArtifact struct {
	EngineID          string       `json:"engine_id"`
	EngineVersion     string       `json:"engine_version,omitempty"`
	EngineDBVersion   string       `json:"engine_db_version,omitempty"`
	Status            EngineStatus `json:"status"`
	Artifacts         []Artifact   `json:"artifacts,omitempty"`
	EcosystemsCovered []string     `json:"ecosystems_covered,omitempty"`
}

// Subject returns the NATS subject this trigger publishes to.
func (t NormalizeTriggerV1) Subject() string { return "scan.normalize." + string(t.Family) }

// Validate checks the invariants a trigger must satisfy before it is
// published — the same "reject before it costs a queue slot" discipline
// ScanJobV1.Validate follows.
func (t NormalizeTriggerV1) Validate() error {
	var problems []string

	if t.SchemaVersion != SchemaNormalizeTriggerV1 {
		problems = append(problems, fmt.Sprintf("schema_version = %q, want %q",
			t.SchemaVersion, SchemaNormalizeTriggerV1))
	}
	for name, v := range map[string]string{
		"trigger_id": t.TriggerID, "scan_id": t.ScanID,
		"tenant_id": t.TenantID, "project_id": t.ProjectID,
	} {
		if v == "" {
			problems = append(problems, name+" is empty")
		}
	}
	if !t.Family.Valid() {
		problems = append(problems, fmt.Sprintf("unknown family %q", t.Family))
	}
	if t.NormalizationVersion < 1 {
		problems = append(problems, "normalization_version must be >= 1")
	}
	if t.IssuedAt.IsZero() {
		problems = append(problems, "issued_at is unset")
	}
	if len(t.Engines) == 0 {
		problems = append(problems, "engines is empty — a trigger with nothing to normalize should not have been published")
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid NormalizeTriggerV1: %s", strings.Join(problems, "; "))
	}
	return nil
}
