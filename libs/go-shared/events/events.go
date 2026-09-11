// Package events defines the three envelopes that cross process boundaries.
//
// These are the Go implementation of docs/02-CONTRACTS.md §4–§6, which is the
// SSOT. If the two disagree, the document is right and this is a bug.
//
// THREE RULES SHAPE EVERY TYPE HERE:
//
//  1. ScanJobV1 HAS NO CREDENTIAL FIELD, and never will (ADR-0008). Engine
//     containers receive an archive and nothing else, so compromising a scanner
//     yields the code it was already scanning. If you find yourself needing to
//     add one, route the work through the fetcher instead.
//
//  2. UNKNOWN FIELDS ARE IGNORED, NOT FATAL. A newer publisher must be able to
//     add a field without breaking every older consumer — otherwise the schema
//     can never be evolved without a synchronised deploy of thirteen services.
//
//  3. EVENTS ARE ADVISORY. The database is the source of truth. No event is
//     ever required for correctness; progress logic that depends on receiving
//     every event is a bug (docs/02-CONTRACTS.md §2).
package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema versions. Embedded in every envelope so a consumer can tell what it is
// holding without guessing from shape.
const (
	SchemaScanJobV1    = "scan.job/v1"
	SchemaScanEventV1  = "scan.event/v1"
	SchemaScanResultV1 = "scan.result/v1"
)

// Family is a BOM family, and also the NATS subject suffix.
type Family string

const (
	// FamilyFetch is the source-materialization job that runs before any
	// engine (ADR-0008). It is a family so it gets its own stream subject,
	// consumer and retry budget — a clone failing is not an engine failing.
	FamilyFetch Family = "fetch"
	FamilySBOM  Family = "sbom"
	FamilyCBOM  Family = "cbom"
	FamilyQBOM  Family = "qbom"
	FamilyAIBOM Family = "aibom"
	FamilyHBOM  Family = "hbom"

	// FamilyWebrecon is FamilyFetch's sibling for a url-sourced scan
	// (SourceURL): subdomain discovery plus JS-library fingerprinting, run by
	// services/webrecon rather than the fetcher (05-SECURITY-MODEL.md — a
	// different risk shape, auto-discovering hosts the tenant never named,
	// not just a clone of the one remote they connected). Like fetch, it
	// PRODUCES the input the sbom family consumes rather than requiring one,
	// so it gets its own stream subject, consumer and retry budget.
	FamilyWebrecon Family = "webrecon"
)

// AllFamilies returns every family, in pipeline order.
func AllFamilies() []Family {
	return []Family{FamilyFetch, FamilyWebrecon, FamilySBOM, FamilyCBOM, FamilyQBOM, FamilyAIBOM, FamilyHBOM}
}

// Valid reports whether f is a known family.
func (f Family) Valid() bool {
	for _, x := range AllFamilies() {
		if x == f {
			return true
		}
	}
	return false
}

func (f Family) String() string { return string(f) }

// SourceKind is where a scan's input comes from.
type SourceKind string

const (
	SourceGit    SourceKind = "git"
	SourceUpload SourceKind = "upload"
	SourceImage  SourceKind = "image"
	// SourceURL is a project registered from a live link rather than a
	// repository connection, an upload, or an image reference — its source
	// lives in project.web_sources. Introduced in Milestone 4 of the project-
	// registration plan; Milestone 5's services/webrecon is what actually
	// discovers and fingerprints anything beyond the one submitted page.
	SourceURL SourceKind = "url"
)

// ---------------------------------------------------------------------------
// ScanJobV1
// ---------------------------------------------------------------------------

// ScanJobV1 is one unit of work: ONE ENGINE against ONE archive.
//
// One engine per job (ADR-0004) is what makes retry, timeout and partial
// failure per-engine rather than all-or-nothing. The alternative — one job per
// family — means re-running syft because dependency-check timed out, and
// dependency-check's first NVD sync takes 30–60 minutes.
type ScanJobV1 struct {
	SchemaVersion string `json:"schema_version"`

	// JobID is BOTH the idempotency key AND a path segment in the output
	// prefix. That double duty is deliberate: a retry writes to a new prefix,
	// so it can never overwrite a prior attempt's artifacts.
	JobID    string `json:"job_id"`
	ScanID   string `json:"scan_id"`
	TenantID string `json:"tenant_id"`
	// ProjectID is denormalized here so a worker never has to query the
	// project service — a cross-service call in the job path would make every
	// scan depend on that service being up.
	ProjectID string `json:"project_id"`

	Family Family `json:"family"`
	// Engine is EXACTLY ONE engine id. Not a list.
	Engine                  string `json:"engine"`
	EngineVersionConstraint string `json:"engine_version_constraint,omitempty"`

	Attempt    int       `json:"attempt"`
	IssuedAt   time.Time `json:"issued_at"`
	DeadlineAt time.Time `json:"deadline_at"`

	Workspace  Workspace  `json:"workspace"`
	SourceMeta SourceMeta `json:"source_meta"`

	// EngineConfig is validated against the engine's JSON Schema AT ENQUEUE,
	// not at worker time. A config error discovered by a worker has already
	// cost a container start and a queue round trip.
	EngineConfig map[string]any `json:"engine_config,omitempty"`

	Limits JobLimits `json:"limits"`
	Output OutputRef `json:"output"`
	Trace  TraceCtx  `json:"trace"`
}

// Workspace points at the content-addressed source archive every engine reads.
type Workspace struct {
	ArtifactURI string `json:"artifact_uri"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	RootSubpath string `json:"root_subpath,omitempty"`

	// NativeSBOMRef points at a native document a producer (fetch or webrecon)
	// staged instead of — or alongside — the source archive: a GitHub
	// repository's own CI-published Dependency Graph SBOM (role
	// "native_output", engine_id "fetcher"), or a url source's discovery +
	// JS-fingerprint result (role "native_output", engine_id "webrecon"). Set
	// by the orchestrator's FanOut only on the one job that consumes it
	// (policy.Engine.ConsumesNativeSBOM); empty on every other engine's job,
	// including every other SBOM engine's. For a git/upload-sourced scan,
	// ArtifactURI still carries the real source archive alongside this. For a
	// url-sourced scan there is no source archive at all — see Validate.
	NativeSBOMRef string `json:"native_sbom_ref,omitempty"`
}

// SourceMeta describes what was materialized.
type SourceMeta struct {
	Kind SourceKind `json:"kind"`
	// CommitSHA is pinned by the fetcher and written exactly once per scan.
	// Every engine in a scan sees the same value, which is what stops a report
	// describing a codebase that never existed.
	CommitSHA   string `json:"commit_sha,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
}

// JobLimits are the sandbox quotas for this job.
type JobLimits struct {
	WallClockSec   int   `json:"wall_clock_sec"`
	CPUMillis      int   `json:"cpu_millis"`
	MemoryMB       int   `json:"memory_mb"`
	DiskMB         int   `json:"disk_mb"`
	PIDsMax        int   `json:"pids_max"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
}

// OutputRef is where a worker writes its artifacts.
type OutputRef struct {
	// Prefix embeds job_id, so attempt 2 cannot overwrite attempt 1.
	Prefix string `json:"prefix"`
}

// TraceCtx carries distributed-tracing context across the queue.
type TraceCtx struct {
	TraceParent   string `json:"traceparent,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// Subject returns the NATS subject this job publishes to.
func (j ScanJobV1) Subject() string { return "scan.job." + string(j.Family) }

// ManifestKey is the object a worker HEADs first for idempotency.
//
// ⚠ A WORKER'S FIRST ACTION IS TO CHECK THIS. Present and complete means the
// work was already done — re-emit the stored result, ack, exit. That is what
// makes redelivery safe, and redelivery WILL happen: ack_wait is 30 minutes and
// a worker can die at any point.
func (j ScanJobV1) ManifestKey() string {
	return strings.TrimRight(j.Output.Prefix, "/") + "/manifest.json"
}

// Validate checks the invariants a job must satisfy before it is published.
//
// Publishing an invalid job is worse than rejecting it: it consumes a queue
// slot, starts a container, and fails somewhere less legible.
func (j ScanJobV1) Validate() error {
	var problems []string

	if j.SchemaVersion != SchemaScanJobV1 {
		problems = append(problems, fmt.Sprintf("schema_version = %q, want %q",
			j.SchemaVersion, SchemaScanJobV1))
	}
	for name, v := range map[string]string{
		"job_id": j.JobID, "scan_id": j.ScanID,
		"tenant_id": j.TenantID, "project_id": j.ProjectID,
	} {
		if v == "" {
			problems = append(problems, name+" is empty")
		}
	}
	if !j.Family.Valid() {
		problems = append(problems, fmt.Sprintf("unknown family %q", j.Family))
	}
	if j.Engine == "" {
		problems = append(problems, "engine is empty — one engine per job (ADR-0004)")
	}
	if j.Attempt < 1 {
		problems = append(problems, "attempt must be >= 1")
	}
	if j.DeadlineAt.IsZero() {
		problems = append(problems, "deadline_at is unset, so the reaper can never time this job out")
	}
	if j.Output.Prefix == "" {
		problems = append(problems, "output.prefix is empty")
	} else if !strings.Contains(j.Output.Prefix, j.JobID) {
		// Without job_id in the prefix, a retry overwrites the previous
		// attempt's artifacts and the evidence of what happened is gone.
		problems = append(problems, "output.prefix must contain job_id, or a retry overwrites prior artifacts")
	}
	// Fetch and webrecon are what PRODUCE a scan's input, so they are the two
	// jobs that legitimately start with neither a source archive nor a native
	// document. Every other job must have been handed SOMETHING to read —
	// but which field depends on the source: a git/upload-sourced job gets
	// ArtifactURI; a url-sourced job (no source archive exists) gets
	// NativeSBOMRef instead. See Workspace.NativeSBOMRef.
	if j.Family != FamilyFetch && j.Family != FamilyWebrecon &&
		j.Workspace.ArtifactURI == "" && j.Workspace.NativeSBOMRef == "" {
		problems = append(problems,
			"workspace has neither artifact_uri nor native_sbom_ref, for a job that is not a producer family")
	}
	if err := j.assertNoCredential(); err != nil {
		problems = append(problems, err.Error())
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid ScanJobV1: %s", strings.Join(problems, "; "))
	}
	return nil
}

// credentialKeys are config keys that must never appear in a job.
var credentialKeys = []string{
	"token", "secret", "password", "credential", "apikey", "api_key",
	"auth", "private_key", "cookie", "session",
}

// assertNoCredential enforces ADR-0008 at the envelope layer.
//
// The type has no credential FIELD, so this catches the other route in:
// somebody stuffing one into engine_config, where it would be JSON and would
// look like ordinary configuration.
func (j ScanJobV1) assertNoCredential() error {
	for k := range j.EngineConfig {
		lower := strings.ToLower(k)
		for _, needle := range credentialKeys {
			if strings.Contains(lower, needle) {
				return fmt.Errorf("engine_config contains %q: ScanJobV1 carries no credentials "+
					"(ADR-0008); route credential-bearing work through the fetcher", k)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ScanEventV1
// ---------------------------------------------------------------------------

// Phase is where a job has reached.
type Phase string

const (
	PhaseQueued    Phase = "queued"
	PhaseFetching  Phase = "fetching"
	PhasePreparing Phase = "preparing"
	PhaseRunning   Phase = "running"
	PhaseParsing   Phase = "parsing"
	PhaseUploading Phase = "uploading"
	PhaseDone      Phase = "done"
	PhaseFailed    Phase = "failed"
)

// AllPhases returns every phase in pipeline order.
func AllPhases() []Phase {
	return []Phase{PhaseQueued, PhaseFetching, PhasePreparing, PhaseRunning,
		PhaseParsing, PhaseUploading, PhaseDone, PhaseFailed}
}

// Terminal reports whether no further event is expected for a job.
func (p Phase) Terminal() bool { return p == PhaseDone || p == PhaseFailed }

// MaxEventMessage bounds the human-readable message, in BYTES.
//
// Bytes rather than runes because that is what a database column, a NATS
// payload and a log line are measured in — and because a "200 character" limit
// enforced with len() is a byte limit whether or not it says so.
const MaxEventMessage = 200

// ellipsis marks a truncated message. Three bytes; see Sanitize.
const ellipsis = "…"

// ScanEventV1 is a progress event.
//
// ⚠ ADVISORY AND LOSSY-TOLERANT. The database is the source of truth. If the
// WebSocket drops or an event is lost, a page refresh reads Postgres and is
// correct — that is what makes a lossy stream acceptable.
type ScanEventV1 struct {
	SchemaVersion string `json:"schema_version"`

	EventID  string `json:"event_id"`
	ScanID   string `json:"scan_id"`
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
	Engine   string `json:"engine,omitempty"`

	// Seq is monotonic PER job_id, so a consumer can reorder and can DETECT a
	// gap. Detecting a gap matters more than filling it: the client can refetch
	// state rather than render something subtly wrong.
	Seq int64     `json:"seq"`
	TS  time.Time `json:"ts"`

	Phase Phase `json:"phase"`
	Pct   int   `json:"pct"`

	// Message is shown to humans and is bounded.
	//
	// ⚠ IT NEVER CONTAINS A USER PATH, A REPOSITORY URL, OR ANYTHING FROM THE
	// SCANNED CODE. Event streams reach browsers and logs; treat them as
	// public. Sanitize enforces this.
	Message string `json:"message,omitempty"`

	Metrics map[string]int64 `json:"metrics,omitempty"`
}

// Subject returns the NATS subject this event publishes to.
func (e ScanEventV1) Subject() string { return "scan.event." + e.ScanID }

// Sanitize bounds and cleans the message before publication.
//
// Applied at PUBLISH time rather than trusting callers: a message is assembled
// from scanner output somewhere in the codebase, and "remember not to include
// the path" is exactly the rule that survives three call sites and fails on the
// fourth.
func (e *ScanEventV1) Sanitize() {
	m := e.Message

	// Newlines forge log lines and break single-line log formats.
	m = strings.ReplaceAll(m, "\n", " ")
	m = strings.ReplaceAll(m, "\r", " ")
	m = strings.ReplaceAll(m, "\x00", "")

	// ⚠ THE ELLIPSIS IS THREE BYTES, NOT ONE.
	//
	// `m[:Max-1] + "…"` produces a 202-byte string against a 200-byte limit,
	// because len() counts BYTES and "…" is U+2026 encoded as three of them.
	// Reserve room for it, then back off to a rune boundary — cutting mid-rune
	// yields invalid UTF-8, which Postgres refuses outright on a text column.
	if len(m) > MaxEventMessage {
		cut := m[:MaxEventMessage-len(ellipsis)]
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
		m = cut + ellipsis
	}
	e.Message = strings.TrimSpace(m)

	// ⚠ THE METRIC KEYS GO THROUGH THE SAME GATE AS THE MESSAGE. They reach a
	// browser on the same frame, and a key built from a filename would put a
	// path into the stream through the one field nobody thought to check.
	e.Metrics, _ = SanitizeDiscoveries(e.Metrics)

	if e.Pct < 0 {
		e.Pct = 0
	}
	if e.Pct > 100 {
		e.Pct = 100
	}
}

// : The only characters a discovery key may contain.
//
// ⚠ THE KEYS REACH A BROWSER, AND A KEY IS AS MUCH OF A STRING AS A MESSAGE IS.
// An engine that built a key from a filename would put a path into the event
// stream through the one field nobody thought to check — Message has been
// guarded since Phase 6 and this would have walked straight past it.
const discoveryKeyChars = "abcdefghijklmnopqrstuvwxyz0123456789_."

// : How many distinct discovery keys one result may carry.
//
// An engine emitting a key per FINDING rather than per KIND turns an advisory
// event into an unbounded payload; the cap makes that a truncation with a
// stated cause rather than a browser hanging on a 40MB frame.
const MaxDiscoveryKeys = 32

// SanitizeDiscoveries drops any key that is not a plain lowercase identifier.
//
// Returns the cleaned map and how many keys were dropped, so a caller can say
// so rather than silently publishing fewer numbers than an engine reported.
func SanitizeDiscoveries(in map[string]int64) (map[string]int64, int) {
	if len(in) == 0 {
		return nil, 0
	}
	// ⚠ SORTED, BECAUSE THE CAP TRUNCATES AND MAP ORDER IS RANDOMISED. Without
	// this, publishing the same result twice would keep a different 32 keys
	// each time, and a live feed that disagrees with itself on a replay is
	// worse than one that shows fewer numbers.
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	out := make(map[string]int64, len(in))
	dropped := 0
	for _, key := range keys {
		value := in[key]
		if key == "" || value < 0 || strings.ContainsFunc(key, func(r rune) bool {
			return !strings.ContainsRune(discoveryKeyChars, r)
		}) {
			dropped++
			continue
		}
		// Counted AFTER validation: a rejected key must not consume a slot a
		// good one could have used.
		if len(out) >= MaxDiscoveryKeys {
			dropped++
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil, dropped
	}
	return out, dropped
}

// Validate checks an event before publication.
func (e ScanEventV1) Validate() error {
	var problems []string

	if e.SchemaVersion != SchemaScanEventV1 {
		problems = append(problems, fmt.Sprintf("schema_version = %q", e.SchemaVersion))
	}
	if e.ScanID == "" {
		problems = append(problems, "scan_id is empty")
	}
	if e.TenantID == "" {
		problems = append(problems, "tenant_id is empty")
	}
	if e.Seq < 0 {
		problems = append(problems, "seq must not be negative")
	}
	if e.Pct < 0 || e.Pct > 100 {
		problems = append(problems, fmt.Sprintf("pct = %d, want 0-100", e.Pct))
	}
	if len(e.Message) > MaxEventMessage {
		problems = append(problems, fmt.Sprintf("message is %d chars, limit %d",
			len(e.Message), MaxEventMessage))
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid ScanEventV1: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// ScanResultV1
// ---------------------------------------------------------------------------

// EngineStatus is the terminal state of one engine run.
type EngineStatus string

const (
	// StatusSucceeded means the engine covered everything it claims to.
	StatusSucceeded EngineStatus = "succeeded"

	// ⚠ StatusPartial IS A FIRST-CLASS STATUS, NOT AN ERROR.
	//
	// Grype covered 11 of 12 ecosystems because one lockfile was malformed.
	// That is useful output PLUS a known gap, and both must survive into the
	// report. Collapsing it to "failed" throws away real findings; collapsing
	// it to "succeeded" hides the gap — which is the failure mode this whole
	// product exists to avoid.
	StatusPartial EngineStatus = "partial"

	StatusFailed  EngineStatus = "failed"
	StatusTimeout EngineStatus = "timeout"

	// StatusUnavailable means the engine could not be resolved at runtime. It
	// NEVER fails the whole scan; it is recorded and reported.
	StatusUnavailable EngineStatus = "unavailable"

	// StatusSkipped means the engine was not applicable to this source.
	StatusSkipped EngineStatus = "skipped"
)

// Succeeded reports whether this status contributed usable output.
//
// `partial` counts, because it did produce components — that is the whole point
// of it being a distinct status.
func (s EngineStatus) Succeeded() bool {
	return s == StatusSucceeded || s == StatusPartial
}

// Valid reports whether s is a known status.
func (s EngineStatus) Valid() bool {
	switch s {
	case StatusSucceeded, StatusPartial, StatusFailed,
		StatusTimeout, StatusUnavailable, StatusSkipped:
		return true
	}
	return false
}

// ScanResultV1 is what an engine produced.
type ScanResultV1 struct {
	SchemaVersion string `json:"schema_version"`

	JobID    string `json:"job_id"`
	ScanID   string `json:"scan_id"`
	TenantID string `json:"tenant_id"`

	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version"`

	// EngineDBVersion is REQUIRED for vulnerability engines.
	//
	// Without it a finding cannot be dated, and a compliance report that cannot
	// say "matched against vulnerability data as of X" is not defensible. See
	// Validate, which enforces it.
	EngineDBVersion string `json:"engine_db_version,omitempty"`

	// SourceMeta is what the FETCHER pinned: the exact commit it materialized.
	//
	// It exists because the orchestrator previously read the commit sha out of
	// EngineDBVersion — a field documented as the vulnerability-database
	// vintage. That overload worked, and it made both fields dishonest: a fetch
	// result claimed a database version it had never consulted, and the commit
	// sha lived somewhere nobody would look for it.
	//
	// Optional, so every existing engine result is unaffected. Only the fetch
	// family populates it.
	SourceMeta *SourceMeta `json:"source_meta,omitempty"`

	Invocation Invocation   `json:"invocation"`
	Status     EngineStatus `json:"status"`

	Artifacts []Artifact `json:"artifacts,omitempty"`

	// EcosystemsCovered is what this engine actually looked at. It feeds the
	// mandatory Engine Coverage report section — the honest denominator.
	EcosystemsCovered []string `json:"ecosystems_covered,omitempty"`

	// EcosystemsUncovered is what this engine SAW in the source and could not
	// read — Go code handed to engines that read Java and JavaScript. Each is
	// recorded as an engine_available=false row in scan.ecosystems_detected,
	// and is a gap in Engine Coverage unless another engine in the same scan
	// covered it (Store.CoverageGaps). Optional: an engine that cannot tell
	// leaves it empty, and every existing result is unaffected.
	EcosystemsUncovered []string `json:"ecosystems_uncovered,omitempty"`

	Summary     Summary      `json:"summary"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`

	// Discoveries are FINER-GRAINED counts than Summary's four dimensions, keyed
	// by what was found.
	//
	// ⚠ IT DOES NOT DUPLICATE Summary, AND THE DIFFERENCE IS THE POINT. Summary
	// carries the four dimensions docs/02-CONTRACTS.md §6 defines for every BOM
	// type — `components`, `vulnerabilities`, `licenses`, `crypto_assets` — and
	// an AIBOM engine's models, prompts and vector stores all fold into
	// `components` there, deliberately (see summary._DIMENSION_OF). That is the
	// right answer for a headline figure a reader compares across engines, and
	// it is useless for a live feed: "11 components" says nothing a customer
	// watching a scan wants to know, where "2 vector stores, 2 prompts, 1 RAG
	// pipeline" says exactly it.
	//
	// ⚠ OPTIONAL, AND OMITTED RATHER THAN ZEROED. An engine that counts nothing
	// finer than the four dimensions leaves this nil — the same nil-is-not-zero
	// discipline Summary's pointer fields carry. A zero here would claim the
	// engine looked for prompts and found none.
	//
	// ⚠ COUNTS ONLY. These reach a browser through the advisory event stream, so
	// they are held to the same rule as ScanEventV1.Message: never a path, a URL
	// or anything from the scanned code. `SanitizeDiscoveries` enforces the key
	// shape; the values are integers and cannot carry content.
	Discoveries map[string]int64 `json:"discoveries,omitempty"`

	Error *ResultError `json:"error,omitempty"`
}

// Invocation records exactly what ran, for provenance.
type Invocation struct {
	// ArgvRedacted is the command with any credential removed. It appears in
	// the provenance manifest, so it must be safe to publish.
	ArgvRedacted []string  `json:"argv_redacted"`
	ImageDigest  string    `json:"image_digest,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	DurationMS   int64     `json:"duration_ms"`
	ExitCode     int       `json:"exit_code"`
}

// Artifact is one stored output file.
type Artifact struct {
	Role      string `json:"role"`
	URI       string `json:"uri"`
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// Summary is the headline count from one engine.
//
// ⚠ EVERY FIELD IS A POINTER, AND nil IS NOT ZERO.
//
//	nil  this engine does not measure this dimension
//	0    it measured, and there were none
//
// The distinction is not pedantry. syft catalogues components and never looks
// for vulnerabilities; grype matches vulnerabilities and never catalogues
// licences. Rendering either as `0` asserts a fact the engine never
// established — "grype found 0 licences" reads as a clean result and is really
// a question grype was never asked. That is the same failure this codebase
// refuses everywhere else: an unknown presented as a measured zero (CLAUDE.md
// invariant 3), and an ecosystem silently omitted rather than declared unseen
// (invariant 12).
//
// Which dimensions an engine measures is declared once, in the manifest's
// `produces` list, and the workers derive the summary from it.
//
// Fields are NOT omitempty: an explicit null says "not measured", where an
// absent key says only that something is old. `not-provided` is reported,
// never silently dropped.
type Summary struct {
	Components      *int `json:"components"`
	Vulnerabilities *int `json:"vulnerabilities"`
	Licenses        *int `json:"licenses"`
	CryptoAssets    *int `json:"crypto_assets"`
}

// Count boxes a measured count, so a call site can say what it means.
//
//	Summary{Components: events.Count(0)}   measured, none found
//	Summary{}                              nothing measured
func Count(n int) *int { return &n }

// Measured reports whether any dimension was measured at all.
//
// An engine that produced output and measured nothing is reporting an envelope
// that says nothing about what it found, which is how a report understates a
// scan without anything looking wrong.
func (s Summary) Measured() bool {
	return s.Components != nil || s.Vulnerabilities != nil ||
		s.Licenses != nil || s.CryptoAssets != nil
}

// Diagnostic is a non-fatal problem worth surfacing.
//
// These are how `partial` explains itself: "pom.xml at services/api failed to
// parse" is what turns a bare status into something a user can act on.
type Diagnostic struct {
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
}

// ResultError describes a terminal failure.
type ResultError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Retryable tells the orchestrator whether to nak or ack.
	//
	// Getting this wrong is expensive in both directions: a retryable error
	// acked loses work, and a permanent error naked burns four delivery
	// attempts and 10 minutes of backoff before failing anyway.
	Retryable bool `json:"retryable"`
}

// Subject returns the NATS subject this result publishes to.
func (r ScanResultV1) Subject(family Family) string {
	return "scan.result." + string(family)
}

// vulnerabilityEngines produce findings and therefore REQUIRE a dated database.
var vulnerabilityEngines = map[string]bool{
	"grype": true, "trivy-fs": true, "trivy-image": true,
	"osv-scanner": true, "dependency-check": true,
}

// Validate checks a result before it is accepted.
func (r ScanResultV1) Validate() error {
	var problems []string

	if r.SchemaVersion != SchemaScanResultV1 {
		problems = append(problems, fmt.Sprintf("schema_version = %q", r.SchemaVersion))
	}
	for name, v := range map[string]string{
		"job_id": r.JobID, "scan_id": r.ScanID, "tenant_id": r.TenantID, "engine": r.Engine,
	} {
		if v == "" {
			problems = append(problems, name+" is empty")
		}
	}
	if !r.Status.Valid() {
		problems = append(problems, fmt.Sprintf("unknown status %q", r.Status))
	}

	// ⚠ A vulnerability finding that cannot be dated is not defensible.
	if vulnerabilityEngines[r.Engine] && r.Status.Succeeded() && r.EngineDBVersion == "" {
		problems = append(problems, fmt.Sprintf(
			"engine_db_version is required for the vulnerability engine %q: without it a "+
				"finding cannot be dated, and a report that cannot say "+
				"'matched against vulnerability data as of X' is not defensible", r.Engine))
	}

	// A failure must say why, or the UI can only offer "it failed".
	if r.Status == StatusFailed && r.Error == nil {
		problems = append(problems, "status is failed but error is nil")
	}

	for i, a := range r.Artifacts {
		if a.SHA256 == "" {
			problems = append(problems, fmt.Sprintf("artifact %d has no sha256", i))
		}
		if a.URI == "" {
			problems = append(problems, fmt.Sprintf("artifact %d has no uri", i))
		}
	}

	// A negative count is a parser that subtracted, not a measurement. Caught
	// here because it would otherwise reach a report as a plausible-looking
	// number and be believed.
	for name, v := range map[string]*int{
		"components": r.Summary.Components, "vulnerabilities": r.Summary.Vulnerabilities,
		"licenses": r.Summary.Licenses, "crypto_assets": r.Summary.CryptoAssets,
	} {
		if v != nil && *v < 0 {
			problems = append(problems, fmt.Sprintf("summary.%s is %d", name, *v))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid ScanResultV1: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scan status derivation
// ---------------------------------------------------------------------------

// ScanStatus is the aggregate state of a scan.
type ScanStatus string

const (
	ScanQueued              ScanStatus = "queued"
	ScanFetching            ScanStatus = "fetching"
	ScanRunning             ScanStatus = "running"
	ScanNormalizing         ScanStatus = "normalizing"
	ScanCompleted           ScanStatus = "completed"
	ScanCompletedWithErrors ScanStatus = "completed_with_errors"
	ScanFailed              ScanStatus = "failed"
	ScanCancelled           ScanStatus = "cancelled"
)

// DeriveScanStatus computes a scan's status from its engine runs.
//
// ⚠ MECHANICAL, NEVER HAND-SET (docs/02-CONTRACTS.md §6).
//
//	all succeeded            -> completed
//	>=1 succeeded and >=1 not -> completed_with_errors
//	zero succeeded            -> failed
//
// `partial` counts as succeeded for the first column and as "not succeeded" for
// the second — which is exactly right, and is why a scan where every engine
// returned partial is `completed_with_errors` rather than `completed`. The
// engines produced usable output AND had gaps, and the status has to say both.
func DeriveScanStatus(statuses []EngineStatus) ScanStatus {
	if len(statuses) == 0 {
		// No engine runs at all. Not "completed" — there is nothing to have
		// completed, and reporting success for an empty scan is the kind of
		// vacuous truth that produces an empty BOM somebody trusts.
		return ScanFailed
	}

	var succeeded, clean int
	for _, s := range statuses {
		if s.Succeeded() {
			succeeded++
		}
		if s == StatusSucceeded {
			clean++
		}
	}

	switch {
	case clean == len(statuses):
		return ScanCompleted
	case succeeded > 0:
		return ScanCompletedWithErrors
	default:
		return ScanFailed
	}
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// ErrUnknownSchema is returned when an envelope's schema_version is not one we
// understand.
var ErrUnknownSchema = errors.New("unknown schema version")

// Decode unmarshals an envelope.
//
// ⚠ UNKNOWN FIELDS ARE IGNORED, DELIBERATELY.
//
// This is the opposite of the HTTP handlers, which use DisallowUnknownFields —
// and the difference is the point. A typo'd field in a user's API request is a
// mistake to report. An unrecognized field in a queue message is a NEWER
// PUBLISHER, and rejecting it means the schema can never gain a field without a
// synchronised deploy of every consumer.
func Decode[T any](data []byte, into *T) error {
	// Plain Unmarshal: no DisallowUnknownFields.
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	return nil
}

// PeekSchema reads just the schema_version, so a consumer can route before
// committing to a type.
func PeekSchema(data []byte) (string, error) {
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("peek schema: %w", err)
	}
	if probe.SchemaVersion == "" {
		return "", ErrUnknownSchema
	}
	return probe.SchemaVersion, nil
}
