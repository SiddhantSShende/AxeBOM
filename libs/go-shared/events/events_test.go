package events_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/events"
)

// ---------------------------------------------------------------------------
// Scan status derivation
// ---------------------------------------------------------------------------

// ⚠ THE TABLE FROM docs/02-CONTRACTS.md §6, ASSERTED DIRECTLY.
//
// Status is MECHANICAL and never hand-set. A hand-set status is how a scan with
// a failed engine comes to report success — and that success is printed in a
// compliance document.
func TestDeriveScanStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses []events.EngineStatus
		want     events.ScanStatus
		why      string
	}{
		{
			name:     "all succeeded",
			statuses: []events.EngineStatus{events.StatusSucceeded, events.StatusSucceeded},
			want:     events.ScanCompleted,
		},
		{
			name:     "one failed among successes",
			statuses: []events.EngineStatus{events.StatusSucceeded, events.StatusFailed},
			want:     events.ScanCompletedWithErrors,
			why:      "usable output plus a known gap; both must survive into the report",
		},
		{
			name:     "all failed",
			statuses: []events.EngineStatus{events.StatusFailed, events.StatusFailed},
			want:     events.ScanFailed,
		},
		{
			// ⚠ THE CASE THAT CATCHES NAIVE IMPLEMENTATIONS.
			//
			// `partial` counts as succeeded (it produced components) AND as
			// not-clean (it had gaps). A scan where every engine returned
			// partial is completed_with_errors — not completed, because the
			// gaps are real, and not failed, because the output is real.
			name:     "all partial",
			statuses: []events.EngineStatus{events.StatusPartial, events.StatusPartial},
			want:     events.ScanCompletedWithErrors,
			why:      "partial produced output AND had gaps; the status must say both",
		},
		{
			name:     "single partial",
			statuses: []events.EngineStatus{events.StatusPartial},
			want:     events.ScanCompletedWithErrors,
		},
		{
			name:     "succeeded and partial",
			statuses: []events.EngineStatus{events.StatusSucceeded, events.StatusPartial},
			want:     events.ScanCompletedWithErrors,
		},
		{
			name:     "timeout among successes",
			statuses: []events.EngineStatus{events.StatusSucceeded, events.StatusTimeout},
			want:     events.ScanCompletedWithErrors,
		},
		{
			name:     "unavailable among successes",
			statuses: []events.EngineStatus{events.StatusSucceeded, events.StatusUnavailable},
			want:     events.ScanCompletedWithErrors,
			why:      "a missing engine never fails the whole scan; it is recorded",
		},
		{
			name:     "all unavailable",
			statuses: []events.EngineStatus{events.StatusUnavailable, events.StatusUnavailable},
			want:     events.ScanFailed,
			why:      "nothing scanned anything; reporting success would be vacuous",
		},
		{
			name:     "skipped only",
			statuses: []events.EngineStatus{events.StatusSkipped},
			want:     events.ScanFailed,
		},
		{
			// An empty scan is NOT completed. Reporting success for a scan with
			// no engine runs is the kind of vacuous truth that produces an empty
			// BOM somebody trusts.
			name:     "no runs at all",
			statuses: nil,
			want:     events.ScanFailed,
			why:      "there is nothing to have completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := events.DeriveScanStatus(tt.statuses)
			if got != tt.want {
				t.Errorf("got %q, want %q%s", got, tt.want, suffix(tt.why))
			}
		})
	}
}

func suffix(why string) string {
	if why == "" {
		return ""
	}
	return " — " + why
}

// `partial` counting as succeeded is the distinction the whole status model
// rests on: it produced real findings, and discarding them would be worse than
// the gap it reports.
func TestPartialCountsAsSucceeded(t *testing.T) {
	if !events.StatusPartial.Succeeded() {
		t.Error("partial does not count as succeeded; its findings would be discarded")
	}
	if !events.StatusSucceeded.Succeeded() {
		t.Error("succeeded does not count as succeeded")
	}
	for _, s := range []events.EngineStatus{
		events.StatusFailed, events.StatusTimeout,
		events.StatusUnavailable, events.StatusSkipped,
	} {
		if s.Succeeded() {
			t.Errorf("%s counts as succeeded", s)
		}
	}
}

// ---------------------------------------------------------------------------
// ScanJobV1
// ---------------------------------------------------------------------------

func validJob() events.ScanJobV1 {
	return events.ScanJobV1{
		SchemaVersion: events.SchemaScanJobV1,
		JobID:         "job-1", ScanID: "scan-1",
		TenantID: "tenant-1", ProjectID: "project-1",
		Family: events.FamilySBOM, Engine: "syft",
		Attempt:    1,
		IssuedAt:   time.Now().UTC(),
		DeadlineAt: time.Now().Add(15 * time.Minute).UTC(),
		Workspace:  events.Workspace{ArtifactURI: "s3://b/source.tar.zst", SHA256: "abc"},
		Output:     events.OutputRef{Prefix: "s3://b/scans/scan-1/raw/syft/job-1/"},
	}
}

// ⚠ ADR-0008 AT THE ENVELOPE LAYER.
//
// The type has no credential FIELD, so this catches the other way in: somebody
// putting one in engine_config, where it is just JSON and looks like ordinary
// configuration.
func TestJobRefusesCredentialsInEngineConfig(t *testing.T) {
	for _, key := range []string{
		"token", "github_token", "api_key", "apiKey", "secret",
		"password", "AUTH_HEADER", "private_key", "session_cookie",
	} {
		t.Run(key, func(t *testing.T) {
			job := validJob()
			job.EngineConfig = map[string]any{key: "value"}

			err := job.Validate()
			if err == nil {
				t.Fatalf("engine_config carrying %q was accepted", key)
			}
			if !strings.Contains(err.Error(), "ADR-0008") {
				t.Errorf("the error does not explain the rule: %v", err)
			}
		})
	}

	// Ordinary configuration still works — a guard that blocks real config is
	// an outage.
	job := validJob()
	job.EngineConfig = map[string]any{"scope": "all-layers", "timeout_sec": 300}
	if err := job.Validate(); err != nil {
		t.Errorf("legitimate engine_config was rejected: %v", err)
	}
}

// ⚠ WITHOUT job_id IN THE PREFIX, A RETRY OVERWRITES THE PREVIOUS ATTEMPT'S
// ARTIFACTS — and those artifacts are compliance evidence.
func TestJobRequiresJobIDInTheOutputPrefix(t *testing.T) {
	job := validJob()
	job.Output.Prefix = "s3://b/scans/scan-1/raw/syft/"

	err := job.Validate()
	if err == nil {
		t.Fatal("an output prefix without job_id was accepted")
	}
	if !strings.Contains(err.Error(), "overwrite") {
		t.Errorf("the error does not explain the consequence: %v", err)
	}
}

func TestJobValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*events.ScanJobV1)
	}{
		{"wrong schema", func(j *events.ScanJobV1) { j.SchemaVersion = "scan.job/v2" }},
		{"no job id", func(j *events.ScanJobV1) { j.JobID = "" }},
		{"no tenant", func(j *events.ScanJobV1) { j.TenantID = "" }},
		{"unknown family", func(j *events.ScanJobV1) { j.Family = "unknown" }},
		{"no engine", func(j *events.ScanJobV1) { j.Engine = "" }},
		{"attempt zero", func(j *events.ScanJobV1) { j.Attempt = 0 }},
		{"no deadline", func(j *events.ScanJobV1) { j.DeadlineAt = time.Time{} }},
		{"no workspace", func(j *events.ScanJobV1) { j.Workspace.ArtifactURI = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := validJob()
			tt.mutate(&job)
			if err := job.Validate(); err == nil {
				t.Errorf("accepted an invalid job: %s", tt.name)
			}
		})
	}

	if err := validJob().Validate(); err != nil {
		t.Errorf("a valid job was rejected: %v", err)
	}
}

// The fetch job is what PRODUCES the workspace, so it is the one job that
// legitimately has none.
func TestFetchJobNeedsNoWorkspace(t *testing.T) {
	job := validJob()
	job.Family = events.FamilyFetch
	job.Engine = "fetcher"
	job.Workspace = events.Workspace{}

	if err := job.Validate(); err != nil {
		t.Errorf("a fetch job was rejected for having no workspace: %v", err)
	}
}

// The manifest key is what a worker HEADs first. Idempotency depends on it
// being derived identically everywhere.
func TestManifestKeyIsUnderTheJobPrefix(t *testing.T) {
	job := validJob()
	key := job.ManifestKey()

	if !strings.HasPrefix(key, job.Output.Prefix) {
		t.Errorf("manifest key %q is not under the job prefix %q", key, job.Output.Prefix)
	}
	if !strings.HasSuffix(key, "/manifest.json") {
		t.Errorf("manifest key = %q", key)
	}
	// Two jobs must never share a manifest, or one would satisfy the other's
	// idempotency check and its work would be skipped.
	other := validJob()
	other.JobID = "job-2"
	other.Output.Prefix = "s3://b/scans/scan-1/raw/syft/job-2/"
	if other.ManifestKey() == key {
		t.Error("two jobs derive the same manifest key")
	}
}

func TestJobSubject(t *testing.T) {
	job := validJob()
	if got := job.Subject(); got != "scan.job.sbom" {
		t.Errorf("subject = %q, want scan.job.sbom", got)
	}
}

// ---------------------------------------------------------------------------
// ScanResultV1
// ---------------------------------------------------------------------------

func validResult() events.ScanResultV1 {
	return events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         "job-1", ScanID: "scan-1", TenantID: "tenant-1",
		Engine: "syft", EngineVersion: "1.51.0",
		Status: events.StatusSucceeded,
		Invocation: events.Invocation{
			ArgvRedacted: []string{"syft", "dir:/workspace"},
			StartedAt:    time.Now().UTC(), FinishedAt: time.Now().UTC(),
		},
		Summary: events.Summary{Components: events.Count(412)},
	}
}

// ⚠ A VULNERABILITY FINDING THAT CANNOT BE DATED IS NOT DEFENSIBLE.
//
// A compliance report that cannot say "matched against vulnerability data as
// of X" is not evidence of anything.
func TestVulnerabilityEnginesRequireADatabaseVersion(t *testing.T) {
	for _, engine := range []string{"grype", "trivy-fs", "trivy-image", "osv-scanner", "dependency-check"} {
		t.Run(engine, func(t *testing.T) {
			r := validResult()
			r.Engine = engine
			r.EngineDBVersion = ""

			err := r.Validate()
			if err == nil {
				t.Fatalf("%s reported success with no engine_db_version", engine)
			}
			if !strings.Contains(err.Error(), "defensible") {
				t.Errorf("the error does not explain why: %v", err)
			}

			r.EngineDBVersion = "grype-db v5 2026-08-15T00:00:00Z"
			if err := r.Validate(); err != nil {
				t.Errorf("rejected with a database version present: %v", err)
			}
		})
	}

	// syft catalogues components and matches nothing, so it needs none.
	r := validResult()
	r.Engine = "syft"
	if err := r.Validate(); err != nil {
		t.Errorf("a non-vulnerability engine was required to have a db version: %v", err)
	}
}

// A FAILED engine that does not say why leaves the UI able to offer only "it
// failed", which is not actionable.
func TestFailedResultMustCarryAnError(t *testing.T) {
	r := validResult()
	r.Status = events.StatusFailed
	r.Error = nil

	if err := r.Validate(); err == nil {
		t.Fatal("a failed result with no error was accepted")
	}

	r.Error = &events.ResultError{Code: "ENGINE_CRASHED", Message: "exit 139", Retryable: true}
	if err := r.Validate(); err != nil {
		t.Errorf("rejected with an error present: %v", err)
	}
}

// A partial result is VALID and needs no error — that is what makes it a
// first-class status rather than a failure in disguise.
func TestPartialResultIsValidWithoutAnError(t *testing.T) {
	r := validResult()
	r.Status = events.StatusPartial
	r.EcosystemsCovered = []string{"npm", "pypi"}
	r.Diagnostics = []events.Diagnostic{{
		Severity: "warn", Code: "ENGINE_PARTIAL_ECOSYSTEM",
		Ecosystem: "maven", Message: "pom.xml failed to parse",
	}}

	if err := r.Validate(); err != nil {
		t.Errorf("a partial result was rejected: %v", err)
	}
}

func TestArtifactsRequireADigest(t *testing.T) {
	r := validResult()
	r.Artifacts = []events.Artifact{{Role: "native_output", URI: "s3://b/out.json"}}

	if err := r.Validate(); err == nil {
		t.Fatal("an artifact with no sha256 was accepted")
	}
}

// ---------------------------------------------------------------------------
// ScanEventV1
// ---------------------------------------------------------------------------

// ⚠ EVENT STREAMS REACH BROWSERS AND LOGS. TREAT THEM AS PUBLIC.
//
// A message must never carry a user path, a repository URL, or anything from
// the scanned code.
func TestEventMessageIsSanitized(t *testing.T) {
	tests := []struct{ name, in string }{
		{"newline forges a log line", "scanning\nFAKE LOG ENTRY: admin logged in"},
		{"carriage return", "scanning\rmalicious"},
		{"nul byte", "scan\x00ning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := events.ScanEventV1{Message: tt.in}
			e.Sanitize()

			if strings.ContainsAny(e.Message, "\n\r\x00") {
				t.Errorf("message still contains a control character: %q", e.Message)
			}
		})
	}
}

func TestEventMessageIsBounded(t *testing.T) {
	e := events.ScanEventV1{Message: strings.Repeat("A", 5000)}
	e.Sanitize()

	if len(e.Message) > events.MaxEventMessage {
		t.Errorf("message is %d chars, limit is %d", len(e.Message), events.MaxEventMessage)
	}
}

func TestEventPercentageIsClamped(t *testing.T) {
	for _, in := range []int{-50, 0, 42, 100, 500} {
		e := events.ScanEventV1{Pct: in}
		e.Sanitize()
		if e.Pct < 0 || e.Pct > 100 {
			t.Errorf("pct %d clamped to %d, outside 0-100", in, e.Pct)
		}
	}
}

func TestEventSubjectIsPerScan(t *testing.T) {
	e := events.ScanEventV1{ScanID: "scan-abc"}
	if got := e.Subject(); got != "scan.event.scan-abc" {
		t.Errorf("subject = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// ⚠ UNKNOWN FIELDS ARE IGNORED, NOT FATAL — the opposite of the HTTP handlers,
// and the difference is the point.
//
// A typo'd field in a user's API request is a mistake to report. An
// unrecognized field in a QUEUE MESSAGE is a newer publisher, and rejecting it
// means the schema can never gain a field without a synchronised deploy of
// every consumer.
func TestUnknownFieldsAreIgnoredNotFatal(t *testing.T) {
	// A job from a hypothetical future publisher.
	payload := []byte(`{
		"schema_version": "scan.job/v1",
		"job_id": "job-1", "scan_id": "scan-1",
		"tenant_id": "tenant-1", "project_id": "project-1",
		"family": "sbom", "engine": "syft", "attempt": 1,
		"future_field": {"nested": ["anything", 42]},
		"another_new_thing": true
	}`)

	var job events.ScanJobV1
	if err := events.Decode(payload, &job); err != nil {
		t.Fatalf("an envelope with unknown fields was rejected: %v\n"+
			"    A newer publisher must not break older consumers.", err)
	}
	if job.Engine != "syft" {
		t.Errorf("known fields did not decode: engine = %q", job.Engine)
	}
}

func TestPeekSchemaRoutesWithoutCommitting(t *testing.T) {
	for _, want := range []string{
		events.SchemaScanJobV1, events.SchemaScanEventV1, events.SchemaScanResultV1,
	} {
		payload := []byte(`{"schema_version":"` + want + `"}`)
		got, err := events.PeekSchema(payload)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	if _, err := events.PeekSchema([]byte(`{"no":"schema"}`)); err == nil {
		t.Error("an envelope with no schema_version was accepted")
	}
}

// Every envelope must survive a JSON round trip unchanged — they cross a
// process boundary and are stored.
func TestEnvelopesRoundTrip(t *testing.T) {
	job := validJob()
	job.EngineConfig = map[string]any{"scope": "all-layers"}

	data, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back events.ScanJobV1
	if err := events.Decode(data, &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.JobID != job.JobID || back.Engine != job.Engine ||
		back.Output.Prefix != job.Output.Prefix {
		t.Errorf("job did not round-trip:\n got %+v\nwant %+v", back, job)
	}

	result := validResult()
	result.Diagnostics = []events.Diagnostic{{Severity: "warn", Code: "X", Message: "m"}}
	data, _ = json.Marshal(result)
	var backResult events.ScanResultV1
	if err := events.Decode(data, &backResult); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(backResult.Diagnostics) != 1 {
		t.Errorf("diagnostics did not round-trip: %+v", backResult.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

// ⚠ null AND 0 ARE DIFFERENT CLAIMS, AND THE WIRE FORMAT HAS TO KEEP THEM APART.
//
// The workers published four hardcoded zeros on every job, so syft inventoried
// 21 components in expressjs/express and the envelope said none. Filling the
// fields in unconditionally would have been the same bug wearing a number:
// syft does not match vulnerabilities and grype does not catalogue licences, so
// a 0 in either states a fact the engine never established.
func TestSummaryDistinguishesNotMeasuredFromMeasuredZero(t *testing.T) {
	r := validResult()
	r.Summary = events.Summary{Components: events.Count(21), Licenses: events.Count(0)}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	var wire struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]any{
		"components": float64(21), // measured
		"licenses":   float64(0),  // measured, none found
		// syft matches no vulnerabilities and looks for no crypto. Not the
		// same statement as "found none".
		"vulnerabilities": nil,
		"crypto_assets":   nil,
	} {
		got, present := wire.Summary[name]
		if !present {
			t.Errorf("summary.%s is absent; a consumer cannot tell "+
				"'not measured' from 'older publisher'", name)
			continue
		}
		if got != want {
			t.Errorf("summary.%s = %v, want %v", name, got, want)
		}
	}
}

func TestSummaryMeasured(t *testing.T) {
	if (events.Summary{}).Measured() {
		t.Error("an empty summary claims to have measured something")
	}
	if !(events.Summary{Licenses: events.Count(0)}).Measured() {
		t.Error("a measured zero was treated as nothing measured")
	}
}

// A negative count is a parser that subtracted, not a measurement. Rejected
// here because it would otherwise reach a report as a plausible number.
func TestNegativeCountsAreRejected(t *testing.T) {
	r := validResult()
	r.Summary = events.Summary{Components: events.Count(-1)}

	err := r.Validate()
	if err == nil {
		t.Fatal("a negative component count was accepted")
	}
	if !strings.Contains(err.Error(), "summary.components") {
		t.Errorf("the error does not name the field: %v", err)
	}
}
