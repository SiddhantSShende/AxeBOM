// Package worker renders a queued report and stores the result.
//
// ⚠ RENDERING IS ASYNC AND THAT IS THE CONTRACT, NOT AN OPTIMIZATION.
//
// A Complete BOM can exceed 50k components. A synchronous request would time
// out long before the PDF finished, the client would retry, and the worker
// would render the same report twice — two writes racing for one storage key.
// So the HTTP surface returns 202 with a report id, and this drives the row
// from `queued` through `rendering` to `ready` or `failed`.
//
// The status is never left ambiguous: every exit from Render writes a terminal
// state. A report stuck at `rendering` is indistinguishable, from the outside,
// from a busy worker — and nobody investigates a busy worker.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/reportsig"
	"github.com/axebom/axebom/services/report/internal/export"
	"github.com/axebom/axebom/services/report/internal/render"
	"github.com/axebom/axebom/services/report/internal/service"
	"github.com/axebom/axebom/services/report/internal/store"
)

// Source supplies the canonical BOM for a report.
//
// An interface because the normalized data lives in the `normalize` schema,
// which this service must not JOIN to (ADR-0001, CLAUDE.md invariant 11). The
// real implementation reads it through the normalizer's own surface; the tests
// hand over a fixture.
type Source interface {
	Load(ctx context.Context, r store.Report) (render.BOM, error)
}

// Signer produces a detached signature over an artifact.
type Signer interface {
	SignPayload(payload []byte) (signature []byte, keyID string, err error)
}

// Notifier publishes a notify.> event. See libs/go-shared/events.NotifyEventV1.
type Notifier interface {
	Publish(ctx context.Context, evt events.NotifyEventV1) error
}

// Worker renders one report at a time.
type Worker struct {
	svc    *service.Service
	source Source
	blob   *blob.Store

	// signer may be nil. Reports still render; they are stored unsigned, and
	// the row says so by carrying an empty signing_key_id.
	signer Signer

	// notifier may be nil. A report.ready notification is advisory
	// (docs/02-CONTRACTS.md §2's own rule for every event in this product) —
	// its absence must never turn a successful render into a failed one.
	notifier Notifier
	// frontendURL builds the notification's URL. Empty means notifications
	// are skipped entirely rather than published with a broken link.
	frontendURL string

	log *slog.Logger
}

// New builds a worker.
func New(
	svc *service.Service, src Source, bs *blob.Store, signer Signer,
	notifier Notifier, frontendURL string, log *slog.Logger,
) *Worker {
	if log == nil {
		log = slog.Default()
	}
	return &Worker{
		svc: svc, source: src, blob: bs, signer: signer,
		notifier: notifier, frontendURL: frontendURL, log: log,
	}
}

// Render drives one report to a terminal state.
//
// ⚠ EVERY RETURN PATH AFTER THE CLAIM WRITES A TERMINAL STATE. The deferred
// failure marker exists because the alternative — remembering to call Fail at
// each of eight error sites — is exactly the discipline that decays, and the
// symptom is a report that says `rendering` forever.
func (w *Worker) Render(ctx context.Context, tenantID, reportID string) (err error) {
	report, err := w.svc.Claim(ctx, tenantID, reportID)
	if err != nil {
		// ⚠ NOT AN ERROR WORTH RETRYING. The conditional UPDATE found nothing,
		// which means another worker already claimed it or it is not `queued`.
		// At-least-once delivery makes a duplicate normal, so this is an
		// expected outcome and the message says so.
		w.log.Info("nothing to render; the report was already claimed or is not queued",
			"report_id", reportID)
		return nil
	}

	defer func() {
		if err != nil {
			if failErr := w.svc.Fail(ctx, tenantID, reportID, err); failErr != nil {
				w.log.Error("the failed render could not be recorded",
					"report_id", reportID, "error", failErr)
			}
		}
	}()

	bom, err := w.source.Load(ctx, report)
	if err != nil {
		return errs.Wrap(err, errs.ReportRenderFailed,
			"the normalized BOM could not be read")
	}

	artifact, truncated, note, err := w.renderArtifact(report, bom)
	if err != nil {
		return err
	}

	key := service.StorageKey(tenantID, reportID, report.Format)
	obj, err := w.blob.Put(ctx, key, bytes.NewReader(artifact), blob.PutOptions{
		ContentType: mediaType(report.Format),
	})
	if err != nil {
		return errs.Wrap(err, errs.InternalDependency,
			"the rendered artifact could not be stored")
	}

	signature, keyID, err := w.sign(report, obj, artifact)
	if err != nil {
		// ⚠ A SIGNING FAILURE DOES NOT DISCARD THE RENDER — but it does not
		// pass silently either. The artifact is stored and usable; what it is
		// not is verifiable, and the row records that by carrying no key id.
		// Failing the whole report would turn a Vault blip into "no reports",
		// and quietly marking it ready-and-signed would be a lie.
		w.log.Error("the report was rendered but could not be signed",
			"report_id", reportID, "error", err)
		signature, keyID = "", ""
	}

	if err := w.svc.Finish(ctx, tenantID, reportID, store.Completion{
		StorageRef:     obj.Key,
		SHA256:         obj.SHA256,
		SizeBytes:      obj.Size,
		Signature:      signature,
		SigningKeyID:   keyID,
		Truncated:      truncated,
		TruncationNote: note,

		// ⚠ CAPTURED FROM THE bom LOADED ABOVE, NOT RE-QUERIED. This is the
		// exact data that produced the artifact just stored; see
		// store.Completion's own doc comment for why that matters.
		ProjectName:            bom.ProjectName,
		BOMGeneratedAt:         bom.GeneratedAt,
		LevelNote:              bom.LevelNote,
		CompletenessPct:        coverageOrNil(bom.CoverageComputed, bom.Coverage.CompletenessPct),
		DeclarationPct:         coverageOrNil(bom.CoverageComputed, bom.Coverage.DeclarationPct),
		CoverageFormula:        bom.Coverage.Formula,
		CoverageFields:         enrichCoverageFields(bom.BOMType, bom.Coverage.Fields),
		Engines:                toStoreEngines(bom.Engines),
		EcosystemsWithNoEngine: bom.EcosystemsWithNoEngine,
	}); err != nil {
		return err
	}

	// ⚠ AFTER Finish SUCCEEDS, NEVER BEFORE. The row being `ready` is the fact
	// being announced; publishing first and having Finish then fail would
	// notify a receiver about a report that, from the database's point of
	// view, never finished.
	w.publishReportReady(ctx, tenantID, report, bom)
	return nil
}

// publishReportReady sends the one notify.> event this worker emits today.
//
// ⚠ BEST EFFORT, LIKE SIGNING ABOVE. A notification failing must not turn a
// successful render into a failed one — docs/02-CONTRACTS.md §2's "events are
// advisory" rule, applied here exactly as it already is to PublishAdvisory
// elsewhere in this product.
func (w *Worker) publishReportReady(ctx context.Context, tenantID string, report store.Report, bom render.BOM) {
	if w.notifier == nil {
		return
	}
	if w.frontendURL == "" {
		w.log.Warn("no frontend URL configured; skipping the report.ready notification",
			"report_id", report.ID)
		return
	}

	critical, high := severityCounts(bom.Findings)
	unavailable := unavailableEngineNames(bom.Engines)

	evt := events.NotifyEventV1{
		Schema:   events.NotifyEventSchema,
		Event:    events.NotifyEventReportReady,
		TenantID: tenantID,
		// ⚠ NO ProjectID. render.BOM carries ProjectName, never a project id —
		// resolving one would mean a query this worker does not otherwise need
		// to make. A receiver has ReportID and ScanID to look up the rest.
		ProjectName:        bom.ProjectName,
		ScanID:             report.ScanID,
		ReportID:           report.ID,
		Status:             string(store.StatusReady),
		Components:         len(bom.Components),
		Findings:           len(bom.Findings),
		Critical:           critical,
		High:               high,
		EnginesUnavailable: len(unavailable),
		UnavailableEngines: unavailable,
		URL:                w.frontendURL + "/reports/" + report.ID,
		OccurredAt:         time.Now().UTC().Format(time.RFC3339),
	}

	if err := w.notifier.Publish(ctx, evt); err != nil {
		w.log.Warn("could not publish the report.ready notification",
			"report_id", report.ID, "error", err)
	}
}

// severityCounts tallies the two severities the notify envelope reports.
func severityCounts(findings []render.Finding) (critical, high int) {
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		}
	}
	return critical, high
}

// unavailableEngineNames names engines the Engine Coverage section already
// marks `unavailable` — the same honesty rule extended to a notification.
func unavailableEngineNames(engines []render.EngineCoverage) []string {
	var out []string
	for _, e := range engines {
		if e.Status == "unavailable" {
			out = append(out, e.EngineID)
		}
	}
	return out
}

// coverageOrNil turns render.BOM's collapsed-to-zero coverage number back
// into an absence when the document was never scored — see
// render.BOM.CoverageComputed and store.Completion's own doc comments.
func coverageOrNil(computed bool, pct float64) *float64 {
	if !computed {
		return nil
	}
	return &pct
}

// enrichCoverageFields adds the profile metadata (name, weight, source page)
// that render.FieldCoverage itself does not carry, so a client reading the
// stored summary never has to look the profile up separately to label a row.
//
// ⚠ A CBOM HAS NO SINGLE FIELD SET (render.FieldsFor's own reasoning, echoed
// here). The per-field counts still come through from the normalizer's
// breakdown when present; without profile metadata to enrich them with, they
// are stored with just their id and counts rather than losing the row.
func enrichCoverageFields(bomType model.BOMType, fields []render.FieldCoverage) []store.CoverageField {
	byID := make(map[string]model.ProfileField)
	if profileFields, err := render.FieldsFor(bomType); err == nil {
		for _, f := range profileFields {
			byID[f.ID] = f
		}
	}

	out := make([]store.CoverageField, 0, len(fields))
	for _, fc := range fields {
		cf := store.CoverageField{
			FieldID: fc.FieldID, Present: fc.Present, Declared: fc.Declared, Total: fc.Total,
		}
		if pf, ok := byID[fc.FieldID]; ok {
			cf.Name = pf.Name
			cf.Weight = pf.Weight
			cf.SourcePage = pf.SourcePage
		}
		out = append(out, cf)
	}
	return out
}

// toStoreEngines converts the render model's engine coverage to the
// persisted shape. Field-for-field identical, but kept as separate types:
// render.EngineCoverage belongs to the renderer's in-memory model, and
// store.EngineCoverage is the JSON shape a client reads back — the two are
// free to diverge the day either one needs to.
func toStoreEngines(engines []render.EngineCoverage) []store.EngineCoverage {
	out := make([]store.EngineCoverage, 0, len(engines))
	for _, e := range engines {
		out = append(out, store.EngineCoverage{
			EngineID:        e.EngineID,
			Version:         e.Version,
			Status:          e.Status,
			DatabaseVersion: e.DatabaseVersion,
			Ecosystems:      e.Ecosystems,
			Diagnostic:      e.Diagnostic,
		})
	}
	return out
}

// renderArtifact produces the bytes for one format.
func (w *Worker) renderArtifact(r store.Report, bom render.BOM) ([]byte, bool, string, error) {
	var buf bytes.Buffer

	switch r.Format {
	case "pdf":
		result, err := render.WritePDF(&buf, bom, render.PDFOptions{})
		if err != nil {
			return nil, false, "", err
		}
		return buf.Bytes(), result.Truncated, result.TruncationNote, nil

	case "xlsx":
		sheets, err := render.Sheets(bom)
		if err != nil {
			return nil, false, "", err
		}
		result, err := render.WriteXLSX(&buf, sheets)
		if err != nil {
			return nil, false, "", err
		}
		// ⚠ THE WRITER'S CHANGES ARE REPORTED, NOT SWALLOWED. Escaping is
		// invisible by design and truncation loses data outright, so both are
		// counted and carried into the report's note. A workbook that quietly
		// rewrote its own contents is one nobody can reconcile against the
		// database.
		return buf.Bytes(), false, writerNote(result), nil

	case "spdx", "cyclonedx":
		doc, err := w.standardDocument(r, bom)
		if err != nil {
			return nil, false, "", err
		}
		return doc, false, "", nil

	case "json":
		spdx, err := export.Serialize(toExportDocument(bom), export.SPDX23JSON)
		if err != nil {
			return nil, false, "", errs.Wrap(err, errs.ReportRenderFailed,
				"serializing the SPDX document for the bundle")
		}
		cdx, err := export.Serialize(toExportDocument(bom), export.CycloneDX16JSON)
		if err != nil {
			return nil, false, "", errs.Wrap(err, errs.ReportRenderFailed,
				"serializing the CycloneDX document for the bundle")
		}
		bundle, err := render.WriteJSON(bom, spdx, cdx)
		if err != nil {
			return nil, false, "", errs.Wrap(err, errs.ReportRenderFailed,
				"building the JSON bundle")
		}
		return bundle, false, "", nil

	default:
		// Unreachable: service.Queue validates the format before the row exists.
		// Kept as a refusal rather than a default branch, because a silent
		// fallback here would store one format's bytes under another's name.
		return nil, false, "", errs.Newf(errs.ReportRenderFailed,
			"no renderer for format %q", r.Format)
	}
}

func (w *Worker) standardDocument(r store.Report, bom render.BOM) ([]byte, error) {
	format := export.SPDX23JSON
	if r.Format == "cyclonedx" {
		format = export.CycloneDX16JSON
	}
	doc, err := export.Serialize(toExportDocument(bom), format)
	if err != nil {
		return nil, errs.Wrap(err, errs.ReportRenderFailed,
			"serializing the standard document")
	}
	return doc, nil
}

// writerNote turns the spreadsheet writer's counters into a sentence, or "".
func writerNote(r render.Result) string {
	escaped := r.Total(func(s render.SheetResult) int { return s.Escaped })
	truncated := r.Total(func(s render.SheetResult) int { return s.Truncated })
	stripped := r.Total(func(s render.SheetResult) int { return s.ControlStripped })

	var parts []string
	if escaped > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d cell value(s) began with a spreadsheet formula character and were "+
				"prefixed with an apostrophe so they cannot execute on open. This "+
				"means a name in your dependency tree is shaped like an attack.",
			escaped))
	}
	if truncated > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d value(s) exceeded a spreadsheet cell's 32,767-character limit and "+
				"were cut; the full values are in the JSON export.", truncated))
	}
	if stripped > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d value(s) contained characters that are not representable in a "+
				"spreadsheet and were replaced with U+FFFD.", stripped))
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}

// sign issues the detached signature envelope.
//
// ⚠ THE ENVELOPE IS STORED AS THE EXACT JSON THAT WILL BE SERVED. It is not
// re-encoded on the way out, because reformatting the envelope is what broke
// every signature the first time one was written to a file.
func (w *Worker) sign(r store.Report, obj blob.Object, artifact []byte) (string, string, error) {
	if w.signer == nil {
		return "", "", nil
	}

	env, err := reportsig.Sign(reportsig.Statement{
		ReportID:        r.ID,
		TenantID:        r.TenantID,
		Format:          r.Format,
		GeneratedAt:     r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ProfileID:       model.ProfileID,
		ProfileRevision: model.ProfileRevision,
		ToolName:        "AxeBOM",
		ToolVersion:     version(),
	}, artifact, w.signer)
	if err != nil {
		return "", "", err
	}

	// A sanity check that costs nothing and catches a whole class of confusion:
	// the object store computed a digest from the bytes it actually wrote, and
	// the statement covers the bytes we handed the signer. If those disagree,
	// something between them mutated the artifact.
	if obj.SHA256 != "" && obj.SHA256 != reportsig.Digest(artifact) {
		return "", "", fmt.Errorf(
			"the stored artifact's digest (%s) differs from the signed one (%s); "+
				"the bytes changed between rendering and storage",
			obj.SHA256, reportsig.Digest(artifact))
	}

	encoded, err := json.Marshal(env)
	if err != nil {
		return "", "", err
	}
	return string(encoded), env.KeyID, nil
}

// version is the tool version recorded in signatures and documents.
//
// A build-time value in a real build; a constant here so a render is
// reproducible in a test binary that has no ldflags.
func version() string { return "0.1.0" }

// toExportDocument maps the render model onto the exporter's.
//
// ⚠ GeneratedAt IS CARRIED THROUGH, NOT RE-READ FROM A CLOCK. The exporter
// corrects protobom's `time.Now()` timestamp with it, which is what makes two
// renders of the same stored data byte-identical (ADR-0003).
func toExportDocument(b render.BOM) export.Document {
	doc := export.Document{
		GeneratedAt: b.GeneratedAt,
		DocumentID:  b.ReportID,
		ProjectName: b.ProjectName,
		ToolName:    b.ToolName,
		ToolVersion: b.ToolVersion,
	}

	for _, c := range b.Components {
		doc.Components = append(doc.Components, export.Component{
			Key:              c.Key,
			Name:             c.Fields[model.FieldCertinSbom01ComponentName],
			VersionRaw:       c.Fields[model.FieldCertinSbom02ComponentVersion],
			Purl:             c.Purl,
			Ecosystem:        c.Ecosystem,
			Supplier:         c.Fields[model.FieldCertinSbom04ComponentSupplier],
			Description:      c.Fields[model.FieldCertinSbom03ComponentDescription],
			CertInIdentifier: c.Fields[model.FieldCertinSbom21UniqueIdentifier],
		})
	}

	doc.Roots = b.Roots
	for _, d := range b.Dependencies {
		doc.Dependencies = append(doc.Dependencies, export.Dependency{From: d.From, To: d.To})
	}
	return doc
}

func mediaType(format string) string {
	switch format {
	case "pdf":
		return render.PDFMediaType
	case "xlsx":
		return render.XLSXMediaType
	case "spdx":
		return export.SPDX23JSON.MediaType()
	case "cyclonedx":
		return export.CycloneDX16JSON.MediaType()
	default:
		return render.JSONMediaType
	}
}
