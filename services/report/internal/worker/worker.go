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
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

	bom, err := w.loadNormalizedBOM(ctx, report)
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

// normalizedBOMRetryAttempts and normalizedBOMRetryDelay bound how long
// loadNormalizedBOM waits for normalization to catch up. See its own doc
// comment for why this exists at all.
//
// ⚠ VARS, NOT CONSTS. Tests shrink normalizedBOMRetryDelay so the "gives up
// after every attempt" case does not cost normalizedBOMRetryAttempts *
// (a real few seconds) of wall-clock time; production never touches these.
//
// ⚠ 13×15s = 180s, NOT THE ORIGINAL 5×3s = 15s. The original budget was
// sized for a fast webrecon race (~2s) on the stated assumption that "a slow
// git-sourced scan closes the race long before this worker gets to the
// message" — that assumption was wrong, not just imprecise, and cost a real
// report: confirmed live, a git-sourced scan for a real registered project
// (6 real sandboxed engines: dependency-check, grype, mock-engine,
// osv-scanner, syft, trivy-fs) queued its report at 19:21:16.227, exhausted
// all 5 attempts and failed permanently at 19:21:28.262 — 12s later — while
// the scan itself did not finish until 19:21:56.240, nearly 28s after the
// report had already given up. 180s comfortably covers a realistic
// multi-engine scan (dependency-check's NVD database pull in particular can
// be slow) while leaving 120s of the render job's 5-minute AckWait for the
// actual render, DB write and publish afterward — "seconds of in-process
// work" per queue.go's own AckWait sizing comment.
var (
	normalizedBOMRetryAttempts = 13
	normalizedBOMRetryDelay    = 15 * time.Second
)

// loadNormalizedBOM retries Load a bounded number of times while the
// document does not exist YET, rather than treating a first miss as
// permanent.
//
// ⚠ THIS RACE IS REAL, NOT HYPOTHETICAL, AND JETSTREAM REDELIVERY CANNOT FIX
// IT HERE. A report is deliberately queued the moment its scan is created,
// before the scan has run — bomsource.go's own resolveDocument error already
// says so ("the scan may still be running"). This races EVERY scan, fast or
// slow — a fast webrecon scan by a second or two, a real multi-engine
// git-sourced scan by tens of seconds — not just the fast case an earlier
// version of this comment assumed. Confirmed live twice, now: a webrecon
// report queued at 19:25:05.719 was marked failed at 19:25:05.737 while
// normalize.bom_documents for the same scan was not written until
// 19:25:07.622 (~1.9s later); a git-sourced report queued at 19:21:16.227
// exhausted the ORIGINAL 15s budget and failed at 19:21:28.262, while its
// scan did not finish until 19:21:56.240 (~28s after the report gave up) —
// see normalizedBOMRetryAttempts's own doc comment for why the budget grew
// from 15s to 180s rather than the assumption being trusted a second time.
//
// This is NOT solved by classifying the error as retryable and letting
// queue.go's bus.ErrRetry path redeliver the message: Render's own deferred
// marker calls svc.Fail — status='failed' — unconditionally on ANY error
// before queue.go ever decides retryable or not, and ClaimForRender only
// claims from status='queued'. A redelivery's Claim would find the row
// already `failed` and no-op as "already claimed", never actually retrying
// the load. (That same gap already exists for the blob-store-failure path
// below, which believes itself retryable for the identical reason — a
// separate, pre-existing issue, not fixed here.) Retrying in-process, before
// this attempt's single Fail-on-error can fire, is what actually gives
// normalization the moment it needs — bounded well inside the render job's
// 5-minute AckWait, and paid only by the one report that hit the race: NATS
// JetStream's default pull concurrency (MaxAckPending=8, bus.go) processes
// up to 8 render jobs in parallel, so one report waiting out this budget
// does not block reports for other, unrelated scans behind it.
func (w *Worker) loadNormalizedBOM(ctx context.Context, report store.Report) (render.BOM, error) {
	var bom render.BOM
	var err error
	for attempt := 1; attempt <= normalizedBOMRetryAttempts; attempt++ {
		bom, err = w.source.Load(ctx, report)
		if err == nil || !errors.Is(err, store.ErrNotFound) {
			return bom, err
		}
		if attempt == normalizedBOMRetryAttempts {
			break
		}
		w.log.Info("normalized BOM not written yet; waiting for the scan's "+
			"normalization to catch up", "report_id", report.ID, "attempt", attempt)
		select {
		case <-ctx.Done():
			return render.BOM{}, ctx.Err()
		case <-time.After(normalizedBOMRetryDelay):
		}
	}
	return bom, err
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

	case "docx":
		result, err := render.WriteDOCX(&buf, bom, render.DOCXOptions{})
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

	appendHardware(&doc, b)
	return doc
}

// appendHardware maps the hardware tree into the export document.
//
// ⚠ THIS IS WHAT CLOSES §10.4.1.6, and it is the reason an HBOM can be handed
// to anything other than AxeBOM. Before it, `b.Hardware` reached the XLSX and
// DOCX renderers and stopped there — a customer asking for the CycloneDX or
// SPDX form of their hardware BOM got a document containing zero components,
// which validates and says nothing.
//
// ⚠ EVERY COMPONENT IS `device`, AND THE EDGES ARE `contains`. A parts list
// serialized with software defaults would tell a downstream consumer that a
// gateway depends on a capacitor at run time. See export.Dependency.Kind.
func appendHardware(doc *export.Document, b render.BOM) {
	if len(b.Hardware) == 0 {
		return
	}

	for _, h := range b.Hardware {
		purpose := "device"
		if h.FirmwareVersion != "" && h.ModelNumber == "" {
			// A node that carries a firmware version and no part number is
			// firmware, not a part — cdxgen reports BIOS and embedded
			// controllers exactly that way.
			purpose = "firmware"
		}

		doc.Components = append(doc.Components, export.Component{
			// ⚠ THE DATABASE ID, NOT THE NAME. Two 10k resistors on one board
			// legitimately share a name; keying on it would collapse them into
			// one component and understate the parts list.
			Key:            h.ID,
			Name:           h.Name,
			VersionRaw:     h.Version,
			Description:    h.Description,
			Supplier:       firstNonEmpty(h.SupplierInfo, h.ComponentSupplierInfo),
			Manufacturer:   h.ManufacturerName,
			PrimaryPurpose: purpose,
			Properties:     hardwareProperties(h),
		})
		if h.ParentID != "" {
			doc.Dependencies = append(doc.Dependencies, export.Dependency{
				From: h.ParentID, To: h.ID, Kind: export.KindContains,
			})
		} else {
			doc.Roots = append(doc.Roots, h.ID)
		}
	}
}

// hardwareProperties carries the facts SPDX and CycloneDX have no field for.
//
// ⚠ NAMESPACED BY AUTHORITY, WHICH IS THE POINT OF SPLITTING THEM.
// `certin:hbom:*` are elements a compliance standard requires; `axebom:hbom:*`
// are AxeBOM's own manufacturing fields. A reader — human or machine — must be
// able to tell which claims come with a regulator behind them and which are
// ours, and one flat namespace makes that impossible to recover.
//
// Absent values are omitted rather than written as `not-provided`: the
// two-number coverage model already reports the gap, and a standards document
// full of literal "not-provided" strings is noise a consumer has to filter.
func hardwareProperties(h render.HardwareComponent) []export.Property {
	out := []export.Property{}
	add := func(name, value string) {
		if value != "" && value != "not-provided" {
			out = append(out, export.Property{Name: name, Value: value})
		}
	}

	// --- CERT-In Table 11 + §10.4.1.4 ---
	// ⚠ THE MANUFACTURER IS EMITTED HERE AS WELL AS STRUCTURALLY, and that is
	// not redundancy. It reaches SPDX as a real `originator`, but protobom's
	// CycloneDX serializer never reads Originators — so without this property
	// the manufacturer, the field §10.2.1 exists for, would be silently absent
	// from every CycloneDX hardware BOM. Verified against real output.
	add("certin:hbom:manufacturer", h.ManufacturerName)
	add("certin:hbom:model_number", h.ModelNumber)
	add("certin:hbom:serial_number", h.SerialNumber)
	add("certin:hbom:manufacturer_location", h.ManufacturerLocation)
	add("certin:hbom:origin", h.Origin)
	add("certin:hbom:supplier_location", h.SupplierLocation)
	// ⚠ THE TWO SUPPLIER RELATIONSHIPS STAY SEPARATE HERE TOO. Table 11 lists
	// them twice with different meanings — who sold the customer the product,
	// and who supplied a component to that product's manufacturer. Collapsing
	// them in the export would lose the distinction the whole table exists for.
	add("certin:hbom:component_supplier", h.ComponentSupplierInfo)
	add("certin:hbom:component_supplier_location", h.ComponentSupplierLocation)
	add("certin:hbom:firmware_version", h.FirmwareVersion)
	add("certin:hbom:criticality", h.Criticality)
	add("certin:hbom:technical_specification", h.TechnicalSpecification)
	for _, c := range h.Compliance {
		add("certin:hbom:compliance", c)
	}

	// --- AxeBOM manufacturing and procurement ---
	add("axebom:hbom:quantity", strconv.Itoa(h.Quantity))
	for _, d := range h.Designators {
		add("axebom:hbom:designator", d)
	}
	add("axebom:hbom:package_footprint", h.PackageFootprint)
	add("axebom:hbom:supplier_sku", h.SupplierSKU)
	add("axebom:hbom:preferred_supplier", h.PreferredSupplier)
	add("axebom:hbom:unit_price", h.UnitPrice)
	add("axebom:hbom:extended_price", h.ExtendedPrice)
	add("axebom:hbom:currency", h.Currency)
	add("axebom:hbom:assembly_type", h.AssemblyType)
	add("axebom:hbom:lifecycle_status", h.LifecycleStatus)
	if h.DoNotPopulate {
		// Only when true. `false` is the ordinary case for every fitted part,
		// and writing it on all of them would bury the flag that matters.
		add("axebom:hbom:do_not_populate", "true")
	}
	for _, a := range h.Alternates {
		if id := firstNonEmpty(a.ModelNumber, a.SupplierSKU, a.ManufacturerName); id != "" {
			// The equivalence rides WITH the identifier, never separately: an
			// alternate's part number without "unverified" beside it reads as
			// an approved substitution we never checked.
			add("axebom:hbom:alternate", id+" ("+a.Equivalence+")")
		}
	}
	// Which engine produced this row — a schematic parse and a self-reported
	// host inventory are different kinds of claim.
	add("axebom:hbom:source_engine", h.SourceEngine)

	// --- CERT-In element 24, and the status that keeps it readable ---
	//
	// ⚠ THE STATUS IS EMITTED EVEN WHEN IT IS `not-attempted`, WHICH IS THE
	// ONE EXCEPTION TO THE "omit absent values" RULE ABOVE. Everywhere else an
	// omitted property means "we have no value and the coverage numbers say
	// so". Here, omitting it would leave a hardware component with no
	// vulnerability properties at all — which a downstream consumer reads as
	// "no known vulnerabilities", the single most dangerous wrong inference
	// this export can invite. The status is what makes the absence legible.
	out = append(out, export.Property{
		Name:  "axebom:hbom:vuln_match_status",
		Value: firstNonEmpty(h.VulnMatchStatus, "not-attempted"),
	})
	for _, cpe := range h.CPE23Candidates {
		add("axebom:hbom:cpe23", cpe)
	}
	for _, f := range h.Vulnerabilities {
		// ⚠ THE BASIS AND CONFIDENCE RIDE WITH THE CVE, on exactly the
		// reasoning the alternates above follow: a bare CVE id in a standards
		// document is an assertion that this part is affected. It is not one —
		// it is a string match against NVD's vocabulary — and the qualifier has
		// to be inseparable from the claim or it will be dropped by the first
		// consumer that splits on the property name.
		add("certin:hbom:vulnerability", f.CVEID+" ("+f.MatchBasis+", "+f.MatchConfidence+" confidence, advisory)")
	}

	// ⚠ THE ASSEMBLY RELATIONSHIP, STATED EXPLICITLY, BECAUSE CycloneDX LOSES
	// IT. SPDX carries a real `CONTAINS` relationship; CycloneDX flattens the
	// same edge to `dependencies[].dependsOn`, which asserts that a gateway
	// depends on a resistor at run time rather than containing one. This
	// property is what lets a CycloneDX reader recover what was meant.
	// See export.Dependency.Kind for why it is not fixed at the serializer.
	add("axebom:hbom:parent", h.ParentID)

	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func mediaType(format string) string {
	switch format {
	case "pdf":
		return render.PDFMediaType
	case "docx":
		return render.DOCXMediaType
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
