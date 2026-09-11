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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
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
		//
		// ⚠ THE FLAG USED TO BE HARDCODED `false` WHILE THE NOTE SAID DATA WAS
		// CUT. `report.reports.truncated` is what a client filters on, so a row
		// could carry "N value(s) exceeded a spreadsheet cell's limit and were
		// cut" and still answer "nothing was truncated" to the only question
		// anybody asks programmatically. The file was honest; the database was
		// not.
		cellsCut := result.Total(func(s render.SheetResult) int { return s.Truncated })
		return buf.Bytes(), cellsCut > 0, writerNote(result), nil

	case "spdx", "cyclonedx":
		doc, err := w.standardDocument(r, bom)
		if err != nil {
			return nil, false, "", err
		}
		return doc, false, "", nil

	case "mlbom":
		// ⚠ A DIFFERENT SERIALIZER, NOT A DIFFERENT FLAG. protobom cannot emit
		// `modelCard` at all, so the generic CycloneDX path above produces a
		// valid document in which every AI model is an unremarkable component —
		// see export/mlbom.go's header.
		doc, err := export.SerializeMLBOM(toMLDocument(bom))
		if err != nil {
			return nil, false, "", errs.Wrap(err, errs.ReportRenderFailed,
				"serializing the ML-BOM")
		}
		return doc, false, "", nil

	case "json":
		spdx, err := export.Serialize(toExportDocument(bom), export.SPDX23JSON)
		if err != nil {
			return nil, false, "", errs.Wrap(err, errs.ReportRenderFailed,
				"serializing the SPDX document for the bundle")
		}
		// ⚠ THE SAME CycloneDX THE STANDALONE DOWNLOAD SERVES. The bundle
		// embeds it byte-for-byte so a consumer can verify it against that
		// download's signature; a bundle built with a different writer would
		// fail that check for a CBOM.
		cdx, err := cycloneDXDocument(bom)
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
	if r.Format == "cyclonedx" {
		doc, err := cycloneDXDocument(bom)
		if err != nil {
			return nil, errs.Wrap(err, errs.ReportRenderFailed,
				"serializing the CycloneDX document")
		}
		return doc, nil
	}
	doc, err := export.Serialize(toExportDocument(bom), export.SPDX23JSON)
	if err != nil {
		return nil, errs.Wrap(err, errs.ReportRenderFailed,
			"serializing the standard document")
	}
	return doc, nil
}

// cycloneDXDocument is a BOM's CycloneDX serialization, through whichever
// writer its type needs.
//
// ⚠ A CBOM TAKES THE NATIVE WRITER, NOT protobom. protobom v0.5.8 cannot emit
// a `cryptographic-asset` component or `cryptoProperties` at all, so the generic
// path produced a CycloneDX document in which every crypto asset was a `data`
// component — valid, and not a CBOM to any tool that reads one. See
// export/cbom.go. A QBOM keeps the protobom path: its subject is a device and
// its crypto assets are another document's, carried as properties.
func cycloneDXDocument(bom render.BOM) ([]byte, error) {
	if bom.BOMType == model.BOMTypeCBOM {
		return export.SerializeCBOM(toCBOMDocument(bom))
	}
	return export.Serialize(toExportDocument(bom), export.CycloneDX16JSON)
}

// toCBOMDocument maps the render model onto the CBOM serializer's.
//
// ⚠ IDENTITY COMES FROM cryptoRef AND NOWHERE ELSE, so the CycloneDX bom-refs
// and the SPDX package ids name the same assets the same way.
func toCBOMDocument(b render.BOM) export.CBOMDocument {
	doc := export.CBOMDocument{
		GeneratedAt: b.GeneratedAt,
		DocumentID:  b.ReportID,
		ProjectName: b.ProjectName,
		ToolName:    b.ToolName,
		ToolVersion: b.ToolVersion,
		// The type caveat and the derived-value footnote — the same sentences
		// every other format of this report carries (render.TypeNotes).
		Notes: render.TypeNotes(b),
		// The private-key finding, as one string a metadata property can carry
		// — the same block every other format renders (render.PrivateKeysInSource).
		PrivateKeysInSource: render.PrivateKeysInSourceStatement(b),
	}
	for _, a := range b.CryptoAssets {
		var derivations map[string]string
		if len(a.Derivations) > 0 {
			derivations = make(map[string]string, len(a.Derivations))
			for column, ref := range a.Derivations {
				derivations[column] = render.DerivationCitation(ref, b.Coverage.DerivationSources)
			}
		}
		doc.Assets = append(doc.Assets, export.CBOMAsset{
			Ref:                    cryptoRef(a),
			AssetType:              a.AssetType,
			Name:                   a.Name,
			ComponentKey:           a.ComponentKey,
			AssetKey:               a.AssetKey,
			IdentityRule:           a.IdentityRule,
			IdentityConfidence:     a.IdentityConfidence,
			Primitive:              a.Primitive,
			Mode:                   a.Mode,
			CryptoFunctions:        a.CryptoFunctions,
			ClassicalSecurityLevel: a.ClassicalSecurityLevel,
			AlgorithmList:          a.AlgorithmList,
			KeyID:                  a.KeyID,
			KeyState:               a.KeyState,
			KeySize:                a.KeySize,
			CreationDate:           a.CreationDate,
			ActivationDate:         a.ActivationDate,
			ProtocolVersion:        a.ProtocolVersion,
			CipherSuites:           a.CipherSuites,
			OID:                    a.OID,
			CertSubject:            a.CertSubject,
			CertIssuer:             a.CertIssuer,
			NotValidBefore:         a.NotValidBefore,
			NotValidAfter:          a.NotValidAfter,
			SignatureAlgoRef:       a.SignatureAlgoRef,
			SubjectPublicKeyRef:    a.SubjectPublicKeyRef,
			CertFormat:             a.CertFormat,
			CertExtension:          a.CertExtension,
			QuantumVulnerable:      a.QuantumVulnerable,
			QuantumFamily:          a.QuantumFamily,
			QuantumReadinessGroup:  a.QuantumReadinessGroup,
			DeprecationStatus:      a.DeprecationStatus,
			DeprecationRationale:   a.DeprecationRationale,
			DeprecationReference:   a.DeprecationReference,
			PQCRecommendation:      a.PQCRecommendation,
			Derivations:            derivations,
			// normalize.crypto_assets.attributes: the facts CycloneDX 1.6 has a
			// field for, and the asset keys a certificate or key points at.
			Padding:                  a.AttrString("padding"),
			Curve:                    a.AttrString("curve"),
			ParameterSetIdentifier:   a.AttrString("parameter_set"),
			NISTQuantumSecurityLevel: attrInt(a, "nist_quantum_security_level"),
			MaterialType:             a.AttrString("material_type"),
			MaterialFormat:           a.AttrString("material_format"),
			ExpirationDate:           a.AttrString("expiration_date"),
			AlgorithmKey:             a.AttrString("algorithm_key"),
			SignatureAlgorithmKey:    a.AttrString("signature_algorithm_key"),
			SubjectPublicKeyKey:      a.AttrString("subject_public_key_key"),
			Evidence:                 cbomEvidence(a.Evidence),
			Engines:                  a.Engines,
			PrivateKeyInSource:       a.PrivateKeyInSource(),
		})
	}
	return doc
}

// cbomEvidence carries an asset's locations to the serializer. Which engine saw
// each one is not carried: a CycloneDX 1.6 occurrence has no field for it, so
// the engines travel on the asset (`axebom:crypto:engines`) instead.
func cbomEvidence(evidence []render.CryptoEvidence) []export.CBOMEvidence {
	if len(evidence) == 0 {
		return nil
	}
	out := make([]export.CBOMEvidence, 0, len(evidence))
	for _, e := range evidence {
		out = append(out, export.CBOMEvidence{Path: e.Path, Line: e.Line})
	}
	return out
}

// attrInt is one attribute as *int; nil when absent or not a whole number.
func attrInt(a render.CryptoAsset, key string) *int {
	if n, ok := a.AttrInt(key); ok {
		return &n
	}
	return nil
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
	appendAIModels(&doc, b)
	// ⚠ THE DEVICE FIRST, BECAUSE IT IS THE PARENT OF THE CRYPTO IT CARRIES.
	// A QBOM's assets hang off its device; a CBOM's hang off a declared project
	// subject. Same components, different parent, and the order is what makes
	// the edges resolvable.
	appendQuantumDevice(&doc, b)
	if b.BOMType == model.BOMTypeCBOM && len(b.CryptoAssets) > 0 {
		appendCryptoAssets(&doc, b, subjectKey(&doc, b))
	}
	return doc
}

// appendCryptoAssets, appendAIModels and appendQuantumDevice map the three
// inventories that had no export path at all.
//
// ⚠ BEFORE THESE, SPDX AND CYCLONEDX EMITTED A VALID, EMPTY DOCUMENT FOR A
// CBOM, AN AIBOM AND A QBOM — SIX DOWNLOADABLE ARTIFACTS THAT SAID NOTHING.
//
// `toExportDocument` read `b.Components`, which the Python canonical builders
// never populate for those types (workers/cbom/normalize/pipeline.py writes
// `crypto_assets`, workers/aibom writes `ai_models`, and a QBOM's document holds
// one `quantum_components` row). So `loadComponents` correctly returned zero
// rows, the loop above produced zero components, and `Serialize` returned a
// document whose `packages`/`components` array was empty. It validated. The UI
// offered both formats for every BOM type, so this was reachable, and the
// failure mode is the worst kind: a customer hands an auditor a conformant file
// that asserts their project contains nothing.
//
// This is the identical bug `appendHardware` above was written to fix, and its
// own comment describes — fixed for HBOM only, and left live for the other
// three for as long as no test rendered a populated fixture in every format.

// subjectKey adds the component the document DESCRIBES, and returns its key.
//
// ⚠ CycloneDX AND SPDX BOTH REFUSE A ROOTLESS DOCUMENT — protobom fails with
// "no root nodes found" — so something has to be the subject. For an SBOM it is
// the root package; for an HBOM it is the device. A CBOM and an AIBOM have no
// natural one: an algorithm is not what the BOM is about, it is what the BOM
// contains.
//
// Declaring each asset a root instead LOOKS fine and is wrong in a way that
// only shows up sometimes: with several assets protobom emits a headless
// document (correct), and with exactly ONE it hoists that asset into
// `metadata.component` — publishing that the thing this BOM describes is
// RSA-2048. A project with one crypto asset is perfectly ordinary.
//
// So the subject is stated explicitly: the project, which is what the document
// is actually about, and which we already carry.
func subjectKey(doc *export.Document, b render.BOM) string {
	const key = "subject"
	name := b.ProjectName
	if name == "" {
		name = "project"
	}
	doc.Components = append(doc.Components, export.Component{
		Key: key, Name: name, PrimaryPurpose: "application",
		Properties: []export.Property{
			{Name: "axebom:bom_type", Value: string(b.BOMType)},
		},
	})
	doc.Roots = append(doc.Roots, key)
	return key
}

// appendCryptoAssets emits the crypto inventory beneath a caller-chosen parent.
//
// ⚠ THE PARENT IS AN ARGUMENT BECAUSE IT DIFFERS BY BOM TYPE. A CBOM's assets
// are contained by the project; a QBOM's are contained by the device they were
// assessed for. Hardcoding either would produce a document asserting the wrong
// containment for the other.
func appendCryptoAssets(doc *export.Document, b render.BOM, parent string) {
	for _, a := range b.CryptoAssets {
		ref := cryptoRef(a)
		doc.Components = append(doc.Components, export.Component{
			Key:  ref,
			Name: a.Name,
			// See export.purposeFor: protobom cannot emit CycloneDX's own
			// `cryptographic-asset` type, so on THIS path an asset serializes as
			// `data` with its real type on `certin:crypto:asset_type`. A CBOM's
			// CycloneDX download no longer takes this path — see cbomCycloneDX;
			// SPDX, and a QBOM's CycloneDX, still do.
			PrimaryPurpose: "cryptographic-asset",
			// The description is what SPDX keeps when it drops every property;
			// see render.CryptoAssetSummary.
			Description: render.CryptoAssetSummary(a, b.Coverage.DerivationSources),
			Properties:  cryptoProperties(a, b.Coverage.DerivationSources),
		})
		doc.Dependencies = append(doc.Dependencies, export.Dependency{
			From: parent, To: ref, Kind: export.KindContains,
		})
	}
}

// cryptoRef is THE export identity of one crypto asset — every standard
// document keys on it, and nothing else may build one.
//
// ⚠ IT WAS `crypto/<type>/<name>`, AND THAT COLLAPSED REAL ASSETS. Type plus
// name is not an identity: cbomkit-theia reports two RSA algorithms (a
// signature and a pke) from one certificate. protobom indexed components by
// that key and silently kept one, the CycloneDX `dependsOn` list carried the
// same ref twice (which the schema forbids), and SPDX emitted two packages
// with one SPDXID. The row id is unique by construction.
//
// ⚠ ONE FUNCTION, SO THE IDENTITY CHANGED IN ONE PLACE. The normalizer now
// records a deterministic `asset_key` (migrations/normalize/0020): unique per
// document, like the row id, and — unlike it — the same for the same asset
// after a re-normalization, so a bom-ref a reviewer noted down still names the
// same asset in the next corrected document. It is also what a QBOM's
// crypto-asset references carry. The row id remains the fallback; SPDX ids are
// derived from whichever this returns by export.spdxSafeID, which hashes the
// full value, so the key's `:`/`;`/`=` never reach an SPDXID.
func cryptoRef(a render.CryptoAsset) string {
	if a.AssetKey != "" {
		return a.AssetKey
	}
	if a.ID != "" {
		return "crypto-" + a.ID
	}
	// No row id: a render model built outside the store, i.e. a test fixture.
	// A digest of everything the asset says keeps two different assets apart;
	// only two byte-identical assets could still collide, and every stored row
	// has an id, so production never reaches this branch.
	raw, _ := json.Marshal(a)
	sum := sha256.Sum256(raw)
	return "crypto-" + hex.EncodeToString(sum[:8])
}

// cryptoProperties are the namespaced properties an asset carries on the
// protobom path (SPDX, and a QBOM's CycloneDX).
//
// ⚠ AxeBOM ANALYSIS UNDER `axebom:`, NEVER `certin:`. The quantum family and
// the deprecation status were emitted as `certin:crypto:algorithm_family` and
// `certin:crypto:deprecation_status` — AxeBOM's own verdicts labelled as
// CERT-In Table 9 fields, in a document handed to a regulator. Only Table 9
// values carry `certin:`.
func cryptoProperties(a render.CryptoAsset, sources map[string]string) []export.Property {
	props := []export.Property{{Name: "certin:crypto:asset_type", Value: a.AssetType}}
	add := func(name, value string) {
		if value != "" {
			props = append(props, export.Property{Name: name, Value: value})
		}
	}
	add("certin:crypto:oid", a.OID)
	add("certin:crypto:cert_subject", a.CertSubject)
	add("certin:crypto:cert_issuer", a.CertIssuer)
	add("axebom:crypto:component_key", a.ComponentKey)
	add("axebom:crypto:quantum_family", a.QuantumFamily)
	add("axebom:crypto:deprecation_status", a.DeprecationStatus)
	add("axebom:qbom:readiness_group", a.QuantumReadinessGroup)
	add("axebom:qbom:pqc_recommendation", a.PQCRecommendation)
	if a.QuantumVulnerable {
		add("axebom:qbom:quantum_vulnerable", "true")
	}
	add("axebom:crypto:engines", strings.Join(a.Engines, ", "))
	if a.PrivateKeyInSource() {
		add("axebom:crypto:private_key_in_source", "true")
	}
	for _, column := range sortedKeys(a.Derivations) {
		add("axebom:crypto:derived:"+column, render.DerivationCitation(a.Derivations[column], sources))
	}
	return props
}

// sortedKeys returns a map's keys in order, so properties built from it are
// byte-reproducible (ADR-0003).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func appendAIModels(doc *export.Document, b render.BOM) {
	if len(b.AIModels) == 0 {
		return
	}
	subject := subjectKey(doc, b)

	for _, m := range b.AIModels {
		key := "ai-model/" + m.Name
		props := []export.Property{}
		// ⚠ FROM THE PROFILE, NOT A HAND-LISTED SET. Table 10's elements live in
		// m.Fields keyed by profile-field id, so a CERT-In revision changes the
		// YAML and this follows — no element list is written here (invariant 2).
		for id, v := range m.Fields {
			if v != "" {
				props = append(props, export.Property{Name: "certin:aibom:" + id, Value: v})
			}
		}
		if m.RiskScore != nil {
			// Namespaced apart, because it is explicitly NOT a CERT-In element
			// and is excluded from both coverage numbers — see render/aibom.go.
			props = append(props, export.Property{
				Name: "axebom:aibom:risk_score", Value: strconv.FormatFloat(*m.RiskScore, 'f', 2, 64),
			})
		}
		if len(m.OwaspLLMTop10) > 0 {
			props = append(props, export.Property{
				Name: "axebom:aibom:owasp_llm_top10", Value: strings.Join(m.OwaspLLMTop10, ", "),
			})
		}

		doc.Components = append(doc.Components, export.Component{
			Key: key, Name: m.Name, PrimaryPurpose: "machine-learning-model",
			Properties: props,
		})
		doc.Dependencies = append(doc.Dependencies, export.Dependency{
			From: subject, To: key, Kind: export.KindContains,
		})

		for _, d := range m.Datasets {
			dk := key + "/dataset/" + d.Name
			doc.Components = append(doc.Components, export.Component{
				Key: dk, Name: d.Name, VersionRaw: d.Version,
				PrimaryPurpose: "data",
				Properties: []export.Property{
					{Name: "certin:aibom:dataset_source", Value: d.Source},
					{Name: "certin:aibom:dataset_license", Value: d.License},
				},
			})
			// A dataset is part OF the model, not a runtime dependency of it.
			doc.Dependencies = append(doc.Dependencies, export.Dependency{
				From: key, To: dk, Kind: export.KindContains,
			})
		}
	}
}

// toMLDocument maps the canonical AIBOM onto the ML-BOM serializer's input.
//
// ⚠ THIS IS THE SECOND MAPPING FOR ONE BOM TYPE, AND BOTH ARE WANTED.
// `toExportDocument` produces the generic SPDX/CycloneDX view every BOM type
// gets — an inventory of components. This produces the ML view: the same models
// carrying `modelCard`, their datasets as `data` components, the inference
// services as `services[]`. A consumer asking "what software is in this project"
// wants the first; one asking "what is this model" wants the second, and neither
// can be derived from the other.
func toMLDocument(b render.BOM) export.MLDocument {
	doc := export.MLDocument{
		GeneratedAt: b.GeneratedAt,
		DocumentID:  b.ReportID,
		ProjectName: b.ProjectName,
		ToolName:    b.ToolName,
		ToolVersion: b.ToolVersion,
	}

	for _, m := range b.AIModels {
		fields := m.Fields
		datasets := make([]export.MLDataset, 0, len(m.Datasets))
		for _, d := range m.Datasets {
			datasets = append(datasets, export.MLDataset{
				Name: d.Name, Version: d.Version, License: d.License,
				Source: d.Source, Format: d.Format,
			})
		}
		doc.Models = append(doc.Models, export.MLModel{
			// ⚠ THE MODEL KEY, NOT THE DISPLAY NAME. It is what every other
			// document about this model is keyed by; a bom-ref built from a name
			// would not survive a model being renamed between scans.
			Key:  mlModelKey(m),
			Name: m.Name,
			// ⚠ EVERY ONE OF THESE GOES THROUGH notProvidedToEmpty. A live
			// export leaked `task: "not-provided"` into the ML-BOM and onward
			// into SPDX 3.0's `typeOfModel`, because only licence and developer
			// were filtered — the sentinel is how OUR document shows a gap, and
			// exporting it asserts it as the answer to every tool that reads one.
			Version: notProvidedToEmpty(fields[model.FieldCertinAibom02ModelVersion]),
			Purl:    mlPurl(m),
			Task:    notProvidedToEmpty(fields[model.FieldCertinAibom03ModelType]),
			Licenses: strings.TrimSpace(
				notProvidedToEmpty(fields[model.FieldCertinAibom05Licensing])),
			Author: notProvidedToEmpty(fields[model.FieldCertinAibom04ModelDeveloper]),
			Architectures: splitList(
				notProvidedToEmpty(fields[model.FieldCertinAibom07MlModelsAlgorithms])),
			Inputs:               notProvidedToEmpty(fields[model.FieldCertinAibom13Input]),
			Outputs:              notProvidedToEmpty(fields[model.FieldCertinAibom14Output]),
			Datasets:             datasets,
			Dependencies:         m.Dependencies,
			Evidence:             m.Evidence,
			FoundBy:              m.FoundBy,
			Verified:             m.Verified,
			IdentityRule:         m.IdentityRule,
			IdentityConfidence:   m.IdentityConfidence,
			IntendedUsage:        fields[model.FieldCertinAibom15IntendedUsage],
			OutOfScopeUsage:      fields[model.FieldCertinAibom16OutOfScopeUsage],
			SecurityRequirements: fields[model.FieldCertinAibom12SecurityRequirements],
			EnvironmentalImpact:  fields[model.FieldCertinAibom17EnvironmentalImpact],
			Fields:               fields,
			RiskScore:            m.RiskScore,
			OwaspLLMTop10:        m.OwaspLLMTop10,
		})
	}

	for _, a := range b.AIAssets {
		doc.Assets = append(doc.Assets, export.MLAsset{
			Type: a.Type, Key: a.Key, Name: a.Name, Provider: a.Provider,
			ServesModel: a.ServesModel, Evidence: a.Evidence,
		})
	}
	return doc
}

// mlModelKey is the stable identity a bom-ref is built from.
//
// The render layer does not carry `model_key` on an AIModel today — the AIBOM
// screens read it from services/aibom — so the name is the fallback, and it is
// an honest one: within a single document the model names are already distinct
// (they come from rows keyed by model_key).
func mlModelKey(m render.AIModel) string {
	// ⚠ THE MERGE KEY FIRST. Two scans of one project produce two documents; a
	// bom-ref built from a display name would not survive the model being
	// renamed upstream, and would collide the moment two models shared a name.
	if m.ModelKey != "" {
		return m.ModelKey
	}
	if m.Name != "" {
		return m.Name
	}
	return "unnamed"
}

// mlPurl returns a real package URL for a model, or "".
//
// ⚠ ONLY THE `purl:` TIER OF THE IDENTITY LADDER IS ONE. A model identified as
// `api:openai/gpt-4o`, `name:huggingface/distilbert-base-uncased` or
// `opaque:<uuid>` has no package URL at all, and minting one would put an
// identifier in the field a consumer RESOLVES, pointing at nothing — with the
// resolution failing later reading as our document being wrong, which it would
// be. The full key travels on `axebom:aibom:model_key` regardless.
func mlPurl(m render.AIModel) string {
	const prefix = "purl:"
	if strings.HasPrefix(m.ModelKey, prefix) {
		return strings.TrimPrefix(m.ModelKey, prefix)
	}
	return ""
}

// notProvidedToEmpty drops the explicit sentinel.
//
// ⚠ INVARIANT 3 REQUIRES THE GAP TO BE VISIBLE IN *OUR* DOCUMENT, and the
// sentinel is how it is. Emitting the literal string "not-provided" as a
// model's licence in a CycloneDX file would assert that as the licence to every
// tool that reads it; absence is how the standard says "not stated".
func notProvidedToEmpty(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), model.NotProvided) {
		return ""
	}
	return v
}

// splitList turns a rendered comma-separated cell back into a list.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func appendQuantumDevice(doc *export.Document, b render.BOM) {
	d := b.QuantumDevice
	if d == nil {
		return
	}
	const key = "qbom/device"
	props := []export.Property{}
	add := func(name, value string) {
		if value != "" {
			props = append(props, export.Property{Name: name, Value: value})
		}
	}
	add("certin:qbom:license_information", d.LicenseInfo)
	add("certin:qbom:communication_protocol", d.CommunicationProtocol)
	add("certin:qbom:hardware", d.Hardware)
	add("certin:qbom:environmental_impact", d.EnvironmentalImpact)
	add("certin:qbom:attestations", d.AttestationSignature)
	if len(d.SoftwareDependencies) > 0 {
		add("certin:qbom:software_dependencies", strings.Join(d.SoftwareDependencies, ", "))
	}
	// ⚠ NAMES THE LENDING DOCUMENT. A QBOM's crypto assets are the project's
	// CBOM, re-grouped — an exported file with no provenance would read as this
	// document's own discovery.
	if b.CryptoAssetsFrom.Present() {
		add("axebom:qbom:crypto_assets_from", b.CryptoAssetsFrom.DocumentID)
		add("axebom:qbom:crypto_assets_generated_at", b.CryptoAssetsFrom.GeneratedAt)
	}

	doc.Components = append(doc.Components, export.Component{
		Key: key, Name: d.ModelName, VersionRaw: d.Version,
		Manufacturer: d.VendorOrigin, PrimaryPurpose: "device", Properties: props,
	})
	doc.Roots = append(doc.Roots, key)

	// The device contains the cryptography assessed for it — and those assets
	// have to be emitted as components too, or the edges point at nothing.
	appendCryptoAssets(doc, b, key)
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
	case "mlbom":
		// The same media type as any other CycloneDX 1.6 document, because it IS
		// one. What makes it an ML-BOM is its contents.
		return export.CycloneDX16JSON.MediaType()
	default:
		return render.JSONMediaType
	}
}
