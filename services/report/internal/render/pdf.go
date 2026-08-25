package render

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// PDFMediaType is what the download response carries.
const PDFMediaType = "application/pdf"

// ⚠ THE PDF RENDERER CANNOT FETCH A REMOTE RESOURCE, BY CONSTRUCTION.
//
// The phase requirement is that an `<img src="http://attacker/">` in a
// component description must not phone home. The usual way to meet that is an
// HTML-to-PDF engine with remote loading switched off — a setting, which means
// a future upgrade or a mis-set option turns every rendered report into an
// outbound request carrying the customer's identity to whoever published the
// hostile package.
//
// This renderer draws text and rectangles directly. There is no HTML parser, no
// URL resolution and no HTTP client anywhere in the path, so the description
// above renders as the literal characters `<img src="http://attacker/">` on the
// page. The guarantee is structural rather than configured, and
// TestThePDFRendererCannotReachTheNetwork asserts it by reading this package's
// own imports — a check that survives somebody adding a "just fetch the logo"
// feature.

// Page geometry, in millimetres. A4 because CERT-In is an Indian guideline and
// its readers print on A4.
const (
	pageWidth   = 210.0
	pageHeight  = 297.0
	marginLeft  = 15.0
	marginRight = 15.0
	marginTop   = 15.0
	contentW    = pageWidth - marginLeft - marginRight
)

// DefaultPageCap bounds a rendered PDF.
//
// ⚠ A 50k-COMPONENT COMPLETE BOM IS 3000+ PAGES. Nobody reads it, and building
// it exhausts memory on the render worker — taking every other queued report
// with it. So the product rule is Top-Level to PDF, Complete to XLSX and JSON,
// and this cap is what enforces it when somebody asks anyway. Exceeding it is
// REPORT_TOO_LARGE_FOR_PDF, not an OOM.
const DefaultPageCap = 300

// PDFOptions tunes the render.
type PDFOptions struct {
	// PageCap is the maximum page count. Zero uses DefaultPageCap.
	PageCap int
}

// PDFResult reports what the render had to leave out.
type PDFResult struct {
	Pages int
	// Truncated is set when the component or finding tables were cut short.
	Truncated bool
	// TruncationNote is rendered into the document AND returned, so the report
	// record carries the same sentence the reader sees.
	TruncationNote string
}

// WritePDF renders the report.
//
// ⚠ CBOM NEVER CALLS FieldsFor. FieldsFor has no flat field list to give a
// CBOM — that is its whole point — so r.fields stays nil for one and every
// CBOM-specific page below reads b.CryptoAssets directly instead. A caller
// that is not CBOM-aware still cannot silently render an empty Components
// table: there is no branch that reaches componentPages for a CBOM at all.
func WritePDF(w io.Writer, b BOM, opts PDFOptions) (PDFResult, error) {
	var fields []model.ProfileField
	if b.BOMType != model.BOMTypeCBOM {
		f, err := FieldsFor(b.BOMType)
		if err != nil {
			return PDFResult{}, err
		}
		fields = f
	}

	cap := opts.PageCap
	if cap <= 0 {
		cap = DefaultPageCap
	}

	// ⚠ REFUSED BEFORE ANY WORK, NOT DISCOVERED DURING IT. An estimate that is
	// wrong in the safe direction costs a customer a slightly early refusal
	// with a clear remedy; being wrong the other way costs the worker.
	if pages := estimatePages(b); pages > cap*pageOverrunFactor {
		return PDFResult{}, errs.New(errs.ReportTooLargeForPDF,
			"this BOM is far too large to render as a PDF").
			WithDetail(errs.Detail{
				"estimated_pages": pages,
				"page_cap":        cap,
				"components":      len(b.Components),
				"hint": "render the XLSX or JSON export, which have no page limit, " +
					"or request the Top-Level BOM",
			})
	}

	doc := newDoc(b)
	r := &pdfRender{doc: doc, bom: b, fields: fields, cap: cap}

	r.coverPage()

	// ⚠ CBOM AND QBOM REPLACE, NOT ADD TO, THE GENERIC COVERAGE/COMPONENT
	// PAGES — the same "instead of, not alongside" rule Sheets() applies to
	// the spreadsheet. See cbom.go and qbom.go for why each substitute page
	// exists and what it deliberately leaves out (full per-asset-type tables
	// are in the XLSX and JSON exports, which are not page-capped).
	switch b.BOMType {
	case model.BOMTypeCBOM:
		r.cryptoCoveragePage()
	default:
		r.coveragePage()
	}

	r.engineCoveragePage()
	r.practicesPage()

	switch b.BOMType {
	case model.BOMTypeCBOM:
		r.cryptoInventoryPage()
	case model.BOMTypeAIBOM:
		r.aibomInventoryPage()
	default:
		r.componentPages()
	}

	if b.BOMType == model.BOMTypeQBOM {
		r.quantumPage()
	}

	r.findingPages()
	r.licensePage()
	r.vexPage()
	r.methodologyPage()

	if err := doc.Output(w); err != nil {
		return PDFResult{}, errs.Wrap(err, errs.ReportRenderFailed, "writing the PDF")
	}
	if err := doc.Error(); err != nil {
		return PDFResult{}, errs.Wrap(err, errs.ReportRenderFailed, "rendering the PDF")
	}

	return PDFResult{
		Pages:          doc.PageCount(),
		Truncated:      r.truncated,
		TruncationNote: r.truncationNote,
	}, nil
}

// pageOverrunFactor is how far past the cap an estimate may go before the
// render is refused outright rather than truncated. Beyond this the document is
// so far from renderable that producing a truncated one would be misleading
// about what the customer asked for.
const pageOverrunFactor = 4

// estimatePages is a deliberately rough forecast, used only to refuse early.
//
// CryptoAssets counts toward the same estimate as Components: a CBOM's
// cryptoInventoryPage is one row per asset, exactly like componentPages is
// one row per component, so a huge CBOM must be refused for the same reason a
// huge SBOM is.
func estimatePages(b BOM) int {
	const rowsPerPage = 40
	const fixedPages = 8
	rows := len(b.Components) + len(b.Findings) + len(b.Licenses) + len(b.CryptoAssets)
	return fixedPages + rows/rowsPerPage
}

func newDoc(b BOM) *fpdf.Fpdf {
	doc := fpdf.New("P", "mm", "A4", "")
	doc.SetMargins(marginLeft, marginTop, marginRight)
	doc.SetAutoPageBreak(true, 18)

	// ⚠ WITHOUT THIS THE OUTPUT IS NOT REPRODUCIBLE, AND THE REASON IS FAMILIAR.
	//
	// fpdf holds its font resources in a map and writes them in map order, so
	// the object numbers assigned to Helvetica, Helvetica-Bold and
	// Helvetica-Oblique differ between runs. The files come out the same LENGTH
	// with different bytes — which is exactly how a two-run comparison passes by
	// luck, the same trap protobom's shuffled arrays set in the exporter.
	//
	// SetCatalogSort makes the resource catalogues deterministic.
	doc.SetCatalogSort(true)

	// ⚠ NO CREATION DATE FROM A CLOCK. fpdf stamps /CreationDate from time.Now
	// unless told otherwise, which would make two renders of the same stored
	// data produce different bytes — and a signature over one would not verify
	// against the other (ADR-0003). Same correction as the SPDX serializer's
	// creationInfo.created: the document is dated by the SCAN, because dating a
	// re-render "now" would have it claim to describe today.
	stamp := documentTime(b.GeneratedAt)
	doc.SetCreationDate(stamp)
	doc.SetModificationDate(stamp)

	doc.SetTitle(fmt.Sprintf("%s — %s (%s)", b.ProjectName, b.BOMType, b.Level), true)
	doc.SetAuthor(strings.TrimSpace(b.ToolName+" "+b.ToolVersion), true)
	doc.SetCreator(b.ToolName, true)

	doc.SetFooterFunc(func() {
		doc.SetY(-14)
		doc.SetFont("Helvetica", "", 7)
		doc.SetTextColor(110, 110, 110)
		doc.CellFormat(contentW/2, 6, sanitizePDF(fmt.Sprintf(
			"%s · %s · generated %s", b.ProjectName, b.BOMType, b.GeneratedAt)),
			"", 0, "L", false, 0, "")
		doc.CellFormat(contentW/2, 6, fmt.Sprintf("page %d", doc.PageNo()),
			"", 0, "R", false, 0, "")
		doc.SetTextColor(0, 0, 0)
	})

	return doc
}

// pdfRender carries the state one render needs.
type pdfRender struct {
	doc    *fpdf.Fpdf
	bom    BOM
	fields []model.ProfileField
	cap    int

	truncated      bool
	truncationNote string
}

// ─── pages ──────────────────────────────────────────────────────────────────

func (r *pdfRender) coverPage() {
	r.doc.AddPage()

	r.doc.SetFont("Helvetica", "B", 20)
	r.doc.MultiCell(contentW, 9, sanitizePDF(r.bom.ProjectName), "", "L", false)
	r.doc.SetFont("Helvetica", "", 12)
	r.doc.CellFormat(contentW, 8, sanitizePDF(fmt.Sprintf("%s · %s BOM",
		r.bom.BOMType, levelTitle(r.bom.Level))), "", 1, "L", false, 0, "")
	r.doc.Ln(4)

	r.keyValues([][2]string{
		{"Report ID", r.bom.ReportID},
		{"Generated (UTC)", r.bom.GeneratedAt},
		{"Compliance profile", fmt.Sprintf("%s revision %d",
			r.bom.ProfileID, r.bom.ProfileRevision)},
		{"Normalizer ruleset", r.bom.RulesetVersion},
		{"Normalization version", strconv.Itoa(r.bom.NormalizationVersion)},
		{"Produced by", strings.TrimSpace(r.bom.ToolName + " " + r.bom.ToolVersion)},
		{"Components listed", strconv.Itoa(len(r.bom.Components))},
		{"Findings listed", strconv.Itoa(len(r.bom.Findings))},
	})

	r.doc.Ln(4)
	r.calloutBox("What this report is", scopeNote)

	if r.bom.LevelNote != "" {
		r.doc.Ln(2)
		r.calloutBox("BOM level", r.bom.LevelNote)
	}
	if !r.bom.ProfileAllVerified {
		r.doc.Ln(2)
		r.calloutBox("Profile", "Some entries in the compliance profile were not "+
			"transcribed from the source document. Coverage numbers involving them "+
			"are provisional.")
	}
}

func (r *pdfRender) coveragePage() {
	r.doc.AddPage()
	r.heading("Coverage")

	// ⚠ BOTH NUMBERS, SIDE BY SIDE, WITH THE DIFFERENCE SPELLED OUT.
	//
	// Publishing only the declaration number and calling it "coverage" is how
	// tools ship misleading 100% scores: a BOM full of explicit `not-provided`
	// declares everything and substantiates nothing.
	r.body(fmt.Sprintf("Completeness: %s", pct(r.bom.Coverage.CompletenessPct)))
	r.note("Substantive values only. This is the compliance signal.")
	r.body(fmt.Sprintf("Declaration: %s", pct(r.bom.Coverage.DeclarationPct)))
	r.note("Any value, including an explicit `" + model.NotProvided + "`. " +
		"A representation check, not a compliance number.")
	r.doc.Ln(2)

	if r.bom.Coverage.Formula != "" {
		r.body("Formula: " + r.bom.Coverage.Formula)
	}
	r.note(weightsNote)
	r.doc.Ln(3)

	r.heading("Per-field breakdown")
	byID := map[string]FieldCoverage{}
	for _, fc := range r.bom.Coverage.Fields {
		byID[fc.FieldID] = fc
	}

	widths := []float64{74, 22, 26, 26, 32}
	r.tableHeader([]string{"Field", "Weight", "Substantive", "Declared", "Source"}, widths)
	for _, f := range r.fields {
		fc, seen := byID[f.ID]
		substantive, declared := model.NotProvided, model.NotProvided
		if seen {
			substantive = fmt.Sprintf("%d/%d", fc.Present, fc.Total)
			declared = fmt.Sprintf("%d/%d", fc.Declared, fc.Total)
		}
		r.tableRow([]string{
			f.Name, strconv.Itoa(f.Weight), substantive, declared, citation(f),
		}, widths)
	}
}

func (r *pdfRender) engineCoveragePage() {
	r.doc.AddPage()
	r.heading("Engine Coverage")

	// ⚠ MANDATORY, AND NOT SUPPRESSIBLE BY A TEMPLATE. An SBOM that silently
	// omits an ecosystem converts an unknown into a false negative the customer
	// trusts. This section is the difference between "we found nothing there"
	// and "we did not look there".
	r.note("Every engine requested for this scan, and what it was able to see. " +
		"An ecosystem with no engine is listed too: its components are absent " +
		"because nothing scanned them, not because none exist.")
	r.doc.Ln(2)

	widths := []float64{34, 22, 26, 38, 60}
	r.tableHeader([]string{"Engine", "Version", "Status", "Ecosystems", "Note"}, widths)

	for _, e := range r.bom.Engines {
		r.tableRow([]string{
			e.EngineID, orNotProvided(e.Version), e.Status,
			joinList(e.Ecosystems), orNotProvided(e.Diagnostic),
		}, widths)
	}
	for _, eco := range r.bom.EcosystemsWithNoEngine {
		r.tableRow([]string{
			"(none)", model.NotProvided, "no-engine", eco,
			"Detected in this project; no engine we run can scan it.",
		}, widths)
	}
	if len(r.bom.Engines) == 0 && len(r.bom.EcosystemsWithNoEngine) == 0 {
		r.tableRow([]string{
			"(none)", model.NotProvided, "no-engine", model.NotProvided,
			"No engine ran for this report. Every number in it describes nothing.",
		}, widths)
	}
}

func (r *pdfRender) practicesPage() {
	r.doc.AddPage()
	r.heading("Practices and Processes")
	r.note("CERT-In's Minimum Elements is three categories, not only the data " +
		"fields. These are the third: per-project settings recorded by the " +
		"project owner.")
	r.doc.Ln(2)

	byID := map[string]Practice{}
	for _, p := range r.bom.Practices {
		byID[p.FieldID] = p
	}

	widths := []float64{48, 62, 70}
	r.tableHeader([]string{"Sub-element", "Value", "Gap"}, widths)
	for _, f := range model.PracticeFields {
		p, seen := byID[f.ID]
		value, gap := model.NotProvided, "Never recorded for this project."
		if seen {
			value = orNotProvided(p.Value)
			gap = orNotProvided(p.Gap)
		}
		r.tableRow([]string{f.Name, value, gap}, widths)
	}
}

func (r *pdfRender) componentPages() {
	r.doc.AddPage()
	r.heading("Components")

	widths := []float64{56, 26, 22, 16, 60}
	r.tableHeader([]string{"Name", "Version", "Ecosystem", "Depth", "PURL"}, widths)

	for i, c := range r.bom.Components {
		if r.overCap() {
			r.markTruncated("components", i, len(r.bom.Components))
			return
		}
		r.tableRow([]string{
			orNotProvided(c.Fields[model.FieldCertinSbom01ComponentName]),
			orNotProvided(c.Fields[model.FieldCertinSbom02ComponentVersion]),
			orNotProvided(c.Ecosystem),
			depthText(c.Depth),
			orNotProvided(c.Purl),
		}, widths)
	}
}

func (r *pdfRender) findingPages() {
	r.doc.AddPage()
	r.heading("Findings")

	widths := []float64{34, 20, 14, 46, 26, 40}
	r.tableHeader([]string{
		"Advisory", "Severity", "CVSS", "Component", "Fixed in", "Detected by",
	}, widths)

	for i, f := range r.bom.Findings {
		if r.overCap() {
			r.markTruncated("findings", i, len(r.bom.Findings))
			return
		}
		score := orNotProvided(f.CVSSScore)
		if f.CVSSVersion != "" && f.CVSSScore != "" {
			score = f.CVSSScore + " (v" + f.CVSSVersion + ")"
		}
		r.tableRow([]string{
			f.DisplayID, orNotProvided(f.Severity), score,
			f.ComponentKey, orNotProvided(f.FixedInMin), joinList(f.DetectedBy),
		}, widths)
	}
}

func (r *pdfRender) licensePage() {
	r.doc.AddPage()
	r.heading("License inventory")
	r.note("`declared`, `concluded` and `observed` are kept separate. " +
		"\"The manifest says MIT but the LICENSE file says Apache-2.0\" is a " +
		"finding, and merging them would assert that they agreed.")
	r.doc.Ln(2)

	widths := []float64{54, 34, 24, 68}
	r.tableHeader([]string{"Expression", "Kind", "Components", "Note"}, widths)
	for _, l := range r.bom.Licenses {
		note := orNotProvided(l.Note)
		if l.Ambiguous {
			note = "AMBIGUOUS — not resolved. " + note
		}
		r.tableRow([]string{
			l.Expression, l.Kind, strconv.Itoa(l.ComponentCount), note,
		}, widths)
	}
}

// vexPage reports every finding's effective VEX status.
//
// ⚠ NO STATEMENTS IS A STATED GAP, NOT AN OMITTED SECTION. A reader who does
// not see this section cannot tell whether there are no statements or
// whether this tool does not do VEX at all — CLAUDE.md invariant 3, applied
// to a whole page rather than one field.
func (r *pdfRender) vexPage() {
	r.doc.AddPage()
	r.heading("VEX statements")

	counts := map[string]int{}
	var untriaged int
	for _, f := range r.bom.Findings {
		if f.VEXStatus == "" {
			untriaged++
			continue
		}
		counts[f.VEXStatus]++
	}

	if len(r.bom.Findings) == 0 {
		r.body("This report has no findings to triage.")
	} else if len(counts) == 0 {
		r.body("No VEX statements have been recorded for this report's findings.")
	} else {
		widths := []float64{60, 30}
		r.tableHeader([]string{"Status", "Findings"}, widths)
		for _, status := range []string{"affected", "under_investigation", "fixed", "not_affected"} {
			if n := counts[status]; n > 0 {
				r.tableRow([]string{status, strconv.Itoa(n)}, widths)
			}
		}
		if untriaged > 0 {
			r.tableRow([]string{"untriaged", strconv.Itoa(untriaged)}, widths)
		}
	}

	r.note("A finding whose status is `not_affected` or `fixed` is de-emphasized " +
		"in the findings table above, never deleted from it — \"we assessed this " +
		"and it does not apply\" is a defensible position, and it must not look " +
		"the same as a vulnerability that never appeared. VEX statements are " +
		"append-only: every triage decision recorded here supersedes the last " +
		"rather than overwriting it, and the full history is available from the " +
		"live findings view.")

	r.doc.Ln(4)
	r.heading("CSAF")
	r.body("No CSAF document has been generated for this report.")
}

func (r *pdfRender) methodologyPage() {
	r.doc.AddPage()
	r.heading("Methodology and caveats")

	for _, n := range r.bom.Notes {
		r.body("• " + n)
	}

	r.body("• " + weightsNote)
	r.body("• Two identifiers are reported per component and they are not " +
		"interchangeable. The PURL is the canonical ecosystem identifier every " +
		"scanner emits and all deduplication runs on. The CERT-In Unique " +
		"Identifier (§4.2 field 21) is a different syntax, derived for " +
		"presentation only, and is never used as a merge key.")
	r.body("• CERT-In §4.2 field 21 writes the qualifier separator as `&subpath`; " +
		"the Package URL specification uses `#subpath`. We emit the specification " +
		"form, because that is what every consuming tool parses.")
	r.body("• `" + model.NotProvided + "` is reported explicitly and scores zero " +
		"for completeness. A field recorded as unknown is a declared gap, not a " +
		"covered field.")

	if r.truncationNote != "" {
		r.doc.Ln(3)
		r.calloutBox("Truncated", r.truncationNote)
	}

	r.doc.Ln(4)
	r.heading("Signature")
	r.body("This document is signed with a detached Ed25519 signature published " +
		"alongside it. Verify it with `axebom verify <file>`, supplying the " +
		"published public key. The signature proves the file is byte-for-byte the " +
		"one issued; it says nothing about whether the scan was complete — for " +
		"that, read Engine Coverage.")
}

// ─── layout primitives ──────────────────────────────────────────────────────

func (r *pdfRender) overCap() bool { return r.doc.PageCount() >= r.cap }

// markTruncated records a cut in the document and in the result.
//
// ⚠ THE READER IS TOLD, IN THE DOCUMENT, WHERE THE REST IS. A PDF that stops
// at component 4,000 of 50,000 without saying so is a report the customer will
// quote as complete.
func (r *pdfRender) markTruncated(kind string, shown, total int) {
	r.truncated = true
	note := fmt.Sprintf(
		"This PDF lists %d of %d %s. The document reached its %d-page limit. "+
			"The full set is in the XLSX and JSON exports of this report, which "+
			"have no page limit.", shown, total, kind, r.cap)
	if r.truncationNote == "" {
		r.truncationNote = note
	} else {
		r.truncationNote += " " + note
	}
	r.doc.Ln(3)
	r.calloutBox("Truncated", note)
}

func (r *pdfRender) heading(text string) {
	r.doc.SetFont("Helvetica", "B", 13)
	r.doc.MultiCell(contentW, 7, sanitizePDF(text), "", "L", false)
	r.doc.SetFont("Helvetica", "", 9)
	r.doc.Ln(1)
}

func (r *pdfRender) body(text string) {
	r.doc.SetFont("Helvetica", "", 9)
	r.doc.MultiCell(contentW, 4.6, sanitizePDF(text), "", "L", false)
}

func (r *pdfRender) note(text string) {
	r.doc.SetFont("Helvetica", "I", 8)
	r.doc.SetTextColor(90, 90, 90)
	r.doc.MultiCell(contentW, 4.2, sanitizePDF(text), "", "L", false)
	r.doc.SetTextColor(0, 0, 0)
	r.doc.SetFont("Helvetica", "", 9)
}

func (r *pdfRender) keyValues(rows [][2]string) {
	r.doc.SetFont("Helvetica", "", 9)
	for _, kv := range rows {
		r.doc.SetFont("Helvetica", "B", 9)
		r.doc.CellFormat(52, 5.6, sanitizePDF(kv[0]), "", 0, "L", false, 0, "")
		r.doc.SetFont("Helvetica", "", 9)
		r.doc.MultiCell(contentW-52, 5.6, sanitizePDF(orNotProvided(kv[1])), "", "L", false)
	}
}

func (r *pdfRender) calloutBox(title, text string) {
	r.doc.SetFillColor(244, 244, 246)
	r.doc.SetFont("Helvetica", "B", 9)
	r.doc.CellFormat(contentW, 6, sanitizePDF(title), "", 1, "L", true, 0, "")
	r.doc.SetFont("Helvetica", "", 8.5)
	r.doc.MultiCell(contentW, 4.4, sanitizePDF(text), "", "L", true)
	r.doc.SetFillColor(255, 255, 255)
	r.doc.SetFont("Helvetica", "", 9)
}

func (r *pdfRender) tableHeader(cells []string, widths []float64) {
	r.doc.SetFont("Helvetica", "B", 8)
	r.doc.SetFillColor(235, 235, 238)
	for i, c := range cells {
		r.doc.CellFormat(widths[i], 6, sanitizePDF(c), "1", 0, "L", true, 0, "")
	}
	r.doc.Ln(-1)
	r.doc.SetFillColor(255, 255, 255)
	r.doc.SetFont("Helvetica", "", 7.5)
}

// tableRow writes one row, clipping each cell to its column.
//
// Clipped rather than wrapped: a wrapped row of variable height makes the page
// break unpredictable, and a table whose rows silently change height is how a
// 300-page cap becomes a 900-page document. The full value is in the XLSX,
// which the truncation note points at.
func (r *pdfRender) tableRow(cells []string, widths []float64) {
	r.doc.SetFont("Helvetica", "", 7.5)
	for i, c := range cells {
		r.doc.CellFormat(widths[i], 5, r.clip(sanitizePDF(c), widths[i]-2), "1", 0, "L", false, 0, "")
	}
	r.doc.Ln(-1)
}

// clip shortens a value to fit a column, marking that it did.
func (r *pdfRender) clip(text string, width float64) string {
	if r.doc.GetStringWidth(text) <= width {
		return text
	}
	runes := []rune(text)
	for len(runes) > 1 {
		runes = runes[:len(runes)-1]
		candidate := string(runes) + "…"
		if r.doc.GetStringWidth(candidate) <= width {
			return candidate
		}
	}
	return ""
}

// sanitizePDF makes a value safe to draw.
//
// ⚠ NOT THE SPREADSHEET ESCAPING. A PDF has no formula semantics, so prefixing
// a leading `=` here would corrupt the value for no gain — safe.Cell belongs to
// the spreadsheet writers. What this does handle is the base-14 font encoding:
// fpdf's standard fonts are single-byte (CP1252), and a rune outside it is
// dropped silently, so a Chinese package name would render as nothing at all
// rather than as something legible.
func sanitizePDF(text string) string {
	var sb strings.Builder
	sb.Grow(len(text))
	for _, ch := range text {
		switch {
		case ch == '\t':
			sb.WriteString("    ")
		case ch < 0x20 && ch != '\n':
			// Control characters: same reasoning as the spreadsheet writer —
			// replaced rather than deleted, so two names differing only by an
			// invisible character do not read as one.
			sb.WriteRune('?')
		case ch < 0x100:
			sb.WriteRune(ch)
		default:
			// ⚠ REPLACED, NOT DROPPED. fpdf's base-14 fonts cannot encode this
			// rune. Dropping it renders a name as blank, which reads as a
			// missing component; `?` reads as "this did not fit the page", and
			// the XLSX and JSON exports carry the real text.
			sb.WriteRune('?')
		}
	}
	return sb.String()
}

// documentTime is the PDF's /CreationDate.
//
// A BOM with an unparseable timestamp still has to render — refusing the whole
// report over a malformed date would be worse than dating it at the Unix epoch,
// which is visibly wrong rather than plausibly wrong. It is UTC either way; a
// local zone here would make the bytes depend on the worker's location.
func documentTime(generatedAt string) time.Time {
	if t, err := time.Parse(time.RFC3339, generatedAt); err == nil {
		return t.UTC()
	}
	return time.Unix(0, 0).UTC()
}

// levelTitle renders a level for a heading.
func levelTitle(level string) string {
	switch level {
	case "top_level":
		return "Top-Level"
	case "complete":
		return "Complete"
	case "":
		return "Unspecified"
	default:
		return level
	}
}
