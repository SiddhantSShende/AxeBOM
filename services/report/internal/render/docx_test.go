package render

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// ⚠ TestThePDFRendererCannotReachTheNetwork (pdf_test.go) ALREADY COVERS
// docx.go — it scans every non-test .go file in this package directory, so a
// forbidden import added here would already fail that check. No separate
// import-scan test is duplicated here for that reason; see its own doc
// comment for the reasoning this file relies on.

// TestWriteDOCXProducesAValidDocument unzips the real output and confirms
// every required part is present and word/document.xml is well-formed XML —
// not just "some bytes came out."
func TestWriteDOCXProducesAValidDocument(t *testing.T) {
	var buf bytes.Buffer
	result, err := WriteDOCX(&buf, sampleBOM(), DOCXOptions{})
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if result.Truncated {
		t.Fatal("a small sample BOM should never truncate")
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("the output is not a valid zip: %v", err)
	}

	want := map[string]bool{
		"[Content_Types].xml":          false,
		"_rels/.rels":                  false,
		"word/document.xml":            false,
		"word/_rels/document.xml.rels": false,
	}
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing required part %q", name)
		}
	}

	doc := mustReadZipFile(t, zr, "word/document.xml")
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("word/document.xml is not well-formed XML: %v", err)
		}
	}
	if !strings.Contains(string(doc), "acme-web") {
		t.Error("the document does not contain the project name from the sample BOM")
	}
}

// TestWriteDOCXIncludesTheSameCERTInDisclosuresAsPDF is the actual point of
// bringing docx up to WritePDF's own structure (see WriteDOCX's own doc
// comment): a reader asked for a Word document must get the same mandatory
// disclosures and CERT-In citations the PDF already carries, not a lighter
// summary. Every string here is real, shared content — weightsNote,
// scopeNote and model.PracticeFields' canonical list all come from bom.go,
// the exact same values pdf_test.go's own fixtures exercise for PDF.
func TestWriteDOCXIncludesTheSameCERTInDisclosuresAsPDF(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteDOCX(&buf, sampleBOM(), DOCXOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("the output is not a valid zip: %v", err)
	}
	doc := string(mustReadZipFile(t, zr, "word/document.xml"))

	for _, want := range []string{
		// The mandatory scope/weighting disclosures (bom.go's scopeNote,
		// weightsNote) — omitting either is exactly what a customer reading
		// only the summary percentage would misread as a compliance claim.
		"observed and what could not be",
		"Field weights are AxeBOM",
		// The per-field CERT-In coverage breakdown table actually renders,
		// not just the two summary percentages.
		"Per-field breakdown",
		// Practices renders the FULL canonical list (model.PracticeFields),
		// not only the one entry sampleBOM happens to set — proving a
		// sub-element nobody recorded still appears with its gap stated.
		"Never recorded for this project.",
		// VEX and remediation sections exist at all (previously entirely
		// absent from this renderer).
		"VEX statements",
		"Remediation, workarounds and mitigation",
		// The CERT-In §4.2 field 21 / PURL subpath-separator citation from
		// methodologyPage.
		"CERT-In",
		"field 21",
		// The document is signed and says how to verify it.
		"Ed25519 signature",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("document.xml does not contain %q — a CERT-In disclosure pdf.go carries is missing from docx", want)
		}
	}
}

// TestAHostileFieldValueRendersAsTextNotStructureOrAField is the same
// guarantee TestAHostileDescriptionRendersAsText (pdf_test.go) makes for
// PDF, applied to docx's own real injection surface: MS Word field codes
// (HYPERLINK, INCLUDETEXT and similar) are live when they appear as document
// structure, and a naive template that concatenated raw text into markup
// would let a component name close a </w:t> run early and open one. This
// proves the payload survives only as literal displayed text.
func TestAHostileFieldValueRendersAsTextNotStructureOrAField(t *testing.T) {
	hostile := `</w:t></w:r><w:fldSimple w:instr="HYPERLINK &quot;http://attacker.example&quot;"><w:r><w:t>click</w:t></w:r></w:fldSimple><w:r><w:t xml:space="preserve">`

	b := sampleBOM()
	b.Components = append(b.Components, Component{
		Key:       "name:npm/hostile",
		Ecosystem: "npm",
		Fields: map[string]string{
			model.FieldCertinSbom01ComponentName: hostile,
		},
	})

	var buf bytes.Buffer
	if _, err := WriteDOCX(&buf, b, DOCXOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("the output is not a valid zip: %v", err)
	}
	doc := string(mustReadZipFile(t, zr, "word/document.xml"))

	// The document must still parse — a successful structural break-out
	// would very likely also produce invalid XML (an unbalanced </w:t></w:r>
	// followed by content outside any run), so this is the first signal.
	dec := xml.NewDecoder(strings.NewReader(doc))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("the hostile payload broke document.xml's XML structure "+
				"(err=%v) — it escaped its text run", err)
		}
	}

	// And the literal live-field marker must never appear unescaped: if it
	// did, Word would render it as an actual clickable HYPERLINK field
	// pointed at attacker.example instead of the text a component actually
	// named itself.
	if strings.Contains(doc, `<w:fldSimple w:instr="HYPERLINK`) {
		t.Fatal("the hostile field code appears as LIVE document structure, not escaped text")
	}
	if !strings.Contains(doc, "&lt;/w:t&gt;") {
		t.Fatal("the hostile payload does not appear escaped anywhere — it may have been dropped, not merely failed to inject")
	}
}

// TestDOCXTruncatesTheComponentTableWithAStatedNote — the DefaultComponentCap
// equivalent of PDF's DefaultPageCap: a table this large must be cut, not
// silently rendered forever, and the cut must say so.
func TestDOCXTruncatesTheComponentTableWithAStatedNote(t *testing.T) {
	b := sampleBOM()
	b.Components = nil
	for i := 0; i < 12; i++ {
		b.Components = append(b.Components, Component{
			Key:       "name:npm/pkg" + string(rune('a'+i)),
			Ecosystem: "npm",
			Fields:    map[string]string{model.FieldCertinSbom01ComponentName: "pkg"},
		})
	}

	var buf bytes.Buffer
	result, err := WriteDOCX(&buf, b, DOCXOptions{ComponentCap: 5})
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !result.Truncated {
		t.Fatal("expected truncation with 12 components and a cap of 5")
	}
	if result.TruncationNote == "" {
		t.Error("a truncated render must state so")
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("the output is not a valid zip: %v", err)
	}
	doc := string(mustReadZipFile(t, zr, "word/document.xml"))
	if !strings.Contains(doc, "Truncated") {
		t.Error("the document itself does not mention the truncation")
	}
}

// TestWriteDOCXIsByteReproducible mirrors PDF's own
// TestThePDFIsByteReproducible — a signature is over specific bytes
// (ADR-0003), so re-rendering the same stored data must produce the same
// bytes, not merely the same visible content. archive/zip stamps a
// modification time per entry unless told not to; if this ever regresses it
// will be because a future edit switches Create() for CreateHeader() without
// carrying a fixed Modified time forward.
func TestWriteDOCXIsByteReproducible(t *testing.T) {
	b := sampleBOM()

	var first bytes.Buffer
	if _, err := WriteDOCX(&first, b, DOCXOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	for i := range 10 {
		var again bytes.Buffer
		if _, err := WriteDOCX(&again, b, DOCXOptions{}); err != nil {
			t.Fatalf("rendering (iteration %d): %v", i, err)
		}
		if !bytes.Equal(first.Bytes(), again.Bytes()) {
			t.Fatalf("the DOCX changed between renders on iteration %d "+
				"(%d vs %d bytes)", i, first.Len(), again.Len())
		}
	}
}

func mustReadZipFile(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening %s: %v", name, err)
		}
		defer func() { _ = rc.Close() }()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return data
	}
	t.Fatalf("%s not found in the zip", name)
	return nil
}
