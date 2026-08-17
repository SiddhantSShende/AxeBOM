package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/model"
	"github.com/encorebom/encorebom/services/report/internal/export"
)

// exportedDocuments serializes a small BOM through the real exporters, so the
// embedding tests run against bytes protobom actually produced rather than a
// hand-written stand-in.
func exportedDocuments(t *testing.T) (spdx, cdx []byte) {
	t.Helper()

	doc := export.Document{
		GeneratedAt: "2026-08-17T09:14:03Z",
		DocumentID:  "0199-report",
		ProjectName: "acme-web",
		ToolName:    "EncoreBOM",
		ToolVersion: "0.1.0",
		Roots:       []string{"purl:pkg:npm/lodash@4.17.20"},
		Components: []export.Component{{
			Key:        "purl:pkg:npm/lodash@4.17.20",
			Name:       "lodash",
			VersionRaw: "4.17.20",
			Purl:       "pkg:npm/lodash@4.17.20",
		}},
	}

	var err error
	if spdx, err = export.Serialize(doc, export.SPDX23JSON); err != nil {
		t.Fatalf("serializing SPDX: %v", err)
	}
	if cdx, err = export.Serialize(doc, export.CycloneDX16JSON); err != nil {
		t.Fatalf("serializing CycloneDX: %v", err)
	}
	return spdx, cdx
}

// TestTheEmbeddedDocumentsAreByteIdentical.
//
// ⚠ THE REASON THIS FILE IS NOT INDENTED. A consumer holding the bundle must be
// able to lift the SPDX document out and verify it against the signature issued
// for the standalone download. json.MarshalIndent would reformat the embedded
// copy and the signature would fail on a document that is genuinely identical.
func TestTheEmbeddedDocumentsAreByteIdentical(t *testing.T) {
	spdx, cdx := exportedDocuments(t)

	data, err := WriteJSON(sampleBOM(), spdx, cdx)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("re-reading the bundle: %v", err)
	}

	if !bytes.Equal(bundle.Documents.SPDX, spdx) {
		t.Errorf("the embedded SPDX document differs from the standalone one.\n"+
			"  standalone: %d bytes\n  embedded:   %d bytes\n"+
			"A signature over the standalone download will not verify against this.",
			len(spdx), len(bundle.Documents.SPDX))
	}
	if !bytes.Equal(bundle.Documents.CycloneDX, cdx) {
		t.Errorf("the embedded CycloneDX document differs from the standalone one")
	}
}

// TestTheBundleIsDeterministic — rendering is a pure function of stored inputs
// (ADR-0003), and a signature over a shuffled document never verifies twice.
func TestTheBundleIsDeterministic(t *testing.T) {
	spdx, cdx := exportedDocuments(t)

	first, err := WriteJSON(sampleBOM(), spdx, cdx)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}
	for i := range 20 {
		again, err := WriteJSON(sampleBOM(), spdx, cdx)
		if err != nil {
			t.Fatalf("writing (iteration %d): %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("the bundle changed between runs on iteration %d", i)
		}
	}
}

// TestJSONDoesNotApplySpreadsheetEscaping.
//
// ⚠ THE ESCAPING IS A SPREADSHEET CONCERN AND BELONGS NOWHERE ELSE. JSON has no
// formula semantics, so prefixing values here would corrupt them — and this is
// the format the XLSX writer points a reader at when it has to truncate, so a
// component genuinely named `=cmd|'/c calc'!A1` must round-trip unchanged.
func TestJSONDoesNotApplySpreadsheetEscaping(t *testing.T) {
	b := sampleBOM()
	b.Components = append(b.Components, Component{
		Key:    "name:npm/hostile",
		Fields: map[string]string{model.FieldCertinSbom01ComponentName: ddePayload},
	})

	data, err := WriteJSON(b, nil, nil)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("re-reading: %v", err)
	}

	last := bundle.Canonical.Components[len(bundle.Canonical.Components)-1]
	if got := last.Fields[model.FieldCertinSbom01ComponentName]; got != ddePayload {
		t.Fatalf("the component name was altered:\n  want %q\n  got  %q", ddePayload, got)
	}
}

// TestAnEmptyListIsNotNull — `null` says "this renderer does not report that";
// `[]` says "we looked and there were none". The second is what we mean, and it
// is the same distinction as `not-provided` versus a blank cell.
func TestAnEmptyListIsNotNull(t *testing.T) {
	b := sampleBOM()
	b.EcosystemsWithNoEngine = nil
	b.Notes = nil

	data, err := WriteJSON(b, nil, nil)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	out := string(data)
	if strings.Contains(out, `"ecosystems_with_no_engine":null`) {
		t.Error("ecosystems_with_no_engine rendered as null")
	}
	if !strings.Contains(out, `"ecosystems_with_no_engine":[]`) {
		t.Error("ecosystems_with_no_engine is missing; the section is mandatory " +
			"even when it has nothing to say")
	}
	if strings.Contains(out, `"notes":null`) {
		t.Error("notes rendered as null")
	}
}

// TestTheBundleCarriesBothCoverageNumbersAndTheirCaveats.
func TestTheBundleCarriesBothCoverageNumbersAndTheirCaveats(t *testing.T) {
	data, err := WriteJSON(sampleBOM(), nil, nil)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("re-reading: %v", err)
	}

	if bundle.Coverage.CompletenessPct == 0 || bundle.Coverage.DeclarationPct == 0 {
		t.Error("a coverage number is missing; both are always published")
	}
	if bundle.Coverage.Formula == "" {
		t.Error("the coverage formula is missing, so the numbers are not auditable")
	}
	if !strings.Contains(bundle.Report.WeightsNote, "EncoreBOM's judgement") {
		t.Error("the bundle does not say whose the weights are")
	}
	if bundle.Report.Scope == "" {
		t.Error("the bundle does not state what the report is and is not")
	}
}

// TestTheWordCompliantDoesNotAppearInJSON — the same contract as the workbook,
// checked over the whole serialized artifact.
func TestTheWordCompliantDoesNotAppearInJSON(t *testing.T) {
	spdx, cdx := exportedDocuments(t)
	data, err := WriteJSON(sampleBOM(), spdx, cdx)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	lowered := strings.ToLower(string(data))
	for _, banned := range []string{"compliant", "certified"} {
		if strings.Contains(lowered, banned) {
			t.Errorf("the bundle contains %q", banned)
		}
	}
}

// TestAMalformedEmbeddedDocumentIsRefused — a truncated upload or a failed
// serialization must not produce a bundle that parses as valid JSON everywhere
// except inside the document a reviewer actually opens.
func TestAMalformedEmbeddedDocumentIsRefused(t *testing.T) {
	if _, err := WriteJSON(sampleBOM(), []byte(`{"spdxVersion":`), nil); err == nil {
		t.Fatal("a truncated SPDX document was embedded without complaint")
	}
	if _, err := WriteJSON(sampleBOM(), nil, []byte("not json")); err == nil {
		t.Fatal("a non-JSON CycloneDX document was embedded without complaint")
	}
}

// TestACBOMBundleIsRefused — the same type-discrimination refusal as the
// spreadsheet, so the two formats cannot disagree about what a CBOM is.
func TestACBOMBundleIsRefused(t *testing.T) {
	b := sampleBOM()
	b.BOMType = model.BOMTypeCBOM
	if _, err := WriteJSON(b, nil, nil); err == nil {
		t.Fatal("a CBOM bundle was rendered against the flat SBOM field set")
	}
}
