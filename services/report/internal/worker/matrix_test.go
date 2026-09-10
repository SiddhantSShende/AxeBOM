package worker

import (
	"archive/zip"
	"bytes"
	"html"
	"io"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/report/internal/pdftext"
	"github.com/axebom/axebom/services/report/internal/render"
	"github.com/axebom/axebom/services/report/internal/store"
)

// TestEveryFormatCarriesEveryBOMTypesData.
//
// ⚠ THE TEST WHOSE ABSENCE COST SIX BROKEN ARTIFACTS.
//
// `go test ./services/report/...` passed completely while SPDX and CycloneDX
// emitted a valid, EMPTY document for CBOM, AIBOM and QBOM; while a Word AIBOM
// carried none of CERT-In's Table 10 elements; and while a QBOM PDF rendered an
// empty `Components` table that reads as "the scan found nothing". Every one of
// those sat inside the passing suite's blind spot.
//
// The two tests that should have caught it are the lesson:
//
//   - `TestEveryBOMTypesHonestyLabelReachesEveryFormat` rendered CBOM, QBOM and
//     AIBOM with EMPTY payloads and asserted only that a caveat STRING was
//     present. It never asserted that data rendered, so it passed on documents
//     containing nothing but a caveat.
//   - `TestAnHBOMRendersInEveryFormat` covered xlsx, pdf and json — not docx,
//     spdx or cyclonedx, which is where HBOM's export bug had lived.
//
// So this test is deliberately shaped against both failures: a POPULATED
// fixture per BOM type, a value that could only come from that type's own
// inventory, and EVERY format the product will actually hand a customer —
// driven through `renderArtifact`, the real dispatch, not the renderers
// individually.
func TestEveryFormatCarriesEveryBOMTypesData(t *testing.T) {
	// Every format service.parseFormat accepts. Hardcoding the list here is
	// deliberate: if someone adds a seventh, this test must fail until they
	// decide what it should contain for all five types.
	formats := []string{"pdf", "docx", "xlsx", "json", "spdx", "cyclonedx"}

	types := []struct {
		bomType model.BOMType
		bom     render.BOM
		// marker is a value that can ONLY have come from this BOM type's own
		// inventory. Not a heading, not the tool name, not a caveat — those
		// render for an empty document too, which is exactly how the previous
		// test passed on nothing.
		marker string
	}{
		{model.BOMTypeSBOM, matrixSBOM(), "matrix-sbom-component"},
		{model.BOMTypeCBOM, matrixCBOM(), "matrix-cbom-algorithm"},
		{model.BOMTypeQBOM, matrixQBOM(), "matrix-qbom-device"},
		{model.BOMTypeAIBOM, matrixAIBOM(), "matrix-aibom-model"},
		{model.BOMTypeHBOM, matrixHBOM(), "matrix-hbom-part"},
	}

	w := &Worker{}

	for _, tt := range types {
		for _, format := range formats {
			t.Run(string(tt.bomType)+"/"+format, func(t *testing.T) {
				raw, _, _, err := w.renderArtifact(store.Report{Format: format}, tt.bom)
				if err != nil {
					t.Fatalf("render %s as %s: %v", tt.bomType, format, err)
				}
				if len(raw) == 0 {
					t.Fatalf("%s as %s produced zero bytes", tt.bomType, format)
				}

				if !artifactContains(t, format, raw, tt.marker) {
					t.Errorf(
						"a %s rendered as %s does not contain %q.\n"+
							"  The document is structurally valid and says nothing about "+
							"this BOM type's inventory — which is worse than failing to "+
							"render, because it validates and a customer trusts it.",
						tt.bomType, format, tt.marker)
				}
			})
		}
	}
}

// artifactContains searches a rendered artifact for a value, per format.
func artifactContains(t *testing.T, format string, raw []byte, want string) bool {
	t.Helper()

	switch format {
	case "pdf":
		text := pdftext.Extract(raw)
		if strings.TrimSpace(text) == "" {
			// ⚠ FAIL LOUDLY RATHER THAN RETURN false. An extractor that reads
			// nothing makes every assertion using it pass or fail for the wrong
			// reason; the caller must not be allowed to interpret this as "the
			// value is absent".
			t.Fatalf("no text could be read out of the %d-byte PDF; the extractor "+
				"needs updating before this assertion means anything", len(raw))
		}
		return strings.Contains(text, want)

	case "docx", "xlsx":
		return ooxmlContains(t, raw, want)

	default: // json, spdx, cyclonedx — all JSON
		return strings.Contains(string(raw), want)
	}
}

// ooxmlContains reports whether any entry of a DOCX or XLSX package contains
// want.
//
// ⚠ UNESCAPE BEFORE SEARCHING. Both writers XML-escape an apostrophe to &#39;,
// so a raw substring search on a phrase containing one fails on a document that
// does contain it — which reads as missing data and sends the next person
// hunting a bug that is not there.
func ooxmlContains(t *testing.T, raw []byte, want string) bool {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open package: %v", err)
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		if strings.Contains(html.UnescapeString(string(body)), want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Fixtures — POPULATED, which is the whole point
// ---------------------------------------------------------------------------

func matrixBase(t model.BOMType) render.BOM {
	return render.BOM{
		BOMType:     t,
		ReportID:    "01900000-0000-7000-8000-0000000000m1",
		ProjectName: "matrix-fixture",
		Level:       "complete",
		GeneratedAt: "2026-09-05T00:00:00Z",
		ToolName:    "AxeBOM", ToolVersion: "0.1.0",
		ProfileID: model.ProfileID, ProfileRevision: model.ProfileRevision,
	}
}

func matrixSBOM() render.BOM {
	b := matrixBase(model.BOMTypeSBOM)
	depth := 0
	b.Components = []render.Component{{
		Key: "npm/matrix-sbom-component@1.0.0", Purl: "pkg:npm/matrix-sbom-component@1.0.0",
		Ecosystem: "npm", Depth: &depth, IsDirect: true,
		Fields: map[string]string{
			model.FieldCertinSbom01ComponentName:    "matrix-sbom-component",
			model.FieldCertinSbom02ComponentVersion: "1.0.0",
		},
	}}
	b.Roots = []string{"npm/matrix-sbom-component@1.0.0"}
	return b
}

func matrixCBOM() render.BOM {
	b := matrixBase(model.BOMTypeCBOM)
	b.CryptoAssets = []render.CryptoAsset{{
		AssetType: "algorithm", Name: "matrix-cbom-algorithm",
		QuantumVulnerable: true, QuantumReadinessGroup: "vulnerable",
	}}
	return b
}

func matrixQBOM() render.BOM {
	b := matrixBase(model.BOMTypeQBOM)
	b.QuantumDevice = &render.QuantumDevice{
		ModelName: "matrix-qbom-device", Version: "rev-C",
		VendorOrigin: "Matrix Instruments",
	}
	// ⚠ POPULATED, BECAUSE A QBOM DISPLAYS THE CBOM'S ASSETS. This is the data
	// loadCompanionCryptoAssets now fetches; before it, this slice was always
	// empty in production and the readiness view always said nothing was found.
	b.CryptoAssets = []render.CryptoAsset{{
		AssetType: "algorithm", Name: "matrix-cbom-algorithm",
		QuantumVulnerable: true, QuantumReadinessGroup: "vulnerable",
	}}
	b.CryptoAssetsFrom = render.CryptoAssetSource{
		BOMType: "CBOM", DocumentID: "01900000-0000-7000-8000-0000000000c1",
		GeneratedAt: "2026-09-04T00:00:00Z",
	}
	return b
}

func matrixAIBOM() render.BOM {
	risk := 7.5
	b := matrixBase(model.BOMTypeAIBOM)
	// ⚠ RICH ENOUGH TO EXERCISE THE ML-BOM, not only the generic export. A
	// fixture carrying a name and a risk score would serialize to an ML-BOM with
	// an empty `modelCard` — which validates, and would freeze "says nothing" as
	// the expected answer for the one format whose whole purpose is saying it.
	b.AIModels = []render.AIModel{{
		Name:     "matrix-aibom-model",
		ModelKey: "purl:pkg:huggingface/matrix/aibom-model",
		FoundBy:  []string{"ai-bom", "airom"},
		Evidence: []string{"src/app.py:17"},
		Verified: true,
		// Which rung of the ladder produced the key, and what that is worth.
		IdentityRule:       "hf_repo",
		IdentityConfidence: "high",
		Datasets: []render.AIDataset{{
			Name: "matrix-dataset", License: "CC-BY-4.0",
			Source: "https://example.test/matrix-dataset",
		}},
		Dependencies:  []string{"purl:pkg:pypi/transformers@4.44.2"},
		RiskScore:     &risk,
		OwaspLLMTop10: []string{"LLM01"},
		Fields: map[string]string{
			model.FieldCertinAibom01ModelName:            "matrix-aibom-model",
			model.FieldCertinAibom02ModelVersion:         "1.0",
			model.FieldCertinAibom03ModelType:            "text-generation",
			model.FieldCertinAibom04ModelDeveloper:       "Matrix Systems",
			model.FieldCertinAibom05Licensing:            "Apache-2.0",
			model.FieldCertinAibom07MlModelsAlgorithms:   "MatrixForCausalLM",
			model.FieldCertinAibom13Input:                "text",
			model.FieldCertinAibom14Output:               "text",
			model.FieldCertinAibom15IntendedUsage:        "internal triage only",
			model.FieldCertinAibom16OutOfScopeUsage:      "never for medical advice",
			model.FieldCertinAibom12SecurityRequirements: "runs inside the VPC",
			// ⚠ THE SENTINEL, DELIBERATELY. The golden is where a regression
			// that started exporting `not-provided` as a real value would show.
			model.FieldCertinAibom11Hardware: model.NotProvided,
		},
	}}
	b.AIAssets = []render.AIAsset{
		{Type: "prompt", Key: "prompt:src/app.py:9", Name: "system-prompt",
			Evidence: []string{"src/app.py:9"}, FoundBy: []string{"airom"}},
		{Type: "vector_store", Key: "vector_store:chroma", Name: "chroma", Provider: "chroma"},
		{Type: "endpoint", Key: "endpoint:openai", Name: "OpenAI API",
			Provider: "openai", ServesModel: "gpt-4o"},
	}
	return b
}

func matrixHBOM() render.BOM {
	b := matrixBase(model.BOMTypeHBOM)
	b.Hardware = []render.HardwareComponent{{
		ID: "hw-root", Depth: 0, Quantity: 1,
		Name: "matrix-hbom-part", ModelNumber: "MX-1",
		ManufacturerName: "Matrix Systems", SourceEngine: "hbom-ecad",
	}}
	return b
}
