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

// matrixCBOM is shaped like real cbomkit-theia output, not a single tidy row.
//
// ⚠ TWO ALGORITHMS NAMED "RSA" ARE THE POINT. theia reports RSA twice from one
// certificate (a signature and a pke), and the export keyed assets on
// type+name: protobom kept one, CycloneDX got a duplicate `dependsOn` entry the
// schema forbids, and SPDX two packages with one SPDXID. A one-asset fixture
// could never show that, which is why this one stopped being one.
//
// ⚠ AND SHAPED LIKE A MIGRATION-0020 ROW: every asset has the normalizer's
// asset key (so the bom-refs the golden pins are asset keys), evidence, the
// engines that reported it, and the attributes CycloneDX 1.6 has fields for.
// The algorithm is evidenced twice on one line by two engines — one place, so
// one occurrence — and once more elsewhere.
func matrixCBOM() render.BOM {
	b := matrixBase(model.BOMTypeCBOM)
	level, size := 256, 2048
	line12, line7, line3 := 12, 7, 3
	const (
		aesKey       = "algorithm:aes;mode=gcm;size=256;primitive=ae"
		rsaSigKey    = "algorithm:rsa;digest=sha2-256;scheme=pkcs1v15;primitive=signature"
		rsaPKEKey    = "algorithm:rsa;scheme=oaep;primitive=pke"
		rsaMaterial  = "key:fp:sha256:5f1c0d9e7a2b"
		tlsKey       = "protocol:tls;version=1.3"
		certKey      = "cert:CN=matrix.example;issuer=CN=matrix.example;serial=01"
		certFile     = "certs/matrix.pem"
		theia        = "cbomkit-theia"
		action, cdxg = "cbomkit-action", "cdxgen-cbom"
	)
	fromCert := []render.CryptoEvidence{{Path: certFile, Engine: theia}}
	b.CryptoAssets = []render.CryptoAsset{
		{
			ID: "01900000-0000-7000-8000-00000000c001", AssetType: "algorithm",
			AssetKey: aesKey, IdentityRule: "algorithm", IdentityConfidence: "high",
			Name: "matrix-cbom-algorithm", Primitive: "ae", Mode: "gcm",
			CryptoFunctions: []string{"encrypt", "decrypt"}, ClassicalSecurityLevel: &level,
			OID: "2.16.840.1.101.3.4.1.46", QuantumFamily: "aes",
			QuantumReadinessGroup: "grover_note", DeprecationStatus: "current",
			// A value AxeBOM filled from a cited table, so every format has to
			// carry the footnote (user decision 2026-09-11: derive, count, label).
			Derivations: map[string]string{"classical_security_level": "nist-sp800-57p1r5-table2"},
			Evidence: []render.CryptoEvidence{
				{Path: "src/main/java/Matrix.java", Line: &line12, Engine: action},
				{Path: "src/main/java/Matrix.java", Line: &line12, Engine: cdxg},
				{Path: "web/matrix.ts", Line: &line7, Engine: cdxg},
			},
			Engines:    []string{action, cdxg},
			Attributes: map[string]any{"parameter_set": "256", "nist_quantum_security_level": 5},
		},
		{
			ID: "01900000-0000-7000-8000-00000000c002", AssetType: "algorithm", Name: "RSA",
			AssetKey: rsaSigKey, IdentityRule: "algorithm", IdentityConfidence: "high",
			Primitive: "signature", CryptoFunctions: []string{"sign"}, OID: "1.2.840.113549.1.1.1",
			QuantumVulnerable: true, QuantumFamily: "rsa", QuantumReadinessGroup: "vulnerable",
			DeprecationStatus: "unassessed",
			Evidence:          fromCert, Engines: []string{theia},
			Attributes: map[string]any{"padding": "pkcs1v15", "nist_quantum_security_level": 0},
		},
		{
			ID: "01900000-0000-7000-8000-00000000c003", AssetType: "algorithm", Name: "RSA",
			AssetKey: rsaPKEKey, IdentityRule: "algorithm", IdentityConfidence: "high",
			Primitive: "pke", CryptoFunctions: []string{"encapsulate", "decapsulate"},
			OID: "1.2.840.113549.1.1.1", QuantumVulnerable: true, QuantumFamily: "rsa",
			QuantumReadinessGroup: "vulnerable", DeprecationStatus: "unassessed",
			Evidence: fromCert, Engines: []string{theia},
			Attributes: map[string]any{"padding": "oaep", "nist_quantum_security_level": 0},
		},
		{
			ID: "01900000-0000-7000-8000-00000000c004", AssetType: "key", Name: "RSA-2048",
			AssetKey: rsaMaterial, IdentityRule: "key-fingerprint", IdentityConfidence: "high",
			KeySize: &size, KeyState: "active", QuantumVulnerable: true, QuantumFamily: "rsa",
			QuantumReadinessGroup: "vulnerable", DeprecationStatus: "current",
			Evidence: fromCert, Engines: []string{theia},
			Attributes: map[string]any{
				"material_type": "public-key", "material_format": "PEM", "algorithm_key": rsaPKEKey,
			},
		},
		{
			ID: "01900000-0000-7000-8000-00000000c005", AssetType: "protocol", Name: "TLS",
			AssetKey: tlsKey, IdentityRule: "protocol", IdentityConfidence: "high",
			ProtocolVersion: "1.3", CipherSuites: []string{"TLS_AES_256_GCM_SHA384"},
			DeprecationStatus: "current", QuantumReadinessGroup: "unassessed",
			Evidence: []render.CryptoEvidence{{Path: "config/tls.yaml", Line: &line3, Engine: theia}},
			Engines:  []string{theia},
		},
		{
			ID: "01900000-0000-7000-8000-00000000c006", AssetType: "certificate",
			AssetKey: certKey, IdentityRule: "certificate-issuer-serial", IdentityConfidence: "high",
			Name: "matrix.example", CertSubject: "CN=matrix.example", CertIssuer: "CN=matrix.example",
			NotValidBefore: "2026-09-01T00:00:00Z", NotValidAfter: "2027-09-01T00:00:00Z",
			// "RSA" names two algorithms, so by NAME it must not become a bom-ref;
			// the normalizer's asset key names the signature algorithm exactly, so
			// by KEY it must. The key's name is unique either way.
			SignatureAlgoRef: "RSA", SubjectPublicKeyRef: "RSA-2048",
			CertFormat: "X.509", CertExtension: "pem", QuantumVulnerable: true,
			QuantumFamily: "rsa", QuantumReadinessGroup: "vulnerable", DeprecationStatus: "unassessed",
			Evidence: fromCert, Engines: []string{theia},
			Attributes: map[string]any{
				"signature_algorithm_key": rsaSigKey, "subject_public_key_key": rsaMaterial,
			},
		},
	}
	b.Coverage.DerivationSources = map[string]string{
		"nist-sp800-57p1r5-table2": "NIST SP 800-57 Part 1 Rev. 5, Table 2",
	}
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
