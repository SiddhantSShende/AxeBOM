package worker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/axebom/axebom/services/report/internal/pdftext"
	"github.com/axebom/axebom/services/report/internal/render"
	"github.com/axebom/axebom/services/report/internal/store"
)

// TestTwoSameNamedCryptoAssetsSurviveEveryStandardDocument.
//
// ⚠ THE BUG: cryptoKey was `crypto/<type>/<name>`. matrixCBOM carries two
// algorithms named "RSA", exactly as cbomkit-theia reports them.
func TestTwoSameNamedCryptoAssetsSurviveEveryStandardDocument(t *testing.T) {
	w := &Worker{}
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			raw, _, _, err := w.renderArtifact(store.Report{Format: format}, matrixCBOM())
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}

			if format == "cyclonedx" {
				assertCycloneDXCBOM(t, doc)
				return
			}

			packages, _ := doc["packages"].([]any)
			rsa := 0
			ids := map[string]bool{}
			for _, p := range packages {
				m := p.(map[string]any)
				id := m["SPDXID"].(string)
				if ids[id] {
					t.Errorf("SPDXID %q appears twice", id)
				}
				ids[id] = true
				if m["name"] == "RSA" {
					rsa++
				}
			}
			if rsa != 2 {
				t.Errorf("%d RSA packages in the SPDX document, want 2", rsa)
			}
		})
	}
}

func assertCycloneDXCBOM(t *testing.T, doc map[string]any) {
	t.Helper()
	components, _ := doc["components"].([]any)
	refs := map[string]bool{}
	rsa := 0
	for _, c := range components {
		m := c.(map[string]any)
		if m["type"] != "cryptographic-asset" {
			t.Errorf("%v is a %v component in a CBOM, want cryptographic-asset", m["name"], m["type"])
		}
		if m["cryptoProperties"] == nil {
			t.Errorf("%v carries no cryptoProperties", m["name"])
		}
		ref := m["bom-ref"].(string)
		if refs[ref] {
			t.Errorf("bom-ref %q appears twice", ref)
		}
		refs[ref] = true
		if m["name"] == "RSA" {
			rsa++
		}
	}
	if rsa != 2 {
		t.Errorf("%d RSA components, want 2", rsa)
	}
	refs[doc["metadata"].(map[string]any)["component"].(map[string]any)["bom-ref"].(string)] = true

	deps, _ := doc["dependencies"].([]any)
	for _, d := range deps {
		m := d.(map[string]any)
		seen := map[string]bool{}
		on, _ := m["dependsOn"].([]any)
		for _, to := range on {
			s := to.(string)
			if !refs[s] {
				t.Errorf("%v depends on undefined %q", m["ref"], s)
			}
			if seen[s] {
				t.Errorf("%v lists %q twice — the CycloneDX schema forbids it", m["ref"], s)
			}
			seen[s] = true
		}
	}
}

// TestTheDerivedFieldNoteReachesEveryFormat — user decision 2026-09-11: a
// derived value counts as present AND is labelled, in every artifact.
func TestTheDerivedFieldNoteReachesEveryFormat(t *testing.T) {
	const marker = "nist-sp800-57p1r5-table2"
	w := &Worker{}

	withDerivations := matrixCBOM()
	without := matrixCBOM()
	for i := range without.CryptoAssets {
		without.CryptoAssets[i].Derivations = nil
	}
	without.Coverage.DerivationSources = nil

	for _, format := range []string{"pdf", "docx", "xlsx", "json", "spdx", "cyclonedx"} {
		t.Run(format, func(t *testing.T) {
			raw, _, _, err := w.renderArtifact(store.Report{Format: format}, withDerivations)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !artifactContains(t, format, raw, marker) {
				t.Errorf("a CBOM with derived values rendered as %s does not cite %q", format, marker)
			}

			raw, _, _, err = w.renderArtifact(store.Report{Format: format}, without)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if artifactContains(t, format, raw, marker) {
				t.Errorf("a CBOM with nothing derived still cites %q as %s", marker, format)
			}
		})
	}
}

// TestUnassessedIsCountedOnThePDFSummary — `unassessed` is neither current nor
// hidden: it has its own column.
func TestUnassessedIsCountedOnThePDFSummary(t *testing.T) {
	raw, _, _, err := (&Worker{}).renderArtifact(store.Report{Format: "pdf"}, matrixCBOM())
	if err != nil {
		t.Fatal(err)
	}
	if text := pdftext.Extract(raw); !strings.Contains(text, "Unassessed") {
		t.Error("the PDF's crypto summary has no Unassessed count")
	}
}

// TestTheWordCBOMHasATablePerAssetType — the flat table gave a certificate a
// blank "Key size" cell and no column for its subject.
func TestTheWordCBOMHasATablePerAssetType(t *testing.T) {
	raw, _, _, err := (&Worker{}).renderArtifact(store.Report{Format: "docx"}, matrixCBOM())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Algorithms", "Keys", "Protocols", "Certificates", "Subject Name", "CN=matrix.example"} {
		if !ooxmlContains(t, raw, want) {
			t.Errorf("the Word CBOM does not contain %q", want)
		}
	}
	if ooxmlContains(t, raw, "Key size") {
		t.Error("the Word CBOM still carries the flat table's \"Key size\" column")
	}
}

func TestCryptoRefIsUniquePerRowAndStable(t *testing.T) {
	b := matrixCBOM()
	seen := map[string]bool{}
	for _, a := range b.CryptoAssets {
		ref := cryptoRef(a)
		if seen[ref] {
			t.Errorf("cryptoRef %q is shared by two assets", ref)
		}
		seen[ref] = true
		if ref != cryptoRef(a) {
			t.Errorf("cryptoRef is not stable for %s", a.Name)
		}
	}
	if got := cryptoRef(render.CryptoAsset{ID: "abc"}); got != "crypto-abc" {
		t.Errorf("cryptoRef with a row id = %q, want crypto-abc", got)
	}
}

// TestCryptoRefPrefersTheAssetKey — a row id changes with every
// re-normalization (invariant 10 writes a new document); the asset key names
// the same asset across them, and it is what a QBOM references.
func TestCryptoRefPrefersTheAssetKey(t *testing.T) {
	a := render.CryptoAsset{ID: "abc", AssetKey: "algorithm:rsa;scheme=oaep;primitive=pke"}
	if got := cryptoRef(a); got != a.AssetKey {
		t.Errorf("cryptoRef = %q, want the asset key %q", got, a.AssetKey)
	}
	for _, a := range matrixCBOM().CryptoAssets {
		if cryptoRef(a) != a.AssetKey {
			t.Errorf("%s: cryptoRef = %q, want its asset key", a.Name, cryptoRef(a))
		}
	}
}

// matrixCBOMWithCommittedKey is matrixCBOM with its key read, by the engine
// that reads key files, as private key material committed to the source.
func matrixCBOMWithCommittedKey() render.BOM {
	b := matrixCBOM()
	for i := range b.CryptoAssets {
		if b.CryptoAssets[i].AssetType != "key" {
			continue
		}
		b.CryptoAssets[i].Attributes = map[string]any{
			"material_type": "private-key", "private_key_in_source": true,
		}
		b.CryptoAssets[i].Evidence = []render.CryptoEvidence{
			{Path: "keys/matrix-server.key", Engine: "cbomkit-theia"},
		}
	}
	return b
}

// TestThePrivateKeyFindingReachesEveryFormat — a committed private key is a
// finding in every artifact a customer can download, with where it was found,
// and in none of them when nothing was committed.
func TestThePrivateKeyFindingReachesEveryFormat(t *testing.T) {
	w := &Worker{}
	for _, format := range []string{"pdf", "docx", "xlsx", "json", "spdx", "cyclonedx"} {
		t.Run(format, func(t *testing.T) {
			raw, _, _, err := w.renderArtifact(store.Report{Format: format}, matrixCBOMWithCommittedKey())
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			wants := []string{render.PrivateKeysInSourceTitle, "keys/matrix-server.key"}
			// The PDF wraps prose across lines, which the extractor may split;
			// its heading and table cells are single lines.
			if format != "pdf" {
				wants = append(wants, "never read or stored by AxeBOM")
			}
			for _, want := range wants {
				if !artifactContains(t, format, raw, want) {
					t.Errorf("a CBOM with a committed private key rendered as %s does not contain %q", format, want)
				}
			}

			raw, _, _, err = w.renderArtifact(store.Report{Format: format}, matrixCBOM())
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if artifactContains(t, format, raw, render.PrivateKeysInSourceTitle) {
				t.Errorf("a CBOM with no committed key still renders %q as %s", render.PrivateKeysInSourceTitle, format)
			}
		})
	}
}

// TestEveryCryptoInventoryNamesWhereAndWho — Location (first evidence entry,
// and how many more) and Engines, in the three human-readable formats.
func TestEveryCryptoInventoryNamesWhereAndWho(t *testing.T) {
	w := &Worker{}
	cases := map[string][]string{
		// Matrix.java:12 was evidenced by two engines: one place, so "+1 more"
		// counts only web/matrix.ts.
		"xlsx": {"Location", "Engines", "src/main/java/Matrix.java:12 (+1 more)", "cbomkit-action, cdxgen-cbom"},
		"docx": {"Location", "Engines", "src/main/java/Matrix.java:12 (+1 more)", "cbomkit-action, cdxgen-cbom"},
		// PDF cells are clipped to their column; these fit.
		"pdf": {"Location", "Engines", "certs/matrix.pem", "cbomkit-theia"},
	}
	for format, wants := range cases {
		t.Run(format, func(t *testing.T) {
			raw, _, _, err := w.renderArtifact(store.Report{Format: format}, matrixCBOM())
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			for _, want := range wants {
				if !artifactContains(t, format, raw, want) {
					t.Errorf("the %s crypto inventory does not contain %q", format, want)
				}
			}
		})
	}
}

// TestTheCycloneDXCBOMCarriesEvidenceAndKeyedReferences — the golden's
// fixture, read back: a certificate resolved to the signature algorithm its
// asset key names (by name, "RSA" is two assets), one occurrence per place,
// the key's material type, and the engines on a property.
func TestTheCycloneDXCBOMCarriesEvidenceAndKeyedReferences(t *testing.T) {
	raw, err := cycloneDXDocument(matrixCBOM())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	byRef := map[string]map[string]any{}
	for _, c := range doc["components"].([]any) {
		m := c.(map[string]any)
		byRef[m["bom-ref"].(string)] = m
	}

	cert := byRef["cert:CN=matrix.example;issuer=CN=matrix.example;serial=01"]
	if cert == nil {
		t.Fatal("the certificate's bom-ref is not its asset key")
	}
	cp := cert["cryptoProperties"].(map[string]any)["certificateProperties"].(map[string]any)
	if cp["signatureAlgorithmRef"] != "algorithm:rsa;digest=sha2-256;scheme=pkcs1v15;primitive=signature" {
		t.Errorf("signatureAlgorithmRef = %v, want the RSA signature algorithm by asset key", cp["signatureAlgorithmRef"])
	}
	if cp["subjectPublicKeyRef"] != "key:fp:sha256:5f1c0d9e7a2b" {
		t.Errorf("subjectPublicKeyRef = %v", cp["subjectPublicKeyRef"])
	}

	aes := byRef["algorithm:aes;mode=gcm;size=256;primitive=ae"]
	occ := aes["evidence"].(map[string]any)["occurrences"].([]any)
	if len(occ) != 2 {
		t.Errorf("occurrences = %v, want 2 (one line seen by two engines is one place)", occ)
	}
	ap := aes["cryptoProperties"].(map[string]any)["algorithmProperties"].(map[string]any)
	if ap["nistQuantumSecurityLevel"] != float64(5) || ap["parameterSetIdentifier"] != "256" {
		t.Errorf("algorithm properties = %v", ap)
	}

	key := byRef["key:fp:sha256:5f1c0d9e7a2b"]
	rcm := key["cryptoProperties"].(map[string]any)["relatedCryptoMaterialProperties"].(map[string]any)
	if rcm["type"] != "public-key" || rcm["algorithmRef"] != "algorithm:rsa;scheme=oaep;primitive=pke" {
		t.Errorf("key properties = %v", rcm)
	}

	engines := ""
	for _, p := range aes["properties"].([]any) {
		if m := p.(map[string]any); m["name"] == "axebom:crypto:engines" {
			engines = m["value"].(string)
		}
	}
	if engines != "cbomkit-action, cdxgen-cbom" {
		t.Errorf("axebom:crypto:engines = %q", engines)
	}
}
