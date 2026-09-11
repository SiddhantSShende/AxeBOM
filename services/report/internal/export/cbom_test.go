package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func intp(n int) *int { return &n }

// cbomFixture is shaped like real cbomkit-theia output: two algorithms named
// "RSA", a key, a certificate that references both, and a protocol.
func cbomFixture() CBOMDocument {
	return CBOMDocument{
		GeneratedAt: "2026-09-11T00:00:00Z",
		DocumentID:  "01900000-0000-7000-8000-0000000000ab",
		ProjectName: "acme",
		ToolName:    "AxeBOM", ToolVersion: "0.1.0",
		Notes: []string{"a document-level note"},
		Assets: []CBOMAsset{
			{Ref: "crypto-a1", AssetType: "algorithm", Name: "RSA", Primitive: "signature",
				CryptoFunctions: []string{"sign"}, OID: "1.2.840.113549.1.1.1", QuantumVulnerable: true,
				DeprecationStatus: "unassessed"},
			{Ref: "crypto-a2", AssetType: "algorithm", Name: "RSA", Primitive: "pke",
				CryptoFunctions: []string{"encapsulate", "decapsulate"}},
			{Ref: "crypto-a3", AssetType: "algorithm", Name: "SHA256-RSA", Primitive: "signature",
				ClassicalSecurityLevel: intp(112),
				Derivations:            map[string]string{"classical_security_level": "ref-x — Citation X"}},
			{Ref: "crypto-k1", AssetType: "key", Name: "RSA-2048", KeySize: intp(2048), KeyState: "active",
				CreationDate: "2026-01-02"},
			{Ref: "crypto-c1", AssetType: "certificate", Name: "leaf",
				CertSubject: "CN=leaf", CertIssuer: "CN=ca",
				NotValidBefore: "2026-01-01T00:00:00Z", NotValidAfter: "2027-01-01T00:00:00Z",
				SignatureAlgoRef: "SHA256-RSA", SubjectPublicKeyRef: "RSA-2048",
				CertFormat: "X.509", CertExtension: "pem",
				Evidence: []CBOMEvidence{{Path: "certs/leaf.pem", Line: intp(0)}, {Path: "a.pem", Line: intp(7)}}},
			{Ref: "crypto-p1", AssetType: "protocol", Name: "TLS", ProtocolVersion: "1.3",
				CipherSuites: []string{"TLS_AES_256_GCM_SHA384"}},
		},
	}
}

func decodeCBOM(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return doc
}

func components(doc map[string]any) []map[string]any {
	raw, _ := doc["components"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func byRef(doc map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range components(doc) {
		out[c["bom-ref"].(string)] = c
	}
	return out
}

func property(c map[string]any, name string) (string, bool) {
	props, _ := c["properties"].([]any)
	for _, p := range props {
		m, _ := p.(map[string]any)
		if m["name"] == name {
			return m["value"].(string), true
		}
	}
	return "", false
}

func mustSerialize(t *testing.T, doc CBOMDocument) map[string]any {
	t.Helper()
	raw, err := SerializeCBOM(doc)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return decodeCBOM(t, raw)
}

// TestTwoSameNamedAssetsAreBothInTheCBOM — the collapse this serializer ends.
func TestTwoSameNamedAssetsAreBothInTheCBOM(t *testing.T) {
	doc := mustSerialize(t, cbomFixture())

	rsa := 0
	seen := map[string]bool{}
	for _, c := range components(doc) {
		if c["type"] != "cryptographic-asset" {
			t.Errorf("component %v is %v, want cryptographic-asset", c["name"], c["type"])
		}
		if c["cryptoProperties"] == nil {
			t.Errorf("component %v carries no cryptoProperties", c["name"])
		}
		ref := c["bom-ref"].(string)
		if seen[ref] {
			t.Errorf("bom-ref %q appears twice", ref)
		}
		seen[ref] = true
		if c["name"] == "RSA" {
			rsa++
		}
	}
	if rsa != 2 {
		t.Fatalf("%d RSA algorithms in the CBOM, want 2 — same-named assets collapsed", rsa)
	}
}

// TestEveryDependencyResolvesAndNoneRepeats — the schema forbids duplicate
// dependsOn entries, and a ref that names nothing is a dangling graph.
func TestEveryDependencyResolvesAndNoneRepeats(t *testing.T) {
	doc := mustSerialize(t, cbomFixture())

	known := map[string]bool{}
	for ref := range byRef(doc) {
		known[ref] = true
	}
	meta := doc["metadata"].(map[string]any)
	known[meta["component"].(map[string]any)["bom-ref"].(string)] = true

	deps, _ := doc["dependencies"].([]any)
	if len(deps) == 0 {
		t.Fatal("the CBOM has no dependency graph")
	}
	for _, d := range deps {
		m := d.(map[string]any)
		if !known[m["ref"].(string)] {
			t.Errorf("dependency from unknown ref %v", m["ref"])
		}
		on, _ := m["dependsOn"].([]any)
		dup := map[string]bool{}
		for _, to := range on {
			s := to.(string)
			if !known[s] {
				t.Errorf("%v depends on %q, which the document does not define", m["ref"], s)
			}
			if dup[s] {
				t.Errorf("%v lists %q twice in dependsOn", m["ref"], s)
			}
			dup[s] = true
		}
	}
}

func TestTypeSpecificPropertiesLandInTheRightBlock(t *testing.T) {
	doc := mustSerialize(t, cbomFixture())
	refs := byRef(doc)

	key := refs["crypto-k1"]["cryptoProperties"].(map[string]any)
	if key["assetType"] != "related-crypto-material" {
		t.Errorf("a Table 9 key is %v, want related-crypto-material", key["assetType"])
	}
	rcm := key["relatedCryptoMaterialProperties"].(map[string]any)
	if rcm["size"].(float64) != 2048 || rcm["state"] != "active" {
		t.Errorf("key properties = %v", rcm)
	}
	if _, ok := key["certificateProperties"]; ok {
		t.Error("a key carries certificateProperties")
	}

	proto := refs["crypto-p1"]["cryptoProperties"].(map[string]any)["protocolProperties"].(map[string]any)
	if proto["type"] != "tls" || proto["version"] != "1.3" {
		t.Errorf("protocol properties = %v", proto)
	}

	algo := refs["crypto-a3"]["cryptoProperties"].(map[string]any)["algorithmProperties"].(map[string]any)
	if algo["classicalSecurityLevel"].(float64) != 112 {
		t.Errorf("algorithm properties = %v", algo)
	}
}

// TestACertificateReferencesOnlyWhatItUnambiguouslyNames — the stored value is
// a name; pointing at one of two same-named assets would be a guess.
func TestACertificateReferencesOnlyWhatItUnambiguouslyNames(t *testing.T) {
	fixture := cbomFixture()
	doc := mustSerialize(t, fixture)
	cert := byRef(doc)["crypto-c1"]
	props := cert["cryptoProperties"].(map[string]any)["certificateProperties"].(map[string]any)
	if props["signatureAlgorithmRef"] != "crypto-a3" || props["subjectPublicKeyRef"] != "crypto-k1" {
		t.Errorf("unique names did not resolve to bom-refs: %v", props)
	}

	// Now make the signature algorithm ambiguous.
	fixture.Assets[4].SignatureAlgoRef = "RSA"
	cert = byRef(mustSerialize(t, fixture))["crypto-c1"]
	props = cert["cryptoProperties"].(map[string]any)["certificateProperties"].(map[string]any)
	if _, ok := props["signatureAlgorithmRef"]; ok {
		t.Errorf("an ambiguous name became a bom-ref: %v", props["signatureAlgorithmRef"])
	}
	if v, ok := property(cert, "certin:crypto:signature_algo_ref"); !ok || v != "RSA" {
		t.Errorf("the unresolved raw value was dropped instead of carried: %q", v)
	}
}

// TestValuesOutsideTheSchemaBecomeOtherWithTheRawValueKept.
func TestValuesOutsideTheSchemaBecomeOtherWithTheRawValueKept(t *testing.T) {
	fixture := cbomFixture()
	fixture.Assets[0].Primitive = "RSA"                          // not a primitive
	fixture.Assets[0].Mode = "PKCS1"                             // not a mode
	fixture.Assets[0].CryptoFunctions = []string{"sign", "wrap"} // "wrap" is not a 1.6 function
	fixture.Assets[3].KeyState = "revoked"                       // no `other` in the key-state enum
	fixture.Assets[5].Name = "DTLS"                              // a 1.7 protocol type
	doc := mustSerialize(t, fixture)
	refs := byRef(doc)

	algo := refs["crypto-a1"]["cryptoProperties"].(map[string]any)["algorithmProperties"].(map[string]any)
	if algo["primitive"] != "other" || algo["mode"] != "other" {
		t.Errorf("non-enum primitive/mode = %v / %v, want other", algo["primitive"], algo["mode"])
	}
	for name, want := range map[string]string{
		"certin:crypto:primitive": "RSA", "certin:crypto:mode": "PKCS1", "certin:crypto:crypto_functions": "wrap",
	} {
		if v, _ := property(refs["crypto-a1"], name); v != want {
			t.Errorf("%s = %q, want %q", name, v, want)
		}
	}

	rcm := refs["crypto-k1"]["cryptoProperties"].(map[string]any)["relatedCryptoMaterialProperties"].(map[string]any)
	if _, ok := rcm["state"]; ok {
		t.Errorf("a key state outside the enum was written as state %v", rcm["state"])
	}
	if v, _ := property(refs["crypto-k1"], "certin:crypto:key_state"); v != "revoked" {
		t.Errorf("the raw key state was lost: %q", v)
	}

	proto := refs["crypto-p1"]["cryptoProperties"].(map[string]any)["protocolProperties"].(map[string]any)
	if proto["type"] != "other" {
		t.Errorf("DTLS became protocol type %v in a 1.6 document, want other", proto["type"])
	}
}

// TestADateIsNotPaddedToMidnight — the schema requires date-time, and a
// time of day we do not know would be invented.
func TestADateIsNotPaddedToMidnight(t *testing.T) {
	refs := byRef(mustSerialize(t, cbomFixture()))
	rcm := refs["crypto-k1"]["cryptoProperties"].(map[string]any)["relatedCryptoMaterialProperties"].(map[string]any)
	if _, ok := rcm["creationDate"]; ok {
		t.Errorf("a date-only creation date was emitted as %v", rcm["creationDate"])
	}
	if v, _ := property(refs["crypto-k1"], "certin:crypto:creation_date"); v != "2026-01-02" {
		t.Errorf("the raw creation date was lost: %q", v)
	}
}

// TestAxeBOMAnalysisIsNeverLabelledCertIn — our own verdicts must not travel
// under the regulator's namespace.
func TestAxeBOMAnalysisIsNeverLabelledCertIn(t *testing.T) {
	refs := byRef(mustSerialize(t, cbomFixture()))
	a := refs["crypto-a1"]
	if v, ok := property(a, "axebom:crypto:deprecation_status"); !ok || v != "unassessed" {
		t.Errorf("deprecation status = %q, %v", v, ok)
	}
	if v, ok := property(a, "axebom:crypto:quantum_vulnerable"); !ok || v != "true" {
		t.Errorf("quantum_vulnerable = %q, %v", v, ok)
	}
	if v, ok := property(refs["crypto-a2"], "axebom:crypto:quantum_vulnerable"); !ok || v != "false" {
		t.Errorf("`false` must be emitted as an answer, got %q, %v", v, ok)
	}
	for _, c := range components(mustSerialize(t, cbomFixture())) {
		for _, name := range []string{"certin:crypto:deprecation_status", "certin:crypto:quantum_family",
			"certin:crypto:quantum_vulnerable", "certin:crypto:algorithm_family"} {
			if _, ok := property(c, name); ok {
				t.Errorf("%v carries AxeBOM analysis as %s", c["name"], name)
			}
		}
	}
	if v, _ := property(refs["crypto-a3"], "axebom:crypto:derived:classical_security_level"); v != "ref-x — Citation X" {
		t.Errorf("the derivation label is %q", v)
	}
}

func TestEvidenceIsEmittedWithoutAFakeLineZero(t *testing.T) {
	cert := byRef(mustSerialize(t, cbomFixture()))["crypto-c1"]
	occ := cert["evidence"].(map[string]any)["occurrences"].([]any)
	if len(occ) != 2 {
		t.Fatalf("occurrences = %v", occ)
	}
	first, second := occ[0].(map[string]any), occ[1].(map[string]any)
	if first["location"] != "a.pem" || first["line"].(float64) != 7 {
		t.Errorf("first occurrence = %v", first)
	}
	if _, ok := second["line"]; ok {
		t.Errorf("theia's line 0 (\"no line\") was emitted as a line: %v", second)
	}
}

func certProps(t *testing.T, c map[string]any) map[string]any {
	t.Helper()
	return c["cryptoProperties"].(map[string]any)["certificateProperties"].(map[string]any)
}

func dependsOn(doc map[string]any, from, to string) bool {
	deps, _ := doc["dependencies"].([]any)
	for _, d := range deps {
		m := d.(map[string]any)
		if m["ref"] != from {
			continue
		}
		on, _ := m["dependsOn"].([]any)
		for _, s := range on {
			if s == to {
				return true
			}
		}
	}
	return false
}

// TestAReferenceByAssetKeyWinsOverAnAmbiguousName — the key names one asset
// exactly where the name "RSA" names two; a key that resolves to nothing, or
// to an asset of the wrong type, falls back to the unambiguous-name rule.
func TestAReferenceByAssetKeyWinsOverAnAmbiguousName(t *testing.T) {
	fixture := cbomFixture()
	fixture.Assets[0].AssetKey = "algorithm:rsa;primitive=signature"
	fixture.Assets[3].AssetKey = "key:fp:sha256:00ff"
	fixture.Assets[4].SignatureAlgoRef = "RSA" // two assets by name
	fixture.Assets[4].SignatureAlgorithmKey = "algorithm:rsa;primitive=signature"

	doc := mustSerialize(t, fixture)
	cert := byRef(doc)["crypto-c1"]
	if got := certProps(t, cert)["signatureAlgorithmRef"]; got != "crypto-a1" {
		t.Errorf("signatureAlgorithmRef = %v, want crypto-a1 by asset key", got)
	}
	if _, ok := property(cert, "certin:crypto:signature_algo_ref"); ok {
		t.Error("the raw value was duplicated although the referenced asset carries that name")
	}
	if !dependsOn(doc, "crypto-c1", "crypto-a1") {
		t.Error("the dependency graph does not follow the keyed reference")
	}

	// Resolved by key to an asset of ANOTHER name: the CERT-In value would
	// otherwise be stated nowhere, so it travels as well.
	fixture.Assets[4].SignatureAlgoRef = "sha256WithRSAEncryption"
	cert = byRef(mustSerialize(t, fixture))["crypto-c1"]
	if got := certProps(t, cert)["signatureAlgorithmRef"]; got != "crypto-a1" {
		t.Errorf("signatureAlgorithmRef = %v, want crypto-a1", got)
	}
	if v, _ := property(cert, "certin:crypto:signature_algo_ref"); v != "sha256WithRSAEncryption" {
		t.Errorf("the CERT-In value was lost: %q", v)
	}

	// A key naming nothing in this document: the name rule decides.
	fixture.Assets[4].SignatureAlgoRef = "SHA256-RSA"
	fixture.Assets[4].SignatureAlgorithmKey = "algorithm:absent"
	// A key naming an asset of the wrong type is not followed either.
	fixture.Assets[4].SubjectPublicKeyKey = "algorithm:rsa;primitive=signature"
	cert = byRef(mustSerialize(t, fixture))["crypto-c1"]
	props := certProps(t, cert)
	if props["signatureAlgorithmRef"] != "crypto-a3" || props["subjectPublicKeyRef"] != "crypto-k1" {
		t.Errorf("fallback references = %v / %v, want crypto-a3 / crypto-k1",
			props["signatureAlgorithmRef"], props["subjectPublicKeyRef"])
	}

	// Neither resolves: both raw values travel, the key included.
	fixture.Assets[4].SignatureAlgoRef = "RSA"
	cert = byRef(mustSerialize(t, fixture))["crypto-c1"]
	if _, ok := certProps(t, cert)["signatureAlgorithmRef"]; ok {
		t.Error("an unresolvable reference became a bom-ref")
	}
	if v, _ := property(cert, "axebom:crypto:signature_algorithm_key"); v != "algorithm:absent" {
		t.Errorf("the unresolved asset key was dropped: %q", v)
	}
}

// TestAttributesLandInTheirOneSixFields — padding, curve, parameter set and
// NIST quantum category on the algorithm; material type, format and algorithm
// on the key. Outside the 1.6 schema, the raw value travels on a property.
func TestAttributesLandInTheirOneSixFields(t *testing.T) {
	fixture := cbomFixture()
	fixture.Assets[0].Padding = "PKCS1v15"
	fixture.Assets[0].NISTQuantumSecurityLevel = intp(0)
	fixture.Assets[0].IdentityRule, fixture.Assets[0].IdentityConfidence = "algorithm", "high"
	fixture.Assets[1].AssetKey = "algorithm:rsa;primitive=pke"
	fixture.Assets[1].Padding = "pss"                      // not a 1.6 padding
	fixture.Assets[1].NISTQuantumSecurityLevel = intp(9)   // not a NIST category
	fixture.Assets[2].Curve = "secp256r1"                  // free text in 1.6
	fixture.Assets[2].ParameterSetIdentifier = "ML-DSA-65" // free text in 1.6
	fixture.Assets[3].MaterialType = "private-key"         // a 1.6 material type
	fixture.Assets[3].MaterialFormat = "PEM"               // free text in 1.6
	fixture.Assets[3].AlgorithmKey = "algorithm:rsa;primitive=pke"
	refs := byRef(mustSerialize(t, fixture))

	algo := func(ref string) map[string]any {
		return refs[ref]["cryptoProperties"].(map[string]any)["algorithmProperties"].(map[string]any)
	}
	if a := algo("crypto-a1"); a["padding"] != "pkcs1v15" || a["nistQuantumSecurityLevel"] != float64(0) {
		t.Errorf("a1 algorithm properties = %v (a category of 0 is an answer, not an absence)", a)
	}
	if v, _ := property(refs["crypto-a1"], "axebom:crypto:identity_rule"); v != "algorithm" {
		t.Errorf("identity rule = %q", v)
	}
	a2 := algo("crypto-a2")
	if a2["padding"] != "other" {
		t.Errorf("a padding outside the enum = %v, want other", a2["padding"])
	}
	if _, ok := a2["nistQuantumSecurityLevel"]; ok {
		t.Errorf("a category outside 0..6 was written: %v", a2["nistQuantumSecurityLevel"])
	}
	for name, want := range map[string]string{
		"axebom:crypto:padding": "pss", "axebom:crypto:nist_quantum_security_level": "9",
	} {
		if v, _ := property(refs["crypto-a2"], name); v != want {
			t.Errorf("%s = %q, want %q", name, v, want)
		}
	}
	if a3 := algo("crypto-a3"); a3["curve"] != "secp256r1" || a3["parameterSetIdentifier"] != "ML-DSA-65" {
		t.Errorf("a3 algorithm properties = %v", a3)
	}

	rcm := refs["crypto-k1"]["cryptoProperties"].(map[string]any)["relatedCryptoMaterialProperties"].(map[string]any)
	if rcm["type"] != "private-key" || rcm["format"] != "PEM" || rcm["algorithmRef"] != "crypto-a2" {
		t.Errorf("key properties = %v", rcm)
	}

	fixture.Assets[3].MaterialType = "symmetric-key" // the normalizer's, not 1.6's
	refs = byRef(mustSerialize(t, fixture))
	rcm = refs["crypto-k1"]["cryptoProperties"].(map[string]any)["relatedCryptoMaterialProperties"].(map[string]any)
	if rcm["type"] != "unknown" {
		t.Errorf("a material type outside the enum = %v, want unknown", rcm["type"])
	}
	if v, _ := property(refs["crypto-k1"], "axebom:crypto:material_type"); v != "symmetric-key" {
		t.Errorf("the raw material type was lost: %q", v)
	}
}

// TestOccurrencesAreOnePerPlaceAndEnginesTravelOnTheComponent — two engines
// on one line are one place; the 1.6 occurrence has no engine field, so none
// is invented.
func TestOccurrencesAreOnePerPlaceAndEnginesTravelOnTheComponent(t *testing.T) {
	fixture := cbomFixture()
	fixture.Assets[4].Evidence = append(fixture.Assets[4].Evidence,
		CBOMEvidence{Path: "a.pem", Line: intp(7)}, CBOMEvidence{Path: "certs/leaf.pem"})
	fixture.Assets[4].Engines = []string{"cbomkit-theia", "cbomkit-action", "cbomkit-theia"}
	cert := byRef(mustSerialize(t, fixture))["crypto-c1"]

	occ := cert["evidence"].(map[string]any)["occurrences"].([]any)
	if len(occ) != 2 {
		t.Fatalf("occurrences = %v, want 2", occ)
	}
	for _, o := range occ {
		for field := range o.(map[string]any) {
			if field != "location" && field != "line" {
				t.Errorf("an occurrence carries %q, which this serializer never sets", field)
			}
		}
	}
	if v, _ := property(cert, "axebom:crypto:engines"); v != "cbomkit-action, cbomkit-theia" {
		t.Errorf("axebom:crypto:engines = %q", v)
	}
}

// TestAPrivateKeyInSourceIsAFindingInTheMetadata — stated on the document, so
// a reader who never opens a component is told; marked on the asset, so they
// can see which. Absent when nothing was flagged.
func TestAPrivateKeyInSourceIsAFindingInTheMetadata(t *testing.T) {
	fixture := cbomFixture()
	meta := mustSerialize(t, fixture)["metadata"].(map[string]any)
	for _, name := range []string{"axebom:cbom:finding:private_keys_in_source", "axebom:cbom:private_keys_in_source_count"} {
		if _, ok := property(meta, name); ok {
			t.Errorf("%s is present with nothing flagged", name)
		}
	}

	fixture.Assets[3].PrivateKeyInSource = true
	fixture.PrivateKeysInSource = "Private keys found in source: 1 asset(s) ..."
	doc := mustSerialize(t, fixture)
	meta = doc["metadata"].(map[string]any)
	if v, _ := property(meta, "axebom:cbom:private_keys_in_source_count"); v != "1" {
		t.Errorf("count = %q", v)
	}
	if v, _ := property(meta, "axebom:cbom:finding:private_keys_in_source"); v != fixture.PrivateKeysInSource {
		t.Errorf("finding = %q", v)
	}
	refs := byRef(doc)
	if v, _ := property(refs["crypto-k1"], "axebom:crypto:private_key_in_source"); v != "true" {
		t.Errorf("the flagged key is not marked: %q", v)
	}
	if _, ok := property(refs["crypto-a1"], "axebom:crypto:private_key_in_source"); ok {
		t.Error("an unflagged asset is marked")
	}
}

// TestAnEmptyCBOMSaysSoInsteadOfFailing — zero assets is an honest outcome.
func TestAnEmptyCBOMSaysSoInsteadOfFailing(t *testing.T) {
	doc := mustSerialize(t, CBOMDocument{GeneratedAt: "2026-09-11T00:00:00Z", ProjectName: "empty"})
	if len(components(doc)) != 0 {
		t.Fatal("components appeared from nowhere")
	}
	meta := doc["metadata"].(map[string]any)
	if v, _ := property(meta, "axebom:cbom:crypto_asset_count"); v != "0" {
		t.Errorf("asset count = %q", v)
	}
	if v, _ := property(meta, "axebom:cbom:empty"); !strings.Contains(v, "not evidence that none exist") {
		t.Errorf("an empty CBOM does not say what its emptiness means: %q", v)
	}
}

func TestDuplicateRefsAreRefusedNotMerged(t *testing.T) {
	fixture := cbomFixture()
	fixture.Assets[1].Ref = fixture.Assets[0].Ref
	if _, err := SerializeCBOM(fixture); err == nil {
		t.Fatal("two assets with one bom-ref were serialized; one would have been lost")
	}
}

func TestTheCBOMIsByteStable(t *testing.T) {
	first, err := SerializeCBOM(cbomFixture())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := SerializeCBOM(cbomFixture())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d produced different bytes", i)
		}
	}
	doc := decodeCBOM(t, first)
	if doc["specVersion"] != "1.6" || doc["bomFormat"] != "CycloneDX" {
		t.Errorf("specVersion/bomFormat = %v/%v", doc["specVersion"], doc["bomFormat"])
	}
}
