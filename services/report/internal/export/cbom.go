package export

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ---------------------------------------------------------------------------
// CycloneDX CBOM — the CBOM's real machine-readable form.
//
// ⚠ A CBOM ALREADY EXPORTED, AND WHAT IT EXPORTED WAS NOT A CBOM.
//
// `toExportDocument` mapped every crypto asset onto a generic protobom node.
// protobom v0.5.8 has no `cryptographic-asset` purpose and no field for
// `cryptoProperties`, so each asset serialized as a CycloneDX `data` component
// with its Table 9 values scattered across string properties — a valid
// CycloneDX 1.6 document that no CBOM-aware tool recognises as one. And its
// identity was `crypto/<type>/<name>`, so the two RSA algorithms cbomkit-theia
// reports from one certificate collapsed into a single node, with a duplicate
// `dependsOn` entry the schema forbids.
//
// This serializer uses `CycloneDX/cyclonedx-go` directly, the same way
// mlbom.go does for the ML-BOM: the format's own library models
// `cryptoProperties` in full. What this file owns is the MAPPING — Table 9's
// four field sets onto CycloneDX's four asset types — which is the part where a
// wrong decision produces a document that validates and says something false.
//
// ⚠ THE 1.6 SCHEMA IS THE CONTRACT, NOT THE LIBRARY. cyclonedx-go models 1.7,
// which added `key-wrap`, `dtls`, `quic` and relaxed several enums. Every enum
// below is the 1.6 set (checked against bom-1.6.schema.json), and a value
// outside it becomes `other` with the engine's raw value on a property — never
// a 1.7 value emitted into a document that declares 1.6.
// ---------------------------------------------------------------------------

// CBOMEvidence is one place an engine found an asset.
type CBOMEvidence struct {
	Path string
	Line *int
}

// CBOMAsset is one CERT-In Table 9 asset, as the CycloneDX CBOM sees it.
type CBOMAsset struct {
	// Ref is the asset's bom-ref: the caller's single identity function
	// (worker.cryptoRef), never derived here. Two assets with one ref are
	// refused rather than merged.
	Ref       string
	AssetType string
	Name      string
	// ComponentKey links the asset to a software component in the project's
	// SBOM, when an engine attributed it to one.
	ComponentKey string
	// AssetKey is the normalizer's identity (docs/03-NORMALIZER-SPEC.md §1.6).
	// The certificate and key references below name other assets by it.
	AssetKey           string
	IdentityRule       string
	IdentityConfidence string

	// algorithm
	Primitive              string
	Mode                   string
	CryptoFunctions        []string
	ClassicalSecurityLevel *int
	AlgorithmList          []string
	// Not CERT-In fields (normalize.crypto_assets.attributes), each with a
	// CycloneDX 1.6 algorithmProperties field of its own.
	Padding                  string
	Curve                    string
	ParameterSetIdentifier   string
	NISTQuantumSecurityLevel *int

	// key
	KeyID          string
	KeyState       string
	KeySize        *int
	CreationDate   string
	ActivationDate string
	// Not CERT-In fields: what the engine read the material as, and the asset
	// key of the algorithm the key is for.
	MaterialType   string
	MaterialFormat string
	ExpirationDate string
	AlgorithmKey   string

	// protocol
	ProtocolVersion string
	CipherSuites    []string

	// algorithm and protocol
	OID string

	// certificate
	CertSubject         string
	CertIssuer          string
	NotValidBefore      string
	NotValidAfter       string
	SignatureAlgoRef    string
	SubjectPublicKeyRef string
	CertFormat          string
	CertExtension       string
	// SignatureAlgorithmKey and SubjectPublicKeyKey are the asset keys of what
	// signed the certificate and of the key it certifies, when the normalizer
	// could name them. They win over the name-based references above.
	SignatureAlgorithmKey string
	SubjectPublicKeyKey   string

	Evidence []CBOMEvidence
	// Engines are the engines that reported the asset.
	Engines []string
	// PrivateKeyInSource marks key material an engine read out of a committed
	// file. Never the material itself: AxeBOM does not read or store it.
	PrivateKeyInSource bool

	// AxeBOM analysis — NOT CERT-In fields, excluded from both coverage
	// numbers, and emitted only under `axebom:crypto:*` so no consumer can
	// mistake one for a Table 9 value.
	QuantumVulnerable     bool
	QuantumFamily         string
	QuantumReadinessGroup string
	DeprecationStatus     string
	DeprecationRationale  string
	DeprecationReference  string
	PQCRecommendation     string
	// Derivations are the CERT-In values AxeBOM filled from a cited reference
	// table rather than an engine reporting them: {column: rendered citation}.
	Derivations map[string]string
}

// CBOMDocument is everything the CBOM serializer needs.
type CBOMDocument struct {
	// ⚠ NOT READ FROM A CLOCK. Passed in from the scan record so the same
	// canonical model always serializes to the same bytes (ADR-0003).
	GeneratedAt string
	DocumentID  string
	ProjectName string
	ToolName    string
	ToolVersion string

	Assets []CBOMAsset
	// Notes are document-level statements — the derived-field footnote, the
	// type-discrimination caveat — carried as metadata properties so a reader
	// of the standard document sees what the report's other formats say.
	Notes []string
	// PrivateKeysInSource is the private-key finding as one sentence, or ""
	// when nothing was flagged. A finding, so it gets its own metadata
	// property rather than riding among the notes.
	PrivateKeysInSource string
}

// CBOMFormat is the format name this serializer answers to.
const CBOMFormat Format = "cyclonedx-cbom-1.6-json"

// cbomSubjectRef is metadata.component's bom-ref: the project the CBOM
// describes. See worker.subjectKey for why a CBOM needs a declared subject.
const cbomSubjectRef = "axebom:project"

// cbomTypeRank is CERT-In Table 9's own order: algorithms, keys, protocols,
// certificates.
var cbomTypeRank = map[string]int{"algorithm": 0, "key": 1, "protocol": 2, "certificate": 3}

// The CycloneDX 1.6 enums, from bom-1.6.schema.json.
var (
	cbomPrimitives = set("drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
		"pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown")
	cbomModes     = set("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown")
	cbomFunctions = set("generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
		"sign", "verify", "encapsulate", "decapsulate", "other", "unknown")
	// ⚠ NO `other` IN THIS ONE. A key state outside the set cannot be written
	// as `other` without failing the schema, so it is omitted from
	// `relatedCryptoMaterialProperties` and carried raw on a property instead.
	cbomKeyStates = set("pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed")
	cbomPaddings  = set("pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown")
	// relatedCryptoMaterialProperties.type. The normalizer's `symmetric-key` is
	// not in it; such a value is written as `unknown`, raw value on a property.
	cbomMaterialTypes = set("private-key", "public-key", "secret-key", "key", "ciphertext",
		"signature", "digest", "initialization-vector", "nonce", "seed", "salt",
		"shared-secret", "tag", "additional-data", "password", "credential", "token",
		"other", "unknown")
)

// cbomRefs resolves the references one asset makes to another.
type cbomRefs struct {
	byName map[string][]string
	byKey  map[string]CBOMAsset
}

// resolve returns the bom-ref and the name of the asset a reference points at:
// by asset key when the normalizer recorded one and that asset is in this
// document with the expected type, otherwise by the unambiguous-name rule
// (uniqueRef). Both empty when neither resolves.
//
// ⚠ THE KEY FIRST, BECAUSE A NAME CANNOT TELL THE TWO RSAs APART. The asset key
// of a certificate's signature algorithm names exactly one asset; its name
// matches both the signature and the pke algorithm theia reports, and the name
// rule — correctly — refuses to pick.
func (r cbomRefs) resolve(assetType, key, name string) (ref, targetName string) {
	if target, ok := r.byKey[key]; ok && key != "" && target.AssetType == assetType {
		return target.Ref, target.Name
	}
	if ref := uniqueRef(r.byName, assetType, name); ref != "" {
		return ref, name
	}
	return "", ""
}

func set(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// SerializeCBOM writes a CycloneDX 1.6 CBOM.
//
// ⚠ AN EMPTY CBOM IS SERIALIZED, NOT REFUSED — UNLIKE THE ML-BOM. A scan whose
// engines found no cryptography is a real outcome with an Engine Coverage
// section that explains it; refusing to render would fail the report over an
// honest result. The document says so explicitly instead: its metadata carries
// the asset count and a sentence, so an empty `components` array can never be
// read as "this project uses no cryptography".
func SerializeCBOM(doc CBOMDocument) ([]byte, error) {
	assets := append([]CBOMAsset(nil), doc.Assets...)
	sort.SliceStable(assets, func(i, j int) bool {
		ri, rj := typeRank(assets[i].AssetType), typeRank(assets[j].AssetType)
		if ri != rj {
			return ri < rj
		}
		if assets[i].Name != assets[j].Name {
			return assets[i].Name < assets[j].Name
		}
		return assets[i].Ref < assets[j].Ref
	})

	seen := map[string]bool{}
	for _, a := range assets {
		if a.Ref == "" {
			return nil, fmt.Errorf("crypto asset %q has no bom-ref", a.Name)
		}
		// ⚠ REFUSED, NEVER MERGED. Two assets sharing a ref is exactly the
		// collapse this serializer exists to end; silently keeping one would
		// understate the inventory in a compliance document.
		if seen[a.Ref] {
			return nil, fmt.Errorf("two crypto assets share the bom-ref %q", a.Ref)
		}
		seen[a.Ref] = true
	}

	refs := cbomRefs{byName: map[string][]string{}, byKey: map[string]CBOMAsset{}}
	for _, a := range assets {
		if _, ok := cbomTypeRank[a.AssetType]; ok {
			k := a.AssetType + "\x00" + a.Name
			refs.byName[k] = append(refs.byName[k], a.Ref)
			if a.AssetKey != "" {
				refs.byKey[a.AssetKey] = a
			}
		}
	}

	components := make([]cdx.Component, 0, len(assets))
	deps := map[string]map[string]bool{}
	link := func(from, to string) {
		if deps[from] == nil {
			deps[from] = map[string]bool{}
		}
		deps[from][to] = true
	}
	unsupported, privateKeys := 0, 0
	for _, a := range assets {
		c, ok := cbomComponent(a, refs)
		if !ok {
			unsupported++
			continue
		}
		components = append(components, c)
		link(cbomSubjectRef, a.Ref)
		if a.PrivateKeyInSource {
			privateKeys++
		}
		switch a.AssetType {
		case "certificate":
			// The certificate DEPENDS ON what signed it and on the key it
			// certifies — the two edges a reviewer follows from a certificate.
			if ref, _ := refs.resolve("algorithm", a.SignatureAlgorithmKey, a.SignatureAlgoRef); ref != "" {
				link(a.Ref, ref)
			}
			if ref, _ := refs.resolve("key", a.SubjectPublicKeyKey, a.SubjectPublicKeyRef); ref != "" {
				link(a.Ref, ref)
			}
		case "key":
			// A key depends on the algorithm it is for — by asset key only: a
			// key records no algorithm name to fall back on.
			if ref, _ := refs.resolve("algorithm", a.AlgorithmKey, ""); ref != "" {
				link(a.Ref, ref)
			}
		}
	}

	meta := map[string]string{
		"axebom:cbom:crypto_asset_count": strconv.Itoa(len(components)),
	}
	if len(components) == 0 {
		meta["axebom:cbom:empty"] = "No cryptographic assets were discovered. That is " +
			"not evidence that none exist: see the report's Engine Coverage section " +
			"for what each engine examined and what it could not see."
	}
	if unsupported > 0 {
		meta["axebom:cbom:unsupported_asset_types"] = strconv.Itoa(unsupported)
	}
	// ⚠ A FINDING IN THE DOCUMENT'S OWN METADATA, NOT ONLY ON THE ASSET. A reader
	// who never opens a component must still be told a private key was
	// committed; each flagged component's own property says which.
	if privateKeys > 0 {
		meta["axebom:cbom:private_keys_in_source_count"] = strconv.Itoa(privateKeys)
	}
	if finding := strings.TrimSpace(doc.PrivateKeysInSource); finding != "" {
		meta["axebom:cbom:finding:private_keys_in_source"] = finding
	}
	for i, n := range doc.Notes {
		if strings.TrimSpace(n) != "" {
			meta[fmt.Sprintf("axebom:cbom:note:%02d", i+1)] = n
		}
	}

	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.JSONSchema = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	// Only a real UUID — the schema pins serialNumber to an RFC-4122 URN. See
	// mlbom.go for how the official validator caught this there.
	if isUUID(doc.DocumentID) {
		bom.SerialNumber = "urn:uuid:" + strings.ToLower(doc.DocumentID)
	}
	bom.Metadata = &cdx.Metadata{
		Timestamp: dateTimeOrEmpty(doc.GeneratedAt),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    orUnnamed(doc.ToolName),
				Version: doc.ToolVersion,
			}},
		},
		Component: &cdx.Component{
			BOMRef: cbomSubjectRef,
			Type:   cdx.ComponentTypeApplication,
			Name:   orUnnamed(doc.ProjectName),
		},
		Properties: mlProperties(meta),
	}
	bom.Components = &components
	bom.Dependencies = mlDependencies(deps)

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	// ⚠ Encode, NOT EncodeVersion — AND THE LIBRARY IS WHY.
	//
	// EncodeVersion runs cyclonedx-go's down-conversion first, and v0.11.0's
	// `supportsComponentType` has no case for `cryptographic-asset`: it returns
	// false for EVERY spec version, so the converter rewrote each crypto asset
	// to `type: application` — a CBOM asserting its RSA keys are runnable
	// programs. The first test run caught it. This serializer only ever sets
	// 1.6 fields (every enum above is the 1.6 set), so the conversion has
	// nothing legitimate to do; the `$schema` it would have set is set above.
	if err := enc.Encode(bom); err != nil {
		return nil, fmt.Errorf("encode CBOM: %w", err)
	}
	return buf.Bytes(), nil
}

// cbomComponent maps one asset onto a CycloneDX `cryptographic-asset`.
//
// ⚠ BRANCHES ON THE ASSET TYPE, AND ONLY FILLS THAT TYPE'S PROPERTIES — the
// same rule CBOMSheets applies (invariant 5). A certificate carries no
// algorithmProperties; a key carries no certificateProperties.
func cbomComponent(a CBOMAsset, refs cbomRefs) (cdx.Component, bool) {
	props := map[string]string{}
	cp := &cdx.CryptoProperties{OID: a.OID}

	switch a.AssetType {
	case "algorithm":
		cp.AssetType = cdx.CryptoAssetTypeAlgorithm
		ap := &cdx.CryptoAlgorithmProperties{ClassicalSecurityLevel: a.ClassicalSecurityLevel}
		if v := strings.TrimSpace(a.Primitive); v != "" {
			ap.Primitive = cdx.CryptoPrimitive(enumOrOther(cbomPrimitives, v, "certin:crypto:primitive", props))
		}
		if v := strings.TrimSpace(a.Mode); v != "" {
			ap.Mode = cdx.CryptoAlgorithmMode(enumOrOther(cbomModes, v, "certin:crypto:mode", props))
		}
		if len(a.CryptoFunctions) > 0 {
			functions, raw := []cdx.CryptoFunction{}, []string{}
			added := map[string]bool{}
			for _, f := range a.CryptoFunctions {
				value := strings.ToLower(strings.TrimSpace(f))
				if !cbomFunctions[value] {
					raw = append(raw, f)
					value = "other"
				}
				if !added[value] {
					added[value] = true
					functions = append(functions, cdx.CryptoFunction(value))
				}
			}
			ap.CryptoFunctions = &functions
			if len(raw) > 0 {
				props["certin:crypto:crypto_functions"] = strings.Join(raw, ", ")
			}
		}
		// CERT-In's algorithm "List" has no CycloneDX field; it is a Table 9
		// value, so it travels under certin:, not axebom:.
		if len(a.AlgorithmList) > 0 {
			props["certin:crypto:algorithm_list"] = strings.Join(a.AlgorithmList, ", ")
		}
		// The normalizer's attributes with a 1.6 field of their own. They are
		// not CERT-In values, so an out-of-schema one travels under axebom:.
		if v := strings.TrimSpace(a.Padding); v != "" {
			ap.Padding = cdx.CryptoPadding(enumOrOther(cbomPaddings, v, "axebom:crypto:padding", props))
		}
		ap.Curve = strings.TrimSpace(a.Curve)
		ap.ParameterSetIdentifier = strings.TrimSpace(a.ParameterSetIdentifier)
		if l := a.NISTQuantumSecurityLevel; l != nil {
			// The 1.6 schema bounds it to 0..6. Outside that it is not a NIST
			// category, and writing it would fail validation.
			if *l >= 0 && *l <= 6 {
				level := *l
				ap.NistQuantumSecurityLevel = &level
			} else {
				props["axebom:crypto:nist_quantum_security_level"] = strconv.Itoa(*l)
			}
		}
		cp.AlgorithmProperties = ap

	case "key":
		// ⚠ A TABLE 9 KEY IS CycloneDX `related-crypto-material`, AND ITS TYPE
		// IS WHAT THE ENGINE READ IT AS, OR `unknown`. Absent, or outside the 1.6
		// enum, the material type is `unknown` rather than a guess — calling a
		// public key private would be an assertion a reviewer acts on. The raw
		// value travels on a property.
		cp.AssetType = cdx.CryptoAssetTypeRelatedCryptoMaterial
		rcm := &cdx.RelatedCryptoMaterialProperties{
			Type:   cdx.RelatedCryptoMaterialTypeUnknown,
			ID:     a.KeyID,
			Size:   a.KeySize,
			Format: strings.TrimSpace(a.MaterialFormat),
		}
		if v := strings.ToLower(strings.TrimSpace(a.MaterialType)); v != "" {
			if cbomMaterialTypes[v] {
				rcm.Type = cdx.RelatedCryptoMaterialType(v)
			} else {
				props["axebom:crypto:material_type"] = a.MaterialType
			}
		}
		if ref, _ := refs.resolve("algorithm", a.AlgorithmKey, ""); ref != "" {
			rcm.AlgorithmRef = cdx.BOMReference(ref)
		} else {
			props["axebom:crypto:algorithm_key"] = a.AlgorithmKey
		}
		if v := strings.ToLower(strings.TrimSpace(a.KeyState)); v != "" {
			if cbomKeyStates[v] {
				rcm.State = cdx.CryptoKeyState(v)
			} else {
				props["certin:crypto:key_state"] = a.KeyState
			}
		}
		rcm.CreationDate = dateTimeOrProperty(a.CreationDate, "certin:crypto:creation_date", props)
		rcm.ActivationDate = dateTimeOrProperty(a.ActivationDate, "certin:crypto:activation_date", props)
		rcm.ExpirationDate = dateTimeOrProperty(a.ExpirationDate, "axebom:crypto:expiration_date", props)
		cp.RelatedCryptoMaterialProperties = rcm

	case "protocol":
		cp.AssetType = cdx.CryptoAssetTypeProtocol
		pp := &cdx.CryptoProtocolProperties{
			Type:    cbomProtocolType(a.Name),
			Version: a.ProtocolVersion,
		}
		if len(a.CipherSuites) > 0 {
			suites := make([]cdx.CipherSuite, 0, len(a.CipherSuites))
			for _, s := range a.CipherSuites {
				suites = append(suites, cdx.CipherSuite{Name: s})
			}
			pp.CipherSuites = &suites
		}
		cp.ProtocolProperties = pp

	case "certificate":
		cp.AssetType = cdx.CryptoAssetTypeCertificate
		cert := &cdx.CertificateProperties{
			SubjectName:          a.CertSubject,
			IssuerName:           a.CertIssuer,
			CertificateFormat:    a.CertFormat,
			CertificateExtension: a.CertExtension,
		}
		cert.NotValidBefore = dateTimeOrProperty(a.NotValidBefore, "certin:crypto:not_valid_before", props)
		cert.NotValidAfter = dateTimeOrProperty(a.NotValidAfter, "certin:crypto:not_valid_after", props)
		// ⚠ A REFERENCE ONLY WHEN IT RESOLVES TO EXACTLY ONE ASSET. The asset
		// key the normalizer recorded (attributes.signature_algorithm_key,
		// subject_public_key_key) names one asset exactly. Failing that, the
		// stored value is a NAME; two algorithms can share it (theia reports RSA
		// twice), and pointing at either would be a guess stated as a fact.
		//
		// ⚠ THE CERT-In VALUE IS NEVER LOST. Unresolved, it travels as a property
		// instead of a bom-ref; resolved by key to an asset of another name, it
		// travels as well, because the referenced component no longer states it.
		if ref, target := refs.resolve("algorithm", a.SignatureAlgorithmKey, a.SignatureAlgoRef); ref != "" {
			cert.SignatureAlgorithmRef = cdx.BOMReference(ref)
			if a.SignatureAlgoRef != target {
				props["certin:crypto:signature_algo_ref"] = a.SignatureAlgoRef
			}
		} else {
			props["certin:crypto:signature_algo_ref"] = a.SignatureAlgoRef
			props["axebom:crypto:signature_algorithm_key"] = a.SignatureAlgorithmKey
		}
		if ref, target := refs.resolve("key", a.SubjectPublicKeyKey, a.SubjectPublicKeyRef); ref != "" {
			cert.SubjectPublicKeyRef = cdx.BOMReference(ref)
			if a.SubjectPublicKeyRef != target {
				props["certin:crypto:subject_public_key_ref"] = a.SubjectPublicKeyRef
			}
		} else {
			props["certin:crypto:subject_public_key_ref"] = a.SubjectPublicKeyRef
			props["axebom:crypto:subject_public_key_key"] = a.SubjectPublicKeyKey
		}
		cp.CertificateProperties = cert

	default:
		// Not a Table 9 type. Never defaulted to `algorithm` — that is the
		// false-coverage mistake invariant 5 names. Counted by the caller.
		return cdx.Component{}, false
	}

	props["axebom:crypto:component_key"] = a.ComponentKey
	props["axebom:crypto:identity_rule"] = a.IdentityRule
	props["axebom:crypto:identity_confidence"] = a.IdentityConfidence
	// ⚠ ON THE COMPONENT, NOT ON EACH OCCURRENCE. A 1.6 occurrence has no field
	// for the tool that saw it, and inventing one would fail the schema.
	props["axebom:crypto:engines"] = strings.Join(cbomSortedUnique(a.Engines), ", ")
	if a.PrivateKeyInSource {
		props["axebom:crypto:private_key_in_source"] = "true"
	}
	// ⚠ EMITTED EVEN WHEN FALSE. "Not quantum-vulnerable" is an answer; an
	// absent property reads as "not assessed".
	props["axebom:crypto:quantum_vulnerable"] = strconv.FormatBool(a.QuantumVulnerable)
	props["axebom:crypto:quantum_family"] = a.QuantumFamily
	props["axebom:crypto:quantum_readiness_group"] = a.QuantumReadinessGroup
	props["axebom:crypto:deprecation_status"] = a.DeprecationStatus
	props["axebom:crypto:deprecation_rationale"] = a.DeprecationRationale
	props["axebom:crypto:deprecation_reference"] = a.DeprecationReference
	props["axebom:crypto:pqc_recommendation"] = a.PQCRecommendation
	for column, citation := range a.Derivations {
		props["axebom:crypto:derived:"+column] = citation
	}

	c := cdx.Component{
		BOMRef:           a.Ref,
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             orUnnamed(a.Name),
		CryptoProperties: cp,
		Properties:       mlProperties(props),
	}
	if occurrences := cbomOccurrences(a.Evidence); len(occurrences) > 0 {
		c.Evidence = &cdx.Evidence{Occurrences: &occurrences}
	}
	return c, true
}

// cbomOccurrences renders evidence in a stable order.
func cbomOccurrences(evidence []CBOMEvidence) []cdx.EvidenceOccurrence {
	out := make([]cdx.EvidenceOccurrence, 0, len(evidence))
	for _, e := range evidence {
		if strings.TrimSpace(e.Path) == "" {
			continue
		}
		occ := cdx.EvidenceOccurrence{Location: e.Path}
		// Line 0 is what theia writes for "no line"; it is not line zero.
		if e.Line != nil && *e.Line > 0 {
			line := *e.Line
			occ.Line = &line
		}
		out = append(out, occ)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}
		return lineOf(out[i]) < lineOf(out[j])
	})
	// ⚠ ONE OCCURRENCE PER (path, line). Two engines evidencing the same line
	// are one place; listing it twice would read as two uses.
	deduped := make([]cdx.EvidenceOccurrence, 0, len(out))
	for i, o := range out {
		if i > 0 && o.Location == out[i-1].Location && lineOf(o) == lineOf(out[i-1]) {
			continue
		}
		deduped = append(deduped, o)
	}
	return deduped
}

// cbomSortedUnique returns the values sorted, without blanks or repeats.
func cbomSortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func lineOf(o cdx.EvidenceOccurrence) int {
	if o.Line == nil {
		return 0
	}
	return *o.Line
}

// cbomProtocolType maps a protocol NAME onto the 1.6 protocol-type enum.
//
// ⚠ DTLS AND QUIC ARE 1.7 VALUES. A 1.6 document carries them as `other`, with
// the real protocol still in the component name.
func cbomProtocolType(name string) cdx.CryptoProtocolType {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(name)))
	if len(fields) == 0 {
		return cdx.CryptoProtocolType("unknown")
	}
	word := fields[0]
	switch {
	case strings.HasPrefix(word, "dtls"):
		return cdx.CryptoProtocolType("other")
	case strings.HasPrefix(word, "tls"):
		return cdx.CryptoProtocolType("tls")
	case strings.HasPrefix(word, "ssh"):
		return cdx.CryptoProtocolType("ssh")
	case strings.HasPrefix(word, "ipsec"):
		return cdx.CryptoProtocolType("ipsec")
	case strings.HasPrefix(word, "ike"):
		return cdx.CryptoProtocolType("ike")
	case strings.HasPrefix(word, "sstp"):
		return cdx.CryptoProtocolType("sstp")
	case strings.HasPrefix(word, "wpa"):
		return cdx.CryptoProtocolType("wpa")
	default:
		return cdx.CryptoProtocolType("other")
	}
}

// enumOrOther returns v when the schema allows it, otherwise `other` — with the
// engine's raw value recorded under property, so the enum never loses it.
func enumOrOther(allowed map[string]bool, v, property string, props map[string]string) string {
	if lowered := strings.ToLower(v); allowed[lowered] {
		return lowered
	}
	props[property] = v
	return "other"
}

// dateTimeOrProperty returns v when it is a full RFC 3339 date-time, which is
// what the 1.6 schema requires. A date alone would need a time we do not know,
// so it travels raw on a property instead of being padded to midnight.
func dateTimeOrProperty(v, property string, props map[string]string) string {
	if v = strings.TrimSpace(v); v == "" {
		return ""
	}
	if dt := dateTimeOrEmpty(v); dt != "" {
		return dt
	}
	props[property] = v
	return ""
}

func dateTimeOrEmpty(v string) string {
	if _, err := time.Parse(time.RFC3339, v); err == nil {
		return v
	}
	return ""
}

// uniqueRef returns the bom-ref of the single asset of a type with this name,
// or "" when there is none or more than one.
func uniqueRef(byName map[string][]string, assetType, name string) string {
	if name == "" {
		return ""
	}
	if refs := byName[assetType+"\x00"+name]; len(refs) == 1 {
		return refs[0]
	}
	return ""
}

func typeRank(assetType string) int {
	if r, ok := cbomTypeRank[assetType]; ok {
		return r
	}
	return len(cbomTypeRank)
}
