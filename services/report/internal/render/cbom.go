package render

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// ─── CBOM ───────────────────────────────────────────────────────────────────
//
// ⚠ CERT-In TABLE 9 IS FOUR TABLES, NOT ONE, AND THIS FILE KEEPS THEM APART.
//
// Algorithms, Keys, Protocols and Certificates have different field sets (PDF
// p.45-48; the profile owns their sizes — invariant 2). FieldsFor refuses to flatten
// them into one list because there is no honest way to: a certificate has no
// `key_size`, a key has no `issuer_name`, and scoring either against the
// other's fields reports every CBOM at roughly 30% coverage, falsely, in a
// document shown to a regulator. So CBOM gets its own sheets — one inventory
// table per asset type, one coverage table that keeps the per-type field sets
// separate — instead of the generic Components / Field Coverage sheets every
// other BOM type uses.
//
// Unlike HBOM, a CBOM IS discovered — cbomkit-theia or an equivalent engine
// finds these assets by scanning, the same way Syft finds packages. The
// caveat this file carries is not "this was imported, not scanned"; it is
// "this has no single coverage number by design", which is why
// CBOMTypeDiscriminationNote reads differently from HBOMProvenanceNote.

// CryptoAsset is one row of normalize.crypto_assets.
//
// ⚠ EVERY ASSET CARRIES EVERY TYPE'S FIELDS, EMPTY WHERE THEY DO NOT APPLY —
// SAME AS THE TABLE, AND FOR THE SAME REASON.
//
// Storage is one wide struct (mirroring the one wide table,
// migrations/normalize/0003) because a scan produces one stream of assets
// whose type is a column value, not a table choice made in advance. What
// matters is that nothing in this package RENDERS every column for every
// asset in one table — CBOMSheets branches on AssetType and shows a type only
// its own fields, which is the actual coverage rule (invariant 5), not a
// presentation preference.
//
// ⚠ SNAKE_CASE JSON, MATCHING THE COLUMNS AND THE PROJECT API. This struct had
// no tags, so the JSON bundle carried `AssetType`/`CertSubject` while
// `GET /v1/projects/{id}/crypto-assets` carried `asset_type`/`cert_subject` for
// the same row — a consumer reading both had two vocabularies for one table.
type CryptoAsset struct {
	// ID is the normalize.crypto_assets row id — the export identity's
	// fallback (worker.cryptoRef) for an asset with no AssetKey. Two assets can
	// share a type AND a name — theia reports two RSA algorithms from one
	// certificate — and an identity built from those collapsed them into one.
	ID string `json:"id,omitempty"`
	// AssetKey is the normalizer's identity for the asset — the
	// docs/03-NORMALIZER-SPEC.md §1.6 merge key (`algorithm:…`,
	// `key:fp:sha256:…`, `cert:…`, `protocol:…`, `opaque:…`), unique per
	// document (migrations/normalize/0020). It is what every export identifies
	// the asset by and what a QBOM's crypto-asset references name: unlike the
	// row id, it survives re-normalization.
	AssetKey string `json:"asset_key,omitempty"`
	// IdentityRule is the §1.6 ladder rule that produced AssetKey;
	// IdentityConfidence is how much weight it bears (high / medium / low).
	IdentityRule       string `json:"identity_rule,omitempty"`
	IdentityConfidence string `json:"identity_confidence,omitempty"`
	// AssetType is "algorithm", "key", "protocol" or "certificate" — see the
	// CHECK constraint on normalize.crypto_assets.asset_type. It decides which
	// of the fields below CBOMSheets reads; the rest are never rendered for
	// this row, regardless of whether the loader populated them.
	AssetType string `json:"asset_type"`
	Name      string `json:"name"`
	// ComponentKey links this asset to a software component when the engine
	// could attribute it to one. Empty for a standalone certificate or a
	// protocol observed on the wire rather than compiled into a package.
	ComponentKey string `json:"component_key,omitempty"`

	// ---- algorithm (Table 9) ----
	Primitive              string   `json:"primitive,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	CryptoFunctions        []string `json:"crypto_functions,omitempty"`
	ClassicalSecurityLevel *int     `json:"classical_security_level,omitempty"`
	AlgorithmList          []string `json:"algorithm_list,omitempty"`

	// ---- key (Table 9) ----
	KeyID          string `json:"key_id,omitempty"`
	KeyState       string `json:"key_state,omitempty"`
	KeySize        *int   `json:"key_size,omitempty"`
	CreationDate   string `json:"creation_date,omitempty"`
	ActivationDate string `json:"activation_date,omitempty"`

	// ---- protocol (Table 9) ----
	ProtocolVersion string   `json:"protocol_version,omitempty"`
	CipherSuites    []string `json:"cipher_suites,omitempty"`

	// ---- shared by algorithm and protocol ----
	OID string `json:"oid,omitempty"`

	// ---- certificate (Table 9) ----
	CertSubject         string `json:"cert_subject,omitempty"`
	CertIssuer          string `json:"cert_issuer,omitempty"`
	NotValidBefore      string `json:"not_valid_before,omitempty"`
	NotValidAfter       string `json:"not_valid_after,omitempty"`
	SignatureAlgoRef    string `json:"signature_algo_ref,omitempty"`
	SubjectPublicKeyRef string `json:"subject_public_key_ref,omitempty"`
	CertFormat          string `json:"cert_format,omitempty"`
	CertExtension       string `json:"cert_extension,omitempty"`

	// ---- AxeBOM analysis (migrations/normalize/0003 and /0005) ----
	//
	// ⚠ NOT CERT-In FIELDS. `scored: false` in the profile, EXCLUDED from both
	// coverage numbers. If any of these moved completeness_pct, a customer's
	// compliance score would change because AxeBOM shipped a new detection
	// rule — with nothing different about their actual software.
	//
	// QuantumVulnerable carries no omitempty: `false` is an answer.
	QuantumVulnerable    bool   `json:"quantum_vulnerable"`
	PQCRecommendation    string `json:"pqc_recommendation,omitempty"`
	DeprecationStatus    string `json:"deprecation_status,omitempty"`
	QuantumFamily        string `json:"quantum_family,omitempty"`
	GroverNote           string `json:"grover_note,omitempty"`
	QuantumRationale     string `json:"quantum_rationale,omitempty"`
	DeprecationRationale string `json:"deprecation_rationale,omitempty"`
	DeprecationReference string `json:"deprecation_reference,omitempty"`
	EffectiveQuantumBits *int   `json:"effective_quantum_bits,omitempty"`
	// QuantumReadinessGroup is one of vulnerable / grover_note / post_quantum /
	// unassessed, computed ONCE in Python at CBOM-normalization time
	// (migrations/normalize/0005; axebom_shared.crypto.quantum_rules.
	// readiness_group). Empty means unset: a row written before this column
	// existed, or an asset the CBOM normalizer never ran analyse() over.
	//
	// ⚠ NEVER RE-DERIVE THIS IN GO. The migration's own comment says why: a
	// second implementation of the vulnerable/grover_note/post_quantum branch
	// is exactly the mistake that lets the CBOM and the QBOM disagree about
	// the same asset the first time either rule changes.
	QuantumReadinessGroup string `json:"quantum_readiness_group,omitempty"`

	// Derivations names the CERT-In columns on this row that AxeBOM filled
	// from a cited reference table rather than an engine reporting them:
	// {column: reference_id} (migrations/normalize/0019). Such a value counts
	// as present; every format footnotes it — see DerivedFieldNote.
	Derivations map[string]string `json:"derivations,omitempty"`

	// ---- evidence and provenance (migrations/normalize/0020) — never scored ----

	// Evidence is where engines saw the asset, repository-relative and
	// verbatim. Location is evidence, never identity: one certificate in two
	// folders is one asset with two entries here.
	Evidence []CryptoEvidence `json:"evidence,omitempty"`
	// Attributes are the non-CERT-In facts the normalizer kept — padding,
	// curve, parameter set, NIST quantum category, key-material type, whether
	// a private key was committed, the asset keys a certificate or key refers
	// to. Read through the Attr* methods; never rendered as a Table 9 column.
	Attributes map[string]any `json:"attributes,omitempty"`
	// Engines are the distinct engines that reported the asset, sorted
	// (normalize.crypto_asset_provenance).
	Engines []string `json:"engines,omitempty"`
}

// CryptoEvidence is one place an engine saw a crypto asset. Line is nil when
// the engine named a file but no line — never 0, which is not a line.
type CryptoEvidence struct {
	Path   string `json:"path"`
	Line   *int   `json:"line"`
	Engine string `json:"engine,omitempty"`
}

// AttrString reads one attribute as text: "" when absent or not a scalar.
func (a CryptoAsset) AttrString(key string) string {
	switch v := a.Attributes[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	case int:
		return strconv.Itoa(v)
	}
	return ""
}

// AttrInt reads one attribute as a whole number.
func (a CryptoAsset) AttrInt(key string) (int, bool) {
	switch v := a.Attributes[key].(type) {
	case int:
		return v, true
	case float64:
		if v == math.Trunc(v) && !math.IsInf(v, 0) {
			return int(v), true
		}
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n), true
		}
	}
	return 0, false
}

// PrivateKeyInSource reports whether an engine that reads key files found this
// asset's private key committed to the scanned source.
//
// ⚠ ONLY A JSON `true` COUNTS. The normalizer sets it only for material read
// out of a file — never for a key the code generates at runtime, which would
// accuse a repository of committing a key it never contained
// (workers/cbom/normalize/pipeline.py).
func (a CryptoAsset) PrivateKeyInSource() bool {
	v, _ := a.Attributes["private_key_in_source"].(bool)
	return v
}

// CryptoLocations are an asset's distinct evidence locations — "path:line",
// or "path" where the engine reported no line — sorted by path, then line.
//
// ⚠ ONE ENTRY PER (path, line). Two engines evidencing the same line are one
// place; listing it twice would read as two uses.
func CryptoLocations(a CryptoAsset) []string {
	type location struct {
		path string
		line int
	}
	seen := map[location]bool{}
	var found []location
	for _, e := range a.Evidence {
		path := strings.TrimSpace(e.Path)
		if path == "" {
			continue
		}
		l := location{path: path}
		if e.Line != nil && *e.Line > 0 {
			l.line = *e.Line
		}
		if !seen[l] {
			seen[l] = true
			found = append(found, l)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].path != found[j].path {
			return found[i].path < found[j].path
		}
		return found[i].line < found[j].line
	})
	out := make([]string, 0, len(found))
	for _, l := range found {
		if l.line > 0 {
			out = append(out, l.path+":"+strconv.Itoa(l.line))
		} else {
			out = append(out, l.path)
		}
	}
	return out
}

// CryptoLocationCell is the inventory's Location value: the first location,
// and how many more there are. The full list is in the JSON bundle.
func CryptoLocationCell(a CryptoAsset) string {
	locations := CryptoLocations(a)
	switch len(locations) {
	case 0:
		return model.NotProvided
	case 1:
		return locations[0]
	}
	return locations[0] + " (+" + strconv.Itoa(len(locations)-1) + " more)"
}

// CryptoEnginesCell is the inventory's Engines value.
func CryptoEnginesCell(a CryptoAsset) string {
	return orNotProvided(strings.Join(a.Engines, ", "))
}

// cryptoEvidenceHeader are the per-row "where, and who said so" columns every
// crypto inventory carries.
//
// ⚠ THEY APPLY TO EVERY ASSET TYPE ALIKE, so they do not reintroduce the flat
// table invariant 5 forbids — and they sit after the CERT-In fields, so no
// reader takes a file path for a Table 9 value.
var cryptoEvidenceHeader = []string{"Location", "Engines"}

// cryptoAssetTypeOrder is CERT-In Table 9's own presentation order — PDF
// p.45-48 lists algorithms, then keys, then protocols, then certificates.
var cryptoAssetTypeOrder = []string{"algorithm", "key", "protocol", "certificate"}

var cryptoAssetTypeLabel = map[string]string{
	"algorithm":   "Algorithms",
	"key":         "Keys",
	"protocol":    "Protocols",
	"certificate": "Certificates",
}

// CBOMSheets are every sheet a CBOM report carries, IN PLACE OF the generic
// Field Coverage and Components sheets Sheets() builds for every other type.
func CBOMSheets(b BOM) []Sheet {
	sheets := []Sheet{cryptoFieldCoverageSheet(b)}
	for _, t := range cryptoAssetTypeOrder {
		sheets = append(sheets, cryptoInventorySheet(t, b.CryptoAssets))
	}
	return sheets
}

// cryptoFieldCoverageSheet is fieldCoverageSheet's CBOM equivalent: the same
// columns, from the same source, but grouped by asset type instead of
// assuming one flat list exists.
//
// ⚠ THE COUNTS COME FROM b.Coverage.Fields, NEVER RECOMPUTED HERE. The
// normalizer's score_crypto already scored each asset against its own type's
// field set (that is the whole point of it existing) and wrote the result to
// bom_documents.coverage_breakdown; re-deriving it in the renderer would be a
// second implementation of the same rule, and the two would disagree the
// first time one changed.
func cryptoFieldCoverageSheet(b BOM) Sheet {
	rows := CryptoFieldCoverageRows(b)
	// ⚠ THE FOOTNOTE TRAVELS WITH THE NUMBERS IT QUALIFIES. The Notes sheet
	// carries it too (TypeNotes), but a reader who opens only this sheet is
	// looking at the Substantive column the derived values are counted in.
	if note := DerivedFieldNote(b); note != "" {
		trailer := make([]string, len(CryptoFieldCoverageHeader))
		trailer[0] = "Note"
		trailer[2] = note
		rows = append(rows, trailer)
	}
	return Sheet{
		Name:   "Crypto Field Coverage",
		Header: CryptoFieldCoverageHeader,
		Rows:   StaticRows(rows),
		Width:  24,
	}
}

// CryptoFieldCoverageHeader is the row every renderer of the breakdown starts
// with. Exported alongside the rows so the Word document and the workbook
// cannot label the same numbers differently — which is also why the sheet
// above uses it instead of its own copy, as it used to.
//
// "Of which derived" is a SUBSET of Substantive, never added to it: the values
// AxeBOM filled from a cited reference table (user decision 2026-09-11 —
// derive, count, label).
var CryptoFieldCoverageHeader = []string{
	"Asset Type", "Field ID", "Field", "Weight",
	"Substantive", "Of which derived (AxeBOM, cited)",
	"Declared (incl. " + model.NotProvided + ")", "Entities", "Source",
}

// DerivedFieldNote is the footnote every format carries when AxeBOM filled
// CERT-In values from a cited reference table rather than an engine reporting
// them. Empty when nothing on this BOM was derived.
//
// ⚠ ONE SENTENCE, BUILT ONCE, RENDERED EVERYWHERE — the same reasoning
// TypeNotes records: a caveat present in one format and absent from another is
// worse than one absent everywhere, because the reader holding the other format
// has no way to know it exists.
func DerivedFieldNote(b BOM) string {
	perColumn := map[string]int{}
	refs := map[string]bool{}
	total := 0
	for _, a := range b.CryptoAssets {
		for column, ref := range a.Derivations {
			perColumn[column]++
			refs[ref] = true
			total++
		}
	}
	if total == 0 {
		return ""
	}

	columns := make([]string, 0, len(perColumn))
	for column := range perColumn {
		columns = append(columns, column)
	}
	sort.Strings(columns)
	columnParts := make([]string, 0, len(columns))
	for _, column := range columns {
		columnParts = append(columnParts, column+" ×"+strconv.Itoa(perColumn[column]))
	}

	sources := make([]string, 0, len(refs))
	for ref := range refs {
		sources = append(sources, ref)
	}
	sort.Strings(sources)
	sourceParts := make([]string, 0, len(sources))
	for _, ref := range sources {
		sourceParts = append(sourceParts, DerivationCitation(ref, b.Coverage.DerivationSources))
	}

	return strconv.Itoa(total) + " field value(s) were derived from cited reference " +
		"tables, not reported by an engine (" + strings.Join(columnParts, ", ") + "): " +
		strings.Join(sourceParts, "; ") + ". A derived value counts as present — it is a " +
		"fixed property of the fully identified algorithm — and is labelled so a reader " +
		"can tell AxeBOM's lookup from an engine's claim."
}

// DerivationCitation renders one reference id with its citation, when the
// document recorded one.
func DerivationCitation(ref string, sources map[string]string) string {
	if c := strings.TrimSpace(sources[ref]); c != "" {
		return ref + " — " + c
	}
	return ref
}

// DerivedColumnsText lists which of an asset's columns were derived, and from
// which reference: "classical_security_level (ref); oid (ref)". Empty when the
// engine reported everything on the row.
func DerivedColumnsText(a CryptoAsset) string {
	columns := make([]string, 0, len(a.Derivations))
	for column := range a.Derivations {
		columns = append(columns, column)
	}
	sort.Strings(columns)
	parts := make([]string, 0, len(columns))
	for _, column := range columns {
		parts = append(parts, column+" ("+a.Derivations[column]+")")
	}
	return strings.Join(parts, "; ")
}

// CryptoAssetSummary is the one-line description a standard document carries
// for an asset, in a field every format keeps.
//
// ⚠ SPDX DROPS EVERY PROPERTY. protobom renders properties into SPDX only
// under a mod this product does not enable, so an SPDX CBOM said nothing about
// an asset but its name and `primaryPackagePurpose: OTHER` — not whether it was
// a key or a certificate, and not which of its values AxeBOM derived. The
// package description survives, so the facts a reader most needs go there —
// and a committed private key is one of them (PrivateKeysInSource).
func CryptoAssetSummary(a CryptoAsset, sources map[string]string) string {
	summary := "Cryptographic asset (CERT-In Table 9 type: " + a.AssetType + ")."
	if len(a.Derivations) > 0 {
		columns := make([]string, 0, len(a.Derivations))
		for column := range a.Derivations {
			columns = append(columns, column)
		}
		sort.Strings(columns)
		parts := make([]string, 0, len(columns))
		for _, column := range columns {
			parts = append(parts, column+" from "+DerivationCitation(a.Derivations[column], sources))
		}
		summary += " Derived from cited reference tables, not reported by an engine: " +
			strings.Join(parts, "; ") + "."
	}
	if a.PrivateKeyInSource() {
		summary += " " + PrivateKeysInSourceTitle + ": private key material for this " +
			"asset was found committed to the scanned source (" + locationsText(a) + "). " +
			privateKeysInSourceAdvice
	}
	return summary
}

// CryptoFieldCoverageRows is Table 9's per-asset-type breakdown.
//
// ⚠ EXTRACTED BECAUSE THE WORD DOCUMENT HAD NO FIELD COVERAGE AT ALL.
// docxCoveragePage renders a flat per-field table and returns early when the
// field list is empty — which it always is for a CBOM, because Table 9 is
// type-discriminated and FieldsFor deliberately refuses to flatten it
// (invariant 5). The early return was correct; the missing alternative was not,
// so a CBOM's Word artifact carried two coverage percentages and no way to see
// where they came from.
func CryptoFieldCoverageRows(b BOM) [][]string {
	byID := make(map[string]FieldCoverage, len(b.Coverage.Fields))
	for _, fc := range b.Coverage.Fields {
		byID[fc.FieldID] = fc
	}

	var rows [][]string
	for _, t := range cryptoAssetTypeOrder {
		for _, f := range model.CryptoFieldsByAssetType[t] {
			fc, seen := byID[f.ID]
			present, declared, total := model.NotProvided, model.NotProvided, model.NotProvided
			if seen {
				present = strconv.Itoa(fc.Present)
				declared = strconv.Itoa(fc.Declared)
				total = strconv.Itoa(fc.Total)
			}
			rows = append(rows, []string{
				cryptoAssetTypeLabel[t], f.ID, f.Name, strconv.Itoa(f.Weight),
				present, declared, total, citation(f),
			})
		}
	}

	return rows
}

// cryptoInventorySheet renders ONE asset type's assets against ONLY that
// type's fields.
//
// ⚠ THE LITERAL CASE INVARIANT 5 EXISTS TO PREVENT. Putting every type's
// columns in one table and leaving the inapplicable ones blank for each row
// LOOKS harmless and IS the 30%-coverage mistake: a reader sees a certificate
// row with an empty `key_size` cell and cannot tell "not asked for this type"
// from "not reported". A separate sheet per type makes the question not
// arise — there is no `key_size` column on the Certificates sheet at all.
func cryptoInventorySheet(assetType string, assets []CryptoAsset) Sheet {
	fields := model.CryptoFieldsByAssetType[assetType]

	header := make([]string, 0, len(fields)+3+len(cryptoEvidenceHeader)+len(cryptoAnalysisHeader))
	// The asset key is the identity the CycloneDX bom-ref and a QBOM's
	// crypto-asset references carry, so a reader can find this row from either.
	header = append(header, "Asset Key", "Component Key")
	for _, f := range fields {
		header = append(header, f.Name)
	}
	// ⚠ RIGHT AFTER THE CERT-In FIELDS IT QUALIFIES, NOT APPENDED TO A CELL. A
	// "†" on `256` would turn a number into text; a column says, per row, which
	// of the values to its left AxeBOM looked up and from where.
	header = append(header, derivedColumnHeader)
	header = append(header, cryptoEvidenceHeader...)
	header = append(header, cryptoAnalysisHeader...)

	rows := RowSource(func(emit func([]string) error) error {
		for _, a := range assets {
			if a.AssetType != assetType {
				continue
			}
			row := make([]string, 0, len(header))
			row = append(row, orNotProvided(a.AssetKey), orNotProvided(a.ComponentKey))
			for _, f := range fields {
				row = append(row, orNotProvided(cryptoFieldValue(f.ID, a)))
			}
			row = append(row, derivedCell(a))
			// Paths come from the customer's repository; the sheet writer's
			// cell() escapes a leading formula character (invariant 8).
			row = append(row, CryptoLocationCell(a), CryptoEnginesCell(a))
			row = append(row, cryptoAnalysisRow(a)...)
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{
		Name:   "Crypto - " + cryptoAssetTypeLabel[assetType],
		Header: header,
		Rows:   rows,
		Width:  22,
	}
}

// derivedColumnHeader labels the per-row derivation column on every inventory.
const derivedColumnHeader = "Derived From Reference (AxeBOM, cited)"

// derivedCell is the derivation column's value for one row.
//
// ⚠ "none", NOT `not-provided`. This is not a CERT-In field whose value is
// unknown; it is AxeBOM saying every value on the row came from an engine.
func derivedCell(a CryptoAsset) string {
	if text := DerivedColumnsText(a); text != "" {
		return text
	}
	return "none"
}

// cryptoFieldValue reads the one struct field a CERT-In Table 9 field id maps
// to. One switch covering every type's ids ("name" and "asset_type" appear
// once per type because each type's copy is a distinct profile field id)
// rather than a per-type function, so the mapping from id to column lives in
// exactly one place — the same reasoning loadComponents' own comment gives for
// its column-to-field-id map.
func cryptoFieldValue(fieldID string, a CryptoAsset) string {
	switch fieldID {
	case model.FieldCertinCryptoAlgoName, model.FieldCertinCryptoKeyName,
		model.FieldCertinCryptoProtoName, model.FieldCertinCryptoCertName:
		return a.Name
	case model.FieldCertinCryptoAlgoAssetType, model.FieldCertinCryptoKeyAssetType,
		model.FieldCertinCryptoProtoAssetType, model.FieldCertinCryptoCertAssetType:
		return a.AssetType
	case model.FieldCertinCryptoAlgoPrimitive:
		return a.Primitive
	case model.FieldCertinCryptoAlgoMode:
		return a.Mode
	case model.FieldCertinCryptoAlgoCryptoFunctions:
		return joinList(a.CryptoFunctions)
	case model.FieldCertinCryptoAlgoSecurityLevel:
		return intOrNotProvided(a.ClassicalSecurityLevel)
	case model.FieldCertinCryptoAlgoOid, model.FieldCertinCryptoProtoOid:
		return a.OID
	case model.FieldCertinCryptoAlgoList:
		return joinList(a.AlgorithmList)
	case model.FieldCertinCryptoKeyId:
		return a.KeyID
	case model.FieldCertinCryptoKeyState:
		return a.KeyState
	case model.FieldCertinCryptoKeySize:
		return intOrNotProvided(a.KeySize)
	case model.FieldCertinCryptoKeyCreationDate:
		return a.CreationDate
	case model.FieldCertinCryptoKeyActivationDate:
		return a.ActivationDate
	case model.FieldCertinCryptoProtoVersion:
		return a.ProtocolVersion
	case model.FieldCertinCryptoProtoCipherSuites:
		return joinList(a.CipherSuites)
	case model.FieldCertinCryptoCertSubjectName:
		return a.CertSubject
	case model.FieldCertinCryptoCertIssuerName:
		return a.CertIssuer
	case model.FieldCertinCryptoCertNotValidBefore:
		return a.NotValidBefore
	case model.FieldCertinCryptoCertNotValidAfter:
		return a.NotValidAfter
	case model.FieldCertinCryptoCertSigAlgoRef:
		return a.SignatureAlgoRef
	case model.FieldCertinCryptoCertSubjectPkRef:
		return a.SubjectPublicKeyRef
	case model.FieldCertinCryptoCertFormat:
		return a.CertFormat
	case model.FieldCertinCryptoCertExtension:
		return a.CertExtension
	default:
		return ""
	}
}

// cryptoAnalysisHeader are AxeBOM's own analysis columns, appended AFTER
// every type's CERT-In fields on every inventory sheet.
//
// ⚠ LABELLED IN THE HEADER TEXT ITSELF. The generic field-coverage sheet
// labels an extension field through citation(); an inventory sheet has no
// per-column citation cell, so the label has to live in the column name or a
// reader will take AxeBOM's own quantum analysis for a CERT-In field.
var cryptoAnalysisHeader = []string{
	"Quantum Vulnerable (AxeBOM analysis)",
	"PQC Recommendation (AxeBOM analysis)",
	"Deprecation Status (AxeBOM analysis)",
	"Quantum Family (AxeBOM analysis)",
	"Effective Bits After Grover (AxeBOM analysis)",
	"Grover Note (AxeBOM analysis)",
	"Quantum Rationale (AxeBOM analysis)",
	"Deprecation Rationale (AxeBOM analysis)",
	"Deprecation Reference (AxeBOM analysis)",
	"Quantum Readiness Group (AxeBOM analysis)",
}

func cryptoAnalysisRow(a CryptoAsset) []string {
	return []string{
		boolText(a.QuantumVulnerable),
		orNotProvided(a.PQCRecommendation),
		orNotProvided(a.DeprecationStatus),
		orNotProvided(a.QuantumFamily),
		intOrNotProvided(a.EffectiveQuantumBits),
		orNotProvided(a.GroverNote),
		orNotProvided(a.QuantumRationale),
		orNotProvided(a.DeprecationRationale),
		orNotProvided(a.DeprecationReference),
		orNotProvided(a.QuantumReadinessGroup),
	}
}

// CBOMTypeDiscriminationNote is the line every CBOM report carries.
//
// ⚠ IT EXPLAINS THE ABSENCE OF THE ONE THING EVERY OTHER BOM TYPE HAS: a
// single flat Components sheet and a single coverage percentage per field. A
// reader who has just seen an SBOM will look for the same shape here and, not
// finding it, may assume something broke rather than that CERT-In itself
// defines four different tables (p.45-48). This says which is true.
const CBOMTypeDiscriminationNote = "CERT-In Table 9 defines four different " +
	"field sets — Algorithms, Keys, Protocols and Certificates — not one, so " +
	"this report has no single \"Components\" sheet and no single per-field " +
	"coverage percentage the way an SBOM does. Each asset type has its own " +
	"inventory sheet, showing only that type's fields, and the Crypto Field " +
	"Coverage sheet scores each type against its own field set. Merging them " +
	"into one table would score a certificate against a key's fields and " +
	"report a false gap, or the reverse."

// ─── PDF (minimum-bar treatment — see qbom.go and pdf.go for the shared
// scope decision) ───────────────────────────────────────────────────────────

// cryptoCoveragePage replaces coveragePage in the PDF for a CBOM.
//
// ⚠ NO PER-FIELD TABLE HERE, DELIBERATELY. r.fields is empty for a CBOM —
// FieldsFor has nothing flat to give it — so coveragePage's per-field
// breakdown table would render a header with zero rows under it, which reads
// as "no coverage was computed" rather than the true state, "coverage exists
// but is type-discriminated". The two real numbers are still shown; the full
// per-type breakdown is one call away in the XLSX and JSON exports, which
// have the row budget four separate tables need and a page-capped PDF does
// not.
func (r *pdfRender) cryptoCoveragePage() {
	r.doc.AddPage()
	r.heading("Coverage")

	r.body("Completeness: " + pct(r.bom.Coverage.CompletenessPct))
	r.note("Substantive values only, each asset scored against its OWN asset " +
		"type's CERT-In Table 9 field set. This is the compliance signal.")
	r.body("Declaration: " + pct(r.bom.Coverage.DeclarationPct))
	r.note("Any value, including an explicit `" + model.NotProvided + "`. A " +
		"representation check, not a compliance number.")
	r.doc.Ln(2)

	if r.bom.Coverage.Formula != "" {
		r.body("Formula: " + r.bom.Coverage.Formula)
	}
	r.note(weightsNote)
	r.doc.Ln(3)

	r.heading("Crypto assets by type")
	r.note(CBOMTypeDiscriminationNote)
	r.doc.Ln(2)

	// ⚠ `unassessed` GETS ITS OWN COLUMN. It is neither current nor weak: no
	// verdict could be reached (an unsized RSA key, an unrecognised name, a
	// protocol with no version). Folded into either neighbour it would read as
	// fine or as condemned — and hidden, it would read as nothing to look at.
	widths := []float64{46, 24, 38, 44, 30}
	r.tableHeader([]string{
		"Asset type", "Count", "Quantum-vulnerable", "Deprecated / weak / broken", "Unassessed",
	}, widths)
	for _, t := range cryptoAssetTypeOrder {
		total, vulnerable, weak, unassessed := 0, 0, 0, 0
		for _, a := range r.bom.CryptoAssets {
			if a.AssetType != t {
				continue
			}
			total++
			if a.QuantumVulnerable {
				vulnerable++
			}
			switch a.DeprecationStatus {
			case "deprecated", "weak", "broken":
				weak++
			case "unassessed":
				unassessed++
			}
		}
		r.tableRow([]string{
			cryptoAssetTypeLabel[t], strconv.Itoa(total), strconv.Itoa(vulnerable),
			strconv.Itoa(weak), strconv.Itoa(unassessed),
		}, widths)
	}
	r.doc.Ln(3)
	r.note("Full per-type field coverage (present, of which derived, declared and " +
		"total against each type's own field set) is in the XLSX and JSON " +
		"exports' Crypto Field Coverage sheet — four separate tables do not fit " +
		"this page budget without truncating the report's other mandatory sections.")
	// The footnote sits under the numbers it qualifies, not only in Notes.
	if note := DerivedFieldNote(r.bom); note != "" {
		r.doc.Ln(2)
		r.note(note)
	}
}

// cryptoInventoryPage replaces componentPages in the PDF for a CBOM.
//
// ⚠ TYPE, NAME, LOCATION, ENGINES AND READINESS ONLY — NEVER A TYPE'S OWN
// FIELDS. Those columns apply uniformly to every asset type, so listing them
// together does not repeat the mistake this file exists to prevent. A
// `key_size` or `cert_subject` column would; the full per-type tables stay in
// the XLSX and JSON exports.
func (r *pdfRender) cryptoInventoryPage() {
	r.doc.AddPage()
	r.heading("Cryptographic Assets")
	r.note("Type, name, where it was found, which engines reported it and the " +
		"quantum-readiness bucket only, to fit the page budget. The full per-type " +
		"field tables, and every location, are in the XLSX and JSON exports.")
	r.doc.Ln(2)

	widths := []float64{22, 48, 50, 30, 30}
	r.tableHeader([]string{"Type", "Name", "Location", "Engines", "Quantum readiness"}, widths)
	for i, a := range r.bom.CryptoAssets {
		if r.overCap() {
			r.markTruncated("crypto assets", i, len(r.bom.CryptoAssets))
			return
		}
		r.tableRow([]string{
			cryptoAssetTypeLabel[a.AssetType], orNotProvided(a.Name),
			CryptoLocationCell(a), CryptoEnginesCell(a), orNotProvided(a.QuantumReadinessGroup),
		}, widths)
	}
}

// ─── Private keys found in source ───────────────────────────────────────────
//
// ⚠ A FINDING, IN EVERY FORMAT, AND ABSENT WHEN THERE IS NONE.
//
// A private key committed to a repository is readable by everyone who can read
// the repository, for as long as its history exists. The normalizer flags the
// asset (attributes.private_key_in_source) and records the
// CBOM_PRIVATE_KEY_IN_SOURCE diagnostic; this block is how a reader holding any
// ONE artifact is told — the reasoning TypeNotes records for why a statement
// cannot live in only some formats. It is a finding, so it is rendered as one:
// never folded into a methodology note, and never phrased as a pass.
//
// AxeBOM never reads or stores the key material. The paths are the finding.

// PrivateKeysInSourceTitle heads the block in every format.
const PrivateKeysInSourceTitle = "Private keys found in source"

// privateKeysInSourceAdvice is what the reader must do. Deleting the file is
// not enough, which is why history is named.
const privateKeysInSourceAdvice = "The key material itself is never read or " +
	"stored by AxeBOM; this report records only where it was found. Treat each " +
	"key as exposed: rotate it, then remove it from the source, including from " +
	"the repository's history — a later commit that deletes the file leaves the " +
	"key recoverable from every commit before it."

// PrivateKeyInSource is one asset in the block.
type PrivateKeyInSource struct {
	AssetType string   `json:"asset_type"`
	Name      string   `json:"name"`
	AssetKey  string   `json:"asset_key,omitempty"`
	Locations []string `json:"locations"`
	Engines   []string `json:"engines,omitempty"`
}

// PrivateKeysInSource lists every flagged asset, in a stable order; nil when
// nothing was flagged.
func PrivateKeysInSource(b BOM) []PrivateKeyInSource {
	var out []PrivateKeyInSource
	for _, a := range b.CryptoAssets {
		if !a.PrivateKeyInSource() {
			continue
		}
		out = append(out, PrivateKeyInSource{
			AssetType: a.AssetType,
			Name:      a.Name,
			AssetKey:  a.AssetKey,
			Locations: CryptoLocations(a),
			Engines:   a.Engines,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].AssetKey < out[j].AssetKey
	})
	return out
}

// PrivateKeysInSourceFinding is the block's statement; "" when nothing was
// flagged.
func PrivateKeysInSourceFinding(b BOM) string {
	n := len(PrivateKeysInSource(b))
	if n == 0 {
		return ""
	}
	return PrivateKeysInSourceTitle + ": " + strconv.Itoa(n) + " asset(s) carry " +
		"private key material committed to the scanned source. " + privateKeysInSourceAdvice
}

// PrivateKeysInSourceLines are one line per flagged asset, naming where it was
// found.
func PrivateKeysInSourceLines(b BOM) []string {
	keys := PrivateKeysInSource(b)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		where := "no path reported"
		if len(k.Locations) > 0 {
			where = strings.Join(k.Locations, "; ")
		}
		out = append(out, cryptoAssetTypeSingular(k.AssetType)+" \""+orNotProvided(k.Name)+"\" — "+where)
	}
	return out
}

// PrivateKeysInSourceStatement is the whole block as one string — the finding
// and every flagged asset with where it was found — for a format that can
// carry only one value, such as a CycloneDX metadata property. "" when none.
func PrivateKeysInSourceStatement(b BOM) string {
	finding := PrivateKeysInSourceFinding(b)
	if finding == "" {
		return ""
	}
	return finding + " Found: " + strings.Join(PrivateKeysInSourceLines(b), " | ") + "."
}

// locationsText is every location of an asset, for a sentence.
func locationsText(a CryptoAsset) string {
	if locations := CryptoLocations(a); len(locations) > 0 {
		return strings.Join(locations, "; ")
	}
	return "no path reported"
}

// cryptoAssetTypeSingular names one asset's type in a sentence.
func cryptoAssetTypeSingular(assetType string) string {
	switch assetType {
	case "algorithm":
		return "Algorithm"
	case "key":
		return "Key"
	case "protocol":
		return "Protocol"
	case "certificate":
		return "Certificate"
	}
	return orNotProvided(assetType)
}

// privateKeyRows are the block's table rows — one per location, so a reader
// can filter the spreadsheet by path — capped at limit (<= 0 means no cap).
func privateKeyRows(keys []PrivateKeyInSource, limit int) (rows [][]string, truncated bool) {
	for _, k := range keys {
		locations := k.Locations
		if len(locations) == 0 {
			locations = []string{"no path reported"}
		}
		for _, location := range locations {
			if limit > 0 && len(rows) >= limit {
				return rows, true
			}
			rows = append(rows, []string{
				cryptoAssetTypeSingular(k.AssetType), orNotProvided(k.Name), location,
				orNotProvided(strings.Join(k.Engines, ", ")), orNotProvided(k.AssetKey),
			})
		}
	}
	return rows, false
}

// privateKeysInSourceHeader labels privateKeyRows' columns.
var privateKeysInSourceHeader = []string{"Asset Type", "Name", "Location", "Engines", "Asset Key"}

// privateKeysInSourceSheet is the XLSX block. ok is false when nothing was
// flagged: the sheet is absent, not empty.
//
// ⚠ THE STATEMENT IS THE FIRST ROW, so a reader who opens only this sheet reads
// what to do before the list. Every cell — the paths come from the customer's
// repository — goes through the sheet writer's cell() (invariant 8).
func privateKeysInSourceSheet(b BOM) (Sheet, bool) {
	keys := PrivateKeysInSource(b)
	if len(keys) == 0 {
		return Sheet{}, false
	}
	rows := [][]string{{"Finding", PrivateKeysInSourceFinding(b), "", "", ""}}
	list, _ := privateKeyRows(keys, 0)
	return Sheet{
		Name:   "Private Keys in Source",
		Header: privateKeysInSourceHeader,
		Rows:   StaticRows(append(rows, list...)),
		Width:  40,
	}, true
}

// privateKeysInSourcePage is the PDF block; nothing at all when none.
func (r *pdfRender) privateKeysInSourcePage() {
	keys := PrivateKeysInSource(r.bom)
	if len(keys) == 0 {
		return
	}
	r.doc.AddPage()
	r.heading(PrivateKeysInSourceTitle)
	r.calloutBox("Finding", PrivateKeysInSourceFinding(r.bom))
	r.doc.Ln(3)

	rows, _ := privateKeyRows(keys, 0)
	widths := []float64{24, 46, 80, 30}
	r.tableHeader(privateKeysInSourceHeader[:4], widths)
	for i, row := range rows {
		if r.overCap() {
			r.markTruncated("private-key locations", i, len(rows))
			return
		}
		r.tableRow(row[:4], widths)
	}
}
