package render

import (
	"strconv"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// ─── CBOM ───────────────────────────────────────────────────────────────────
//
// ⚠ CERT-In TABLE 9 IS FOUR TABLES, NOT ONE, AND THIS FILE KEEPS THEM APART.
//
// Algorithms, Keys, Protocols and Certificates have different field sets — 8,
// 7, 5 and 10 fields respectively (PDF p.45-48). FieldsFor refuses to flatten
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
type CryptoAsset struct {
	// AssetType is "algorithm", "key", "protocol" or "certificate" — see the
	// CHECK constraint on normalize.crypto_assets.asset_type. It decides which
	// of the fields below CBOMSheets reads; the rest are never rendered for
	// this row, regardless of whether the loader populated them.
	AssetType string
	Name      string
	// ComponentKey links this asset to a software component when the engine
	// could attribute it to one. Empty for a standalone certificate or a
	// protocol observed on the wire rather than compiled into a package.
	ComponentKey string

	// ---- algorithm (Table 9, 8 fields) ----
	Primitive              string
	Mode                   string
	CryptoFunctions        []string
	ClassicalSecurityLevel *int
	AlgorithmList          []string

	// ---- key (Table 9, 7 fields) ----
	KeyID          string
	KeyState       string
	KeySize        *int
	CreationDate   string
	ActivationDate string

	// ---- protocol (Table 9, 5 fields) ----
	ProtocolVersion string
	CipherSuites    []string

	// ---- shared by algorithm and protocol ----
	OID string

	// ---- certificate (Table 9, 10 fields) ----
	CertSubject         string
	CertIssuer          string
	NotValidBefore      string
	NotValidAfter       string
	SignatureAlgoRef    string
	SubjectPublicKeyRef string
	CertFormat          string
	CertExtension       string

	// ---- AxeBOM analysis (migrations/normalize/0003 and /0005) ----
	//
	// ⚠ NOT CERT-In FIELDS. `scored: false` in the profile, EXCLUDED from both
	// coverage numbers. If any of these moved completeness_pct, a customer's
	// compliance score would change because AxeBOM shipped a new detection
	// rule — with nothing different about their actual software.
	QuantumVulnerable    bool
	PQCRecommendation    string
	DeprecationStatus    string
	QuantumFamily        string
	GroverNote           string
	QuantumRationale     string
	DeprecationRationale string
	DeprecationReference string
	EffectiveQuantumBits *int
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
	QuantumReadinessGroup string
}

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

	return Sheet{
		Name: "Crypto Field Coverage",
		Header: []string{
			"Asset Type", "Field ID", "Field", "Weight",
			"Substantive", "Declared (incl. " + model.NotProvided + ")", "Entities",
			"Source",
		},
		Rows:  StaticRows(rows),
		Width: 24,
	}
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

	header := make([]string, 0, len(fields)+1+len(cryptoAnalysisHeader))
	header = append(header, "Component Key")
	for _, f := range fields {
		header = append(header, f.Name)
	}
	header = append(header, cryptoAnalysisHeader...)

	rows := RowSource(func(emit func([]string) error) error {
		for _, a := range assets {
			if a.AssetType != assetType {
				continue
			}
			row := make([]string, 0, len(header))
			row = append(row, orNotProvided(a.ComponentKey))
			for _, f := range fields {
				row = append(row, orNotProvided(cryptoFieldValue(f.ID, a)))
			}
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

// cryptoFieldValue reads the one struct field a CERT-In Table 9 field id maps
// to. One switch covering all thirty ids (8+7+5+10, "name" and "asset_type"
// counted once per type because each type's copy is a distinct profile field
// id) rather than a per-type function, so the mapping from id to column lives
// in exactly one place — the same reasoning loadComponents' own comment gives
// for its column-to-field-id map.
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

	widths := []float64{60, 34, 44, 44}
	r.tableHeader([]string{"Asset type", "Count", "Quantum-vulnerable", "Deprecated / weak / broken"}, widths)
	for _, t := range cryptoAssetTypeOrder {
		total, vulnerable, weak := 0, 0, 0
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
			}
		}
		r.tableRow([]string{
			cryptoAssetTypeLabel[t], strconv.Itoa(total), strconv.Itoa(vulnerable), strconv.Itoa(weak),
		}, widths)
	}
	r.doc.Ln(3)
	r.note("Full per-type field coverage (present/declared/total against each " +
		"type's own field set) is in the XLSX and JSON exports' Crypto Field " +
		"Coverage sheet — four separate tables do not fit this page budget " +
		"without truncating the report's other mandatory sections.")
}

// cryptoInventoryPage replaces componentPages in the PDF for a CBOM.
//
// ⚠ NAME, TYPE AND READINESS ONLY — NEVER A TYPE'S OWN FIELDS. Those three
// columns apply uniformly to every asset type, so listing them together does
// not repeat the mistake this file exists to prevent. A `key_size` or
// `cert_subject` column would; the full per-type tables stay in the XLSX and
// JSON exports.
func (r *pdfRender) cryptoInventoryPage() {
	r.doc.AddPage()
	r.heading("Cryptographic Assets")
	r.note("Name, type and quantum-readiness bucket only, to fit the page " +
		"budget. The full per-type field tables are in the XLSX and JSON exports.")
	r.doc.Ln(2)

	widths := []float64{30, 100, 40}
	r.tableHeader([]string{"Type", "Name", "Quantum readiness"}, widths)
	for i, a := range r.bom.CryptoAssets {
		if r.overCap() {
			r.markTruncated("crypto assets", i, len(r.bom.CryptoAssets))
			return
		}
		r.tableRow([]string{
			cryptoAssetTypeLabel[a.AssetType], orNotProvided(a.Name), orNotProvided(a.QuantumReadinessGroup),
		}, widths)
	}
}
