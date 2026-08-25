package render

import (
	"encoding/json"
	"fmt"
)

// JSONMediaType is what the download response carries.
const JSONMediaType = "application/json"

// BundleSchema versions the envelope below.
//
// Bumped whenever a field changes meaning. A consumer that pinned the old
// version can then refuse rather than silently misreading a renamed field —
// which is the failure mode an unversioned envelope guarantees.
const BundleSchema = "axebom.report.bundle/v1"

// Bundle is the JSON download: the canonical document plus both standard ones.
//
// ⚠ THE FORMAT WITH NO CAPS. PDF is page-capped and XLSX has a worksheet row
// limit; this is where a Complete BOM of any size goes, and it is what the
// other two point at when they have to truncate. So it must never gain a limit
// of its own.
type Bundle struct {
	Schema string `json:"schema"`

	Report    BundleReport    `json:"report"`
	Coverage  Coverage        `json:"coverage"`
	Engines   BundleEngines   `json:"engine_coverage"`
	Practices []Practice      `json:"practices"`
	Canonical BundleCanonical `json:"canonical"`

	// Documents carries the standard serializations.
	//
	// ⚠ EMBEDDED BYTE-FOR-BYTE, WHICH IS WHY THIS FILE IS NOT INDENTED.
	//
	// Each artifact carries its own detached signature, and a consumer holding
	// the bundle must be able to lift the SPDX document out of it and verify it
	// against the signature issued for the standalone download. That only works
	// if the bytes match.
	//
	// json.Marshal compacts a RawMessage — it strips insignificant whitespace —
	// and json.MarshalIndent then reformats it entirely. The exporter emits
	// compact JSON (export.Serialize ends in json.Marshal), so compaction is a
	// no-op and the embedded copy is identical. Switching this file to
	// MarshalIndent for readability would silently break that, which is why the
	// round trip is a test rather than a comment.
	Documents BundleDocuments `json:"documents"`

	Notes []string `json:"notes"`
}

// BundleReport is the report's own metadata.
type BundleReport struct {
	ID          string `json:"id"`
	ProjectName string `json:"project_name"`
	BOMType     string `json:"bom_type"`
	Level       string `json:"level"`
	LevelNote   string `json:"level_note,omitempty"`
	// GeneratedAt is the SCAN's time — UTC, RFC3339, literal Z — not the
	// render's, so a re-render describes the same moment.
	GeneratedAt string `json:"generated_at"`

	ProfileID          string `json:"profile_id"`
	ProfileRevision    int    `json:"profile_revision"`
	ProfileAllVerified bool   `json:"profile_all_verified"`

	RulesetVersion       string `json:"ruleset_version"`
	NormalizationVersion int    `json:"normalization_version"`
	ToolName             string `json:"tool_name"`
	ToolVersion          string `json:"tool_version"`

	// WeightsNote states whose judgement the coverage weights are. Present in
	// every artifact, for the same reason it is on the spreadsheet's summary.
	WeightsNote string `json:"weights_note"`
	// Scope is the product's honest label. It is a field rather than prose in a
	// template so it cannot be dropped by a caller assembling this by hand.
	Scope string `json:"scope"`
}

// BundleEngines is the mandatory Engine Coverage section.
type BundleEngines struct {
	Engines []EngineCoverage `json:"engines"`
	// EcosystemsWithNoEngine is never omitted, even when empty: `[]` states
	// that we checked, whereas a missing key reads as a renderer that does not
	// report this at all.
	EcosystemsWithNoEngine []string `json:"ecosystems_with_no_engine"`
}

// BundleCanonical is AxeBOM's own model, which neither standard format can
// carry in full.
type BundleCanonical struct {
	Components []Component `json:"components"`
	Findings   []Finding   `json:"findings"`
	Licenses   []License   `json:"licenses"`
	// CryptoAssets, QuantumDevice and AIModels are omitted (not `null`) for a
	// BOM type that carries none of them — SPDX and CycloneDX cannot express
	// Table 9, Table 8 or Table 10 in full, so this is the only artifact
	// where a CBOM/QBOM/AIBOM consumer can read them structured.
	CryptoAssets  []CryptoAsset  `json:"crypto_assets,omitempty"`
	QuantumDevice *QuantumDevice `json:"quantum_device,omitempty"`
	AIModels      []AIModel      `json:"ai_models,omitempty"`
}

// BundleDocuments holds the standard serializations.
type BundleDocuments struct {
	SPDX      json.RawMessage `json:"spdx_2_3,omitempty"`
	CycloneDX json.RawMessage `json:"cyclonedx_1_6,omitempty"`
}

// WriteJSON builds the bundle.
//
// ⚠ NO SPREADSHEET ESCAPING HERE, DELIBERATELY.
//
// safe.Cell exists because a spreadsheet importer executes a leading `=`. JSON
// has no such behaviour, and prefixing values with a quote would corrupt them —
// a component genuinely named `=cmd|'/c calc'!A1` must round-trip through this
// format unchanged, because this is the format the XLSX writer points a reader
// at when it has to truncate. The escaping belongs to the spreadsheet writers
// and nowhere else.
func WriteJSON(b BOM, spdx, cyclonedx []byte) ([]byte, error) {
	// ⚠ NOT FieldsFor. FieldsFor's error means "no flat field list", which is
	// true and correct for a CBOM and NOT a reason to refuse the bundle — see
	// bom.go's FieldsFor comment. This only rejects a BOM type that is not one
	// of the five the product knows about at all.
	if !b.BOMType.Valid() {
		return nil, fmt.Errorf("unknown BOM type %q", b.BOMType)
	}

	bundle := Bundle{
		Schema: BundleSchema,
		Report: BundleReport{
			ID:                   b.ReportID,
			ProjectName:          b.ProjectName,
			BOMType:              string(b.BOMType),
			Level:                b.Level,
			LevelNote:            b.LevelNote,
			GeneratedAt:          b.GeneratedAt,
			ProfileID:            b.ProfileID,
			ProfileRevision:      b.ProfileRevision,
			ProfileAllVerified:   b.ProfileAllVerified,
			RulesetVersion:       b.RulesetVersion,
			NormalizationVersion: b.NormalizationVersion,
			ToolName:             b.ToolName,
			ToolVersion:          b.ToolVersion,
			WeightsNote:          weightsNote,
			Scope:                scopeNote,
		},
		Coverage: b.Coverage,
		Engines: BundleEngines{
			Engines:                b.Engines,
			EcosystemsWithNoEngine: orEmpty(b.EcosystemsWithNoEngine),
		},
		Practices: b.Practices,
		Canonical: BundleCanonical{
			Components:    b.Components,
			Findings:      b.Findings,
			Licenses:      b.Licenses,
			CryptoAssets:  b.CryptoAssets,
			QuantumDevice: b.QuantumDevice,
			AIModels:      b.AIModels,
		},
		Notes: orEmpty(b.Notes),
	}

	if len(spdx) > 0 {
		if !json.Valid(spdx) {
			return nil, fmt.Errorf("the SPDX document is not valid JSON")
		}
		bundle.Documents.SPDX = json.RawMessage(spdx)
	}
	if len(cyclonedx) > 0 {
		if !json.Valid(cyclonedx) {
			return nil, fmt.Errorf("the CycloneDX document is not valid JSON")
		}
		bundle.Documents.CycloneDX = json.RawMessage(cyclonedx)
	}

	// Compact, not indented — see BundleDocuments. `jq` renders this for a
	// human; nothing can un-reformat an embedded document.
	return json.Marshal(bundle)
}

// scopeNote is the product's central honest label, carried in every artifact.
//
// AxeBOM reports violations against a configured policy. It never asserts
// that a project IS compliant — the word does not appear in generated output —
// and stating the scope positively stops a reader supplying the missing claim
// themselves.
const scopeNote = "This report states what was observed and what could not be " +
	"observed. It reports gaps against the configured profile; it does not " +
	"certify a project against CERT-In."

// orEmpty renders a nil slice as `[]` rather than `null`.
//
// `null` and `[]` read differently to a consumer: one says "this renderer does
// not produce that", the other says "we looked and there were none". The second
// is what we mean, and it is the same distinction as `not-provided` versus a
// blank cell.
func orEmpty(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}
