package render

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// BOM is everything the tabular renderers need. Populated from the database by
// the report service; nothing here reads a clock or a connection.
//
// ⚠ NOTHING IN HERE IS COMPUTED. Coverage percentages, the formula that
// produced them, and every field value arrive already normalized. The renderer
// re-deriving a percentage would be a second implementation of the scoring
// rules, and the two would disagree the first time one of them changed.
type BOM struct {
	ReportID    string
	ProjectName string
	BOMType     model.BOMType
	// Level is the CERT-In BOM level this report was projected to.
	Level string
	// LevelNote states what the level left out. Rendered whenever non-empty.
	LevelNote string
	// GeneratedAt is the SCAN's time, RFC3339 with a literal Z — not the
	// render's. A re-render must not claim to describe today.
	GeneratedAt string

	ProfileID       string
	ProfileRevision int
	// ProfileAllVerified is false when any profile entry was assumed rather
	// than transcribed from the source document. The report says so.
	ProfileAllVerified bool

	RulesetVersion       string
	NormalizationVersion int
	ToolName             string
	ToolVersion          string

	Components []Component
	// Roots are the component keys with Depth == 0, plus every orphan (Depth
	// == nil — unreachable from any root, so it has no parent to hang off of
	// either). Export formats that need a root-element list (SPDX, CycloneDX)
	// use this; it is NOT a restatement of the normalizer's own "declared
	// roots" concept (which is legitimately empty when the scan produced no
	// dependency graph at all — see normalize/graph.py). Folding orphans in
	// here is an export-layer necessity, not a claim that they were
	// discovered as roots: a valid SPDX/CycloneDX document must have every
	// node reachable from its root-element list, and an orphan with no
	// incoming edge has no other way to be reachable.
	Roots []string
	// Dependencies are the direct "depends_on" edges backing Field 07 and the
	// export formats' dependency graph. Structural — never fabricated: absent
	// entirely for a source-only scan with no resolved lockfile.
	Dependencies []Dependency
	// Hardware is populated for an HBOM only. It is the same data the
	// component sheet renders as columns, kept as a tree so the assembly
	// structure survives into the report.
	Hardware []HardwareComponent
	// CryptoAssets is populated for a CBOM, and READ (never re-discovered) by a
	// QBOM's readiness view, which groups these same assets rather than
	// running its own detection. Never rendered as one flat table — see
	// CBOMSheets, which branches on AssetType, and CLAUDE.md invariant 5.
	CryptoAssets []CryptoAsset
	// QuantumDevice is CERT-In Table 8's device metadata for a QBOM. Nil is a
	// legitimate state, not a loading failure: there is no quantum-hardware
	// scanner, so a project classified QBOM before anybody filled in the
	// device form has genuinely recorded nothing yet. The QBOM sheets render
	// that as a stated gap rather than omitting the section (invariant 3).
	QuantumDevice *QuantumDevice
	// AIModels is CERT-In Table 10's model inventory for an AIBOM. Never
	// rendered through componentSheet/componentPages — an AI model's identity
	// (name, developer, licence) has no PURL/Depth/Scope, the SBOM concepts
	// those generic sheets are built around — see AIBOMSheets.
	AIModels []AIModel
	Findings []Finding
	Licenses []License
	Engines  []EngineCoverage
	// EcosystemsWithNoEngine is the list this product exists to be honest
	// about: something was detected and nothing we run can scan it.
	EcosystemsWithNoEngine []string
	Practices              []Practice
	Coverage               Coverage
	// CoverageComputed is false when the underlying BOM document has never had
	// its coverage scored — Coverage.CompletenessPct/DeclarationPct are then
	// meaningless zero values, not "0%", and a caller persisting them (the
	// worker, into report.reports) must store an absence, not a number.
	CoverageComputed bool
	// Notes are methodology footnotes rendered verbatim.
	Notes []string
}

// Component is one row of the components sheet.
type Component struct {
	Key string
	// Purl is the canonical ecosystem PURL — the MERGE KEY. Not the CERT-In
	// identifier, which is a separate, derived, render-only field carried in
	// Fields under its profile id.
	Purl      string
	Ecosystem string
	// Depth is nil for an orphan: no number, because no position in the tree
	// was ever established.
	Depth      *int
	IsDirect   bool
	IsOrphan   bool
	Scope      string
	DetectedBy []string

	// Fields holds profile-field values keyed by model.ProfileField.ID.
	//
	// ⚠ A MAP, NOT A STRUCT, AND THAT IS THE POINT. The column set comes from
	// the profile at render time, so a CERT-In revision is a YAML change plus a
	// regeneration — no column list to update here, and no count written
	// anywhere (CLAUDE.md invariant 2).
	Fields map[string]string
}

// Dependency is one direct "depends_on" edge, component keys on both ends.
type Dependency struct {
	From string
	To   string
}

// Finding is one deduplicated vulnerability against one component.
type Finding struct {
	DisplayID    string
	ClusterID    string
	Aliases      []string
	ComponentKey string
	Severity     string
	CVSSVector   string
	CVSSScore    string
	CVSSVersion  string
	FixedInMin   string
	DetectedBy   []string
	// SeverityConflict is set when sources disagreed. Surfaced rather than
	// resolved: v2, v3.1 and v4.0 are different scales and averaging them
	// invents a number no source asserted.
	SeverityConflict string
	VEXStatus        string
	VEXJustification string
	// VEXRemediation, VEXWorkarounds and VEXDowntime are CERT-In §6's
	// remediation/workarounds/restart-downtime fields (p.35), copied from the
	// EFFECTIVE VEX statement — human-authored triage text, never generated.
	// Empty when the finding has no effective statement, or the statement
	// recorded none of this text.
	VEXRemediation string
	VEXWorkarounds string
	VEXDowntime    string
	// CSAFMitigation is certin.csaf.mitigation — populated only when a CSAF
	// advisory was actually generated for the winning VEX statement. A
	// statement with no generated advisory renders `not-provided`, honestly:
	// CSAF is generated per statement, on demand, not for every triage.
	CSAFMitigation string
}

// License is one row of the licence inventory.
type License struct {
	Expression string
	// Kind is declared, concluded or observed. Kept separate all the way to the
	// sheet: "the manifest says MIT, the LICENSE file says Apache-2.0" is a
	// finding, and collapsing them asserts they agreed.
	Kind           string
	ComponentCount int
	// Ambiguous marks a licence we refused to resolve, such as a deprecated
	// `GPL-2.0` that could be -only or -or-later. Choosing is a legal error,
	// not a data-quality one.
	Ambiguous bool
	Note      string
}

// EngineCoverage is one engine's terminal state.
type EngineCoverage struct {
	EngineID string
	Version  string
	// Status is succeeded, partial, failed, unavailable or timeout.
	Status string
	// DatabaseVersion is OUR stamp, never the engine's self-report.
	DatabaseVersion string
	Ecosystems      []string
	Diagnostic      string
}

// Practice is one of CERT-In Table 5's Practices and Processes settings.
type Practice struct {
	FieldID string
	Value   string
	// Gap explains why this sub-element is unrecorded, including the case where
	// it holds an explicit `not-provided`.
	Gap string
}

// Coverage carries both numbers and the per-field breakdown behind them.
type Coverage struct {
	// CompletenessPct counts substantive values only. The honest compliance
	// signal.
	CompletenessPct float64
	// DeclarationPct counts any value including an explicit `not-provided`. A
	// representation check, NOT a compliance number.
	DeclarationPct float64
	// Formula is rendered by the normalizer so the numbers are auditable.
	Formula string
	Fields  []FieldCoverage
}

// FieldCoverage is one profile field's counts.
type FieldCoverage struct {
	FieldID string
	// Present counts entities holding a substantive value.
	Present int
	// Declared counts entities holding any value, `not-provided` included.
	Declared int
	Total    int
}

// weightsNote states whose judgement the weights are.
//
// ⚠ REQUIRED BY THE PHASE FILE, AND IT IS NOT A FORMALITY. CERT-In does not
// assign weights to its fields; AxeBOM does, to produce a single percentage.
// A reader who assumes the weighting is the guideline's would treat our
// judgement as the regulator's.
const weightsNote = "Field weights are AxeBOM's judgement, not CERT-In's. " +
	"The guideline assigns no weights; they exist so a single percentage can be " +
	"produced, and the per-field breakdown below is the unweighted evidence."

// FieldsFor returns the profile field set for a BOM type.
//
// ⚠ CBOM STILL HAS NO SINGLE FIELD SET, AND THIS FUNCTION STILL SAYS SO.
//
// CERT-In Table 9 is type-discriminated: algorithms, keys, protocols and
// certificates have DIFFERENT field sets, so there is no flat list to return
// — scoring a certificate against `key_size` reports every CBOM at roughly
// 30% coverage, falsely, in a compliance document. That reasoning has not
// changed.
//
// What changed is what a caller does with the error. Sheets, WriteJSON and
// WritePDF no longer treat it as a reason to refuse the WHOLE report — a CBOM
// report never calls FieldsFor at all, and renders CBOMSheets instead, which
// builds one inventory and one coverage table per asset type. This function
// keeps erroring for CBOM so that a caller which is NOT CBOM-aware — a future
// format, a test — cannot silently receive zero fields and render an empty
// sheet that reads as "this CBOM has no data" instead of "this caller forgot
// to branch".
func FieldsFor(t model.BOMType) ([]model.ProfileField, error) {
	switch t {
	case model.BOMTypeSBOM:
		return model.SBOMFields, nil
	case model.BOMTypeQBOM:
		return model.QBOMFields, nil
	case model.BOMTypeAIBOM:
		return model.AIBOMFields, nil
	case model.BOMTypeHBOM:
		return model.HBOMFields, nil
	case model.BOMTypeCBOM:
		return nil, fmt.Errorf(
			"a CBOM has no single field set: CERT-In Table 9 discriminates by " +
				"asset type, and one flat column list would score every asset " +
				"against fields that do not apply to it — render CBOMSheets instead")
	default:
		return nil, fmt.Errorf("unknown BOM type %q", t)
	}
}

// Sheets builds the workbook for a BOM.
//
// Order is deliberate: Summary first because it carries the caveats, Engine
// Coverage before the data because it says what the data could not see.
//
// ⚠ CBOM AND QBOM BRANCH HERE, BEFORE fieldCoverageSheet OR componentSheet ARE
// EVER CALLED — not by calling them and discarding an error.
//
// A CBOM has no flat field list (FieldsFor's whole point) and no rows shaped
// like a Component, so it gets CBOMSheets in place of BOTH generic sheets,
// never in addition to them — a "Components" sheet with zero rows next to a
// correct crypto inventory would read as "the scan found nothing" rather than
// "this format does not apply here". A QBOM DOES have a flat Table 8 field
// list — FieldsFor succeeds for it — so fieldCoverageSheet still runs; only
// componentSheet is replaced, because Table 8 describes one piece of
// hardware, not a dependency tree, and componentSheet's identity columns
// (PURL, Depth, Orphan, Scope…) do not mean anything for it.
func Sheets(b BOM) ([]Sheet, error) {
	sheets := []Sheet{
		summarySheet(b),
		engineCoverageSheet(b),
	}

	// extraNotes carries the type-specific honesty label into the Notes sheet
	// (below), the same sheet every other methodology note lands on — a
	// separate "CBOM caveats" sheet nobody thinks to open is how a caveat goes
	// unread.
	var extraNotes []string

	switch b.BOMType {
	case model.BOMTypeCBOM:
		sheets = append(sheets, practicesSheet(b))
		sheets = append(sheets, CBOMSheets(b)...)
		extraNotes = append(extraNotes, CBOMTypeDiscriminationNote)

	case model.BOMTypeQBOM:
		fields, err := FieldsFor(b.BOMType)
		if err != nil {
			return nil, err
		}
		sheets = append(sheets, fieldCoverageSheet(b, fields), practicesSheet(b))
		sheets = append(sheets, QBOMSheets(b)...)
		extraNotes = append(extraNotes, QBOMFormDisclosure)

	case model.BOMTypeAIBOM:
		fields, err := FieldsFor(b.BOMType)
		if err != nil {
			return nil, err
		}
		sheets = append(sheets, fieldCoverageSheet(b, fields), practicesSheet(b))
		sheets = append(sheets, AIBOMSheets(b, fields)...)
		extraNotes = append(extraNotes, AIBOMExtensionsNote)

	default:
		fields, err := FieldsFor(b.BOMType)
		if err != nil {
			return nil, err
		}
		sheets = append(sheets,
			fieldCoverageSheet(b, fields),
			practicesSheet(b),
			componentSheet(b, fields),
		)
	}

	sheets = append(sheets, findingSheet(b), vexFieldCoverageSheet(b), licenseSheet(b))

	// ⚠ THE HARDWARE SHEETS GO BEFORE THE NOTES, NOT AFTER. The notes sheet
	// carries the provenance line saying this BOM was imported rather than
	// discovered; a reader who reaches the tree first and the caveat last has
	// already formed an impression the caveat then has to undo.
	if b.BOMType == model.BOMTypeHBOM {
		sheets = append(sheets, HBOMSheets(b.Hardware)...)
	}

	// A copy, not a mutation of the caller's BOM: Sheets must not have a
	// visible side effect on the value it was handed.
	notesBOM := b
	notesBOM.Notes = append(append([]string{}, b.Notes...), extraNotes...)
	return append(sheets, notesSheet(notesBOM)), nil
}

// ─── Summary ────────────────────────────────────────────────────────────────

func summarySheet(b BOM) Sheet {
	rows := [][]string{
		{"Report ID", b.ReportID},
		{"Project", orNotProvided(b.ProjectName)},
		{"BOM type", string(b.BOMType)},
		{"BOM level", b.Level},
		{"Generated at (UTC)", b.GeneratedAt},
		{"", ""},
		{"Completeness %", pct(b.Coverage.CompletenessPct)},
		{"  — counts", "substantive values only; this is the compliance signal"},
		{"Declaration %", pct(b.Coverage.DeclarationPct)},
		{"  — counts", "any value including an explicit `" + model.NotProvided +
			"`; a representation check, not a compliance number"},
		{"Coverage formula", b.Coverage.Formula},
		{"Weighting", weightsNote},
		{"", ""},
		{"Compliance profile", fmt.Sprintf("%s revision %d", b.ProfileID, b.ProfileRevision)},
		{"Profile entries verified against the source document",
			boolText(b.ProfileAllVerified)},
		{"Normalizer ruleset", b.RulesetVersion},
		{"Normalization version", strconv.Itoa(b.NormalizationVersion)},
		{"Produced by", strings.TrimSpace(b.ToolName + " " + b.ToolVersion)},
	}

	if b.LevelNote != "" {
		rows = append(rows, []string{"", ""}, []string{"BOM level note", b.LevelNote})
	}

	// ⚠ THE PRODUCT'S CENTRAL HONEST LABEL, IN EVERY WORKBOOK.
	//
	// AxeBOM reports violations against a configured policy. It never
	// asserts that a project IS compliant, and the word does not appear in
	// generated output. This line is the positive statement of that, so a
	// reader does not supply the missing claim themselves.
	rows = append(rows,
		[]string{"", ""},
		[]string{"Scope of this report", scopeNote},
	)

	return Sheet{
		Name:   "Summary",
		Header: []string{"Item", "Value"},
		Rows:   StaticRows(rows),
		Width:  48,
	}
}

// ─── Engine coverage ────────────────────────────────────────────────────────

// engineCoverageSheet is MANDATORY and not suppressible.
//
// ⚠ AN SBOM THAT SILENTLY OMITS AN ECOSYSTEM IS WORSE THAN NO SBOM. It converts
// an unknown into a false negative the customer trusts. Every requested engine
// appears with its terminal status — `unavailable` included — and so does every
// ecosystem we detected and cannot scan at all.
func engineCoverageSheet(b BOM) Sheet {
	rows := make([][]string, 0, len(b.Engines)+len(b.EcosystemsWithNoEngine)+1)

	for _, e := range b.Engines {
		rows = append(rows, []string{
			e.EngineID,
			orNotProvided(e.Version),
			e.Status,
			orNotProvided(e.DatabaseVersion),
			joinList(e.Ecosystems),
			orNotProvided(e.Diagnostic),
		})
	}

	for _, eco := range b.EcosystemsWithNoEngine {
		rows = append(rows, []string{
			"(none)",
			model.NotProvided,
			"no-engine",
			model.NotProvided,
			eco,
			"Detected in this project. No engine we run can scan it, so its " +
				"components and vulnerabilities are absent from this report — " +
				"absent because unscanned, not because none exist.",
		})
	}

	if len(rows) == 0 {
		rows = append(rows, []string{
			"(none)", model.NotProvided, "no-engine", model.NotProvided, model.NotProvided,
			"No engine ran for this report. Every number in it describes nothing.",
		})
	}

	return Sheet{
		Name: "Engine Coverage",
		Header: []string{
			"Engine", "Engine version", "Status", "Database version (our stamp)",
			"Ecosystems covered", "Note",
		},
		Rows:  StaticRows(rows),
		Width: 34,
	}
}

// ─── Field coverage ─────────────────────────────────────────────────────────

// fieldCoverageSheet is the field table, rendered from the profile.
//
// Every row carries its source page, so a reviewer can check the field against
// the guideline rather than against our summary of it.
func fieldCoverageSheet(b BOM, fields []model.ProfileField) Sheet {
	byID := make(map[string]FieldCoverage, len(b.Coverage.Fields))
	for _, fc := range b.Coverage.Fields {
		byID[fc.FieldID] = fc
	}

	rows := make([][]string, 0, len(fields)+2)
	for _, f := range fields {
		fc, seen := byID[f.ID]
		present, declared, total := model.NotProvided, model.NotProvided, model.NotProvided
		if seen {
			present = strconv.Itoa(fc.Present)
			declared = strconv.Itoa(fc.Declared)
			total = strconv.Itoa(fc.Total)
		}
		rows = append(rows, []string{
			f.ID,
			ordinalText(f.Ordinal),
			f.Name,
			f.CanonicalPath,
			strconv.Itoa(f.Weight),
			boolText(f.Scored),
			present,
			declared,
			total,
			citation(f),
		})
	}

	return Sheet{
		Name: "Field Coverage",
		Header: []string{
			"Field ID", "CERT-In #", "Field", "Canonical path", "Weight", "Scored",
			"Substantive", "Declared (incl. " + model.NotProvided + ")", "Entities",
			"Source",
		},
		Rows:  StaticRows(rows),
		Width: 26,
	}
}

// citation renders where a field came from.
//
// An `extension` entry is AxeBOM's own analysis, and it is labelled that way
// so nobody reads our judgement as the guideline's. Extensions carry
// `scored: false`, so they cannot move a compliance percentage.
func citation(f model.ProfileField) string {
	switch f.Status {
	case "extension":
		return "AxeBOM extension — not a CERT-In field"
	case "verified":
		if f.SourcePage > 0 {
			return fmt.Sprintf("CERT-In v2.0 p.%d", f.SourcePage)
		}
		return "CERT-In v2.0"
	default:
		return fmt.Sprintf("%s (status: %s)", "CERT-In v2.0", f.Status)
	}
}

func ordinalText(n int) string {
	if n <= 0 {
		return model.NotProvided
	}
	return strconv.Itoa(n)
}

// ─── Practices ──────────────────────────────────────────────────────────────

// practicesSheet renders CERT-In Table 5's third category.
//
// ⚠ NOT A REPORT SECTION WE INVENTED. "Minimum Elements" is three categories,
// and a tool implementing only the data fields while claiming CERT-In coverage
// is overstating. The values are per-project settings; this sheet reports them
// and their gaps.
func practicesSheet(b BOM) Sheet {
	byID := make(map[string]Practice, len(b.Practices))
	for _, p := range b.Practices {
		byID[p.FieldID] = p
	}

	rows := make([][]string, 0, len(model.PracticeFields))
	for _, f := range model.PracticeFields {
		p, seen := byID[f.ID]
		value, gap := model.NotProvided, "Never recorded for this project."
		if seen {
			value = orNotProvided(p.Value)
			gap = p.Gap
		}
		rows = append(rows, []string{f.Name, f.ID, value, orNotProvided(gap)})
	}

	return Sheet{
		Name:   "Practices",
		Header: []string{"Sub-element", "Field ID", "Value", "Gap"},
		Rows:   StaticRows(rows),
		Width:  40,
	}
}

// ─── Components ─────────────────────────────────────────────────────────────

// componentSheet is one column per profile field, plus AxeBOM's own identity
// columns.
//
// ⚠ THE TWO IDENTIFIERS ARE SEPARATE COLUMNS, LABELLED.
//
// `PURL (merge key)` is the canonical ecosystem PURL every scanner emits and all
// dedup runs on. The CERT-In Unique Identifier is a different syntax
// (`pkg:supplier/Org/Name@1.0`), derived and render-only, and it appears under
// its own profile field. Putting them in one column — or letting a reader assume
// they are the same — is how dedup gets keyed on the wrong one.
func componentSheet(b BOM, fields []model.ProfileField) Sheet {
	header := append([]string(nil), componentIdentityHeader...)
	for _, f := range fields {
		header = append(header, f.Name)
	}

	components := b.Components
	rows := RowSource(func(emit func([]string) error) error {
		for _, c := range components {
			row := make([]string, 0, len(header))
			row = append(row,
				c.Key,
				orNotProvided(c.Purl),
				orNotProvided(c.Ecosystem),
				depthText(c.Depth),
				boolText(c.IsDirect),
				boolText(c.IsOrphan),
				orNotProvided(c.Scope),
				joinList(c.DetectedBy),
			)
			for _, f := range fields {
				// ⚠ EXPLICIT, NEVER BLANK. A blank cell reads as "we did not
				// look"; `not-provided` says we looked and there was nothing.
				// Omission is what hides a gap — and either way it scores zero
				// for completeness.
				row = append(row, orNotProvided(c.Fields[f.ID]))
			}
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{Name: "Components", Header: header, Rows: rows, Width: 22}
}

var componentIdentityHeader = []string{
	"Component Key",
	"PURL (merge key)",
	"Ecosystem",
	"Depth",
	"Direct",
	"Orphan",
	"Scope",
	"Detected By",
}

// depthText renders a nullable depth.
//
// ⚠ An orphan renders `not-provided`, never 0 and never 1. A number here would
// assert a position in the dependency tree that no engine established, and
// forcing orphans to depth 1 would inflate the direct-dependency count — which
// is exactly the number a Top-Level report is built on.
func depthText(d *int) string {
	if d == nil {
		return model.NotProvided
	}
	return strconv.Itoa(*d)
}

// ─── Findings ───────────────────────────────────────────────────────────────

func findingSheet(b BOM) Sheet {
	findings := b.Findings
	rows := RowSource(func(emit func([]string) error) error {
		for _, f := range findings {
			err := emit([]string{
				f.DisplayID,
				f.ClusterID,
				joinList(f.Aliases),
				f.ComponentKey,
				orNotProvided(f.Severity),
				orNotProvided(f.CVSSVersion),
				orNotProvided(f.CVSSScore),
				orNotProvided(f.CVSSVector),
				orNotProvided(f.SeverityConflict),
				orNotProvided(f.FixedInMin),
				joinList(f.DetectedBy),
				orNotProvided(f.VEXStatus),
				orNotProvided(f.VEXJustification),
				orNotProvided(f.VEXRemediation),
				orNotProvided(f.VEXWorkarounds),
				orNotProvided(f.VEXDowntime),
				orNotProvided(f.CSAFMitigation),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return Sheet{
		Name: "Findings",
		Header: []string{
			"Advisory", "Cluster ID", "Aliases", "Component", "Severity",
			"CVSS version", "CVSS score", "CVSS vector", "Severity conflict",
			"Fixed in (min)", "Detected By", "VEX status", "VEX justification",
			"Remediation", "Workarounds", "Restart/Downtime Required",
			"CSAF recommended mitigation",
		},
		Rows:  rows,
		Width: 20,
	}
}

// ─── VEX / CSAF field coverage ──────────────────────────────────────────────

// vexFieldCoverageSheet scores CERT-In §6's remediation/workarounds/downtime
// and §6's CSAF mitigation field against findings that have SOME effective
// VEX statement.
//
// ⚠ SCORED OVER TRIAGED FINDINGS, NOT EVERY FINDING. A finding nobody has
// looked at yet is "not yet assessed" — a different fact from "assessed, and
// remediation text was left out". Scoring the denominator over every finding
// would conflate the two, which is exactly what CLAUDE.md invariant 3 (a
// `not-provided` value is reported, never hidden, but also never asserted to
// mean something it does not) warns against one level up: absence of triage
// is not evidence of a coverage gap in the remediation fields themselves.
//
// ⚠ COMPUTED AT RENDER TIME FROM b.Findings, NOT A STORE QUERY. Mirrors
// engineCoverageSheet's pattern (compute from already-loaded data), not
// fieldCoverageSheet's (read a precomputed normalizer breakdown) — nothing
// upstream computes VEX/CSAF coverage today, and these four fields are not
// part of any BOM type's flat FieldsFor() list.
func vexFieldCoverageSheet(b BOM) Sheet {
	type counter struct{ present, declared, total int }
	counts := map[string]*counter{
		model.FieldCertinVexRemediation: {},
		model.FieldCertinVexWorkarounds: {},
		model.FieldCertinVexDowntime:    {},
		model.FieldCertinCsafMitigation: {},
	}
	fieldOrder := []string{
		model.FieldCertinVexRemediation,
		model.FieldCertinVexWorkarounds,
		model.FieldCertinVexDowntime,
		model.FieldCertinCsafMitigation,
	}
	values := func(f Finding) map[string]string {
		return map[string]string{
			model.FieldCertinVexRemediation: f.VEXRemediation,
			model.FieldCertinVexWorkarounds: f.VEXWorkarounds,
			model.FieldCertinVexDowntime:    f.VEXDowntime,
			model.FieldCertinCsafMitigation: f.CSAFMitigation,
		}
	}

	for _, f := range b.Findings {
		if f.VEXStatus == "" {
			// Untriaged — excluded from the denominator entirely, per the
			// doc comment above.
			continue
		}
		fv := values(f)
		for _, id := range fieldOrder {
			c := counts[id]
			c.total++
			v := strings.TrimSpace(fv[id])
			if v == "" {
				continue
			}
			c.declared++
			if v != model.NotProvided {
				c.present++
			}
		}
	}

	names := map[string]string{
		model.FieldCertinVexRemediation: "Remediation",
		model.FieldCertinVexWorkarounds: "Workarounds",
		model.FieldCertinVexDowntime:    "Restart/Downtime Required",
		model.FieldCertinCsafMitigation: "CSAF Recommended Mitigation Steps",
	}

	rows := make([][]string, 0, len(fieldOrder))
	for _, id := range fieldOrder {
		c := counts[id]
		rows = append(rows, []string{
			id, names[id], strconv.Itoa(c.present), strconv.Itoa(c.declared), strconv.Itoa(c.total),
		})
	}

	return Sheet{
		Name: "VEX Field Coverage",
		Header: []string{
			"Field ID", "Field", "Substantive", "Declared (incl. " + model.NotProvided + ")",
			"Triaged findings",
		},
		Rows:  StaticRows(rows),
		Width: 26,
	}
}

// ─── Licences ───────────────────────────────────────────────────────────────

func licenseSheet(b BOM) Sheet {
	rows := make([][]string, 0, len(b.Licenses))
	for _, l := range b.Licenses {
		rows = append(rows, []string{
			l.Expression,
			l.Kind,
			strconv.Itoa(l.ComponentCount),
			boolText(l.Ambiguous),
			orNotProvided(l.Note),
		})
	}

	return Sheet{
		Name: "Licenses",
		Header: []string{
			"Expression", "Kind (declared/concluded/observed)", "Components",
			"Ambiguous", "Note",
		},
		Rows:  StaticRows(rows),
		Width: 32,
	}
}

// ─── Notes ──────────────────────────────────────────────────────────────────

func notesSheet(b BOM) Sheet {
	rows := make([][]string, 0, len(b.Notes)+4)
	rows = append(rows, []string{"Weighting", weightsNote})
	if b.LevelNote != "" {
		rows = append(rows, []string{"BOM level", b.LevelNote})
	}
	if !b.ProfileAllVerified {
		rows = append(rows, []string{"Profile",
			"Some entries in the compliance profile were not transcribed from the " +
				"source document. Coverage numbers involving them are provisional."})
	}
	for _, n := range b.Notes {
		rows = append(rows, []string{"Methodology", n})
	}

	return Sheet{
		Name:   "Notes",
		Header: []string{"Topic", "Note"},
		Rows:   StaticRows(rows),
		Width:  60,
	}
}

// ─── Shared value rendering ─────────────────────────────────────────────────

// orNotProvided renders an absent value explicitly.
//
// ⚠ THE ONE RULE THIS FILE EXISTS TO ENFORCE. Empty is ambiguous — it could be
// "no value" or "no column". `not-provided` is a statement. It is reported and
// it scores zero for completeness; both halves matter.
func orNotProvided(v string) string {
	if strings.TrimSpace(v) == "" {
		return model.NotProvided
	}
	return v
}

// joinList renders a list, or `not-provided` when it is empty.
//
// An empty list is NOT a substantive value — `[]` scores zero exactly like the
// empty string does.
func joinList(items []string) string {
	if len(items) == 0 {
		return model.NotProvided
	}
	return strings.Join(items, ", ")
}

// intOrNotProvided renders a nullable integer explicitly.
//
// Same reasoning as depthText: nil is not zero. A classical security level or
// a key size that was never reported must not render as `0`, which reads as a
// measured value — "zero bits" — rather than as the absence it actually is.
func intOrNotProvided(n *int) string {
	if n == nil {
		return model.NotProvided
	}
	return strconv.Itoa(*n)
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func pct(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64) + "%"
}
