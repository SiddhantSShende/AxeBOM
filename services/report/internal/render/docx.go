package render

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// DOCXMediaType is what the download response carries.
const DOCXMediaType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

// DefaultComponentCap bounds how many inventory rows a DOCX renders.
//
// ⚠ THE SAME REASONING AS PDF's DefaultPageCap, A DIFFERENT SHAPE OF LIMIT.
// A single Word table with tens of thousands of rows is sluggish to open and
// can exhaust memory building the document — the same failure mode
// DefaultPageCap exists to prevent for PDF, just measured in rows instead of
// pages because a docx has no fixed page geometry to estimate against.
// Exceeding it truncates with a stated note (matching PDF's markTruncated),
// never fails outright the way PDF's pre-flight refusal does — a docx does
// not have PDF's per-page rendering cost, so there is no equivalent case for
// refusing before starting.
const DefaultComponentCap = 2000

// DOCXOptions tunes the render.
type DOCXOptions struct {
	// ComponentCap is the maximum inventory rows rendered. Zero uses
	// DefaultComponentCap.
	ComponentCap int
}

// DOCXResult reports what the render had to leave out.
type DOCXResult struct {
	Truncated      bool
	TruncationNote string
}

// WriteDOCX renders the report as a real, valid .docx.
//
// ⚠ THE SAME SECTIONS AS WritePDF, IN THE SAME ORDER, FOR THE SAME REASON —
// this is not a lighter alternative format, it is the CERT-In-facing
// document in an editable shape. Every citation (citation, CERT-In v2.0
// p.N), every mandatory disclosure (scopeNote, weightsNote, the per-field
// CERT-In coverage breakdown, Engine Coverage's "no engine ran" honesty,
// Practices' full model.PracticeFields list — including sub-elements never
// recorded, not only the ones present) and every not-provided rendering
// (orNotProvided, the literal sentinel CLAUDE.md invariant 3 requires, never
// a decorative dash) are the SAME shared functions pdf.go already calls, so
// the two formats cannot silently drift apart on what they claim.
//
// ⚠ STDLIB ONLY, BY CONSTRUCTION — NO THIRD-PARTY DOCX LIBRARY, THE SAME
// GUARANTEE PDF's OWN COMMENT MAKES FOR ITSELF. A .docx is a zip of XML; this
// writes that zip directly with archive/zip and encoding/xml's escaper, so
// there is no HTML/rich-text engine in the path that could resolve a remote
// resource, and no field-code library that could emit a live MS Word field
// (HYPERLINK, INCLUDETEXT and similar are a real, documented docx injection
// vector for attacker-influenced text — a component name is exactly that).
// Every piece of BOM-derived text reaches the document through escXML before
// it is ever concatenated into markup, so it can only ever appear as literal
// displayed text, never as document structure or a field code.
// TestAHostileFieldValueRendersAsTextNotStructureOrAField asserts this
// against actually hostile input, not just by inspection.
func WriteDOCX(w io.Writer, b BOM, opts DOCXOptions) (DOCXResult, error) {
	var fields []model.ProfileField
	if b.BOMType != model.BOMTypeCBOM {
		f, err := FieldsFor(b.BOMType)
		if err != nil {
			return DOCXResult{}, err
		}
		fields = f
	}

	cap := opts.ComponentCap
	if cap <= 0 {
		cap = DefaultComponentCap
	}

	var doc docxBuilder
	result := DOCXResult{}

	docxCoverPage(&doc, b)
	docxCoveragePage(&doc, b, fields)
	docxEngineCoveragePage(&doc, b)
	// A finding, before the inventory it was drawn from; absent when nothing
	// was flagged. See PrivateKeysInSource.
	docxPrivateKeysInSource(&doc, b, cap, &result)
	docxPracticesPage(&doc, b)

	// ⚠ SAME QBOM FALL-THROUGH THE PDF HAD. See pdf.go's comment on this switch:
	// a QBOM landed in `default` and rendered an empty Components table that
	// reads as "nothing was found".
	switch b.BOMType {
	case model.BOMTypeCBOM:
		docxCryptoAssets(&doc, b.CryptoAssets, cap, &result)
	case model.BOMTypeAIBOM:
		docxAIModels(&doc, b.AIModels, fields, cap, &result)
	case model.BOMTypeHBOM:
		docxHardware(&doc, b.Hardware, cap, &result)
	case model.BOMTypeQBOM:
		// docxQuantumDevice below is this type's inventory.
	default:
		docxComponents(&doc, b.Components, cap, &result)
	}

	// ⚠ NO `&& b.QuantumDevice != nil` GUARD — THAT WAS AN INVARIANT-3 BREACH.
	//
	// A project classified QBOM before anybody filled in the device form has
	// genuinely recorded nothing, and invariant 3 says an unknown is reported
	// explicitly, never omitted, because omission hides the gap. The PDF
	// (qbom.go:274) and the XLSX (qbom.go:97) both render every element as
	// `not-provided` with a stated reason. This renderer alone dropped the
	// entire section, so the Word document was the one artifact where a missing
	// device looked like a BOM type with no device concept at all.
	if b.BOMType == model.BOMTypeQBOM {
		docxQuantumDevice(&doc, b.QuantumDevice, b.CryptoAssets, QBOMCryptoSourceNote(b))
	}

	docxFindings(&doc, b.Findings, cap, &result)
	docxLicenses(&doc, b.Licenses)
	docxVEXSection(&doc, b.Findings)
	docxMethodologyPage(&doc, b, result)

	if result.Truncated && result.TruncationNote == "" {
		result.TruncationNote = fmt.Sprintf(
			"One or more inventory tables were cut to %d rows. Render the XLSX or JSON export for the complete data — neither has a row limit.", cap)
	}

	if err := doc.write(w); err != nil {
		return DOCXResult{}, errs.Wrap(err, errs.ReportRenderFailed, "writing the DOCX")
	}
	return result, nil
}

func docxCoverPage(doc *docxBuilder, b BOM) {
	doc.heading(1, orNotProvided(b.ProjectName))
	doc.para(fmt.Sprintf("%s · %s BOM", b.BOMType, levelTitle(b.Level)))

	doc.keyValues([][2]string{
		{"Report ID", b.ReportID},
		{"Generated (UTC)", b.GeneratedAt},
		{"Compliance profile", fmt.Sprintf("%s revision %d", b.ProfileID, b.ProfileRevision)},
		{"Normalizer ruleset", b.RulesetVersion},
		{"Normalization version", strconv.Itoa(b.NormalizationVersion)},
		{"Produced by", trimJoin(b.ToolName, b.ToolVersion)},
		{"Components listed", strconv.Itoa(len(b.Components))},
		{"Findings listed", strconv.Itoa(len(b.Findings))},
	})

	doc.callout("What this report is", scopeNote)
	if b.LevelNote != "" {
		doc.callout("BOM level", b.LevelNote)
	}
	if !b.ProfileAllVerified {
		doc.callout("Profile", "Some entries in the compliance profile were not "+
			"transcribed from the source document. Coverage numbers involving them "+
			"are provisional.")
	}
}

func docxCoveragePage(doc *docxBuilder, b BOM, fields []model.ProfileField) {
	doc.heading(2, "Coverage")

	if b.CoverageComputed {
		doc.body("Completeness: " + pct(b.Coverage.CompletenessPct))
		doc.note("Substantive values only. This is the compliance signal.")
		doc.body("Declaration: " + pct(b.Coverage.DeclarationPct))
		doc.note("Any value, including an explicit `" + model.NotProvided + "`. " +
			"A representation check, not a compliance number.")
		if b.Coverage.Formula != "" {
			doc.body("Formula: " + b.Coverage.Formula)
		}
	} else {
		doc.body("Coverage has not yet been computed for this BOM document.")
	}
	doc.note(weightsNote)

	// ⚠ CBOM HAS NO SINGLE FIELD SET (FieldsFor's own doc comment) — Table 9
	// discriminates by asset type, so there is no FLAT breakdown to render.
	//
	// This used to `return` here, which left the Word document with two coverage
	// percentages and nothing behind them — the one artifact where a reader
	// could not see which fields those numbers came from. The XLSX has always
	// had the per-asset-type sheet; it just was not shared.
	if b.BOMType == model.BOMTypeCBOM {
		doc.heading(3, "Per-field breakdown, by asset type")
		doc.note("Table 9 defines four different field sets. Each asset type is " +
			"scored against its own, because scoring a certificate against a " +
			"key's fields reports a gap that is not there.")
		rows := [][]string{CryptoFieldCoverageHeader}
		doc.table(append(rows, CryptoFieldCoverageRows(b)...))
		return
	}
	if len(fields) == 0 {
		return
	}

	doc.heading(3, "Per-field breakdown")
	byID := map[string]FieldCoverage{}
	for _, fc := range b.Coverage.Fields {
		byID[fc.FieldID] = fc
	}
	rows := [][]string{{"Field", "Weight", "Substantive", "Declared", "Source"}}
	for _, f := range fields {
		fc, seen := byID[f.ID]
		substantive, declared := model.NotProvided, model.NotProvided
		if seen {
			substantive = fmt.Sprintf("%d/%d", fc.Present, fc.Total)
			declared = fmt.Sprintf("%d/%d", fc.Declared, fc.Total)
		}
		rows = append(rows, []string{f.Name, strconv.Itoa(f.Weight), substantive, declared, citation(f)})
	}
	doc.table(rows)
}

func docxEngineCoveragePage(doc *docxBuilder, b BOM) {
	doc.heading(2, "Engine Coverage")
	doc.note("Every engine requested for this scan, and what it was able to see. " +
		"An ecosystem with no engine is listed too: its components are absent " +
		"because nothing scanned them, not because none exist.")

	rows := [][]string{{"Engine", "Version", "Status", "Ecosystems", "Note"}}
	for _, e := range b.Engines {
		rows = append(rows, []string{
			e.EngineID, orNotProvided(e.Version), e.Status,
			joinList(e.Ecosystems), orNotProvided(e.Diagnostic),
		})
	}
	for _, eco := range b.EcosystemsWithNoEngine {
		rows = append(rows, []string{
			"(none)", model.NotProvided, "no-engine", eco,
			"Detected in this project; no engine we run can scan it.",
		})
	}
	if len(b.Engines) == 0 && len(b.EcosystemsWithNoEngine) == 0 {
		rows = append(rows, []string{
			"(none)", model.NotProvided, "no-engine", model.NotProvided,
			"No engine ran for this report. Every number in it describes nothing.",
		})
	}
	doc.table(rows)
}

func docxPracticesPage(doc *docxBuilder, b BOM) {
	doc.heading(2, "Practices and Processes")
	doc.note("CERT-In's Minimum Elements is three categories, not only the data " +
		"fields. These are the third: per-project settings recorded by the " +
		"project owner.")

	byID := map[string]Practice{}
	for _, p := range b.Practices {
		byID[p.FieldID] = p
	}
	// ⚠ THE FULL CANONICAL LIST, NOT ONLY WHAT EXISTS. A sub-element nobody
	// ever recorded must still appear, with its gap stated — the same "not
	// covered by omission" rule invariant 3 applies everywhere else.
	rows := [][]string{{"Sub-element", "Value", "Gap"}}
	for _, f := range model.PracticeFields {
		p, seen := byID[f.ID]
		value, gap := model.NotProvided, "Never recorded for this project."
		if seen {
			value = orNotProvided(p.Value)
			gap = orNotProvided(p.Gap)
		}
		rows = append(rows, []string{f.Name, value, gap})
	}
	doc.table(rows)
}

func docxComponents(doc *docxBuilder, components []Component, cap int, result *DOCXResult) {
	doc.heading(2, "Components")
	rows := [][]string{{"Name", "Version", "Ecosystem", "Depth", "PURL"}}
	n := len(components)
	if n > cap {
		n = cap
		result.Truncated = true
	}
	for _, c := range components[:n] {
		rows = append(rows, []string{
			orNotProvided(c.Fields[model.FieldCertinSbom01ComponentName]),
			orNotProvided(c.Fields[model.FieldCertinSbom02ComponentVersion]),
			orNotProvided(c.Ecosystem),
			depthText(c.Depth),
			orNotProvided(c.Purl),
		})
	}
	doc.table(rows)
}

// docxCryptoAssets renders Table 9 the way CBOMSheets does: one table per asset
// type, each showing only that type's own CERT-In fields.
//
// ⚠ IT USED TO BE ONE FLAT TABLE — Type, Name, Component, Primitive, Key size,
// OID — for every asset, and its comment called that "a deliberate, stated
// simplification". It was the one artifact that still rendered the shape
// invariant 5 exists to prevent: a certificate row with an empty "Key size"
// cell, which a reader cannot tell from "not reported", and no column at all
// for a certificate's subject, issuer or validity.
func docxCryptoAssets(doc *docxBuilder, assets []CryptoAsset, cap int, result *DOCXResult) {
	doc.heading(2, "Cryptographic assets")
	shown := 0
	for _, t := range cryptoAssetTypeOrder {
		fields := model.CryptoFieldsByAssetType[t]
		header := make([]string, 0, len(fields)+3+len(cryptoEvidenceHeader))
		for _, f := range fields {
			if isCryptoAssetTypeField(f.ID) {
				continue // the table's own heading states the type
			}
			header = append(header, f.Name)
		}
		header = append(header, derivedColumnHeader)
		header = append(header, cryptoEvidenceHeader...)
		header = append(header,
			"Quantum-vulnerable (AxeBOM analysis)",
			"Deprecation (AxeBOM analysis)")

		var rows [][]string
		for _, a := range assets {
			if a.AssetType != t {
				continue
			}
			if shown >= cap {
				result.Truncated = true
				break
			}
			row := make([]string, 0, len(header))
			for _, f := range fields {
				if isCryptoAssetTypeField(f.ID) {
					continue
				}
				row = append(row, orNotProvided(cryptoFieldValue(f.ID, a)))
			}
			row = append(row,
				derivedCell(a),
				CryptoLocationCell(a),
				CryptoEnginesCell(a),
				boolText(a.QuantumVulnerable),
				orNotProvided(a.DeprecationStatus))
			rows = append(rows, row)
			shown++
		}
		if len(rows) == 0 {
			continue
		}
		doc.heading(3, cryptoAssetTypeLabel[t])
		doc.table(append([][]string{header}, rows...))
	}
}

// docxPrivateKeysInSource is the Word block — the finding, then where each key
// was found. Nothing at all when nothing was flagged. See PrivateKeysInSource.
func docxPrivateKeysInSource(doc *docxBuilder, b BOM, cap int, result *DOCXResult) {
	keys := PrivateKeysInSource(b)
	if len(keys) == 0 {
		return
	}
	doc.heading(2, PrivateKeysInSourceTitle)
	doc.callout("Finding", PrivateKeysInSourceFinding(b))
	list, truncated := privateKeyRows(keys, cap)
	if truncated {
		result.Truncated = true
	}
	rows := [][]string{privateKeysInSourceHeader[:4]}
	for _, row := range list {
		rows = append(rows, row[:4])
	}
	doc.table(rows)
}

// isCryptoAssetTypeField reports whether a Table 9 field id is one of the four
// per-type `asset_type` fields — redundant under a per-type heading.
func isCryptoAssetTypeField(id string) bool {
	switch id {
	case model.FieldCertinCryptoAlgoAssetType, model.FieldCertinCryptoKeyAssetType,
		model.FieldCertinCryptoProtoAssetType, model.FieldCertinCryptoCertAssetType:
		return true
	}
	return false
}

// docxAIModels renders CERT-In Table 10, then the two AxeBOM extensions.
//
// ⚠ IT USED TO RENDER ONLY THE EXTENSIONS. Every one of Table 10's elements
// lives in m.Fields, and this function never touched that map — so the Word
// version of an AIBOM carried exactly two values, and both were the ones
// aibom.go:31 explicitly labels as NOT CERT-In fields, derived from a third
// party's heuristics and excluded from both coverage numbers.
//
// A compliance artifact containing only the two things that do not count
// towards compliance is worse than an empty one: it looks complete.
//
// Fields come from the profile, like the XLSX's inventory sheet — no element
// list is written here, so a CERT-In revision changes the YAML and this
// follows (invariant 2).
func docxAIModels(doc *docxBuilder, models []AIModel, fields []model.ProfileField,
	cap int, result *DOCXResult,
) {
	doc.heading(2, "AI models")
	if len(models) == 0 {
		// ⚠ SAID EXPLICITLY. Without this the heading stood alone and read as a
		// rendering failure rather than an empty inventory.
		doc.body("No AI models were recorded for this project.")
		return
	}
	n := len(models)
	if n > cap {
		n = cap
		result.Truncated = true
	}
	for _, m := range models[:n] {
		doc.heading(3, m.Name)

		rows := [][]string{{"Element", "Value"}}
		for _, f := range fields {
			// Explicit, never blank — the same rule componentSheet applies: a
			// blank cell reads as "we did not look".
			rows = append(rows, []string{f.Name, orNotProvided(m.Fields[f.ID])})
		}
		doc.table(rows)

		if m.RiskScore != nil {
			doc.body(fmt.Sprintf("Risk score (AxeBOM extension): %.2f", *m.RiskScore))
		}
		doc.body("OWASP LLM Top 10 (AxeBOM extension): " + joinList(m.OwaspLLMTop10))
		if len(m.Datasets) > 0 {
			rows := [][]string{{"Dataset", "Version", "License", "Source"}}
			for _, d := range m.Datasets {
				rows = append(rows, []string{
					d.Name, orNotProvided(d.Version), orNotProvided(d.License), orNotProvided(d.Source),
				})
			}
			doc.table(rows)
		}
	}
}

func docxHardware(doc *docxBuilder, tree []HardwareComponent, cap int, result *DOCXResult) {
	doc.heading(2, "Hardware")
	rows := [][]string{{"Depth", "Name", "Model", "Manufacturer", "Criticality", "Firmware"}}
	n := len(tree)
	if n > cap {
		n = cap
		result.Truncated = true
	}
	for _, h := range tree[:n] {
		rows = append(rows, []string{
			strconv.Itoa(h.Depth), h.Name, orNotProvided(h.ModelNumber), orNotProvided(h.ManufacturerName),
			orNotProvided(h.Criticality), orNotProvided(h.FirmwareVersion),
		})
	}
	doc.table(rows)
}

// docxQuantumDevice renders Table 8 plus the readiness view a QBOM exists for.
//
// ⚠ IT USED TO HARDCODE SIX ELEMENTS AND TAKE ONLY THE DEVICE. Table 8 has
// eleven, and `d == nil` is a legitimate state, so the Word document rendered
// roughly half a QBOM on a good day and none of it on an ordinary one. Both
// problems are fixed by not owning a field list here: QuantumDeviceRows is the
// same profile-driven builder the XLSX uses, so the two cannot disagree.
//
// The readiness table is included because it is the *point* of a QBOM — the
// device metadata is context for it. Without it the Word artifact carried the
// least useful half.
func docxQuantumDevice(doc *docxBuilder, d *QuantumDevice, assets []CryptoAsset, sourceNote string) {
	doc.heading(2, "Quantum device")
	rows := [][]string{{"Element", "Value"}}
	rows = append(rows, QuantumDeviceRows(d)...)
	doc.table(rows)

	doc.heading(2, "Quantum readiness")
	if sourceNote != "" {
		doc.body(sourceNote)
	}

	vulnerable, postQuantum, grover, unassessed := groupByReadiness(assets)
	doc.body(readinessNote(len(vulnerable), len(postQuantum), len(grover), len(unassessed)))

	readiness := [][]string{{"Bucket", "Asset", "Detail"}}
	for _, g := range []struct {
		label  string
		assets []CryptoAsset
	}{
		{"Vulnerable to Shor's algorithm — migration required", vulnerable},
		{"Already post-quantum (NIST PQC family in use)", postQuantum},
		{"Symmetric, Grover note only — a sizing observation, NOT a vulnerability", grover},
		{"Unassessed — matched no quantum rule", unassessed},
	} {
		readiness = append(readiness, readinessGroupRows(g.label, g.assets)...)
	}
	doc.table(readiness)
}

func docxFindings(doc *docxBuilder, findings []Finding, cap int, result *DOCXResult) {
	doc.heading(2, "Findings")
	rows := [][]string{{"Advisory", "Severity", "CVSS", "Component", "Fixed in", "Detected by"}}
	n := len(findings)
	if n > cap {
		n = cap
		result.Truncated = true
	}
	for _, f := range findings[:n] {
		score := orNotProvided(f.CVSSScore)
		if f.CVSSVersion != "" && f.CVSSScore != "" {
			score = f.CVSSScore + " (v" + f.CVSSVersion + ")"
		}
		rows = append(rows, []string{
			f.DisplayID, orNotProvided(f.Severity), score,
			f.ComponentKey, orNotProvided(f.FixedInMin), joinList(f.DetectedBy),
		})
	}
	doc.table(rows)
}

func docxLicenses(doc *docxBuilder, licenses []License) {
	doc.heading(2, "License inventory")
	doc.note("`declared`, `concluded` and `observed` are kept separate. " +
		"\"The manifest says MIT but the LICENSE file says Apache-2.0\" is a " +
		"finding, and merging them would assert that they agreed.")

	rows := [][]string{{"Expression", "Kind", "Components", "Note"}}
	for _, l := range licenses {
		note := orNotProvided(l.Note)
		if l.Ambiguous {
			note = "AMBIGUOUS — not resolved. " + note
		}
		rows = append(rows, []string{l.Expression, l.Kind, strconv.Itoa(l.ComponentCount), note})
	}
	doc.table(rows)
}

// docxVEXSection mirrors pdf.go's vexPage + remediationSection.
//
// ⚠ NO STATEMENTS IS A STATED GAP, NOT AN OMITTED SECTION — same reasoning
// as pdf.go's own comment, CLAUDE.md invariant 3 applied to a whole section.
func docxVEXSection(doc *docxBuilder, findings []Finding) {
	doc.heading(2, "VEX statements")

	counts := map[string]int{}
	var untriaged int
	for _, f := range findings {
		if f.VEXStatus == "" {
			untriaged++
			continue
		}
		counts[f.VEXStatus]++
	}

	switch {
	case len(findings) == 0:
		doc.body("This report has no findings to triage.")
	case len(counts) == 0:
		doc.body("No VEX statements have been recorded for this report's findings.")
	default:
		rows := [][]string{{"Status", "Findings"}}
		for _, status := range []string{"affected", "under_investigation", "fixed", "not_affected"} {
			if n := counts[status]; n > 0 {
				rows = append(rows, []string{status, strconv.Itoa(n)})
			}
		}
		if untriaged > 0 {
			rows = append(rows, []string{"untriaged", strconv.Itoa(untriaged)})
		}
		doc.table(rows)
	}

	doc.note("A finding whose status is `not_affected` or `fixed` is de-emphasized " +
		"in the findings table above, never deleted from it — \"we assessed this " +
		"and it does not apply\" is a defensible position, and it must not look " +
		"the same as a vulnerability that never appeared. VEX statements are " +
		"append-only: every triage decision recorded here supersedes the last " +
		"rather than overwriting it, and the full history is available from the " +
		"live findings view.")

	docxRemediationSection(doc, findings)

	doc.heading(3, "CSAF")
	doc.body("No CSAF document has been generated for this report.")
}

// docxRemediationSection mirrors pdf.go's remediationSection — CERT-In §6
// (p.35): remediation, workarounds and restart/downtime are named fields,
// not free-form notes this renderer invents. Human-authored text carried
// through from a VEX statement, never generated here.
func docxRemediationSection(doc *docxBuilder, findings []Finding) {
	doc.heading(3, "Remediation, workarounds and mitigation")

	var withText []Finding
	for _, f := range findings {
		if f.VEXStatus != "affected" && f.VEXStatus != "under_investigation" {
			continue
		}
		if f.VEXRemediation == "" && f.VEXWorkarounds == "" && f.VEXDowntime == "" && f.CSAFMitigation == "" {
			continue
		}
		withText = append(withText, f)
	}

	if len(withText) == 0 {
		doc.body("No remediation, workaround, downtime or mitigation text has been " +
			"recorded for this report's affected findings.")
		return
	}
	for _, f := range withText {
		doc.keyValues([][2]string{
			{"Finding", f.DisplayID + " — " + f.ComponentKey},
			{"Remediation", f.VEXRemediation},
			{"Workarounds", f.VEXWorkarounds},
			{"Restart/downtime required", f.VEXDowntime},
			{"CSAF recommended mitigation", f.CSAFMitigation},
		})
	}
}

func docxMethodologyPage(doc *docxBuilder, b BOM, result DOCXResult) {
	doc.heading(2, "Methodology and caveats")

	// ⚠ TypeNotes, NOT JUST b.Notes — see render.TypeNotes for why the
	// type-specific caveat was absent from this document.
	for _, n := range append(append([]string{}, b.Notes...), TypeNotes(b)...) {
		doc.body("• " + n)
	}

	// What normalization could not do — same lines, same reasoning as the PDF.
	for _, n := range NormalizeDiagnosticLines(b) {
		doc.body("• " + n)
	}
	doc.body("• " + weightsNote)
	doc.body("• Two identifiers are reported per component and they are not " +
		"interchangeable. The PURL is the canonical ecosystem identifier every " +
		"scanner emits and all deduplication runs on. The CERT-In Unique " +
		"Identifier (§4.2 field 21) is a different syntax, derived for " +
		"presentation only, and is never used as a merge key.")
	doc.body("• CERT-In §4.2 field 21 writes the qualifier separator as `&subpath`; " +
		"the Package URL specification uses `#subpath`. We emit the specification " +
		"form, because that is what every consuming tool parses.")
	doc.body("• `" + model.NotProvided + "` is reported explicitly and scores zero " +
		"for completeness. A field recorded as unknown is a declared gap, not a " +
		"covered field.")

	if result.Truncated {
		doc.callout("Truncated", result.TruncationNote)
	}

	doc.heading(3, "Signature")
	doc.body("This document is signed with a detached Ed25519 signature published " +
		"alongside it. Verify it with `axebom verify <file>`, supplying the " +
		"published public key. The signature proves the file is byte-for-byte the " +
		"one issued; it says nothing about whether the scan was complete — for " +
		"that, read Engine Coverage.")
}

func trimJoin(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " " + b
}

// ---------------------------------------------------------------------------
// docxBuilder — the minimal OOXML writer.
//
// ⚠ EVERY STRING THAT REACHES markup GOES THROUGH escXML FIRST, AND ONLY
// THROUGH escXML — never string concatenation of raw BOM-derived text. This
// is what makes TestAHostileFieldValueRendersAsTextNotStructureOrAField's
// guarantee hold: there is exactly one place text becomes markup-safe, so
// there is exactly one place to audit.
// ---------------------------------------------------------------------------

type docxBuilder struct {
	buf bytes.Buffer
}

func (d *docxBuilder) heading(level int, text string) {
	fmt.Fprintf(&d.buf,
		`<w:p><w:pPr><w:pStyle w:val="Heading%d"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		level, escXML(text))
}

func (d *docxBuilder) para(text string) {
	fmt.Fprintf(&d.buf,
		`<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, escXML(text))
}

// body renders one line of ordinary prose, mirroring pdf.go's r.body.
func (d *docxBuilder) body(text string) { d.para(text) }

// note renders a smaller, italicized explanatory line, mirroring pdf.go's
// r.note (a shorter-font annotation under a value or a table).
func (d *docxBuilder) note(text string) {
	fmt.Fprintf(&d.buf,
		`<w:p><w:pPr><w:rPr><w:i/><w:sz w:val="18"/></w:rPr></w:pPr>`+
			`<w:r><w:rPr><w:i/><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		escXML(text))
}

// callout renders a titled block, mirroring pdf.go's r.calloutBox — used for
// the handful of disclosures CERT-In or CLAUDE.md invariant 3 make
// mandatory (scope, level projection, truncation), so they read as a
// deliberate statement rather than one more paragraph among many.
func (d *docxBuilder) callout(title, text string) {
	fmt.Fprintf(&d.buf,
		`<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, escXML(title))
	d.para(text)
}

// keyValues renders a two-column table with a bold left column, mirroring
// pdf.go's r.keyValues.
func (d *docxBuilder) keyValues(rows [][2]string) {
	table := make([][]string, 0, len(rows))
	for _, kv := range rows {
		table = append(table, []string{kv[0], orNotProvided(kv[1])})
	}
	d.keyValueTable(table)
}

func (d *docxBuilder) keyValueTable(rows [][]string) {
	d.buf.WriteString(d.tableOpenTag())
	for _, row := range rows {
		d.buf.WriteString(`<w:tr>`)
		fmt.Fprintf(&d.buf,
			`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>`+
				`<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`,
			escXML(row[0]))
		fmt.Fprintf(&d.buf,
			`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>`+
				`<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`,
			escXML(row[1]))
		d.buf.WriteString(`</w:tr>`)
	}
	d.buf.WriteString(`</w:tbl>`)
}

// table renders rows[0] as a bold header row.
func (d *docxBuilder) table(rows [][]string) {
	if len(rows) <= 1 {
		d.note("(none)")
		return
	}
	d.buf.WriteString(d.tableOpenTag())
	for i, row := range rows {
		d.buf.WriteString(`<w:tr>`)
		for _, cell := range row {
			d.buf.WriteString(`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>`)
			if i == 0 {
				fmt.Fprintf(&d.buf,
					`<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, escXML(cell))
			} else {
				fmt.Fprintf(&d.buf,
					`<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, escXML(cell))
			}
			d.buf.WriteString(`</w:tc>`)
		}
		d.buf.WriteString(`</w:tr>`)
	}
	d.buf.WriteString(`</w:tbl>`)
}

func (d *docxBuilder) tableOpenTag() string {
	return `<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/><w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="auto"/><w:left w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="auto"/><w:right w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:insideH w:val="single" w:sz="4" w:color="auto"/><w:insideV w:val="single" w:sz="4" w:color="auto"/>` +
		`</w:tblBorders></w:tblPr>`
}

// escXML is the ONE place BOM-derived text becomes markup-safe.
func escXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const docxRootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

const docxDocumentRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>`

func (d *docxBuilder) write(w io.Writer) error {
	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body>` + d.buf.String() +
		`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1417" w:right="1417" w:bottom="1417" w:left="1417"/></w:sectPr>` +
		`</w:body></w:document>`

	zw := zip.NewWriter(w)
	files := []struct{ name, content string }{
		{"[Content_Types].xml", docxContentTypes},
		{"_rels/.rels", docxRootRels},
		{"word/document.xml", document},
		{"word/_rels/document.xml.rels", docxDocumentRels},
	}
	for _, f := range files {
		fw, err := zw.Create(f.name)
		if err != nil {
			return err
		}
		if _, err := fw.Write([]byte(f.content)); err != nil {
			return err
		}
	}
	return zw.Close()
}
