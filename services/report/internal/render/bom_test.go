package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func sampleBOM() BOM {
	depth := 1
	return BOM{
		ReportID:           "0199-report",
		ProjectName:        "acme-web",
		BOMType:            model.BOMTypeSBOM,
		Level:              "top_level",
		LevelNote:          "This is a Top-Level BOM: it lists 2 direct dependencies and omits 7 transitive ones.",
		GeneratedAt:        "2026-08-17T09:14:03Z",
		ProfileID:          model.ProfileID,
		ProfileRevision:    model.ProfileRevision,
		ProfileAllVerified: model.ProfileAllVerified,
		RulesetVersion:     "2026.08.1",
		ToolName:           "AxeBOM",
		ToolVersion:        "0.1.0",
		Components: []Component{
			{
				Key:        "purl:pkg:npm/lodash@4.17.20",
				Purl:       "pkg:npm/lodash@4.17.20",
				Ecosystem:  "npm",
				Depth:      &depth,
				IsDirect:   true,
				Scope:      "required",
				DetectedBy: []string{"syft", "grype"},
				Fields: map[string]string{
					model.FieldCertinSbom01ComponentName:    "lodash",
					model.FieldCertinSbom02ComponentVersion: "4.17.20",
					model.FieldCertinSbom21UniqueIdentifier: "pkg:supplier/OpenJSFoundation/lodash@4.17.20",
				},
			},
			{
				// An orphan: no root reaches it, so it has no depth.
				Key:        "name:npm/mystery@0.0.1",
				Ecosystem:  "npm",
				IsOrphan:   true,
				Scope:      "required",
				DetectedBy: []string{"trivy-fs"},
			},
		},
		Findings: []Finding{{
			DisplayID:    "CVE-2021-23337",
			ClusterID:    "0199-cluster",
			Aliases:      []string{"GHSA-35jh-r3h4-6jhm"},
			ComponentKey: "purl:pkg:npm/lodash@4.17.20",
			Severity:     "high",
			CVSSVersion:  "3.1",
			CVSSScore:    "7.2",
			FixedInMin:   "4.17.21",
			DetectedBy:   []string{"grype", "osv-scanner"},
		}},
		Licenses: []License{{
			Expression: "MIT", Kind: "declared", ComponentCount: 1,
		}},
		Engines: []EngineCoverage{
			{EngineID: "syft", Version: "1.51.0", Status: "succeeded", Ecosystems: []string{"npm"}},
			{
				EngineID: "dependency-check", Version: "13.0.0", Status: "unavailable",
				Diagnostic: "ENGINE_DB_NOT_PROVISIONED",
			},
		},
		EcosystemsWithNoEngine: []string{"conan"},
		Practices: []Practice{{
			FieldID: model.FieldCertinSbomPpFrequency, Value: "per-commit",
		}},
		Coverage: Coverage{
			CompletenessPct: 12.40,
			DeclarationPct:  100.00,
			Formula:         "sum(weight × substantive) / sum(weight × entities)",
			Fields: []FieldCoverage{
				{FieldID: model.FieldCertinSbom01ComponentName, Present: 2, Declared: 2, Total: 2},
			},
		},
		Notes: []string{
			"CERT-In §4.2 field 21 writes the qualifier separator as `&subpath`; " +
				"the PURL specification uses `#subpath`. We emit the PURL form.",
		},
	}
}

// TestEveryProfileFieldIsAColumn is the phase requirement, checked without ever
// writing a count.
//
// ⚠ THE ASSERTION IS AGAINST THE PROFILE, NOT AGAINST A NUMBER. Writing "want
// 21 columns" here would be the same defect the invariant forbids in product
// code: the day CERT-In revises the guideline, a hardcoded test agrees with the
// old count and the report ships a false claim with a green suite behind it.
func TestEveryProfileFieldIsAColumn(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	components := findSheet(t, sheets, "Components")
	header := strings.Join(components.Header, "\x00")

	for _, f := range model.SBOMFields {
		if !strings.Contains(header, f.Name) {
			t.Errorf("profile field %s (%q) has no column", f.ID, f.Name)
		}
	}

	want := len(componentIdentityHeader) + len(model.SBOMFields)
	if len(components.Header) != want {
		t.Errorf("the Components sheet has %d columns; the identity block plus the "+
			"profile is %d", len(components.Header), want)
	}
}

// TestNotProvidedRendersExplicitly — never blank, never omitted.
//
// A blank cell reads as "this report has no such column" or "we did not look".
// `not-provided` says we looked and there was nothing, which is a different
// statement — and one that still scores zero for completeness.
func TestNotProvidedRendersExplicitly(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	rows := collect(t, findSheet(t, sheets, "Components"))
	if len(rows) != 2 {
		t.Fatalf("got %d component rows, want 2", len(rows))
	}

	// The second component carries no profile-field values at all.
	for i, value := range rows[1] {
		if strings.TrimSpace(value) == "" {
			t.Errorf("column %d (%q) is blank; it must say %q",
				i, findSheet(t, sheets, "Components").Header[i], model.NotProvided)
		}
	}
}

// TestAnOrphanHasNoDepth — `not-provided`, never 0 and never 1.
//
// Forcing an orphan to depth 1 would inflate the direct-dependency count, which
// is the number a Top-Level report is built on.
func TestAnOrphanHasNoDepth(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	sheet := findSheet(t, sheets, "Components")
	depthCol := columnIndex(t, sheet, "Depth")
	rows := collect(t, sheet)

	if got := rows[1][depthCol]; got != model.NotProvided {
		t.Fatalf("the orphan's depth is %q, want %q — a number asserts a position "+
			"in the tree that no engine established", got, model.NotProvided)
	}
}

// TestTheTwoIdentifiersAreDifferentColumns pins CLAUDE.md invariant 4.
//
// `component.purl` is the merge key every scanner emits. The CERT-In Unique
// Identifier is a different syntax, derived and render-only. Collapsing them —
// or letting a reader assume they are the same — is how dedup gets keyed on the
// wrong one.
func TestTheTwoIdentifiersAreDifferentColumns(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	sheet := findSheet(t, sheets, "Components")
	purlCol := columnIndex(t, sheet, "PURL (merge key)")

	var certinCol = -1
	for _, f := range model.SBOMFields {
		if f.ID == model.FieldCertinSbom21UniqueIdentifier {
			certinCol = columnIndex(t, sheet, f.Name)
		}
	}
	if certinCol < 0 {
		t.Fatal("the CERT-In Unique Identifier field is missing from the profile")
	}
	if purlCol == certinCol {
		t.Fatal("the PURL and the CERT-In identifier share a column")
	}

	row := collect(t, sheet)[0]
	if !strings.HasPrefix(row[purlCol], "pkg:npm/") {
		t.Errorf("the merge-key column holds %q, which is not an ecosystem PURL", row[purlCol])
	}
	if !strings.HasPrefix(row[certinCol], "pkg:supplier/") {
		t.Errorf("the CERT-In column holds %q, which is not the CERT-In form", row[certinCol])
	}
}

// TestEngineCoverageNamesEcosystemsWithNoEngine.
//
// ⚠ THE SECTION THIS PRODUCT EXISTS FOR. An SBOM that silently omits an
// ecosystem converts an unknown into a false negative the customer trusts.
func TestEngineCoverageNamesEcosystemsWithNoEngine(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	rows := collect(t, findSheet(t, sheets, "Engine Coverage"))
	joined := flatten(rows)

	for _, want := range []string{"syft", "dependency-check", "unavailable", "conan", "no-engine"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Engine Coverage does not mention %q", want)
		}
	}
}

// TestEngineCoverageIsNeverEmpty — a report with no engines has to say so
// loudly, because every number in it describes nothing.
func TestEngineCoverageIsNeverEmpty(t *testing.T) {
	b := sampleBOM()
	b.Engines = nil
	b.EcosystemsWithNoEngine = nil

	sheets, err := Sheets(b)
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	rows := collect(t, findSheet(t, sheets, "Engine Coverage"))
	if len(rows) == 0 {
		t.Fatal("the Engine Coverage sheet is empty; it is mandatory and not suppressible")
	}
	if !strings.Contains(flatten(rows), "No engine ran") {
		t.Errorf("an engine-less report does not say so: %v", rows)
	}
}

// TestBothCoverageNumbersAppearWithTheirFormula — publishing only the
// declaration number and calling it "coverage" is how tools ship misleading
// 100% scores.
func TestBothCoverageNumbersAppearWithTheirFormula(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	summary := flatten(collect(t, findSheet(t, sheets, "Summary")))
	for _, want := range []string{
		"Completeness %", "12.40%",
		"Declaration %", "100.00%",
		"sum(weight × substantive)",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary does not carry %q", want)
		}
	}
	if !strings.Contains(summary, "AxeBOM's judgement, not CERT-In's") {
		t.Error("the summary does not say whose the weights are — a reader would " +
			"otherwise take our weighting for the regulator's")
	}
}

// TestTheWordCompliantDoesNotAppear.
//
// ⚠ A CONTRACT, NOT A STYLE RULE. AxeBOM reports violations against a
// configured policy; it never asserts that a project IS compliant. This walks
// every rendered cell, so the check cannot be defeated by adding the word to a
// sheet nobody thought to look at.
func TestTheWordCompliantDoesNotAppear(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	for _, s := range sheets {
		text := strings.ToLower(strings.Join(s.Header, " ") + " " + flatten(collect(t, s)))
		for _, banned := range []string{"compliant", "certified", "conforms to cert-in"} {
			if strings.Contains(text, banned) {
				t.Errorf("sheet %q contains %q. The product reports violations "+
					"against a configured policy; it does not certify anything.",
					s.Name, banned)
			}
		}
	}
}

// TestEveryPracticeSubElementAppears — CERT-In "Minimum Elements" is three
// categories. A tool implementing only the data fields and claiming coverage of
// the minimum elements is overstating.
func TestEveryPracticeSubElementAppears(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	rows := collect(t, findSheet(t, sheets, "Practices"))
	if len(rows) != len(model.PracticeFields) {
		t.Fatalf("the Practices sheet has %d rows; the profile defines %d sub-elements",
			len(rows), len(model.PracticeFields))
	}

	joined := flatten(rows)
	for _, f := range model.PracticeFields {
		if !strings.Contains(joined, f.ID) {
			t.Errorf("practice %s is missing", f.ID)
		}
	}
	// The five that were never recorded must each carry a stated gap.
	if !strings.Contains(joined, "Never recorded for this project") {
		t.Error("an unrecorded practice has no gap text")
	}
}

// TestFieldCoverageCitesTheSourceDocument — a reviewer checks a field against
// the guideline, not against our summary of it.
func TestFieldCoverageCitesTheSourceDocument(t *testing.T) {
	sheets, err := Sheets(sampleBOM())
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	rows := collect(t, findSheet(t, sheets, "Field Coverage"))
	if len(rows) != len(model.SBOMFields) {
		t.Fatalf("the Field Coverage sheet has %d rows; the profile has %d SBOM fields",
			len(rows), len(model.SBOMFields))
	}
	if !strings.Contains(flatten(rows), "CERT-In v2.0 p.") {
		t.Error("no row carries a page citation")
	}
}

// TestACBOMHasNoFlatFieldSet.
//
// ⚠ REFUSED, NOT APPROXIMATED. CERT-In Table 9 discriminates by asset type:
// algorithms, keys, protocols and certificates have different field sets.
// Scoring a certificate against `key_size` reports every CBOM at roughly 30%
// coverage — falsely, in a document shown to a regulator.
func TestACBOMHasNoFlatFieldSet(t *testing.T) {
	if _, err := FieldsFor(model.BOMTypeCBOM); err == nil {
		t.Fatal("a CBOM was given a single flat column list")
	}

	// Every other type resolves, so the refusal is specific rather than a gap.
	for _, tp := range []model.BOMType{
		model.BOMTypeSBOM, model.BOMTypeQBOM, model.BOMTypeAIBOM, model.BOMTypeHBOM,
	} {
		fields, err := FieldsFor(tp)
		if err != nil {
			t.Errorf("FieldsFor(%s): %v", tp, err)
		}
		if len(fields) == 0 {
			t.Errorf("FieldsFor(%s) returned no fields", tp)
		}
	}
}

// TestRemediationFieldsAppearOnTheFindingsSheet proves the four CERT-In §6
// columns (Remediation, Workarounds, Restart/Downtime Required, CSAF
// Recommended Mitigation Steps) render with real text when present, and
// `not-provided` when a triaged finding's statement left them blank.
func TestRemediationFieldsAppearOnTheFindingsSheet(t *testing.T) {
	b := sampleBOM()
	b.Findings = append(b.Findings, Finding{
		DisplayID:      "CVE-2024-00000",
		ClusterID:      "0199-cluster-2",
		ComponentKey:   "purl:pkg:npm/lodash@4.17.20",
		VEXStatus:      "affected",
		VEXRemediation: "Upgrade to lodash 4.17.21.",
		VEXWorkarounds: "Disable the affected code path via feature flag.",
		VEXDowntime:    "No restart required.",
		CSAFMitigation: "Apply vendor patch and redeploy.",
	}, Finding{
		DisplayID:    "CVE-2024-11111",
		ClusterID:    "0199-cluster-3",
		ComponentKey: "purl:pkg:npm/lodash@4.17.20",
		VEXStatus:    "under_investigation",
		// Triaged, but nothing recorded yet — must render not-provided, not
		// blank, for every one of the four columns.
	})

	sheet := findingSheet(b)
	rows := collect(t, sheet)

	remediationCol := columnIndex(t, sheet, "Remediation")
	workaroundsCol := columnIndex(t, sheet, "Workarounds")
	downtimeCol := columnIndex(t, sheet, "Restart/Downtime Required")
	mitigationCol := columnIndex(t, sheet, "CSAF recommended mitigation")

	if len(rows) != len(b.Findings) {
		t.Fatalf("got %d rows, want %d findings", len(rows), len(b.Findings))
	}

	withText := rows[1]
	if got := withText[remediationCol]; got != "Upgrade to lodash 4.17.21." {
		t.Errorf("Remediation = %q", got)
	}
	if got := withText[workaroundsCol]; got != "Disable the affected code path via feature flag." {
		t.Errorf("Workarounds = %q", got)
	}
	if got := withText[downtimeCol]; got != "No restart required." {
		t.Errorf("Downtime = %q", got)
	}
	if got := withText[mitigationCol]; got != "Apply vendor patch and redeploy." {
		t.Errorf("CSAF mitigation = %q", got)
	}

	untriagedText := rows[2]
	for _, col := range []int{remediationCol, workaroundsCol, downtimeCol, mitigationCol} {
		if got := untriagedText[col]; got != model.NotProvided {
			t.Errorf("column %d = %q, want %q for a triaged-but-blank finding", col, got, model.NotProvided)
		}
	}
}

// TestVEXFieldCoverageExcludesUntriagedFindings proves the denominator is
// findings with SOME effective VEX statement, not every finding — a finding
// nobody has looked at yet is "not yet assessed", not "remediation omitted".
func TestVEXFieldCoverageExcludesUntriagedFindings(t *testing.T) {
	b := sampleBOM() // b.Findings[0] has no VEXStatus at all — untriaged.
	b.Findings = append(b.Findings,
		Finding{VEXStatus: "affected", VEXRemediation: "Upgrade."},
		Finding{VEXStatus: "affected"}, // triaged, remediation left blank
	)

	sheet := vexFieldCoverageSheet(b)
	rows := collect(t, sheet)

	idCol := columnIndex(t, sheet, "Field ID")
	totalCol := columnIndex(t, sheet, "Triaged findings")
	presentCol := columnIndex(t, sheet, "Substantive")

	for _, row := range rows {
		if row[idCol] != model.FieldCertinVexRemediation {
			continue
		}
		if row[totalCol] != "2" {
			t.Errorf("total = %q, want 2 — the untriaged finding must not count", row[totalCol])
		}
		if row[presentCol] != "1" {
			t.Errorf("present = %q, want 1 — only one of the two triaged findings has remediation text", row[presentCol])
		}
		return
	}
	t.Fatalf("no %q row in the VEX Field Coverage sheet", model.FieldCertinVexRemediation)
}

// TestAHostileComponentNameReachesTheWorkbookEscaped is the end-to-end version
// of the injection test: real BOM, real sheets, real workbook.
func TestAHostileComponentNameReachesTheWorkbookEscaped(t *testing.T) {
	b := sampleBOM()
	b.Components = append(b.Components, Component{
		Key:       "name:npm/hostile",
		Ecosystem: "npm",
		Fields: map[string]string{
			model.FieldCertinSbom01ComponentName: ddePayload,
		},
	})

	sheets, err := Sheets(b)
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	var buf bytes.Buffer
	result, err := WriteXLSX(&buf, sheets)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	if result.Total(func(s SheetResult) int { return s.Escaped }) == 0 {
		t.Fatal("the workbook reports nothing escaped, but a component is named " +
			"with a DDE payload")
	}

	sheet := findSheet(t, sheets, "Components")
	col := columnIndex(t, sheet, nameOf(t, model.FieldCertinSbom01ComponentName))
	axis := cellAxis(t, col, 4) // header + two sample components + this one
	if got := readCell(t, buf.Bytes(), "Components", axis); !strings.HasPrefix(got, "'") {
		t.Fatalf("%s holds %q, unescaped", axis, got)
	}
}

// TestAHostileRemediationValueReachesTheWorkbookEscaped proves the new
// remediation/mitigation columns go through the SAME cell() escaping path as
// every other column — this codebase has exactly one place a cell value is
// produced (sheet.go's cell()), and both writers call it; a column added
// outside that path is a second, unescaped route into the workbook.
func TestAHostileRemediationValueReachesTheWorkbookEscaped(t *testing.T) {
	b := sampleBOM()
	b.Findings = append(b.Findings, Finding{
		DisplayID:      "CVE-2024-99999",
		ComponentKey:   "purl:pkg:npm/lodash@4.17.20",
		VEXStatus:      "affected",
		VEXRemediation: ddePayload,
	})

	sheets, err := Sheets(b)
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	var buf bytes.Buffer
	result, err := WriteXLSX(&buf, sheets)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}
	if result.Total(func(s SheetResult) int { return s.Escaped }) == 0 {
		t.Fatal("the workbook reports nothing escaped, but a finding carries a DDE payload as remediation text")
	}

	sheet := findSheet(t, sheets, "Findings")
	col := columnIndex(t, sheet, "Remediation")
	axis := cellAxis(t, col, len(b.Findings)+1) // header + every finding, this one last
	if got := readCell(t, buf.Bytes(), "Findings", axis); !strings.HasPrefix(got, "'") {
		t.Fatalf("%s holds %q, unescaped", axis, got)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func findSheet(t *testing.T, sheets []Sheet, name string) Sheet {
	t.Helper()
	for _, s := range sheets {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no sheet named %q", name)
	return Sheet{}
}

func collect(t *testing.T, s Sheet) [][]string {
	t.Helper()
	var rows [][]string
	if err := s.Rows(func(row []string) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatalf("collecting rows from %q: %v", s.Name, err)
	}
	return rows
}

func flatten(rows [][]string) string {
	var sb strings.Builder
	for _, row := range rows {
		sb.WriteString(strings.Join(row, " | "))
		sb.WriteString("\n")
	}
	return sb.String()
}

func columnIndex(t *testing.T, s Sheet, header string) int {
	t.Helper()
	for i, h := range s.Header {
		if h == header {
			return i
		}
	}
	t.Fatalf("sheet %q has no column %q (columns: %v)", s.Name, header, s.Header)
	return -1
}

// cellAxis converts a 0-based column and a 1-based row to a cell reference.
func cellAxis(t *testing.T, col, row int) string {
	t.Helper()
	axis, err := excelize.CoordinatesToCellName(col+1, row)
	if err != nil {
		t.Fatalf("cell reference for column %d row %d: %v", col, row, err)
	}
	return axis
}

func nameOf(t *testing.T, fieldID string) string {
	t.Helper()
	for _, f := range model.SBOMFields {
		if f.ID == fieldID {
			return f.Name
		}
	}
	t.Fatalf("no profile field %q", fieldID)
	return ""
}

// TestSupplementaryCoverageIsRenderedAndLabelledAsNotCompliance.
//
// ⚠ IT WAS COMPUTED FOR A WHOLE PHASE AND READ BY NOTHING. The HBOM
// manufacturing score has been written to
// `normalize.bom_documents.supplementary_coverage` since migration 0011 and
// appeared in no report, no export and no screen. A number a customer cannot
// see is a number that does not exist — the same class of loss invariant 12
// names for engine gaps, one layer up.
//
// ⚠ AND THE LABEL IS THE POINT. A percentage on a compliance document is read
// as a compliance percentage unless something says otherwise, so the profile's
// own label, its id, and the sentence naming AxeBOM as the authority all render
// together. Rendering the number without them would be worse than omitting it.
func TestSupplementaryCoverageIsRenderedAndLabelledAsNotCompliance(t *testing.T) {
	b := sampleBOM()
	b.SupplementaryCoverage = []SupplementaryCoverage{{
		ProfileID:       "aibom-operational-v1",
		ProfileRevision: 1,
		Label:           "AI operational surface",
		IsCompliance:    false,
		CompletenessPct: 62.5,
	}}

	sheets, err := Sheets(b)
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "Summary")))

	for _, want := range []string{
		"AI operational surface %",
		"62.5",
		"aibom-operational-v1 revision 1",
		"not a compliance standard",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the Summary sheet does not carry %q", want)
		}
	}
	// ⚠ AND IT SAYS SO ABOUT THE TWO NUMBERS IT MUST NOT BE MISTAKEN FOR.
	if !strings.Contains(joined, "does not contribute to the completeness") {
		t.Error("the Summary sheet does not say that this number is excluded " +
			"from the compliance percentages, which is the only thing that " +
			"stops a reader treating it as one")
	}
}
