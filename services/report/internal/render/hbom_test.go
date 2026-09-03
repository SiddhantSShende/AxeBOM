package render

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func hardware() []HardwareComponent {
	return []HardwareComponent{
		{
			Depth: 0, Quantity: 1,
			Name: "AxeBOM Edge Gateway 4400", ModelNumber: "ENC-GW-4400",
			ManufacturerName: "Encore Systems Pvt Ltd", ManufacturerLocation: "Pune, India",
			Origin:       "India",
			SupplierInfo: "Bharat Integrators Ltd", SupplierLocation: "New Delhi, India",
			Criticality: "critical", FirmwareVersion: "4.2.1",
			Compliance: []string{"RoHS", "CE"},
		},
		{
			Depth: 1, Quantity: 1,
			Name: "Mainboard assembly", ModelNumber: "ENC-MB-01",
			ManufacturerName:      "Encore Systems Pvt Ltd",
			ComponentSupplierInfo: "Kaveri Electronics", ComponentSupplierLocation: "Chennai, India",
			Criticality: "high",
		},
		{
			Depth: 2, Quantity: 1,
			Name: "ARM Cortex-M7 microcontroller", ModelNumber: "STM32H753ZI",
			ManufacturerName: "STMicroelectronics", ManufacturerLocation: "Geneva, Switzerland",
			Origin:                "Switzerland",
			ComponentSupplierInfo: "Arrow Electronics", ComponentSupplierLocation: "Bengaluru, India",
			Criticality:    "high",
			Findings:       []string{"CVE-2024-1111"},
			EnrichedFields: map[string]string{"manufacturer_location": "nexar"},
		},
	}
}

func rowsOf(t *testing.T, s Sheet) [][]string {
	t.Helper()
	var out [][]string
	if err := s.Rows(func(row []string) error {
		out = append(out, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheTwoSupplierRelationshipsAreRenderedSeparately.
//
// ⚠ TABLE 11 LISTS SUPPLIER INFORMATION AND LOCATION TWICE, with different
// descriptions. Rendering them in one column would assert that a distributor
// sold the customer a gateway — false, and unfalsifiable from the output.
func TestTheTwoSupplierRelationshipsAreRenderedSeparately(t *testing.T) {
	sheets := HBOMSheets(hardware())
	origin := sheets[1]

	var productIdx, componentIdx = -1, -1
	for i, h := range origin.Header {
		switch h {
		case "Product Supplier":
			productIdx = i
		case "Component Supplier":
			componentIdx = i
		}
	}
	if productIdx < 0 || componentIdx < 0 {
		t.Fatalf("the origin sheet does not carry both supplier columns: %v", origin.Header)
	}

	rows := rowsOf(t, origin)
	if rows[0][productIdx] != "Bharat Integrators Ltd" {
		t.Errorf("the product supplier is %q", rows[0][productIdx])
	}
	if rows[0][componentIdx] != model.NotProvided {
		t.Errorf("the gateway has no component supplier; got %q", rows[0][componentIdx])
	}
	if rows[2][componentIdx] != "Arrow Electronics" {
		t.Errorf("the MCU's component supplier is %q", rows[2][componentIdx])
	}
	if rows[2][productIdx] != model.NotProvided {
		t.Errorf("Arrow did not sell the customer a product; got %q", rows[2][productIdx])
	}
}

// TestTheIndentIsNotPartOfTheName.
//
// ⚠ PADDING A NAME WITH SPACES IS WRONG TWICE: the value no longer matches the
// component's actual name, so a filter or a VLOOKUP against it fails; and a
// leading space is one of the characters formula-injection escaping has to
// consider, so the indent would interact with the security control.
func TestTheIndentIsNotPartOfTheName(t *testing.T) {
	sheets := HBOMSheets(hardware())
	tree := sheets[0]
	rows := rowsOf(t, tree)

	nameIdx := -1
	for i, h := range tree.Header {
		if h == "Component" {
			nameIdx = i
		}
	}

	for i, row := range rows {
		name := row[nameIdx]
		if name != strings.TrimSpace(name) {
			t.Errorf("row %d name %q carries indentation", i, name)
		}
	}
	if rows[0][nameIdx] != "AxeBOM Edge Gateway 4400" {
		t.Errorf("the root name was altered: %q", rows[0][nameIdx])
	}
	// The depth IS available, as a number.
	if rows[2][0] != "2" {
		t.Errorf("depth column = %q, want 2", rows[2][0])
	}
}

// TestEnrichedValuesAreAttributed.
//
// A datasheet's claim about a manufacturer is a different kind of fact from a
// serial number read off the device. A compliance document that presents both
// identically is overstating one of them.
func TestEnrichedValuesAreAttributed(t *testing.T) {
	rows := rowsOf(t, HBOMSheets(hardware())[0])
	last := rows[0][len(rows[0])-1]
	if last != "customer-supplied" {
		t.Errorf("an un-enriched component is attributed %q", last)
	}
	if got := rows[2][len(rows[2])-1]; got != "nexar" {
		t.Errorf("an enriched component is attributed %q, want nexar", got)
	}
}

func TestEnrichmentAttributionIsDeterministic(t *testing.T) {
	// ⚠ MAP ITERATION ORDER IS RANDOMIZED IN GO. A report whose bytes differ
	// between runs cannot be diffed, checksummed, or signed to mean anything.
	enriched := map[string]string{
		"manufacturer_location": "nexar",
		"origin":                "mouser",
		"technology_node":       "nexar",
		"compliance":            "mouser",
	}
	first := enrichmentSummary(enriched)
	for range 50 {
		if got := enrichmentSummary(enriched); got != first {
			t.Fatalf("attribution changed between calls: %q then %q", first, got)
		}
	}
	if first != "mouser, nexar" {
		t.Errorf("attribution = %q, want sorted", first)
	}
}

// TestTheProvenanceNoteDeniesExaminingHardware.
//
// ⚠ THIS TEST USED TO REQUIRE THE WORD "IMPORTED", AND THAT REQUIREMENT WAS
// OVERTAKEN RATHER THAN WRONG.
//
// It was right while a CSV and a form were the only ways a hardware BOM could
// exist. `hbom-ecad` parses design files out of a repository, which is a real
// scan, so a note insisting the document was "imported" would now understate
// the product in one direction while its caveat overstated in the other.
//
// ⚠ WHAT THE NOTE MUST STILL DO IS UNCHANGED, and it is what this now asserts:
// deny that anything examined physical hardware, and say that no tool can. A
// reader who assumes the automated coverage the SBOM sections have will find
// out at an audit.
//
// The assertion is on the CLAIM rather than on chosen words, so a future
// rewording that keeps the meaning does not fail, and one that loses the denial
// does.
func TestTheProvenanceNoteDeniesExaminingHardware(t *testing.T) {
	note := strings.ToLower(HBOMProvenanceNote)

	// It must deny that AxeBOM looked at the hardware...
	denies := strings.Contains(note, "did not examine any hardware")
	if !denies {
		t.Errorf("the provenance note does not deny examining hardware: %s", HBOMProvenanceNote)
	}
	// ...and say that the limit is the state of the art, not a gap in this
	// product, so a reader does not go looking for a setting to turn on.
	if !strings.Contains(note, "no open-source tool can") {
		t.Errorf("the note does not say the limit is universal: %s", HBOMProvenanceNote)
	}
	// ...and distinguish a design from the thing built from it, which is the
	// misreading most available to somebody holding a parsed schematic.
	if !strings.Contains(note, "not what was built") {
		t.Errorf("the note does not distinguish design from built product: %s", HBOMProvenanceNote)
	}

	// And it never uses the word "compliant" — this product reports violations
	// against a configured policy and never asserts compliance.
	if strings.Contains(note, "compliant") {
		t.Errorf("the note asserts compliance: %s", HBOMProvenanceNote)
	}
}

// TestTheSourceNoteDistinguishesADesignFromAHostInventory.
//
// A schematic states an intent; a host inventory states what one operating
// system could see at one moment. They describe different objects, and a
// document that mixes them without saying so lets a reader take one for the
// other.
func TestTheSourceNoteDistinguishesADesignFromAHostInventory(t *testing.T) {
	design := hardwareSourceNote([]HardwareComponent{{SourceEngine: "hbom-ecad"}})
	host := hardwareSourceNote([]HardwareComponent{{SourceEngine: "hbom-cdxgen-host"}})
	both := hardwareSourceNote([]HardwareComponent{
		{SourceEngine: "hbom-ecad"}, {SourceEngine: "hbom-cdxgen-host"},
	})

	if !strings.Contains(design, "DESIGN FILES") {
		t.Errorf("the design-source note does not name its source: %q", design)
	}
	if !strings.Contains(host, "never reached the device") {
		t.Errorf("the host-inventory note does not say AxeBOM never touched it: %q", host)
	}
	if !strings.Contains(both, "not reconciled") {
		t.Errorf("a mixed document must say the two sources are not reconciled: %q", both)
	}
	// A CSV import or a form has no engine, and must not claim one.
	if got := hardwareSourceNote([]HardwareComponent{{Name: "x"}}); got != "" {
		t.Errorf("a hand-entered BOM must claim no engine, got %q", got)
	}
}

// TestAnObsoletePartWithNoAlternateIsSurfacedInTheNotes.
//
// It is the most actionable fact a hardware BOM contains and one row among
// hundreds on the Lifecycle sheet. The notes are what a reader sees first.
func TestAnObsoletePartWithNoAlternateIsSurfacedInTheNotes(t *testing.T) {
	stranded := []HardwareComponent{
		{Name: "gateway", Criticality: "high"},
		{Name: "obsolete-mcu", Criticality: "high", LifecycleStatus: "obsolete"},
		{Name: "covered-mcu", Criticality: "high", LifecycleStatus: "eol",
			Alternates: []HardwareAlternate{{ModelNumber: "ALT-1", Equivalence: "drop-in"}}},
	}
	notes := strings.Join(HBOMNotes(stranded), "\n")

	if !strings.Contains(notes, "1 component(s) are obsolete or end-of-life with NO approved alternate") {
		t.Errorf("the stranded part is not surfaced; the one WITH an alternate must "+
			"not be counted. notes:\n%s", notes)
	}
}

func TestAnHBOMWithNoCriticalityIsToldWhy(t *testing.T) {
	// The difference between a gap a customer can close and one they read as a
	// product defect.
	bare := []HardwareComponent{{Depth: 0, Name: "gateway"}}
	notes := HBOMNotes(bare)

	if len(notes) < 2 {
		t.Fatalf("no criticality note: %v", notes)
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "10.4.1.4") {
		t.Errorf("the note does not cite the requirement: %s", joined)
	}
	if !strings.Contains(joined, "form") {
		t.Errorf("the note does not say how to close the gap: %s", joined)
	}
}

func TestAPopulatedHBOMDoesNotRaiseTheCriticalityNote(t *testing.T) {
	// ⚠ ASSERTS THE ABSENCE OF ONE NOTE, NOT A TOTAL COUNT. This test used to
	// require exactly one note, which made it fail the moment ANY unrelated
	// note was added — element 24's vulnerability caveat, here. A count is a
	// proxy for the property; the property is that a BOM which DOES declare
	// criticality is not told it does not.
	notes := HBOMNotes(hardware())
	joined := strings.Join(notes, " ")
	if strings.Contains(joined, "No component declares a criticality rating") {
		t.Errorf("a populated BOM raised the criticality note: %v", notes)
	}
}

// TestHBOMSheetsAreIncludedForHardwareBOMsOnly.
func TestHBOMSheetsAreIncludedForHardwareBOMsOnly(t *testing.T) {
	hbom := BOM{BOMType: model.BOMTypeHBOM, Hardware: hardware()}
	sheets, err := Sheets(hbom)
	if err != nil {
		t.Fatal(err)
	}

	names := map[string]bool{}
	for _, s := range sheets {
		names[s.Name] = true
	}
	if !names["Hardware Tree"] || !names["Origin and Suppliers"] {
		t.Fatalf("an HBOM is missing its hardware sheets: %v", names)
	}

	sbom := BOM{BOMType: model.BOMTypeSBOM}
	sheets, err = Sheets(sbom)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sheets {
		if s.Name == "Hardware Tree" {
			t.Error("an SBOM carries a hardware tree sheet")
		}
	}
}

// TestTheNotesSheetIsLast.
//
// ⚠ THE CAVEAT MUST NOT ARRIVE AFTER THE READER HAS FORMED AN IMPRESSION —
// but it also must not be buried mid-workbook. Notes stay last so they are
// where a reader looks for them, and the hardware sheets go before them rather
// than after.
func TestTheNotesSheetIsLast(t *testing.T) {
	sheets, err := Sheets(BOM{BOMType: model.BOMTypeHBOM, Hardware: hardware()})
	if err != nil {
		t.Fatal(err)
	}
	if last := sheets[len(sheets)-1].Name; last != "Notes" {
		t.Errorf("the last sheet is %q, want Notes", last)
	}
}

// TestHardwareCellsAreEscapedLikeEveryOther.
//
// ⚠ THIS PRODUCT'S ENTIRE OUTPUT SURFACE IS SPREADSHEETS, and a component named
// `=cmd|'/c calc'!A1` executes when the file opens. The escaping lives in
// cell(), not at call sites, so a new sheet inherits it — this test proves that
// inheritance rather than assuming it.
func TestHardwareCellsAreEscapedLikeEveryOther(t *testing.T) {
	hostile := []HardwareComponent{{
		Depth: 0, Quantity: 1,
		Name:                  `=cmd|'/c calc'!A1`,
		ModelNumber:           `+2+3`,
		ManufacturerName:      `-1+1`,
		ComponentSupplierInfo: "@SUM(1:2)",
	}}

	var stats cellStats
	for _, sheet := range HBOMSheets(hostile) {
		for _, row := range rowsOf(t, sheet) {
			for _, value := range row {
				escaped := cell(value, &stats)
				if escaped == "" {
					continue
				}
				switch escaped[0] {
				case '=', '+', '-', '@', '\t', '\r':
					t.Errorf("cell %q was not escaped", value)
				}
			}
		}
	}
	if stats.escaped == 0 {
		t.Fatal("no cell was escaped, so this test proves nothing")
	}
}

// ---------------------------------------------------------------------------
// Engineering, Procurement and Lifecycle
// ---------------------------------------------------------------------------

func costed() []HardwareComponent {
	return []HardwareComponent{
		{Depth: 0, Name: "gateway", Quantity: 1, LifecycleStatus: "active"},
		{
			Depth: 1, Name: "resistor", ModelNumber: "RC0402", Quantity: 3,
			Designators: []string{"R1", "R4", "R17"}, PackageFootprint: "0402",
			AssemblyType: "smt", UnitPrice: "0.001800", ExtendedPrice: "0.005400",
			Currency: "USD", LifecycleStatus: "active",
		},
		{
			Depth: 1, Name: "mcu", ModelNumber: "STM32", Quantity: 1,
			Designators: []string{"U1"}, ExtendedPrice: "8.420000", Currency: "USD",
			LifecycleStatus: "obsolete",
		},
		{
			Depth: 1, Name: "test point", ModelNumber: "TP-1", Quantity: 1,
			Designators: []string{"TP1"}, DoNotPopulate: true, AssemblyType: "tht",
			LifecycleStatus: "nrnd",
			Alternates:      []HardwareAlternate{{ModelNumber: "TP-2", Equivalence: "drop-in"}},
		},
	}
}

func sheetNamed(t *testing.T, sheets []Sheet, name string) Sheet {
	t.Helper()
	for _, s := range sheets {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no sheet named %q", name)
	return Sheet{}
}

// TestTheCostRollUpNeverSumsAcrossCurrencies.
//
// ⚠ 4.10 USD + 3.20 EUR IS NOT A NUMBER. There is no exchange rate in this
// data, and inventing one would put a fabricated figure in a procurement
// document. Two currencies get two totals and an explicit refusal to combine.
func TestTheCostRollUpNeverSumsAcrossCurrencies(t *testing.T) {
	mixed := []HardwareComponent{
		{Name: "a", Quantity: 1, ExtendedPrice: "4.100000", Currency: "USD"},
		{Name: "b", Quantity: 1, ExtendedPrice: "3.200000", Currency: "EUR"},
	}
	rows := collect(t, sheetNamed(t, HBOMSheets(mixed), "Procurement"))

	var totals []string
	for _, r := range rows {
		if strings.HasPrefix(r[0], "TOTAL") {
			totals = append(totals, r[0]+" = "+r[6]+" "+r[7])
		}
	}
	if len(totals) != 2 {
		t.Fatalf("got %d totals, want one per currency: %v", len(totals), totals)
	}
	joined := strings.Join(totals, " | ")
	if !strings.Contains(joined, "EUR") || !strings.Contains(joined, "USD") {
		t.Errorf("totals do not cover both currencies: %v", totals)
	}
	if !strings.Contains(flatten(rows), "more than one currency") {
		t.Error("a multi-currency BOM must refuse a grand total in as many words")
	}
	// And 7.30 must appear nowhere — that is the sum nobody asked for.
	if strings.Contains(flatten(rows), "7.3") {
		t.Error("the two currencies were summed")
	}
}

// TestTheCostRollUpSaysHowManyLinesAreUnpriced.
//
// A total over a parts list where half the prices are missing is not the cost
// of the product, and a reader who is not told will treat it as one.
func TestTheCostRollUpSaysHowManyLinesAreUnpriced(t *testing.T) {
	rows := collect(t, sheetNamed(t, HBOMSheets(costed()), "Procurement"))

	var total string
	for _, r := range rows {
		if strings.HasPrefix(r[0], "TOTAL") {
			total = r[0] + " = " + r[6]
		}
	}
	if total == "" {
		t.Fatal("no total row")
	}
	// Two of four lines carry no extended price.
	if !strings.Contains(total, "2 line(s) unpriced") {
		t.Errorf("the total does not disclose unpriced lines: %q", total)
	}
	// ⚠ EXACT DECIMAL. 0.005400 + 8.420000 = 8.425400 and not 8.425399999…;
	// the sum runs through big.Rat precisely because the column is numeric.
	if !strings.Contains(total, "8.425400") {
		t.Errorf("total = %q, want an exact 8.425400", total)
	}
}

// TestTheLifecycleSheetLeadsWithWhatIsBroken.
//
// An obsolete part is the finding. Alphabetical order buries it among four
// hundred `active` rows until a build stops.
func TestTheLifecycleSheetLeadsWithWhatIsBroken(t *testing.T) {
	rows := collect(t, sheetNamed(t, HBOMSheets(costed()), "Lifecycle"))

	if rows[0][0] != "obsolete" {
		t.Errorf("first row is %q; obsolete parts must lead", rows[0][0])
	}
	if rows[1][0] != "nrnd" {
		t.Errorf("second row is %q; NRND is the window in which acting is cheap", rows[1][0])
	}

	// The action column names the consequence, not the status.
	if !strings.Contains(rows[0][7], "will stop a build") {
		t.Errorf("an obsolete part with no alternate does not name its consequence: %q", rows[0][7])
	}
	if !strings.Contains(rows[1][7], "alternate is recorded") {
		t.Errorf("an NRND part WITH an alternate should say so: %q", rows[1][7])
	}
}

// TestTheEngineeringSheetSpellsOutDNP.
//
// ⚠ A BOOLEAN COLUMN HEADED WITH AN INITIALISM IS WHAT A READER GETS
// BACKWARDS, and backwards here means a factory omitting a part the design
// needs.
func TestTheEngineeringSheetSpellsOutDNP(t *testing.T) {
	sheet := sheetNamed(t, HBOMSheets(costed()), "Engineering")
	rows := collect(t, sheet)

	if sheet.Header[6] != "Fitted" {
		t.Errorf("column 7 is %q, want the positive phrasing Fitted", sheet.Header[6])
	}
	var fitted, notFitted int
	for _, r := range rows {
		switch {
		case r[6] == "Yes":
			fitted++
		case strings.HasPrefix(r[6], "No"):
			notFitted++
		default:
			t.Errorf("unreadable fitted value %q", r[6])
		}
	}
	if notFitted != 1 || fitted != 3 {
		t.Errorf("fitted=%d notFitted=%d, want 3 and 1", fitted, notFitted)
	}
	// The designators are what make a line placeable.
	if rows[1][3] != "R1, R4, R17" {
		t.Errorf("designators = %q", rows[1][3])
	}
}

// TestAnAlternateAlwaysCarriesItsEquivalence.
//
// An MPN on its own reads as an approved substitution. "(unverified)" beside
// it is the difference between a decision somebody made and one nobody has.
func TestAnAlternateAlwaysCarriesItsEquivalence(t *testing.T) {
	got := alternatesSummary([]HardwareAlternate{
		{ModelNumber: "ALT-1"}, // no equivalence stated
		{ModelNumber: "ALT-2", Equivalence: "drop-in"},
	})
	if !strings.Contains(got, "ALT-1 (unverified)") {
		t.Errorf("an alternate with no stated equivalence must default to unverified: %q", got)
	}
	if !strings.Contains(got, "ALT-2 (drop-in)") {
		t.Errorf("a stated equivalence must survive: %q", got)
	}
}

// ---------------------------------------------------------------------------
// CERT-In element 24 — advisory matching, and the blank cell that must not
// read as "clear"
// ---------------------------------------------------------------------------

func TestVulnerabilitySheetListsEveryComponentNotOnlyTheMatchedOnes(t *testing.T) {
	// ⚠ THE FAILURE THIS PREVENTS: a sheet listing only matches renders EMPTY
	// when nothing was searched, which is indistinguishable from a clean bill
	// of health.
	components := []HardwareComponent{
		{Name: "Mainboard", VulnMatchStatus: "not-attempted"},
		{Name: "Resistor", VulnMatchStatus: "no-match"},
		{Name: "MCU", VulnMatchStatus: "matched", Vulnerabilities: []HardwareFinding{
			{CVEID: "CVE-2021-1472", MatchBasis: "vendor+product", MatchConfidence: "low"},
		}},
	}

	rows := rowsOf(t, hardwareVulnerabilitySheet(components))
	if len(rows) != 3 {
		t.Fatalf("expected one row per component, got %d", len(rows))
	}
	for _, name := range []string{"Mainboard", "Resistor", "MCU"} {
		var found bool
		for _, row := range rows {
			if row[0] == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is missing from the Vulnerabilities sheet", name)
		}
	}
}

func TestAnUnsearchedComponentSaysSoInWordsNotInACode(t *testing.T) {
	// ⚠ "not-attempted" IN A CELL NEXT TO AN EMPTY CVE COLUMN IS READ AS
	// "nothing found" BY ANYBODY SKIMMING.
	for _, status := range []string{"not-attempted", "", "no-cpe"} {
		label := vulnStatusLabel(status)
		if !strings.Contains(label, "NOT SEARCHED") {
			t.Errorf("status %q renders as %q, which does not say nobody looked", status, label)
		}
	}
	if strings.Contains(vulnStatusLabel("no-match"), "NOT SEARCHED") {
		t.Error("a real negative must not be labelled as unsearched")
	}
	if !strings.Contains(vulnStatusLabel("matched"), "advisory") {
		t.Error("a match must be labelled advisory")
	}
}

func TestTheNoteWarnsWhenNothingWasSearchedAtAll(t *testing.T) {
	note := vulnerabilityNote([]HardwareComponent{
		{Name: "a", VulnMatchStatus: "not-attempted"},
		{Name: "b", VulnMatchStatus: "no-cpe"},
	})
	lower := strings.ToLower(note)
	for _, want := range []string{"no vulnerability lookup was performed", "not that nothing was found"} {
		if !strings.Contains(lower, want) {
			t.Errorf("the note does not contain %q: %s", want, note)
		}
	}
}

func TestTheNoteExplainsThatCleanScoresZeroOnElement24(t *testing.T) {
	// ⚠ THE SCORING IS COUNTERINTUITIVE AND THE REPORT HAS TO SAY SO. A part
	// with no known vulnerability scores zero on element 24 while a vulnerable
	// one scores full marks. A reader who does not know that will read the
	// percentage as a security signal, which it is not.
	note := vulnerabilityNote([]HardwareComponent{
		{Name: "a", VulnMatchStatus: "matched", Vulnerabilities: []HardwareFinding{{CVEID: "CVE-1"}}},
		{Name: "b", VulnMatchStatus: "no-match"},
	})
	lower := strings.ToLower(note)
	if !strings.Contains(lower, "declares") {
		t.Errorf("the note does not say the element scores declaration: %s", note)
	}
	if !strings.Contains(lower, "advisory") {
		t.Errorf("the note does not label the matching advisory: %s", note)
	}
	if !strings.Contains(lower, "found clean scores the same zero") {
		t.Errorf("the note does not state the inversion: %s", note)
	}
}

func TestTheNoteCountsTheUnsearchedComponentsWhenSomeWereSearched(t *testing.T) {
	note := vulnerabilityNote([]HardwareComponent{
		{Name: "a", VulnMatchStatus: "matched", Vulnerabilities: []HardwareFinding{{CVEID: "CVE-1"}}},
		{Name: "b", VulnMatchStatus: "no-cpe"},
		{Name: "c", VulnMatchStatus: "not-attempted"},
	})
	if !strings.Contains(note, "2 of 3") {
		t.Errorf("the note does not count the unsearched components: %s", note)
	}
}

func TestHBOMNotesCarriesTheVulnerabilityCaveat(t *testing.T) {
	// The Phase 15 bug was HBOMNotes being written and wired to nothing.
	notes := HBOMNotes([]HardwareComponent{{Name: "a", VulnMatchStatus: "not-attempted"}})
	var found bool
	for _, n := range notes {
		if strings.Contains(strings.ToLower(n), "no vulnerability lookup was performed") {
			found = true
		}
	}
	if !found {
		t.Errorf("the vulnerability caveat never reaches HBOMNotes: %v", notes)
	}
}

func TestTheSheetRendersTheSearchedCPESoAMatchIsAuditable(t *testing.T) {
	// ⚠ AN ADVISORY MATCH THAT DOES NOT SAY WHAT IT SEARCHED WITH CANNOT BE
	// CHECKED BY THE READER, which is the only thing that makes "advisory"
	// meaningful rather than a disclaimer.
	components := []HardwareComponent{{
		Name:            "MCU",
		VulnMatchStatus: "matched",
		Vulnerabilities: []HardwareFinding{{
			CVEID:           "CVE-2021-1472",
			CPE23:           "cpe:2.3:h:cisco:rv340:*:*:*:*:*:*:*:*",
			MatchBasis:      "vendor+product",
			MatchConfidence: "low",
		}},
	}}
	row := rowsOf(t, hardwareVulnerabilitySheet(components))[0]
	joined := strings.Join(row, "|")
	for _, want := range []string{"cpe:2.3:h:cisco:rv340", "vendor+product", "low"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the row omits %q, so the match cannot be audited: %v", want, row)
		}
	}
}

func TestAnUnsearchedComponentStillShowsTheCPEsThatWouldHaveBeenUsed(t *testing.T) {
	// So a customer with no NVD key can see exactly what enabling one buys.
	components := []HardwareComponent{{
		Name:            "MCU",
		VulnMatchStatus: "not-attempted",
		CPE23Candidates: []string{"cpe:2.3:h:st:stm32h753zi:*:*:*:*:*:*:*:*"},
	}}
	row := rowsOf(t, hardwareVulnerabilitySheet(components))[0]
	if !strings.Contains(strings.Join(row, "|"), "stm32h753zi") {
		t.Errorf("the candidate CPE is not rendered: %v", row)
	}
}
