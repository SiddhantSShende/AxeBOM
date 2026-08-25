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

// TestTheProvenanceNoteSaysImportedNotScanned.
//
// ⚠ THE REST OF THIS PRODUCT SCANS. An HBOM does not, because nothing can. A
// report that leaves that ambiguous invites the reader to assume the same
// automated coverage the SBOM sections have — an assumption discovered at an
// audit, which is the worst possible moment.
func TestTheProvenanceNoteSaysImportedNotScanned(t *testing.T) {
	note := HBOMProvenanceNote

	if !strings.Contains(note, "IMPORTED") {
		t.Errorf("the provenance note does not say the BOM was imported: %s", note)
	}
	if !strings.Contains(note, "does not discover") {
		t.Errorf("the provenance note does not deny discovery: %s", note)
	}
	// And it never uses the word "compliant" — this product reports violations
	// against a configured policy and never asserts compliance.
	if strings.Contains(strings.ToLower(note), "compliant") {
		t.Errorf("the note asserts compliance: %s", note)
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
	notes := HBOMNotes(hardware())
	if len(notes) != 1 {
		t.Errorf("a populated BOM raised %d notes: %v", len(notes), notes)
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
