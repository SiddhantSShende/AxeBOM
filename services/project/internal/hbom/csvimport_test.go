package hbom

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These cases mirror workers/hbom/test_hbom.py's CSV-import section by hand —
// there is no golden-file sharing mechanism between the two languages, so a
// change to either module's behaviour must be reflected in both test suites.

// nestedFixture loads the shared fixture used by both the Python and Go
// suites (fixtures/hbom-nested/parts.csv), with an explicit mapping matching
// what workers/hbom/csv_import.py's ColumnMapping.suggest() would have
// produced for these exact headers.
func nestedFixture(t *testing.T) *ImportResult {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "fixtures", "hbom-nested", "parts.csv")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mapping := map[string]string{
		"Level":                     "level",
		"Part Number":               "part_number",
		"Description":               "description",
		"Qty":                       "quantity",
		"Manufacturer":              "manufacturer",
		"Manufacturer Location":     "manufacturer_location",
		"Supplier":                  "supplier",
		"Supplier Location":         "supplier_location",
		"Product Supplier":          "product_supplier",
		"Product Supplier Location": "product_supplier_location",
		"Firmware Version":          "firmware_version",
		"Origin":                    "origin",
		"Criticality":               "criticality",
		"Technology Node":           "technology_node",
		"Compliance":                "compliance",
		"Serial Number":             "serial_number",
	}
	result, err := Parse(data, mapping)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return result
}

func modelNumbers(cs []*Component) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ModelNumber
	}
	return out
}

func TestLevelColumnBuildsTheTree(t *testing.T) {
	result := nestedFixture(t)
	if len(result.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(result.Roots))
	}
	root := result.Roots[0]
	// The fixture has no column mapped to "name" (product_name); the fallback
	// chain uses the part number instead — matching
	// test_the_level_column_builds_the_tree in workers/hbom/test_hbom.py.
	if root.ProductName != "ENC-GW-4400" {
		t.Errorf("root.ProductName = %q, want ENC-GW-4400", root.ProductName)
	}
	if got := root.Depth(); got != 3 {
		t.Errorf("root.Depth() = %d, want 3 (gateway -> mainboard -> DDR3L -> die)", got)
	}

	if got, want := modelNumbers(root.Children), []string{"ENC-MB-01", "ENC-PSU-02", "ENC-ENC-01"}; !equal(got, want) {
		t.Errorf("root children = %v, want %v", got, want)
	}

	mainboard := root.Children[0]
	if got, want := modelNumbers(mainboard.Children), []string{"STM32H753ZI", "MT41K256M16", "W25Q128JV"}; !equal(got, want) {
		t.Errorf("mainboard children = %v, want %v", got, want)
	}

	sdram := mainboard.Children[1]
	if got, want := modelNumbers(sdram.Children), []string{"MT41K-DIE"}; !equal(got, want) {
		t.Errorf("sdram children = %v, want %v", got, want)
	}
}

func TestReturningToAShallowerLevelReattachesCorrectly(t *testing.T) {
	// Row 6 (W25Q128JV) is level 2 following a level-3 row. It belongs to the
	// mainboard, not the memory die — a stack that was not truncated would
	// attach it to whatever was last seen at any depth.
	result := nestedFixture(t)
	mainboard := result.Roots[0].Children[0]
	found := false
	for _, c := range mainboard.Children {
		if c.ModelNumber == "W25Q128JV" {
			found = true
		}
	}
	if !found {
		t.Fatal("the flash chip did not reattach to the mainboard")
	}
}

func TestComplianceSplitsOnEitherSeparator(t *testing.T) {
	result := nestedFixture(t)
	root := result.Roots[0]
	if got, want := root.Compliance, []string{"RoHS", "CE"}; !equal(got, want) {
		t.Errorf("root.Compliance = %v, want %v", got, want)
	}
}

func TestASkippedLevelIsRejectedAndNamesTheRow(t *testing.T) {
	csvText := "level,part_number,description\n0,A,product\n1,B,assembly\n3,C,orphan\n"
	mapping := map[string]string{"level": "level", "part_number": "part_number", "description": "description"}

	_, err := Parse([]byte(csvText), mapping)
	if err == nil {
		t.Fatal("expected an error for a skipped level")
	}
	msg := err.Error()
	for _, want := range []string{"row 4", "level 3", "level 1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
	if !strings.Contains(strings.ToLower(msg), "skip") {
		t.Errorf("error %q does not say 'skip'", msg)
	}
}

func TestAnOutlineLevelIsUnderstood(t *testing.T) {
	csvText := "level,part_number,description\n1,A,product\n1.1,B,assembly\n1.1.1,C,part\n"
	mapping := map[string]string{"level": "level", "part_number": "part_number", "description": "description"}

	result, err := Parse([]byte(csvText), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := result.Roots[0].Depth(); got != 2 {
		t.Errorf("depth = %d, want 2", got)
	}
}

func TestALevelThatIsNotANumberIsRejectedLegibly(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number"}
	_, err := Parse([]byte("level,part_number\n0,A\nsub,B\n"), mapping)
	if err == nil || !strings.Contains(err.Error(), "row 3") {
		t.Fatalf("error = %v, want it to mention row 3", err)
	}
}

func TestDepthBeyondTheCapIsReportedNotRecursed(t *testing.T) {
	rows := []string{"level,part_number,description"}
	for level := 0; level < MaxDepth+3; level++ {
		rows = append(rows, formatCSVRow(level))
	}
	mapping := map[string]string{"level": "level", "part_number": "part_number", "description": "description"}

	result, err := Parse([]byte(strings.Join(rows, "\n")+"\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("exceeding the depth cap produced no diagnostic")
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "10") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning mentions the depth cap: %v", result.Warnings)
	}
	if got := result.Roots[0].Depth(); got > MaxDepth {
		t.Errorf("depth = %d, exceeds cap %d", got, MaxDepth)
	}
}

func formatCSVRow(level int) string {
	n := strconv.Itoa(level)
	return strings.Join([]string{n, "PART-" + n, "component"}, ",")
}

func TestAnUnmappedHeaderIsReportedNotSwallowed(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number"}
	result, err := Parse([]byte("level,part_number,Crit.\n0,A,critical\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	found := false
	for _, h := range result.UnmappedHeaders {
		if h == "Crit." {
			found = true
		}
	}
	if !found {
		t.Errorf("unmapped headers = %v, want it to include %q", result.UnmappedHeaders, "Crit.")
	}
}

func TestAFileWithNoLevelColumnIsRejectedWithAReason(t *testing.T) {
	mapping := map[string]string{"part_number": "part_number", "description": "description"}
	_, err := Parse([]byte("part_number,description\nA,thing\n"), mapping)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "level") {
		t.Errorf("error %q does not mention level", msg)
	}
	if !strings.Contains(msg, "sibling") && !strings.Contains(msg, "sub-component") {
		t.Errorf("error %q does not explain the consequence", msg)
	}
}

func TestAComponentWithNoDescriptionStillHasAName(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number"}
	result, err := Parse([]byte("level,part_number\n0,ENC-1\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.Roots[0].ProductName != "ENC-1" {
		t.Errorf("product name = %q, want ENC-1", result.Roots[0].ProductName)
	}
}

func TestRepeatedSiblingPartsWarnRatherThanFail(t *testing.T) {
	csvText := "level,part_number,description\n0,BOARD,board\n1,CAP-1,capacitor\n1,CAP-1,capacitor again\n"
	mapping := map[string]string{"level": "level", "part_number": "part_number", "description": "description"}

	result, err := Parse([]byte(csvText), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected a duplicate-part warning")
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "CAP-1") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one mentioning CAP-1", result.Warnings)
	}
	if got := result.Total(); got != 3 {
		t.Errorf("total = %d, want 3 — a duplicate must not be dropped, only reported", got)
	}
}

func TestTheSamePartUnderDifferentParentsIsNotAWarning(t *testing.T) {
	result := nestedFixture(t)
	for _, w := range result.Warnings {
		if strings.Contains(w, "Arrow") {
			t.Errorf("unexpected warning about a shared supplier, not a duplicate part: %q", w)
		}
	}
}

func TestABOMFieldIsStrippedFromTheFirstCell(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number"}
	// The literal byte sequence EF BB BF (UTF-8 BOM) prefixing the header row.
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte("level,part_number\n0,ENC-1\n")...)

	result, err := Parse(data, mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.Roots[0].ModelNumber != "ENC-1" {
		t.Errorf("model number = %q, want ENC-1 — the BOM leaked into the header name", result.Roots[0].ModelNumber)
	}
}

func TestARowWithExtraFieldsDoesNotCrashTheImport(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number"}
	_, err := Parse([]byte("level,part_number\n0,A,surprise,extra\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v, want no error for a row with surplus fields", err)
	}
}

func TestATruncatedRowDoesNotCrashTheImport(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number", "description": "description"}
	result, err := Parse([]byte("level,part_number,description\n0,A\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v, want no error for a truncated row", err)
	}
	if result.Roots[0].ModelNumber != "A" {
		t.Errorf("model number = %q, want A", result.Roots[0].ModelNumber)
	}
}

func TestFirstMappedColumnWinsForModelNumber(t *testing.T) {
	// part_number and mpn both target model_number; part_number must win
	// because it precedes mpn in canonicalOrder — matching the Python dict's
	// insertion order.
	mapping := map[string]string{"level": "level", "PN": "part_number", "MPN": "mpn"}
	result, err := Parse([]byte("level,PN,MPN\n0,FROM-PART-NUMBER,FROM-MPN\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := result.Roots[0].ModelNumber; got != "FROM-PART-NUMBER" {
		t.Errorf("model number = %q, want FROM-PART-NUMBER (part_number must win over mpn)", got)
	}
}

func TestQuantityDefaultsToOneWhenUnparseable(t *testing.T) {
	mapping := map[string]string{"level": "level", "part_number": "part_number", "quantity": "quantity"}
	result, err := Parse([]byte("level,part_number,quantity\n0,A,lots\n"), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := result.Roots[0].Quantity; got != 1 {
		t.Errorf("quantity = %d, want 1 (unparseable quantity must not fail the row)", got)
	}
}

func TestNoLevelColumnInMappingIsRejected(t *testing.T) {
	mapping := map[string]string{"part_number": "part_number"}
	_, err := Parse([]byte("part_number\nA\n"), mapping)
	if err == nil {
		t.Fatal("expected an error when no column maps to level")
	}
}

// --- small local helpers, to avoid pulling in a third-party assertion lib ---

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
