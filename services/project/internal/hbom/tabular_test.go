package hbom_test

import (
	"bytes"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/axebom/axebom/services/project/internal/hbom"
)

// The import screen accepted `.csv` and nothing else, which meant telling a
// customer to open their spreadsheet and re-save it before AxeBOM would read
// it — by hand, using a library already linked into this binary.

func mapping() map[string]string {
	return map[string]string{
		"Level": "level", "Part": "part_number", "Description": "description",
		"Qty": "quantity", "Manufacturer": "manufacturer",
	}
}

func workbook(t *testing.T, sheet string, rows [][]string, extraSheets ...string) []byte {
	t.Helper()
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	first := f.GetSheetName(0)
	if err := f.SetSheetName(first, sheet); err != nil {
		t.Fatalf("name sheet: %v", err)
	}
	for i, row := range rows {
		cell, _ := excelize.CoordinatesToCellName(1, i+1)
		values := make([]any, len(row))
		for j, v := range row {
			values[j] = v
		}
		if err := f.SetSheetRow(sheet, cell, &values); err != nil {
			t.Fatalf("write row: %v", err)
		}
	}
	for _, name := range extraSheets {
		if _, err := f.NewSheet(name); err != nil {
			t.Fatalf("add sheet: %v", err)
		}
	}
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatalf("write workbook: %v", err)
	}
	return buf.Bytes()
}

// TestEveryFormatBuildsTheSameTree.
//
// ⚠ THE POINT IS THAT THERE IS ONE TREE BUILDER. Three formats reaching three
// parsers is how two of them start disagreeing about what a level means — so
// the assertion is not "xlsx works", it is "xlsx, tsv and csv produce the
// IDENTICAL tree from identical data".
func TestEveryFormatBuildsTheSameTree(t *testing.T) {
	rows := [][]string{
		{"Level", "Part", "Description", "Qty", "Manufacturer"},
		{"0", "ENC-GW-4400", "Edge Gateway", "1", "Encore Systems"},
		{"1", "RC0402FR-0710KL", "10k resistor", "3", "Yageo"},
	}

	csvBody := "Level,Part,Description,Qty,Manufacturer\n" +
		"0,ENC-GW-4400,Edge Gateway,1,Encore Systems\n" +
		"1,RC0402FR-0710KL,10k resistor,3,Yageo\n"
	tsvBody := "Level\tPart\tDescription\tQty\tManufacturer\n" +
		"0\tENC-GW-4400\tEdge Gateway\t1\tEncore Systems\n" +
		"1\tRC0402FR-0710KL\t10k resistor\t3\tYageo\n"

	cases := map[string][]byte{
		"parts.csv":  []byte(csvBody),
		"parts.tsv":  []byte(tsvBody),
		"parts.xlsx": workbook(t, "BOM", rows),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			format := hbom.DetectFormat(name, data)
			result, err := hbom.ParseFormat(data, mapping(), format)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if result.Total() != 2 {
				t.Fatalf("%s: %d components, want 2", name, result.Total())
			}
			root := result.Roots[0]
			if root.ModelNumber != "ENC-GW-4400" || len(root.Children) != 1 {
				t.Fatalf("%s: root = %+v", name, root)
			}
			if child := root.Children[0]; child.Quantity != 3 || child.ManufacturerName != "Yageo" {
				t.Errorf("%s: child = %+v", name, child)
			}
		})
	}
}

// TestAWorkbookRenamedToCsvIsStillReadAsAWorkbook.
//
// ⚠ THE CASE THAT ACTUALLY HAPPENS. Somebody exports a BOM, renames it, and
// uploads it. Trusting the extension alone would hand a zip archive to a CSV
// reader, which reports "the file has no header row" — a message about the
// wrong thing entirely.
func TestAWorkbookRenamedToCsvIsStillReadAsAWorkbook(t *testing.T) {
	data := workbook(t, "Sheet1", [][]string{
		{"Level", "Part"},
		{"0", "ENC-GW-4400"},
	})

	if got := hbom.DetectFormat("parts.csv", data); got != hbom.FormatXLSX {
		t.Fatalf("DetectFormat = %q, want xlsx — the magic bytes say zip", got)
	}
}

// TestTheOtherSheetsAreNamedRatherThanSilentlySkipped.
//
// A parts-list workbook routinely carries "Notes" or "Revisions" tabs. Only the
// first sheet is read — guessing which one holds the BOM would be a guess about
// somebody's data — but a reader who cannot see that has no way to notice their
// parts were on the second one.
func TestTheOtherSheetsAreNamedRatherThanSilentlySkipped(t *testing.T) {
	data := workbook(t, "BOM", [][]string{
		{"Level", "Part"},
		{"0", "ENC-GW-4400"},
	}, "Notes", "Revisions")

	sheets := hbom.SheetNames(data, hbom.FormatXLSX)
	if len(sheets) != 3 {
		t.Fatalf("sheets = %v, want three named", sheets)
	}
	if sheets[0] != "BOM" {
		t.Errorf("the first sheet is %q; that is the one that gets read", sheets[0])
	}
}

func TestAnEmptyWorkbookSaysSoRatherThanReportingNoHeaderRow(t *testing.T) {
	data := workbook(t, "BOM", nil)
	_, err := hbom.ParseFormat(data, mapping(), hbom.FormatXLSX)
	if err == nil {
		t.Fatal("an empty workbook parsed without error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("empty")) {
		t.Errorf("the error does not say the sheet is empty: %v", err)
	}
}
