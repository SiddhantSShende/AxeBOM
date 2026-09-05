// CSV is NOT a format this product ships, and that is a decision rather than an
// oversight.
//
// ⚠ `service.parseFormat` DELIBERATELY REJECTS "csv" — see its own test, which
// asserts the rejection. There is no `csv` case in `worker.renderArtifact`, no
// media type, no storage extension, and no entry in the frontend's Format
// union. Nothing in the product can produce one of these files.
//
// So why is the writer here? Because the formula-injection contract it proves
// is REAL and shared. `cell()` is what escapes a leading `=`/`+`/`-`/`@`, both
// this writer and the XLSX writer call it, and CSV is the sharper half of the
// problem — a `.xlsx` cell carries an explicit type, a CSV field carries
// nothing, so whatever opens it decides. The tests in xlsx_test.go exercise
// that path through this writer because it is the one with no type system to
// hide behind.
//
// ⚠ IF YOU ARE HERE TO WIRE IT UP: that is a product decision, not a cleanup.
// It needs parseFormat, renderArtifact, mediaType, StorageKey, the frontend
// union, and an answer to "one file per sheet, so which sheet?" — a report is a
// workbook and CSV is one table. If you are here to delete it, delete the
// escaping tests' subject too, and be sure the XLSX-only versions still prove
// invariant 8.
//
// What must not happen is it staying ambiguous. Well-written code wired to
// nothing reads as a feature to a reviewer and as coverage to a maintainer.
package render

import (
	"encoding/csv"
	"fmt"
	"io"
)

// CSVMediaType is what the download response carries.
//
// `text/csv` and not `application/vnd.ms-excel`: the latter makes some browsers
// hand the file straight to Excel, which is the launch path the escaping in
// cell() exists to make harmless. No reason to invite it.
const CSVMediaType = "text/csv; charset=utf-8"

// WriteCSV streams one sheet as CSV.
//
// ⚠ CSV IS THE SHARPER HALF OF THE FORMULA-INJECTION PROBLEM, NOT THE MILDER ONE.
//
// In XLSX a cell carries an explicit type, so a string stays a string. CSV
// carries no types at all: whatever imports the file decides what each field
// means, and Excel's decision for a field starting `=` is "formula". That is why
// the escaping cannot live in the XLSX writer — it lives in cell(), which both
// writers call.
//
// CSV is one table, so a workbook becomes one file per sheet. Callers that need
// the whole report in one artifact use XLSX or JSON.
func WriteCSV(w io.Writer, s Sheet) (SheetResult, error) {
	cw := csv.NewWriter(w)
	out := SheetResult{Name: s.Name}
	var stats cellStats

	// The header is escaped like every other row, for the reason given in
	// writeSheet: an exemption is a second path into a cell.
	if len(s.Header) > 0 {
		if err := cw.Write(escapeAll(s.Header, &stats)); err != nil {
			return SheetResult{}, fmt.Errorf("writing the header of %q: %w", s.Name, err)
		}
	}

	err := s.Rows(func(values []string) error {
		out.Rows++
		return cw.Write(escapeAll(values, &stats))
	})
	if err != nil {
		return SheetResult{}, fmt.Errorf("streaming rows into %q: %w", s.Name, err)
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return SheetResult{}, fmt.Errorf("flushing %q: %w", s.Name, err)
	}

	out.Escaped = stats.escaped
	out.Truncated = stats.truncated
	out.ControlStripped = stats.controlStripped
	return out, nil
}

// escapeAll runs a whole row through cell().
//
// ⚠ Note what this does NOT do: quoting. encoding/csv already quotes a field
// containing a comma, a quote or a newline, and doing it here as well would
// double-quote every such value. Quoting is a CSV syntax concern; escaping is a
// "what will the importer execute" concern. They are different problems and
// solving one does not solve the other — a correctly quoted `"=cmd|'/c calc'!A1"`
// still executes.
func escapeAll(values []string, stats *cellStats) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = cell(v, stats)
	}
	return out
}
