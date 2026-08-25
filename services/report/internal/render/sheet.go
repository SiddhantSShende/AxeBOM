// Package render turns a canonical BOM into the artifacts a customer downloads.
//
// XLSX and CSV share one table model and — the part that matters — ONE cell
// function. Two writers with two escaping paths is two chances to get it wrong,
// and only one of them would be covered by the test somebody remembered to
// write.
//
// See docs/phases/PHASE-09-reports.md and CLAUDE.md invariant 8.
package render

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/axebom/axebom/services/report/internal/render/safe"
)

// Sheet is one table. The writers are format-specific; this is not.
type Sheet struct {
	Name string
	// Header is row 1. It is escaped like any other row — see cell().
	Header []string
	Rows   RowSource
	// Width is the column width hint, in characters. Zero means the default.
	Width float64
}

// RowSource pushes rows one at a time.
//
// ⚠ A PUSH ITERATOR, NOT A SLICE, BECAUSE A COMPLETE BOM DOES NOT FIT.
//
// The product rule is Top-Level to PDF, Complete to XLSX/JSON, which makes this
// the writer that has to survive 50k components. Materializing them as
// [][]string before writing would hold the whole report in memory twice — once
// as rows and once as the workbook — for no benefit.
//
// Returning an error from emit aborts the sheet; returning an error from the
// source itself aborts the workbook. Both propagate, because a report that
// silently stops halfway is a report with missing components and no way to tell.
type RowSource func(emit func(row []string) error) error

// StaticRows adapts an in-memory table to a RowSource. For small sheets and for
// tests; the component and finding sheets stream from the database.
func StaticRows(rows [][]string) RowSource {
	return func(emit func([]string) error) error {
		for _, row := range rows {
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	}
}

// Result records every change the writer had to make to the data.
//
// ⚠ REPORTED, NOT SILENT. Escaping and truncation both alter what the customer
// reads. Escaping is invisible by design (see safe.Cell), and truncation loses
// data outright — so the counts are returned and the caller renders them into
// the report's notes. A compliance artifact that quietly rewrote its own
// contents is one nobody can reconcile against the database.
type Result struct {
	Sheets []SheetResult
}

// SheetResult is one sheet's write record.
type SheetResult struct {
	Name string
	Rows int
	// Escaped counts values that began with a formula character. A non-zero
	// count means something in the dependency tree is shaped like an attack,
	// which a security team wants told rather than silently defused.
	Escaped int
	// Truncated counts values longer than a spreadsheet cell can hold.
	Truncated int
	// ControlStripped counts values containing characters that are not legal
	// in XML at all.
	ControlStripped int
}

// Total sums a counter across every sheet.
func (r Result) Total(pick func(SheetResult) int) int {
	n := 0
	for _, s := range r.Sheets {
		n += pick(s)
	}
	return n
}

// Excel's own limits. Exceeding either produces a file Excel refuses to open,
// so they are enforced here rather than discovered by a customer.
const (
	// maxRows is the row count of a worksheet, header included.
	maxRows = 1_048_576
	// maxCellRunes is the character limit of a single cell.
	maxCellRunes = 32_767
	// maxSheetNameRunes is the worksheet-name limit.
	maxSheetNameRunes = 31
)

// truncationMarker is appended to a value the cell could not hold. Visible on
// purpose: a silently shortened licence text or dependency list reads as
// complete.
const truncationMarker = " …[truncated]"

// rowLimit is maxRows, as a variable so the overflow test can reach it.
//
// Writing 1,048,577 rows through a real workbook to exercise one comparison
// would make the suite slow enough that somebody eventually skips it, and a
// skipped test does not guard anything. The code path is identical; only the
// threshold moves.
var rowLimit = maxRows

// cellStats accumulates what cell() had to change.
type cellStats struct {
	escaped         int
	truncated       int
	controlStripped int
}

// cell produces the exact string that goes into a spreadsheet cell.
//
// ⚠ THIS IS THE ONLY PLACE A CELL VALUE IS PRODUCED, FOR EVERY FORMAT.
//
// Both writers call it; neither has an alternative path. That is the whole
// point of the package layout — an escaping rule applied at call sites survives
// exactly until the next call site is added.
//
// Three transformations, in this order, and the order matters:
//
//  1. Strip characters XML cannot represent. XLSX is zipped XML, so a NUL or a
//     stray 0x01 in a package name — which a hostile package can absolutely
//     have — produces a workbook Excel reports as corrupt. Same class as the
//     NUL-byte truncation the normalizer handles at the Postgres boundary.
//  2. Escape a leading formula character (safe.Cell).
//  3. Truncate to what a cell can hold.
//
// Escaping before truncating keeps the guard prefix even on a value that had to
// be cut; truncating first and then escaping would be fine too, but stripping
// after escaping could remove the prefix, which is why stripping is first.
func cell(value string, stats *cellStats) string {
	cleaned, stripped := stripControl(value)
	if stripped {
		stats.controlStripped++
	}

	if safe.IsDangerous(cleaned) {
		stats.escaped++
	}
	escaped := safe.Cell(cleaned)

	if utf8.RuneCountInString(escaped) > maxCellRunes {
		stats.truncated++
		return truncate(escaped)
	}
	return escaped
}

// stripControl removes characters that are not legal in XML 1.0.
//
// Legal control characters are TAB, LF and CR; everything below 0x20 otherwise
// is not representable, and neither is the 0x7F..0x9F block in practice. They
// are REPLACED with U+FFFD rather than deleted, so a name that was tampered
// with does not silently become a different, valid-looking name — two packages
// whose names differ only by an invisible control character must not collapse
// into one row.
func stripControl(value string) (string, bool) {
	if !strings.ContainsFunc(value, isIllegalXML) {
		return value, false
	}
	return strings.Map(func(r rune) rune {
		if isIllegalXML(r) {
			return '�'
		}
		return r
	}, value), true
}

func isIllegalXML(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case r < 0x20:
		return true
	case r >= 0x7F && r <= 0x9F:
		return true
	case r == utf8.RuneError:
		// An invalid UTF-8 byte decodes to this. Passing it through unchanged
		// is fine; flagging it is not, or every mojibake name reads as tampering.
		return false
	default:
		return false
	}
}

// truncate cuts a value to the cell limit, marker included.
func truncate(value string) string {
	keep := maxCellRunes - utf8.RuneCountInString(truncationMarker)
	runes := []rune(value)
	if keep < 0 || keep > len(runes) {
		keep = len(runes)
	}
	return string(runes[:keep]) + truncationMarker
}

// sheetName returns a name a workbook will accept, or an error.
//
// ⚠ REFUSED, NOT SILENTLY MANGLED. Sheet names are ours, not user data, so a
// bad one is a bug in this package — and a writer that quietly renamed
// "Engine Coverage" would break the one section the report may not omit.
func sheetName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("sheet name is empty")
	}
	if utf8.RuneCountInString(name) > maxSheetNameRunes {
		return "", fmt.Errorf(
			"sheet name %q is %d characters; a worksheet name may not exceed %d",
			name, utf8.RuneCountInString(name), maxSheetNameRunes)
	}
	if strings.ContainsAny(name, `:\/?*[]`) {
		return "", fmt.Errorf(`sheet name %q contains one of the characters a worksheet name may not use (: \ / ? * [ ])`, name)
	}
	return name, nil
}
