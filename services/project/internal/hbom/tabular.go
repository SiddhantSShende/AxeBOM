package hbom

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/xuri/excelize/v2"
)

// Reading a parts list, whatever the exporter wrote it as.
//
// ⚠ THE IMPORT SCREEN ACCEPTED `.csv` AND NOTHING ELSE.
//
// A parts list arrives from KiCad, Altium, OrCAD, an ERP export or somebody's
// spreadsheet, and the single most common form of all of those is an `.xlsx`.
// Telling a customer to open their file and re-save it as CSV before AxeBOM
// will read it is asking them to do by hand what a library already in this
// binary does — `excelize` is here for the report writer.
//
// ⚠ THE TREE LOGIC IS UNTOUCHED BY THIS. Everything below produces a header
// and rows; `Parse` builds the tree from them exactly as it did, so the level
// sequencing, the depth cap, the empty-row handling and every diagnostic
// message keep behaving identically no matter which format the rows came from.
// A second parser with its own tree builder is how two formats start
// disagreeing about what a level means.

// Format is a parts-list file shape this package can read.
type Format string

const (
	FormatCSV  Format = "csv"
	FormatTSV  Format = "tsv"
	FormatXLSX Format = "xlsx"
)

// MaxSheetCells bounds an XLSX read.
//
// ⚠ A SPREADSHEET DECLARES ITS DIMENSION, AND THE DECLARATION IS ATTACKER
// CONTROLLED. `<dimension ref="A1:XFD1048576"/>` costs nothing to write and
// asks the reader for 17 billion cells. excelize streams rows, so the guard is
// on what we accumulate rather than on what the file claims.
const MaxSheetCells = 2_000_000

// DetectFormat names the shape of an uploaded parts list.
//
// ⚠ FILENAME FIRST HERE, UNLIKE THE ENGINE ADAPTERS — AND FOR A REASON.
// `hbom-host-report` sniffs content because it walks a whole source tree and
// must not read the wrong file. This function is handed ONE file a human just
// chose in a file picker, and the extension is that human's own statement about
// what it is. The magic-byte check below is the safety net for the case that
// actually happens: a `.csv` that is really a workbook, because somebody
// renamed it.
func DetectFormat(filename string, data []byte) Format {
	// PK\x03\x04 — every XLSX is a zip, whatever it is called.
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return FormatXLSX
	}

	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".xlsx"), strings.HasSuffix(lower, ".xlsm"):
		return FormatXLSX
	case strings.HasSuffix(lower, ".tsv"), strings.HasSuffix(lower, ".tab"):
		return FormatTSV
	default:
		return FormatCSV
	}
}

// ReadTable turns an uploaded file into a header row and its data rows.
func ReadTable(data []byte, format Format) (header []string, rows [][]string, err error) {
	switch format {
	case FormatXLSX:
		return readXLSX(data)
	case FormatTSV:
		return readDelimited(data, '\t')
	default:
		return readDelimited(data, ',')
	}
}

func readDelimited(data []byte, comma rune) ([]string, [][]string, error) {
	text := strings.TrimPrefix(string(data), "\uFEFF")

	reader := csv.NewReader(strings.NewReader(text))
	reader.Comma = comma
	// Rows with a different field count than the header are tolerated, like
	// Python's csv.DictReader — a truncated last line or a stray trailing
	// comma is a real-world export artifact, not a reason to reject the whole
	// file.
	reader.FieldsPerRecord = -1

	head, err := reader.Read()
	if err != nil {
		return nil, nil, &ImportError{Message: "the file has no header row"}
	}

	var rows [][]string
	for {
		record, rerr := reader.Read()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, nil, importErr(len(rows)+2,
				"row %d: could not be parsed: %v", len(rows)+2, rerr)
		}
		rows = append(rows, record)
		if len(rows) > MaxRows {
			break // Parse reports the cap; stopping here bounds the memory.
		}
	}
	return head, rows, nil
}

func readXLSX(data []byte) ([]string, [][]string, error) {
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, &ImportError{
			Message: "this file could not be opened as a spreadsheet. If it is a CSV, " +
				"save it with a .csv extension; if it is an older .xls, re-save it as .xlsx.",
		}
	}
	defer func() { _ = f.Close() }()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, nil, &ImportError{Message: "the workbook has no sheets"}
	}

	// ⚠ THE FIRST SHEET, AND THE OTHERS ARE NAMED RATHER THAN SILENTLY READ.
	// A parts list workbook routinely carries a "Notes" or "Revisions" tab, and
	// guessing which one holds the BOM would be a guess about somebody's data.
	// The caller surfaces the sheet list so a human can see what was skipped.
	rowsIter, err := f.Rows(sheets[0])
	if err != nil {
		return nil, nil, &ImportError{Message: fmt.Sprintf("sheet %q could not be read", sheets[0])}
	}
	defer func() { _ = rowsIter.Close() }()

	var header []string
	var rows [][]string
	cells := 0

	for rowsIter.Next() {
		record, rerr := rowsIter.Columns()
		if rerr != nil {
			return nil, nil, &ImportError{Message: fmt.Sprintf("sheet %q: %v", sheets[0], rerr)}
		}
		cells += len(record)
		if cells > MaxSheetCells {
			return nil, nil, &ImportError{
				Message: fmt.Sprintf("the sheet exceeds %d cells; split it or raise the cap "+
					"deliberately", MaxSheetCells),
			}
		}
		if header == nil {
			header = record
			continue
		}
		rows = append(rows, record)
		if len(rows) > MaxRows {
			break
		}
	}

	if header == nil {
		return nil, nil, &ImportError{Message: "the first sheet is empty"}
	}
	return header, rows, nil
}

// SheetNames lists a workbook's sheets, so the UI can say which one was read.
// Empty for a non-workbook.
func SheetNames(data []byte, format Format) []string {
	if format != FormatXLSX {
		return nil
	}
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	return f.GetSheetList()
}
