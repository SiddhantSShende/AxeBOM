package render

import (
	"fmt"
	"io"

	"github.com/xuri/excelize/v2"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// XLSXMediaType is what the download response and the artifact record carry.
const XLSXMediaType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

// WriteXLSX streams a workbook to w.
//
// ⚠ STREAMING, BECAUSE THIS IS THE COMPLETE-BOM FORMAT.
//
// PDF gets a page cap and Top-Level; XLSX and JSON are where a Complete BOM
// actually goes, so this writer has to hold up at 50k components. excelize's
// StreamWriter appends rows to the sheet XML as they arrive instead of building
// the whole worksheet in memory first.
//
// ⚠ EVERY VALUE GOES THROUGH cell(). There is no other way to put a string in a
// cell here, deliberately.
func WriteXLSX(w io.Writer, sheets []Sheet) (Result, error) {
	if len(sheets) == 0 {
		return Result{}, fmt.Errorf("a workbook needs at least one sheet")
	}

	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	var result Result

	for _, s := range sheets {
		name, err := sheetName(s.Name)
		if err != nil {
			return Result{}, err
		}
		if _, err := f.NewSheet(name); err != nil {
			return Result{}, fmt.Errorf("creating sheet %q: %w", name, err)
		}

		sheetResult, err := writeSheet(f, name, s)
		if err != nil {
			return Result{}, err
		}
		result.Sheets = append(result.Sheets, sheetResult)
	}

	// excelize starts every workbook with an empty "Sheet1". Left in place it
	// would be the first tab a customer sees.
	if idx, err := f.GetSheetIndex("Sheet1"); err == nil && idx >= 0 {
		if err := f.DeleteSheet("Sheet1"); err != nil {
			return Result{}, fmt.Errorf("removing the placeholder sheet: %w", err)
		}
	}
	f.SetActiveSheet(0)

	if err := f.Write(w); err != nil {
		return Result{}, errs.Wrap(err, errs.ReportRenderFailed, "writing the workbook")
	}
	return result, nil
}

// writeSheet streams one sheet's header and rows.
func writeSheet(f *excelize.File, name string, s Sheet) (SheetResult, error) {
	sw, err := f.NewStreamWriter(name)
	if err != nil {
		return SheetResult{}, fmt.Errorf("opening a stream writer for %q: %w", name, err)
	}

	// Widths must be set before the first row; after that the stream has moved
	// past the column definitions.
	if s.Width > 0 && len(s.Header) > 0 {
		if err := sw.SetColWidth(1, len(s.Header), s.Width); err != nil {
			return SheetResult{}, fmt.Errorf("setting column widths on %q: %w", name, err)
		}
	}

	out := SheetResult{Name: name}
	var stats cellStats

	// ⚠ The header goes through cell() too.
	//
	// Headers are ours, not user data, so nothing in them should ever be
	// dangerous — which is exactly why they must not be exempted. An exemption
	// is a second path into a cell, and the next person to need one will reach
	// for it with data that is not ours.
	if len(s.Header) > 0 {
		if err := emitRow(sw, 1, s.Header, &stats); err != nil {
			return SheetResult{}, fmt.Errorf("writing the header of %q: %w", name, err)
		}
	}

	row := 0
	if len(s.Header) > 0 {
		row = 1
	}
	err = s.Rows(func(values []string) error {
		row++
		if row > rowLimit {
			return errs.New(errs.ReportTooLargeForXLSX,
				"this BOM has more rows than a worksheet can hold").
				WithDetail(errs.Detail{
					"sheet":     name,
					"row_limit": rowLimit,
					"hint":      "render the JSON export, which has no row limit",
				})
		}
		out.Rows++
		return emitRow(sw, row, values, &stats)
	})
	if err != nil {
		return SheetResult{}, fmt.Errorf("streaming rows into %q: %w", name, err)
	}

	if err := sw.Flush(); err != nil {
		return SheetResult{}, fmt.Errorf("flushing %q: %w", name, err)
	}

	out.Escaped = stats.escaped
	out.Truncated = stats.truncated
	out.ControlStripped = stats.controlStripped
	return out, nil
}

// emitRow writes one row at the given 1-based row number.
func emitRow(sw *excelize.StreamWriter, row int, values []string, stats *cellStats) error {
	origin, err := excelize.CoordinatesToCellName(1, row)
	if err != nil {
		return err
	}

	// ⚠ []any of STRINGS, never of typed values.
	//
	// Handing excelize a float or a time would let it decide the cell type, and
	// a numeric cell renders a version like "1.10" as 1.1. Everything in a BOM
	// is text as far as the spreadsheet is concerned; the canonical model is
	// where the types live.
	//
	// It also keeps the formula field untouched — excelize only writes a
	// formula when asked via excelize.Cell{Formula: ...}, which nothing here
	// does. That is the structural half of the injection defence: the cell is
	// typed as a string, so Excel does not parse it. The escaping in cell() is
	// the other half, for every consumer that re-parses the text — a CSV export
	// of this sheet, a paste into another spreadsheet, an importer that guesses.
	cells := make([]any, len(values))
	for i, v := range values {
		cells[i] = cell(v, stats)
	}

	return sw.SetRow(origin, cells)
}
