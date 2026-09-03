package hbom

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// canonicalColumns maps a canonical column id — the value a confirmed column
// mapping assigns to a customer's header — to the Component attribute it
// fills. Matches workers/hbom/csv_import.py's CANONICAL_COLUMNS exactly,
// which is the superset frontend/src/lib/hbom.ts's own CANONICAL_COLUMNS (the
// ids offered in the mapping UI) draws from.
//
// ⚠ NON-CERT-In COLUMNS ARE STORED NOW, NOT IGNORED. `unit_cost` used to map
// to "" — accepted and thrown away — because there was no column to put it in.
// Migration 0011 added them, and the scan path (workers/hbom) has been reading
// them since. Leaving this map behind meant the INTERACTIVE import silently
// dropped designators, prices, SKUs and lifecycle that a SCAN of the very same
// file kept, which is a difference no customer could see or explain.
var canonicalColumns = map[string]string{
	"level":                     "level",
	"part_number":               "model_number",
	"description":               "product_details",
	"quantity":                  "quantity",
	"manufacturer":              "manufacturer_name",
	"mpn":                       "model_number",
	"supplier":                  "component_supplier_info",
	"unit_cost":                 "unit_price",
	"name":                      "product_name",
	"version":                   "product_version",
	"serial_number":             "serial_number",
	"manufacturer_location":     "manufacturer_location",
	"supplier_location":         "component_supplier_location",
	"product_supplier":          "supplier_info",
	"product_supplier_location": "supplier_location",
	"firmware_version":          "firmware_version",
	"origin":                    "origin",
	"criticality":               "criticality",
	"technology_node":           "technology_node",
	"compliance":                "compliance",
	"power_supply":              "power_supply",
	"license":                   "license_info",
	"test_result":               "test_result",
	"technical_specification":   "technical_specification",
	"manufacturing_date":        "manufacturing_date",
	"warranty":                  "warranty_amc",

	// --- manufacturing and procurement -------------------------------------
	// Not CERT-In elements; scored separately against
	// docs/reference/hbom-manufacturing-v1.yaml.
	"currency":           "currency",
	"designator":         "designators",
	"footprint":          "package_footprint",
	"supplier_sku":       "supplier_sku",
	"preferred_supplier": "preferred_supplier",
	"dni":                "do_not_populate",
	"assembly_type":      "assembly_type",
	"lifecycle":          "lifecycle_status",
	"datasheet":          "datasheet_url",
}

// canonicalOrder is canonicalColumns' key order, FIXED to match the Python
// dict's insertion order.
//
// ⚠ ORDER IS LOAD-BEARING. A Go map iterates in randomized order; Python's
// does not. `part_number` and `mpn` both target `model_number`, and the
// "first column wins" rule in build() below depends on visiting
// `part_number` before `mpn` — exactly the order the Python dict literal
// declares. Iterating canonicalColumns directly would make the winner
// nondeterministic between requests, which is worse than either answer.
var canonicalOrder = []string{
	"level", "part_number", "description", "quantity", "manufacturer", "mpn",
	"supplier", "unit_cost", "name", "version", "serial_number",
	"manufacturer_location", "supplier_location", "product_supplier",
	"product_supplier_location", "firmware_version", "origin", "criticality",
	"technology_node", "compliance", "power_supply", "license", "test_result",
	"technical_specification", "manufacturing_date", "warranty",
	"currency", "designator", "footprint", "supplier_sku",
	"preferred_supplier", "dni", "assembly_type", "lifecycle", "datasheet",
}

// MaxRows caps a single import. A file this long is almost certainly an
// export mistake — matches workers/hbom/csv_import.py's max_rows default.
const MaxRows = 50_000

// ImportError is a CSV that cannot be turned into a tree. Distinguished from
// a generic error so a handler can decide the HTTP shape; Row is 0 when the
// failure names no single row. Mirrors workers/hbom/csv_import.py's
// HBOMImportError.
type ImportError struct {
	Message string
	Row     int
}

func (e *ImportError) Error() string { return e.Message }

func importErr(row int, format string, args ...any) *ImportError {
	return &ImportError{Row: row, Message: fmt.Sprintf(format, args...)}
}

// ImportResult is what an import produced, and what it could not. Mirrors
// workers/hbom/csv_import.py's ImportResult.
type ImportResult struct {
	Roots []*Component

	// Rows that were read but carried nothing beyond an (absent) level.
	EmptyRows []int

	// Headers present in the file that no canonical column claimed. Reported,
	// never swallowed — see the module docstring on csv_import.py.
	UnmappedHeaders []string

	// Diagnostics that did not stop the import.
	Warnings []string
}

// Total is the node count across every root.
func (r *ImportResult) Total() int {
	n := 0
	for _, root := range r.Roots {
		n += root.Count()
	}
	return n
}

// MaxDepthReached is the deepest level across every root.
func (r *ImportResult) MaxDepthReached() int {
	max := 0
	for _, root := range r.Roots {
		if d := root.Depth(); d > max {
			max = d
		}
	}
	return max
}

// Parse turns a CSV parts list into a component tree.
//
// ⚠ `mapping` IS ALWAYS SUPPLIED BY THE CALLER, NEVER GUESSED HERE. The
// frontend confirms a column mapping with a human before ever calling
// preview or import (HardwareImport.tsx); unlike
// workers/hbom/csv_import.py's `parse()`, this function has no
// suggest-a-mapping fallback path because the API contract it serves never
// omits one.
//
// `mapping` is header -> canonical column id (e.g. "Qty" -> "quantity").
func Parse(data []byte, mapping map[string]string) (*ImportResult, error) {
	text := strings.TrimPrefix(string(data), "\uFEFF")

	reader := csv.NewReader(strings.NewReader(text))
	// Rows with a different field count than the header are tolerated, like
	// Python's csv.DictReader — a truncated last line or a stray trailing
	// comma is a real-world export artifact, not a reason to reject the
	// whole file.
	reader.FieldsPerRecord = -1

	header, err := reader.Read()
	if err != nil {
		return nil, &ImportError{Message: "the file has no header row"}
	}
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}

	result := &ImportResult{}
	for _, h := range header {
		if h == "" {
			continue
		}
		if _, ok := mapping[h]; !ok {
			result.UnmappedHeaders = append(result.UnmappedHeaders, h)
		}
	}

	hasLevel := false
	for _, target := range mapping {
		if target == "level" {
			hasLevel = true
			break
		}
	}
	if !hasLevel {
		return nil, &ImportError{Message: "no column is mapped to `level`. The level column is what " +
			"builds the sub-component tree; without it every part would be a sibling of the " +
			"product rather than a part of it."}
	}

	var stack []*Component
	var roots []*Component
	previousLevel := 0
	havePrevious := false
	rowNumber := 1 // the header

	for {
		record, rerr := reader.Read()
		if rerr == io.EOF {
			break
		}
		rowNumber++
		if rowNumber-1 > MaxRows {
			return nil, importErr(0, "the file exceeds %d rows. A parts list that long is "+
				"almost certainly an export mistake; split it or raise the cap deliberately.", MaxRows)
		}
		if rerr != nil {
			return nil, importErr(rowNumber, "row %d: could not be parsed as CSV: %v", rowNumber, rerr)
		}

		values := canonicalizeRow(header, record, mapping)
		levelText := strings.TrimSpace(values["level"])

		if levelText == "" && allBlank(values) {
			result.EmptyRows = append(result.EmptyRows, rowNumber)
			continue
		}

		level, err := parseLevel(levelText, rowNumber)
		if err != nil {
			return nil, err
		}

		// ⚠ THE SEQUENCE CHECK. A level-3 row after a level-1 row has no
		// parent, and quietly reparenting it produces a structurally valid
		// BOM that is factually wrong.
		if havePrevious && level > previousLevel+1 {
			return nil, importErr(rowNumber,
				"row %d: level %d follows level %d. A sub-component cannot skip a level — the "+
					"level-%d assembly it belongs to is not in the file. Check for a missing row "+
					"or an off-by-one in the export.", rowNumber, level, previousLevel, previousLevel+1)
		}

		if level > MaxDepth {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"row %d: level %d exceeds the depth cap of %d; this component and anything below "+
					"it were not imported. The gap is recorded rather than the tree truncated silently.",
				rowNumber, level, MaxDepth))
			previousLevel = level
			havePrevious = true
			continue
		}

		component := build(values, level, rowNumber)

		if level == 0 || len(stack) == 0 {
			roots = append(roots, component)
			stack = []*Component{component}
		} else {
			parent := stack[level-1]
			component.ParentLocalID = parent.LocalID
			parent.Children = append(parent.Children, component)
			stack = append(stack[:level], component)
		}
		previousLevel = level
		havePrevious = true
	}

	for _, root := range roots {
		Normalize(root)
	}
	result.Roots = roots
	warnDuplicateParts(result)
	return result, nil
}

func allBlank(values map[string]string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// canonicalizeRow rewrites one row's keys to canonical column names.
//
// ⚠ FIRST MAPPED COLUMN WINS. `part_number` and `mpn` both map to
// `model_number`; whichever the mapping's iteration hits first (canonicalOrder,
// not this function) is irrelevant here — this only refuses to overwrite an
// already-set canonical key, matching Python's `out.setdefault`.
func canonicalizeRow(header, record []string, mapping map[string]string) map[string]string {
	out := make(map[string]string, len(header))
	for i, h := range header {
		if h == "" {
			continue
		}
		canonical, ok := mapping[h]
		if !ok || canonical == "" {
			continue
		}
		if _, exists := out[canonical]; exists {
			continue
		}
		var value string
		if i < len(record) {
			value = record[i]
		}
		out[canonical] = value
	}
	return out
}

// parseLevel reads a level, accepting both `2` and the outline form `1.2.1`.
func parseLevel(text string, rowNumber int) (int, error) {
	if text == "" {
		return 0, importErr(rowNumber, "row %d: no level. Every row needs one.", rowNumber)
	}

	if strings.Contains(text, ".") {
		var parts []string
		for _, p := range strings.Split(text, ".") {
			if strings.TrimSpace(p) != "" {
				parts = append(parts, strings.TrimSpace(p))
			}
		}
		for _, p := range parts {
			if !isDigits(p) {
				return 0, importErr(rowNumber,
					"row %d: level %q is neither a number nor an outline number such as 1.2.1.",
					rowNumber, text)
			}
		}
		return len(parts) - 1, nil
	}

	level, err := strconv.Atoi(text)
	if err != nil {
		return 0, importErr(rowNumber, "row %d: level %q is not a number.", rowNumber, text)
	}
	if level < 0 {
		return 0, importErr(rowNumber, "row %d: level %d is negative.", rowNumber, level)
	}
	return level, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// build turns one canonicalized row into a component.
func build(values map[string]string, level, rowNumber int) *Component {
	c := &Component{
		LocalID:   fmt.Sprintf("row-%d", rowNumber),
		Level:     level,
		SourceRow: rowNumber,
		Quantity:  1,
	}

	for _, canonical := range canonicalOrder {
		attribute := canonicalColumns[canonical]
		if attribute == "" || attribute == "level" || attribute == "quantity" {
			continue
		}
		value := strings.TrimSpace(values[canonical])
		if value == "" {
			continue
		}
		switch attribute {
		case "compliance":
			// RoHS, CE and friends arrive as one cell.
			c.Compliance = splitCompliance(value)
			continue
		case "designators":
			// ⚠ ONE CELL, MANY PLACEMENTS. "R1, R4, R17" is one line item with
			// quantity 3, which is how every CAD and ERP export writes it.
			c.Designators = splitCompliance(value)
			continue
		case "do_not_populate":
			c.DoNotPopulate = parseDNP(value)
			continue
		case "assembly_type":
			c.AssemblyType = parseClosedSet(value, AssemblyTypes, assemblyAliases)
			continue
		case "lifecycle_status":
			c.LifecycleStatus = parseClosedSet(value, LifecycleValues, lifecycleAliases)
			continue
		case "unit_price":
			c.UnitPrice = parsePrice(value)
			continue
		}
		// setdefault semantics: whichever canonical column reaches an
		// attribute FIRST (in canonicalOrder) wins; an empty later column
		// must not clear a populated earlier one.
		if attrValue(c, attribute) == "" {
			setAttr(c, attribute, value)
		}
	}

	if qtyText := strings.TrimSpace(values["quantity"]); qtyText != "" {
		if f, err := strconv.ParseFloat(qtyText, 64); err == nil {
			q := int(f)
			if q < 1 {
				q = 1
			}
			c.Quantity = q
		}
		// A quantity that will not parse is left at 1 and the row is not
		// rejected over one cell — matches csv_import.py's _build().
	}

	// ⚠ A COMPONENT NEEDS A NAME, AND THE PART NUMBER IS THE FALLBACK.
	if c.ProductName == "" {
		switch {
		case c.ModelNumber != "":
			c.ProductName = c.ModelNumber
		case c.ProductDetails != "":
			c.ProductName = c.ProductDetails
		default:
			c.ProductName = fmt.Sprintf("unnamed component (row %d)", rowNumber)
		}
	}

	return c
}

func splitCompliance(value string) []string {
	value = strings.ReplaceAll(value, ";", ",")
	var out []string
	for _, p := range strings.Split(value, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// warnDuplicateParts notes repeated part numbers at the same level under the
// same parent — a warning, not an error. See csv_import.py's
// _warn_on_duplicate_parts.
func warnDuplicateParts(result *ImportResult) {
	for _, root := range result.Roots {
		checkSiblings(root, result)
	}
}

func checkSiblings(c *Component, result *ImportResult) {
	seen := make(map[string]int)
	for _, child := range c.Children {
		key := strings.ToLower(strings.TrimSpace(child.ModelNumber))
		if key == "" {
			continue
		}
		if row, ok := seen[key]; ok {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"part %q appears twice under %q (rows %d and %d). If these are the same part, "+
					"one row with a quantity is more accurate than two.",
				child.ModelNumber, c.ProductName, row, child.SourceRow))
		} else {
			seen[key] = child.SourceRow
		}
		checkSiblings(child, result)
	}
}

// ---------------------------------------------------------------------------
// Manufacturing value parsing
// ---------------------------------------------------------------------------
//
// ⚠ EVERY ONE OF THESE DROPS WHAT IT CANNOT RECOGNISE, AND NONE GUESSES. Same
// rule Normalize applies to `criticality`, for the same reason: mapping an
// unrecognised value onto a plausible neighbour invents a fact about somebody's
// hardware, in a document they hand to an auditor or a contract manufacturer.
//
// Mirrors workers/hbom/csv_import.py's block of the same name.

// assemblyAliases are spellings of smt/tht seen in real exports. Data, not
// inference: each is a name the industry actually uses for that exact process.
var assemblyAliases = map[string]string{
	"smd": "smt", "surface mount": "smt", "surface-mount": "smt",
	"through hole": "tht", "through-hole": "tht", "thru-hole": "tht", "pth": "tht",
	"mech": "mechanical", "hardware": "mechanical",
}

// lifecycleAliases likewise. `nrnd` has the most spellings because it is the
// status distributors word most freely.
var lifecycleAliases = map[string]string{
	"not recommended for new designs": "nrnd", "not recommended": "nrnd", "nrfnd": "nrnd",
	"end of life": "eol", "end-of-life": "eol",
	"discontinued": "obsolete", "inactive": "obsolete",
	"in production": "active", "production": "active",
	"new": "preview", "pre-production": "preview",
}

// dnpTruthy is every spelling of "do not fit" seen in real exports.
//
// ⚠ THE COLUMN HAS NO THIRD STATE, SO AN UNRECOGNISED VALUE MEANS "fitted" —
// AND THAT IS THE SAFE DIRECTION, WHICH IS WHY IT IS ACCEPTABLE.
//
// The two errors are not symmetric. Treating a marked DNP as fitted puts one
// unwanted part on a board. Treating an unrecognised value as DNP OMITS a part
// the design needs, which is a board that does not work and a respin. So the
// list is of the affirmative spellings only, and anything else is fitted.
//
// (An earlier version carried an explicit "falsy" list too, with a comment
// claiming an unrecognised value must not silently become fitted. The list was
// never consulted — both branches returned false — so the comment described
// behaviour the code did not have.)
var dnpTruthy = map[string]bool{
	"1": true, "y": true, "yes": true, "true": true, "dnp": true,
	"dni": true, "x": true, "nofit": true, "do not populate": true,
}

func parseDNP(value string) bool {
	return dnpTruthy[strings.ToLower(strings.TrimSpace(value))]
}

// parseClosedSet maps a cell onto a closed set, or drops it.
//
// Returns "" for anything unrecognised. A dropped value scores as absent,
// which is honest; a coerced one would score as knowledge we do not have.
func parseClosedSet(value string, allowed map[string]bool, aliases map[string]string) string {
	text := strings.ToLower(strings.TrimSpace(value))
	if canonical, ok := aliases[text]; ok {
		text = canonical
	}
	if allowed[text] {
		return text
	}
	return ""
}

// parsePrice reads a unit price, keeping it a STRING.
//
// ⚠ NOT A float64. Postgres casts the bound parameter into numeric(18,6);
// routing it through a float first would lose cents on values like 0.1, and an
// extended price over a 4000-line BOM accumulates that error into a figure
// somebody procures against.
//
// Currency symbols and thousands separators are stripped because exports carry
// them; a value that still will not parse is DROPPED rather than guessed at,
// since a wrong price is worse than an absent one.
func parsePrice(value string) string {
	text := strings.TrimSpace(strings.ReplaceAll(value, ",", ""))
	text = strings.TrimSpace(strings.TrimLeft(text, "$£€₹"))
	if text == "" {
		return ""
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || f < 0 {
		return ""
	}
	// The PARSED value is discarded; the original string is what is stored.
	// Parsing is only how we decide whether it is a number at all.
	return text
}
