// Package safe escapes values before they reach a spreadsheet cell.
//
// ⚠ THIS IS A REPEATEDLY-SHIPPED VULNERABILITY CLASS, AND THIS PRODUCT'S ENTIRE
// OUTPUT SURFACE IS SPREADSHEETS.
//
// A component named
//
//	=cmd|'/c calc'!A1
//
// EXECUTES when the XLSX is opened. Excel treats a leading `=` as a formula,
// and the DDE syntax above launches a process. The attacker does not need to
// reach our servers: they publish a package with a hostile name, a customer
// scans a project that depends on it, and the payload travels inside a
// compliance report the customer trusts enough to open.
//
// The same applies to CSV, and to anything else a spreadsheet will parse.
//
// ⚠ THE ESCAPING BELONGS IN THE WRITER, APPLIED UNCONDITIONALLY.
//
// Not at each call site. A call site will eventually be added without it — that
// is not pessimism, it is what happens to every "remember to sanitize" rule in
// a codebase with more than one author. The writer is the one place every value
// must pass through, so it is the only place the guarantee can be made.
//
// See CLAUDE.md invariant 8 and docs/03-NORMALIZER-SPEC.md §8.
package safe

import "strings"

// dangerous is the set of leading characters a spreadsheet may treat as the
// start of a formula.
//
// `=` and `+` are the obvious ones. `-` is included because `-1+1` parses as a
// formula, and `@` because it introduces a function name in older Excel
// versions and in LibreOffice. TAB and CR are included because they can shift
// the parse to a following cell, which puts a `=` at the start of one.
const dangerous = "=+-@\t\r"

// prefix is prepended to a dangerous value.
//
// A single quote is the spreadsheet convention for "treat the rest as text". It
// is not displayed to the user when the file is opened, so the escaping is
// invisible in normal use — which matters, because an escaping that visibly
// corrupts every value gets removed by the next person who reads a report.
const prefix = "'"

// Cell makes a value safe to write into a spreadsheet cell.
//
// ⚠ CALL THIS ON EVERY VALUE, INCLUDING ONES THAT LOOK SAFE.
//
// "It's just a version number" is how this gets missed: the version comes from
// a manifest inside an attacker-controlled repository, exactly like the name.
// Every string in a BOM is attacker-influenced, so there is no category of
// value that can skip this.
func Cell(value string) string {
	if value == "" {
		return value
	}
	if strings.ContainsRune(dangerous, rune(value[0])) {
		return prefix + value
	}
	return value
}

// Cells escapes a whole row.
func Cells(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = Cell(value)
	}
	return out
}

// IsDangerous reports whether a value would be escaped.
//
// Exposed for tests and for a diagnostic that tells an operator a hostile name
// was found — the escaping is silent by design, and a security team wants to
// know that something in their dependency tree was shaped like an attack.
func IsDangerous(value string) bool {
	if value == "" {
		return false
	}
	return strings.ContainsRune(dangerous, rune(value[0]))
}
