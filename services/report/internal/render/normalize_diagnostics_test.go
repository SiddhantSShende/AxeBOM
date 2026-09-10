package render

import (
	"encoding/json"
	"strings"
	"testing"
)

// ⚠ THIS IS THE TEST THAT MAKES migration 0017 WORTH HAVING.
//
// Every normalize consumer (aibom, cbom, hbom) has always built
// `canonical["diagnostics"]`, and nothing persisted or rendered it — so the
// statements the normalizer made about what it could NOT resolve existed only
// inside a Python process that had already exited.
//
// The concrete loss on real captured `ai-bom` output: two components the engine
// called models are recorded as dependencies instead, and neither the model list
// nor the dependency list ends up naming them. Without these lines the customer
// sees a model count of one, a dependency count of zero, and nothing at all
// saying that three components went in. CLAUDE.md invariant 12.
func diagnosticFixture() BOM {
	return BOM{
		ReportID: "r-1",
		BOMType:  "AIBOM",
		NormalizeDiagnostics: []NormalizeDiagnostic{
			{
				Severity: "info",
				Code:     "AIBOM_MODEL_RECLASSIFIED",
				Message: "transformers was reported as a model but carries a pypi package " +
					"identifier (pkg:pypi/transformers) and no model reference, so it is " +
					"recorded as an AI dependency rather than an AI model.",
			},
			{
				Severity: "warn",
				Code:     "AIBOM_DEPENDENCY_NOT_IN_SBOM",
				Message:  "2 dependencies not catalogued in the SBOM",
			},
		},
	}
}

func TestNormalizeDiagnosticsReachTheNotesSheet(t *testing.T) {
	sheet := notesSheet(diagnosticFixture())

	rows, err := collectRows(sheet.Rows)
	if err != nil {
		t.Fatalf("collect rows: %v", err)
	}

	var joined strings.Builder
	for _, r := range rows {
		joined.WriteString(strings.Join(r, " | "))
		joined.WriteString("\n")
	}
	got := joined.String()

	for _, want := range []string{
		"AIBOM_MODEL_RECLASSIFIED",
		"pkg:pypi/transformers",
		"AIBOM_DEPENDENCY_NOT_IN_SBOM",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Notes sheet does not mention %q.\nA reclassification the customer\n"+
				"cannot see is a silent edit of their inventory.\ngot:\n%s", want, got)
		}
	}
}

func TestASeriousNormalizeDiagnosticIsLabelledAsOne(t *testing.T) {
	sheet := notesSheet(diagnosticFixture())

	rows, err := collectRows(sheet.Rows)
	if err != nil {
		t.Fatalf("collect rows: %v", err)
	}

	var sawWarn bool
	for _, r := range rows {
		if len(r) > 0 && r[0] == "Normalization (warn)" {
			sawWarn = true
		}
	}
	if !sawWarn {
		t.Error("a warn-severity diagnostic rendered under the same topic as an info one — " +
			"severity is the reader's only cue about which lines to act on")
	}
}

func TestTheJSONBundleCarriesNormalizeDiagnosticsStructured(t *testing.T) {
	raw, err := WriteJSON(diagnosticFixture(), nil, nil)
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var bundle struct {
		NormalizeDiagnostics []struct {
			Severity string `json:"severity"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		} `json:"normalize_diagnostics"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}

	if len(bundle.NormalizeDiagnostics) != 2 {
		t.Fatalf("want 2 diagnostics in the bundle, got %d", len(bundle.NormalizeDiagnostics))
	}
	// Structured, not folded into prose: a machine consumer must be able to act
	// on the code without parsing a sentence.
	if bundle.NormalizeDiagnostics[0].Code != "AIBOM_MODEL_RECLASSIFIED" {
		t.Errorf("first diagnostic code = %q", bundle.NormalizeDiagnostics[0].Code)
	}
}

// collectRows drains a RowSource for assertions. Sheets stream by design
// (RowSource is a push iterator so a Complete BOM never materializes twice);
// a Notes sheet is small enough to gather.
func collectRows(src RowSource) ([][]string, error) {
	var out [][]string
	err := src(func(row []string) error {
		cp := make([]string, len(row))
		copy(cp, row)
		out = append(out, cp)
		return nil
	})
	return out, err
}

// ⚠ THE TEST THAT STOPS THIS BECOMING A FOUR-COPY PROBLEM.
//
// TypeNotes exists because a type-specific caveat once reached the XLSX, the JSON
// and the Word document and was absent from the PDF — the artifact most likely to
// be forwarded to somebody who reads only that. Normalize diagnostics say why a
// customer's model count changed; a reader of a single format must not be the one
// person who does not get that sentence.
func TestEveryFormatCarriesTheNormalizeDiagnostics(t *testing.T) {
	b := diagnosticFixture()

	t.Run("xlsx notes sheet", func(t *testing.T) {
		rows, err := collectRows(notesSheet(b).Rows)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if !rowsMention(rows, "AIBOM_MODEL_RECLASSIFIED") {
			t.Error("absent from the XLSX Notes sheet")
		}
	})

	t.Run("prose renderers share one helper", func(t *testing.T) {
		lines := NormalizeDiagnosticLines(b)
		if len(lines) != 2 {
			t.Fatalf("want 2 lines, got %d", len(lines))
		}
		if !strings.Contains(strings.Join(lines, "\n"), "AIBOM_MODEL_RECLASSIFIED") {
			t.Error("the shared helper drops the code")
		}
		// Severity is visible in prose, where there is no Topic column to carry it.
		if !strings.Contains(strings.Join(lines, "\n"), "WARN") {
			t.Error("a warn-severity line is indistinguishable from an info one in prose")
		}
	})

	t.Run("json bundle", func(t *testing.T) {
		raw, err := WriteJSON(b, nil, nil)
		if err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}
		if !strings.Contains(string(raw), "AIBOM_MODEL_RECLASSIFIED") {
			t.Error("absent from the JSON bundle")
		}
	})
}

func rowsMention(rows [][]string, want string) bool {
	for _, r := range rows {
		for _, c := range r {
			if strings.Contains(c, want) {
				return true
			}
		}
	}
	return false
}
