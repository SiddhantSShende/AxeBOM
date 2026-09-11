package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func derivedSample() BOM {
	b := cbomSample()
	b.CryptoAssets[0].Derivations = map[string]string{"classical_security_level": "nist-sp800-57p1r5-table2"}
	b.Coverage.DerivationSources = map[string]string{
		"nist-sp800-57p1r5-table2": "NIST SP 800-57 Part 1 Rev. 5, Table 2",
	}
	b.Coverage.Fields = append(b.Coverage.Fields, FieldCoverage{
		FieldID: model.FieldCertinCryptoAlgoSecurityLevel, Present: 1, Derived: 1, Declared: 1, Total: 1,
	})
	return b
}

func headerIndex(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("no %q column in %v", name, header)
	return -1
}

func TestTheDerivedFieldNoteNamesEveryColumnAndSource(t *testing.T) {
	note := DerivedFieldNote(derivedSample())
	for _, want := range []string{
		"1 field value(s)",
		"classical_security_level ×1",
		"nist-sp800-57p1r5-table2 — NIST SP 800-57 Part 1 Rev. 5, Table 2",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("the note %q does not contain %q", note, want)
		}
	}
	if got := DerivedFieldNote(cbomSample()); got != "" {
		t.Errorf("a BOM with nothing derived carries a derived-value note: %q", got)
	}
}

func TestTheDerivedNoteRidesInTypeNotes(t *testing.T) {
	if !strings.Contains(strings.Join(TypeNotes(derivedSample()), "\n"), "nist-sp800-57p1r5-table2") {
		t.Error("TypeNotes does not carry the derived-value footnote, so no format would")
	}
	if strings.Contains(strings.Join(TypeNotes(cbomSample()), "\n"), "were derived from") {
		t.Error("TypeNotes carries a derived-value footnote for a BOM with nothing derived")
	}
}

// TestTheCoverageSheetCountsDerivedAsASubsetOfSubstantive.
func TestTheCoverageSheetCountsDerivedAsASubsetOfSubstantive(t *testing.T) {
	sheet := findSheet(t, CBOMSheets(derivedSample()), "Crypto Field Coverage")
	derivedCol := headerIndex(t, sheet.Header, "Of which derived (AxeBOM, cited)")
	substantiveCol := headerIndex(t, sheet.Header, "Substantive")

	found := false
	for _, row := range rowsOf(t, sheet) {
		if row[1] != model.FieldCertinCryptoAlgoSecurityLevel {
			continue
		}
		found = true
		if row[derivedCol] != "1" || row[substantiveCol] != "1" {
			t.Errorf("derived/substantive = %s/%s, want 1/1", row[derivedCol], row[substantiveCol])
		}
	}
	if !found {
		t.Fatal("the security-level field has no coverage row")
	}
	if !strings.Contains(flatten(rowsOf(t, sheet)), "nist-sp800-57p1r5-table2") {
		t.Error("the coverage sheet carries no footnote for the value it counts as derived")
	}
}

func TestEachInventorySheetNamesItsDerivedColumns(t *testing.T) {
	sheet := findSheet(t, CBOMSheets(derivedSample()), "Crypto - Algorithms")
	col := headerIndex(t, sheet.Header, "Derived From Reference (AxeBOM, cited)")
	row := rowsOf(t, sheet)[0]
	if !strings.Contains(row[col], "classical_security_level (nist-sp800-57p1r5-table2)") {
		t.Errorf("the derived column reads %q", row[col])
	}
}

// TestTheJSONBundleUsesTheColumnNamesForCryptoAssets — the API and the bundle
// had two vocabularies for one table.
func TestTheJSONBundleUsesTheColumnNamesForCryptoAssets(t *testing.T) {
	raw, err := WriteJSON(derivedSample(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if generic["schema"] != BundleSchema {
		t.Errorf("schema = %v", generic["schema"])
	}
	assets := generic["canonical"].(map[string]any)["crypto_assets"].([]any)
	first := assets[0].(map[string]any)
	for _, key := range []string{"asset_type", "name", "quantum_vulnerable", "derivations"} {
		if _, ok := first[key]; !ok {
			t.Errorf("crypto asset JSON has no %q key: %v", key, first)
		}
	}
	for _, key := range []string{"AssetType", "Name"} {
		if _, ok := first[key]; ok {
			t.Errorf("crypto asset JSON still carries the Go field name %q", key)
		}
	}
}
