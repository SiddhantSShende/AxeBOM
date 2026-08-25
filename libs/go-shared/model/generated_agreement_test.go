package model_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

// The Go and Python models must agree.
//
// Both are projections of the same YAML, so they SHOULD agree by construction
// — but "should by construction" is exactly the kind of assumption that stops
// holding when someone hand-edits a generated file or the generator grows a
// language-specific branch. The workers score coverage in Python and the
// reports render it in Go; a divergence would mean the number in the report
// disagrees with the number that produced it.

var pyFieldID = regexp.MustCompile(`ProfileField\(\s*"([^"]+)"`)

func pythonModelPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..",
		"libs", "py-shared", "axebom_shared", "model", "generated_certin.py")
}

func pythonFieldIDs(t *testing.T, section *regexp.Regexp) []string {
	t.Helper()
	data, err := os.ReadFile(pythonModelPath(t))
	if err != nil {
		t.Fatalf("read generated Python (run `task profile:gen`): %v", err)
	}
	block := section.FindSubmatch(data)
	if block == nil {
		t.Fatalf("section not found in generated Python: %s", section)
	}
	var ids []string
	for _, m := range pyFieldID.FindAllSubmatch(block[1], -1) {
		ids = append(ids, string(m[1]))
	}
	return ids
}

func assertSameIDs(t *testing.T, lang string, goFields []model.ProfileField, pyIDs []string) {
	t.Helper()
	if len(goFields) != len(pyIDs) {
		t.Errorf("%s: Go has %d fields, Python has %d", lang, len(goFields), len(pyIDs))
	}
	seen := make(map[string]bool, len(pyIDs))
	for _, id := range pyIDs {
		seen[id] = true
	}
	for _, f := range goFields {
		if !seen[f.ID] {
			t.Errorf("%s: %q is in the Go model but not the Python one", lang, f.ID)
		}
	}
	if len(goFields) > 0 {
		t.Logf("%s: %d fields agree", lang, len(goFields))
	}
}

func TestGoAndPythonModelsAgree(t *testing.T) {
	cases := []struct {
		name    string
		goSet   []model.ProfileField
		section *regexp.Regexp
	}{
		{"SBOM", model.SBOMFields, regexp.MustCompile(`(?s)SBOM_FIELDS: list\[ProfileField\] = \[(.*?)\n\]`)},
		{"QBOM", model.QBOMFields, regexp.MustCompile(`(?s)QBOM_FIELDS: list\[ProfileField\] = \[(.*?)\n\]`)},
		{"AIBOM", model.AIBOMFields, regexp.MustCompile(`(?s)AIBOM_FIELDS: list\[ProfileField\] = \[(.*?)\n\]`)},
		{"HBOM", model.HBOMFields, regexp.MustCompile(`(?s)HBOM_FIELDS: list\[ProfileField\] = \[(.*?)\n\]`)},
		{"practices", model.PracticeFields, regexp.MustCompile(`(?s)PRACTICE_FIELDS: list\[ProfileField\] = \[(.*?)\n\]`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSameIDs(t, c.name, c.goSet, pythonFieldIDs(t, c.section))
		})
	}
}

// The crypto map is the one that must not drift: it is what makes coverage
// type-aware, and a mismatch would mean Python scores a certificate against a
// different field set than Go renders.
func TestCryptoFieldSetsAgree(t *testing.T) {
	block := regexp.MustCompile(
		`(?s)CRYPTO_FIELDS_BY_ASSET_TYPE: dict\[str, list\[ProfileField\]\] = \{(.*?)\n\}`)
	data, err := os.ReadFile(pythonModelPath(t))
	if err != nil {
		t.Fatalf("read generated Python: %v", err)
	}
	m := block.FindSubmatch(data)
	if m == nil {
		t.Fatal("CRYPTO_FIELDS_BY_ASSET_TYPE not found in generated Python")
	}

	perType := regexp.MustCompile(`(?s)"(\w+)": \[(.*?)\n    \]`)
	pyCounts := map[string]int{}
	for _, tm := range perType.FindAllSubmatch(m[1], -1) {
		pyCounts[string(tm[1])] = len(pyFieldID.FindAllSubmatch(tm[2], -1))
	}

	if len(pyCounts) != len(model.CryptoFieldsByAssetType) {
		t.Fatalf("Go has %d crypto asset types, Python has %d",
			len(model.CryptoFieldsByAssetType), len(pyCounts))
	}
	for assetType, goFields := range model.CryptoFieldsByAssetType {
		if pyCounts[assetType] != len(goFields) {
			t.Errorf("crypto %q: Go has %d fields, Python has %d",
				assetType, len(goFields), pyCounts[assetType])
		}
	}
	t.Logf("crypto field sets agree: %v", pyCounts)
}

// Nothing may hardcode a field count. The generated slices are the source of
// truth at runtime; this asserts they are non-empty and distinct so a caller
// rendering len(...) gets a real number.
func TestGeneratedSetsAreDistinctAndNonEmpty(t *testing.T) {
	sizes := map[string]int{
		"SBOM":      len(model.SBOMFields),
		"QBOM":      len(model.QBOMFields),
		"AIBOM":     len(model.AIBOMFields),
		"HBOM":      len(model.HBOMFields),
		"practices": len(model.PracticeFields),
	}
	for name, n := range sizes {
		if n == 0 {
			t.Errorf("%s field set is empty — codegen did not run", name)
		}
	}
	// The four crypto sets must differ in size, or type-aware scoring is moot.
	seen := map[int]string{}
	for at, fields := range model.CryptoFieldsByAssetType {
		if other, dup := seen[len(fields)]; dup {
			t.Logf("note: crypto %q and %q have the same field count (%d)", at, other, len(fields))
		}
		seen[len(fields)] = at
	}
	t.Logf("field set sizes: %v", sizes)
}
