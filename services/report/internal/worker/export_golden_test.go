package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/axebom/axebom/services/report/internal/export"
	"github.com/axebom/axebom/services/report/internal/render"
)

// Golden documents for the three BOM types that had no export path at all.
//
// ⚠ services/report/internal/export's OWN GOLDEN COVERS A SOFTWARE BOM ONLY.
// Its fixture() is a set of npm/pypi components, so it could never have noticed
// that a CBOM, AIBOM or QBOM serialized to an empty document — the mapping for
// those lives here, in toExportDocument, not in that package.
//
// These exist for two reasons, and the second is the one that matters:
//
//  1. a diff notices a silent mapping change, the same guardrail export's
//     golden provides for software; and
//  2. tools/conformance validates every document in this directory against the
//     OFFICIAL SPDX and CycloneDX schemas. Until now it validated two files,
//     both software. A CBOM export that parses in Go and is rejected by
//     spdx-tools is not an export.
//
// Regenerate DELIBERATELY, with a justification in the commit message:
//
//	AXEBOM_WRITE_GOLDEN=1 go test ./services/report/internal/worker/ -run TestSpecializedExportGolden
const goldenDir = "../../testdata/golden"

func TestSpecializedExportGolden(t *testing.T) {
	writing := os.Getenv("AXEBOM_WRITE_GOLDEN") != ""

	cases := []struct {
		name string
		bom  render.BOM
	}{
		{"cbom", matrixCBOM()},
		{"aibom", matrixAIBOM()},
		{"qbom", matrixQBOM()},
	}
	formats := map[string]export.Format{
		".spdx.json": export.SPDX23JSON,
		".cdx.json":  export.CycloneDX16JSON,
	}

	for _, c := range cases {
		for suffix, format := range formats {
			name := "fixture-" + c.name + suffix
			t.Run(name, func(t *testing.T) {
				got, err := export.Serialize(toExportDocument(c.bom), format)
				if err != nil {
					t.Fatalf("serialize: %v", err)
				}

				// ⚠ THE ASSERTION THAT WOULD HAVE CAUGHT THE ORIGINAL BUG.
				// An empty document is structurally valid and byte-stable, so a
				// golden diff alone would have happily frozen "says nothing"
				// as the expected answer.
				var doc map[string]any
				if err := json.Unmarshal(got, &doc); err != nil {
					t.Fatalf("not valid JSON: %v", err)
				}
				if n := inventoryCount(doc); n == 0 {
					t.Fatalf("%s carries no components at all; it validates and "+
						"asserts the project contains nothing", name)
				}

				path := filepath.Join(goldenDir, name)
				if writing {
					if err := os.WriteFile(path, got, 0o644); err != nil {
						t.Fatal(err)
					}
					t.Logf("wrote %s", path)
					return
				}

				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("reading the golden: %v", err)
				}
				if string(got) != string(want) {
					t.Errorf("%s differs from its golden. If the mapping change "+
						"was intended, regenerate with AXEBOM_WRITE_GOLDEN=1 and "+
						"justify it in the commit message.", name)
				}
			})
		}
	}
}

// TestMLBOMGolden pins the AIBOM's ML-BOM export.
//
// ⚠ IT LANDS IN THE SAME DIRECTORY DELIBERATELY. `tools/conformance` GLOBS
// `*.cdx.json` and validates every match against the OFFICIAL CycloneDX 1.6
// schema — so the ML-BOM is checked by CycloneDX's own validator rather than by
// our opinion of it, without anybody having to remember to add it to a list.
//
// ⚠ AND THE CONTENT ASSERTION IS NOT OPTIONAL HERE. `modelCard` is optional in
// CycloneDX 1.5, 1.6 and 1.7, so a document with zero ML content validates
// perfectly — schema conformance is not evidence of content, and a golden diff
// alone would happily freeze an empty card as the expected answer.
//
// Regenerate DELIBERATELY:
//
//	AXEBOM_WRITE_GOLDEN=1 go test ./services/report/internal/worker/ -run TestMLBOMGolden
func TestMLBOMGolden(t *testing.T) {
	writing := os.Getenv("AXEBOM_WRITE_GOLDEN") != ""
	const name = "fixture-aibom.mlbom.cdx.json"

	got, err := export.SerializeMLBOM(toMLDocument(matrixAIBOM()))
	if err != nil {
		t.Fatalf("serialize ML-BOM: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	assertCarriesAModelCard(t, doc)

	path := filepath.Join(goldenDir, name)
	if writing {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the golden: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from its golden. If the mapping change was "+
			"intended, regenerate with AXEBOM_WRITE_GOLDEN=1 and justify it in "+
			"the commit message.", name)
	}
}

// assertCarriesAModelCard is the check a schema validator cannot make.
func assertCarriesAModelCard(t *testing.T, doc map[string]any) {
	t.Helper()
	components, _ := doc["components"].([]any)
	for _, c := range components {
		m, _ := c.(map[string]any)
		if m["type"] != "machine-learning-model" {
			continue
		}
		card, ok := m["modelCard"].(map[string]any)
		if !ok {
			t.Fatal("the ML-BOM's model carries no modelCard — the one thing " +
				"this format exists for, and the one thing the schema does not " +
				"require")
		}
		if card["modelParameters"] == nil {
			t.Error("the modelCard carries no modelParameters")
		}
		return
	}
	t.Fatal("the ML-BOM has no machine-learning-model component at all")
}

// inventoryCount counts the entries whichever standard this document is.
func inventoryCount(doc map[string]any) int {
	if c, ok := doc["components"].([]any); ok {
		return len(c)
	}
	if p, ok := doc["packages"].([]any); ok {
		return len(p)
	}
	return 0
}
