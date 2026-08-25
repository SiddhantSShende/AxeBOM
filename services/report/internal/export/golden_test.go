package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenDir holds the committed SPDX and CycloneDX documents.
//
// ⚠ THESE ARE THE GUARDRAIL AGAINST A SILENT MAPPING CHANGE.
//
// A wrong mapping does not crash: it produces a document that validates
// cleanly and says something false — a licence in the wrong field, the CERT-In
// identifier where a PURL belongs, a component that quietly vanished. The diff
// is the only thing that notices.
//
// Regenerate DELIBERATELY, with a justification in the commit message:
//
//	AXEBOM_WRITE_GOLDEN=1 go test ./services/report/internal/export/ -run TestGolden
const goldenDir = "../../testdata/golden"

var goldenFiles = map[string]Format{
	"fixture.spdx.json": SPDX23JSON,
	"fixture.cdx.json":  CycloneDX16JSON,
}

func TestGolden(t *testing.T) {
	writing := os.Getenv("AXEBOM_WRITE_GOLDEN") != ""

	for name, format := range goldenFiles {
		t.Run(name, func(t *testing.T) {
			got, err := Serialize(fixture(), format)
			if err != nil {
				t.Fatal(err)
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

			if string(got) == string(want) {
				return
			}

			// Report WHAT changed rather than dumping two documents. A diff a
			// reviewer cannot read is a diff they will approve without reading.
			var gotDoc, wantDoc map[string]any
			_ = json.Unmarshal(got, &gotDoc)
			_ = json.Unmarshal(want, &wantDoc)

			for _, key := range sortedKeys(gotDoc, wantDoc) {
				g, _ := json.Marshal(gotDoc[key])
				w, _ := json.Marshal(wantDoc[key])
				if string(g) != string(w) {
					t.Errorf("%s: %q changed\n  want: %s\n  got:  %s",
						name, key, truncate(string(w)), truncate(string(g)))
				}
			}
			t.Errorf("%s differs from its golden. If this is intended, "+
				"regenerate with AXEBOM_WRITE_GOLDEN=1 and justify it in the "+
				"commit message", name)
		})
	}
}

// TestGoldensAreValidDocuments asserts the committed files are still the
// formats they claim to be — a golden regenerated from a broken mapping would
// otherwise lock the breakage in.
func TestGoldensAreValidDocuments(t *testing.T) {
	spdx := readGolden(t, "fixture.spdx.json")
	if spdx["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion is %v", spdx["spdxVersion"])
	}
	if spdx["dataLicense"] != "CC0-1.0" {
		t.Errorf("dataLicense is %v", spdx["dataLicense"])
	}
	if _, ok := spdx["packages"].([]any); !ok {
		t.Error("SPDX document has no packages array")
	}

	cdx := readGolden(t, "fixture.cdx.json")
	if cdx["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat is %v", cdx["bomFormat"])
	}
	if cdx["specVersion"] != "1.6" {
		t.Errorf("specVersion is %v", cdx["specVersion"])
	}
}

func readGolden(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", name, err)
	}
	return doc
}

func sortedKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// Deterministic report order.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func truncate(s string) string {
	if len(s) <= 300 {
		return s
	}
	return s[:300] + "…"
}
