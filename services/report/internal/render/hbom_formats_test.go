package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func hbomBOM() BOM {
	return BOM{
		BOMType: model.BOMTypeHBOM, Level: "complete",
		ProjectName: "edge-gateway", GeneratedAt: "2026-09-03T00:00:00Z",
		ToolName: "AxeBOM", ToolVersion: "0.1.0",
		ProfileID: model.ProfileID, ProfileRevision: model.ProfileRevision,
		Hardware: costed(),
	}
}

// TestAnHBOMRendersInEveryFormat.
//
// ⚠ THE PDF AND THE JSON BUNDLE BOTH CARRIED NO HARDWARE AT ALL. The PDF had
// no hardware page (an HBOM fell through to componentPages, which renders a
// parts list through PURL/Depth/Orphan columns a capacitor has none of — a page
// of `not-provided`), and BundleCanonical had no `hardware` field, so the one
// artifact where a consumer can read the structured tree simply omitted it.
func TestAnHBOMRendersInEveryFormat(t *testing.T) {
	b := hbomBOM()

	t.Run("xlsx", func(t *testing.T) {
		sheets, err := Sheets(b)
		if err != nil {
			t.Fatalf("sheets: %v", err)
		}
		var buf bytes.Buffer
		if _, err := WriteXLSX(&buf, sheets); err != nil {
			t.Fatalf("xlsx: %v", err)
		}
		if buf.Len() == 0 {
			t.Fatal("empty workbook")
		}
	})

	t.Run("pdf", func(t *testing.T) {
		var buf bytes.Buffer
		res, err := WritePDF(&buf, b, PDFOptions{})
		if err != nil {
			t.Fatalf("pdf: %v", err)
		}
		if buf.Len() == 0 {
			t.Fatal("empty PDF")
		}
		if res.Truncated {
			t.Error("a four-part BOM was truncated")
		}
	})

	t.Run("json bundle carries the structured tree", func(t *testing.T) {
		raw, err := WriteJSON(b, nil, nil)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		var bundle struct {
			Canonical struct {
				Hardware []struct {
					Name        string   `json:"Name"`
					Quantity    int      `json:"Quantity"`
					Designators []string `json:"Designators"`
				} `json:"hardware"`
			} `json:"canonical"`
			Notes []string `json:"notes"`
		}
		if err := json.Unmarshal(raw, &bundle); err != nil {
			t.Fatalf("bundle: %v", err)
		}
		if len(bundle.Canonical.Hardware) != 4 {
			t.Fatalf("bundle carries %d hardware rows, want 4",
				len(bundle.Canonical.Hardware))
		}
		// ⚠ STRUCTURED, NOT STRINGIFIED. SPDX and CycloneDX carry these as
		// namespaced properties because neither has a field for a designator;
		// this is the artifact where the numbers are still numbers.
		for _, h := range bundle.Canonical.Hardware {
			if h.Name == "resistor" {
				if h.Quantity != 3 || len(h.Designators) != 3 {
					t.Errorf("resistor = qty %d, %d designators; want 3 and 3",
						h.Quantity, len(h.Designators))
				}
			}
		}
		// The provenance note must reach the bundle too — it is the caveat the
		// whole document hangs on.
		if !strings.Contains(strings.Join(bundle.Notes, " "), "did not examine any hardware") {
			t.Errorf("the bundle carries no provenance note: %v", bundle.Notes)
		}
	})
}

// TestAHugePartsListIsRefusedRatherThanRenderedAsEightPages.
//
// `estimatePages` summed components, findings, licences and crypto assets and
// NOT hardware — so a 4000-line parts list estimated as an eight-page document
// and the early refusal never fired for the one BOM type whose entire row count
// lives in that field.
func TestAHugePartsListIsRefusedRatherThanRenderedAsEightPages(t *testing.T) {
	small := estimatePages(BOM{Hardware: make([]HardwareComponent, 40)})
	large := estimatePages(BOM{Hardware: make([]HardwareComponent, 40_000)})

	if large <= small {
		t.Fatalf("a 40,000-part BOM estimates %d pages and a 40-part one %d; "+
			"hardware is not counted", large, small)
	}
}

// TestEveryBOMTypesHonestyLabelReachesEveryFormat.
//
// ⚠ THE LABELS USED TO REACH THE XLSX AND NOTHING ELSE.
//
// They were appended inside Sheets() to a local copy of the notes, so
// WriteJSON and the DOCX renderer — both of which read BOM.Notes — never saw
// them. A caveat present in one downloadable artifact and absent from another
// is worse than one absent everywhere: the reader holding the JSON has no way
// to know a caveat exists, and the product reads as having made an unqualified
// claim.
func TestEveryBOMTypesHonestyLabelReachesEveryFormat(t *testing.T) {
	tests := []struct {
		bomType model.BOMType
		bom     BOM
		phrase  string
	}{
		{model.BOMTypeCBOM, BOM{BOMType: model.BOMTypeCBOM}, "asset type"},
		{model.BOMTypeQBOM, BOM{BOMType: model.BOMTypeQBOM}, "quantum"},
		{model.BOMTypeAIBOM, BOM{BOMType: model.BOMTypeAIBOM}, "AxeBOM"},
		{model.BOMTypeHBOM, BOM{BOMType: model.BOMTypeHBOM, Hardware: costed()},
			"did not examine any hardware"},
	}

	for _, tt := range tests {
		t.Run(string(tt.bomType), func(t *testing.T) {
			notes := strings.Join(TypeNotes(tt.bom), " ")
			if !strings.Contains(notes, tt.phrase) {
				t.Fatalf("TypeNotes carries no %q label: %q", tt.phrase, notes)
			}

			raw, err := WriteJSON(tt.bom, nil, nil)
			if err != nil {
				t.Fatalf("json: %v", err)
			}
			var bundle struct {
				Notes []string `json:"notes"`
			}
			if err := json.Unmarshal(raw, &bundle); err != nil {
				t.Fatalf("bundle: %v", err)
			}
			if !strings.Contains(strings.Join(bundle.Notes, " "), tt.phrase) {
				t.Errorf("the JSON bundle carries no %q label: %v", tt.phrase, bundle.Notes)
			}
		})
	}

	// An SBOM has no type-specific caveat, and must not acquire an invented one.
	if notes := TypeNotes(BOM{BOMType: model.BOMTypeSBOM}); len(notes) != 0 {
		t.Errorf("an SBOM gained a caveat it does not have: %v", notes)
	}
}
