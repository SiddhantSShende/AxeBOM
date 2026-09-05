package store

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/report/internal/render"
)

// TestATopLevelQBOMStatesWhyItDidNotNarrowItsCryptoAssets.
//
// ⚠ A GATE THAT WAS CORRECT WHEN WRITTEN AND WAS OUTLIVED BY THE DATA.
// flatInventoryLevelNote explained why a Top-Level report lists every Table 9
// asset — they have no depth to narrow by — but only `case ... &&
// out.BOMType == model.BOMTypeCBOM`, because a CBOM was then the only report
// that carried any. Making a QBOM's crypto assets reachable (they are resolved
// from the companion CBOM document, and they ARE its readiness half) gave a
// second report type those assets without giving it the explanation: a
// Top-Level QBOM matched no case and produced an EMPTY level note.
//
// That is the precise failure the level work exists to prevent — a document
// labelled "Top-Level" that renders a complete inventory and says nothing about
// the discrepancy.
func TestATopLevelQBOMStatesWhyItDidNotNarrowItsCryptoAssets(t *testing.T) {
	depth := 1
	for _, bomType := range []model.BOMType{model.BOMTypeCBOM, model.BOMTypeQBOM} {
		t.Run(string(bomType), func(t *testing.T) {
			out := render.BOM{
				Level:      "top_level",
				BOMType:    bomType,
				Components: []render.Component{{Key: "direct", Depth: &depth, IsDirect: true}},
				CryptoAssets: []render.CryptoAsset{
					{Name: "aes", AssetType: "algorithm", ComponentKey: "direct"},
					{Name: "wire-tls", AssetType: "protocol"},
				},
			}
			applyLevel(&out)

			// Nothing is dropped — that is the documented decision, and this
			// test guards it as much as it guards the note.
			if len(out.CryptoAssets) != 2 {
				t.Fatalf("the level dropped %d asset(s); Table 9 assets have no "+
					"depth, so narrowing them applies a rule this product invented",
					2-len(out.CryptoAssets))
			}
			if !strings.Contains(out.LevelNote, "All 2 cryptographic asset(s) are listed") {
				t.Errorf("a Top-Level %s renders every asset and does not say why: %q",
					bomType, out.LevelNote)
			}
		})
	}
}

// A Complete report claims no level caveat it did not need.
func TestACompleteQBOMClaimsNoLevelCaveat(t *testing.T) {
	out := render.BOM{
		Level:        "complete",
		BOMType:      model.BOMTypeQBOM,
		CryptoAssets: []render.CryptoAsset{{Name: "aes", AssetType: "algorithm"}},
	}
	applyLevel(&out)

	if strings.Contains(out.LevelNote, "cryptographic asset(s) are listed") {
		t.Errorf("a Complete BOM explains an omission that cannot arise: %q", out.LevelNote)
	}
}
