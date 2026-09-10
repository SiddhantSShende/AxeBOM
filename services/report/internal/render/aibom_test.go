package render

import (
	"slices"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
)

func aibomSample(models []AIModel) BOM {
	return BOM{
		ReportID: "0199-aibom", ProjectName: "acme-ml", BOMType: model.BOMTypeAIBOM,
		GeneratedAt: "2026-08-25T09:14:03Z", ToolName: "AxeBOM", ToolVersion: "0.1.0",
		Coverage: Coverage{
			CompletenessPct: 40, DeclarationPct: 60,
			Formula: "sum(weight × substantive) / sum(weight × entities)",
		},
		AIModels: models,
	}
}

func aiModelSample() []AIModel {
	risk := 7.5
	return []AIModel{
		{
			Name: "Llama-3-8B",
			Fields: map[string]string{
				model.FieldCertinAibom01ModelName:      "Llama-3-8B",
				model.FieldCertinAibom04ModelDeveloper: "Meta",
				model.FieldCertinAibom05Licensing:      "llama3",
			},
			Datasets:      []AIDataset{{Name: "the-pile", Format: "text", License: "MIT"}},
			Dependencies:  []string{"purl:pkg:pypi/langchain@0.3.7"},
			RiskScore:     &risk,
			OwaspLLMTop10: []string{"LLM01", "LLM06"},
		},
	}
}

// TestAIBOMReplacesTheGenericComponentSheet — an AI model has no PURL,
// dependency depth or ecosystem; the generic Components sheet must not
// appear next to it, the same rule CBOM's and QBOM's own tests assert for
// their types.
func TestAIBOMReplacesTheGenericComponentSheet(t *testing.T) {
	sheets, err := Sheets(aibomSample(aiModelSample()))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	names := map[string]bool{}
	for _, s := range sheets {
		names[s.Name] = true
	}
	if names["Components"] {
		t.Error("an AIBOM report carries the generic Components sheet, which does " +
			"not fit an AI model's identity (no PURL, depth or ecosystem)")
	}
	if !names["Field Coverage"] {
		t.Error("an AIBOM report is missing the generic Field Coverage sheet — " +
			"Table 10 IS one flat field list, unlike CBOM")
	}
	// ⚠ "AI Assets" IS LISTED EVEN THOUGH THIS FIXTURE HAS NONE. A reader who
	// sees no sheet cannot tell "this repository has no prompts" from "this
	// product does not look for prompts"; the sheet with a header and no rows
	// says the first.
	for _, want := range []string{
		"AI Models", "AI Model Datasets", "AI Model Dependencies", "AI Assets",
	} {
		if !names[want] {
			t.Errorf("an AIBOM report is missing its dedicated sheet %q: %v", want, names)
		}
	}
}

// TestAIModelInventorySheetRendersEveryProfileFieldPlusTheNonProfileColumns.
//
// ⚠ THE COUNT IS DERIVED FROM THE PROFILE, NEVER WRITTEN DOWN (invariant 2).
// The four non-profile columns are named here rather than counted, so adding a
// fifth is a deliberate edit to this list and not an arithmetic change nobody
// reads.
func TestAIModelInventorySheetRendersEveryProfileFieldPlusTheNonProfileColumns(t *testing.T) {
	sheets, err := Sheets(aibomSample(aiModelSample()))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	// Model, then every Table 10 element, then these — provenance and evidence
	// (which engines saw it, and where), and the two AxeBOM extensions that are
	// excluded from both coverage numbers.
	nonProfile := []string{
		"Found By (engines)",
		"Evidence",
		// Which rung of the identity ladder produced this row's key, and
		// whether an engine confirmed the model upstream. Both are degrees of
		// evidence for a row that otherwise looks identical to a confirmed one.
		"Identity",
		"Verified upstream",
		"Risk Score (AxeBOM extension)",
		"OWASP LLM Top-10 (AxeBOM extension)",
	}
	sheet := findSheet(t, sheets, "AI Models")
	if len(sheet.Header) != 1+len(model.AIBOMFields)+len(nonProfile) {
		t.Errorf("AI Models header has %d columns, want 1 (Model) + %d (profile) + %d (%v)",
			len(sheet.Header), len(model.AIBOMFields), len(nonProfile), nonProfile)
	}
	for _, want := range nonProfile {
		if !slices.Contains(sheet.Header, want) {
			t.Errorf("the AI Models sheet has no %q column: %v", want, sheet.Header)
		}
	}

	joined := flatten(collect(t, sheet))
	for _, want := range []string{"Llama-3-8B", "Meta", "llama3", "7.5", "LLM01", "LLM06"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the AI Models sheet is missing %q", want)
		}
	}
}

// TestAModelWithNoValueRendersNotProvidedNeverBlank — CLAUDE.md invariant 3:
// omission hides the gap; a blank cell reads as "we did not look".
func TestAModelWithNoValueRendersNotProvidedNeverBlank(t *testing.T) {
	sheets, err := Sheets(aibomSample([]AIModel{{Name: "bare-model", Fields: map[string]string{}}}))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "AI Models")))
	if !strings.Contains(joined, model.NotProvided) {
		t.Error("a model with no field values does not render any not-provided cells")
	}
}

// TestRiskScoreAndOwaspTop10AreLabelledAsExtensions — CLAUDE.md invariant 3
// applied to a third-party heuristic: it must never be mistaken for a
// CERT-In element in the header a reader sees.
func TestRiskScoreAndOwaspTop10AreLabelledAsExtensions(t *testing.T) {
	sheets, err := Sheets(aibomSample(aiModelSample()))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	sheet := findSheet(t, sheets, "AI Models")
	for _, want := range []string{"Risk Score (AxeBOM extension)", "OWASP LLM Top-10 (AxeBOM extension)"} {
		found := false
		for _, h := range sheet.Header {
			if h == want {
				found = true
			}
		}
		if !found {
			t.Errorf("header %v is missing labelled extension column %q", sheet.Header, want)
		}
	}
}

// TestAIBOMExtensionsNoteAppearsInTheNotes.
func TestAIBOMExtensionsNoteAppearsInTheNotes(t *testing.T) {
	sheets, err := Sheets(aibomSample(aiModelSample()))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "Notes")))
	if !strings.Contains(joined, "AxeBOM extensions derived from Trusera ai-bom") {
		t.Error("the AIBOM extensions note is missing from the Notes sheet")
	}
}

// TestAIModelDatasetsAndDependenciesSheetsRenderPerModelRows.
func TestAIModelDatasetsAndDependenciesSheetsRenderPerModelRows(t *testing.T) {
	sheets, err := Sheets(aibomSample(aiModelSample()))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}

	datasetRows := flatten(collect(t, findSheet(t, sheets, "AI Model Datasets")))
	for _, want := range []string{"Llama-3-8B", "the-pile", "text", "MIT"} {
		if !strings.Contains(datasetRows, want) {
			t.Errorf("AI Model Datasets sheet is missing %q", want)
		}
	}

	depRows := flatten(collect(t, findSheet(t, sheets, "AI Model Dependencies")))
	for _, want := range []string{"Llama-3-8B", "purl:pkg:pypi/langchain@0.3.7"} {
		if !strings.Contains(depRows, want) {
			t.Errorf("AI Model Dependencies sheet is missing %q", want)
		}
	}
}

// TestTheAIAssetSheetRendersWhatNoTable10ElementCovers.
//
// ⚠ SIX REAL DISCOVERIES ON ONE SMALL TREE HAD NOWHERE TO GO. `airom` and
// `cdxgen-ai` report prompts, vector stores, RAG pipelines and the inference
// services a repository talks to, each with file:line evidence — and CERT-In
// Table 10 has no element for any of them. Before this sheet the choice was
// between dropping them and inventing an element; rendering them in their own
// section, scored into neither coverage number, is the third answer.
func TestTheAIAssetSheetRendersWhatNoTable10ElementCovers(t *testing.T) {
	b := aibomSample(aiModelSample())
	b.AIAssets = []AIAsset{
		{
			Type:     "prompt",
			Name:     "system-prompt",
			Evidence: []string{"src/app.py:9"},
			FoundBy:  []string{"airom"},
		},
		{
			Type:        "endpoint",
			Name:        "OpenAI API",
			Provider:    "openai",
			ServesModel: "gpt-4o",
			FoundBy:     []string{"cdxgen-ai"},
		},
	}

	sheets, err := Sheets(b)
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "AI Assets")))

	for _, want := range []string{
		"prompt", "system-prompt", "src/app.py:9", "airom",
		"endpoint", "OpenAI API", "openai", "gpt-4o", "cdxgen-ai",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the AI Assets sheet is missing %q", want)
		}
	}
}

// TestAModelSaysWhichEnginesFoundIt.
//
// ⚠ ONE ENGINE OR THREE IS THE MOST USEFUL SINGLE FACT ON A TABLE 10 ROW, and
// it was invisible while AxeBOM ran one AI discovery engine. Measured on one
// real tree: three engines converge on `meta-llama/Llama-3-8B`, and only one of
// them reports `sentence-transformers/all-MiniLM-L6-v2` at all. Those are
// different degrees of evidence and a reviewer is entitled to see which they
// have.
func TestAModelSaysWhichEnginesFoundIt(t *testing.T) {
	models := aiModelSample()
	models[0].FoundBy = []string{"ai-bom", "airom", "cdxgen-ai"}
	models[0].Evidence = []string{"src/app.py:17", "src/app.py:18"}

	sheets, err := Sheets(aibomSample(models))
	if err != nil {
		t.Fatalf("building sheets: %v", err)
	}
	joined := flatten(collect(t, findSheet(t, sheets, "AI Models")))

	for _, want := range []string{"ai-bom", "airom", "cdxgen-ai", "src/app.py:17"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the AI Models sheet does not report %q", want)
		}
	}
}
