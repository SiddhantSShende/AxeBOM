package export

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleMLDocument() MLDocument {
	risk := 7.5
	return MLDocument{
		GeneratedAt: "2026-01-01T00:00:00Z",
		DocumentID:  "01900000-0000-7000-8000-000000000001",
		ProjectName: "support-assistant",
		ToolName:    "AxeBOM",
		ToolVersion: "0.1.0",
		Models: []MLModel{{
			Key:                "purl:pkg:huggingface/meta-llama/Llama-3-8B",
			Name:               "Llama-3-8B",
			Version:            "12040acc",
			Purl:               "pkg:huggingface/meta-llama/Llama-3-8B",
			Task:               "text-generation",
			Licenses:           "llama3",
			Author:             "Meta",
			Architectures:      []string{"LlamaForCausalLM"},
			Inputs:             "text",
			Outputs:            "text",
			Datasets:           []MLDataset{{Name: "the-pile", License: "MIT", Source: "https://example.test/pile"}},
			Dependencies:       []string{"purl:pkg:pypi/transformers@4.44.2"},
			Evidence:           []string{"src/app.py:17", "src/app.py:18"},
			FoundBy:            []string{"ai-bom", "airom", "cdxgen-ai"},
			Verified:           true,
			IdentityRule:       "hf_repo",
			IdentityConfidence: "high",
			IntendedUsage:      "internal support triage only",
			OutOfScopeUsage:    "never for medical advice",
			Fields: map[string]string{
				"certin.aibom.01.model_name": "Llama-3-8B",
				"certin.aibom.11.hardware":   "not-provided",
			},
			RiskScore:     &risk,
			OwaspLLMTop10: []string{"LLM01"},
		}},
		Assets: []MLAsset{
			{Type: "prompt", Key: "prompt:src/app.py:9", Name: "system-prompt",
				Evidence: []string{"src/app.py:9"}},
			{Type: "vector_store", Key: "vector_store:chroma", Name: "chroma", Provider: "chroma"},
			{Type: "endpoint", Key: "endpoint:openai", Name: "OpenAI API",
				Provider: "openai", ServesModel: "gpt-4o"},
		},
	}
}

func decodeMLBOM(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	if !mlbomIsValidJSON(raw) {
		t.Fatalf("the ML-BOM is not valid JSON:\n%s", raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// TestTheMLBOMCarriesAPopulatedModelCard.
//
// ⚠ `modelCard` IS OPTIONAL IN CycloneDX 1.5, 1.6 AND 1.7, SO A DOCUMENT WITH
// ZERO ML CONTENT VALIDATES AS A PERFECT ML-BOM.
//
// Schema conformance is therefore not evidence of content, and a test that only
// validated would pass on the exact document this exporter exists to replace —
// the generic protobom one, where every AI model is an unremarkable component
// because `sbom.Node` has no ML fields at all. This asserts the content.
func TestTheMLBOMCarriesAPopulatedModelCard(t *testing.T) {
	raw, err := SerializeMLBOM(sampleMLDocument())
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	doc := decodeMLBOM(t, raw)

	components, _ := doc["components"].([]any)
	var found map[string]any
	for _, c := range components {
		m, _ := c.(map[string]any)
		if m["type"] == "machine-learning-model" {
			found = m
			break
		}
	}
	if found == nil {
		t.Fatalf("no machine-learning-model component:\n%s", raw)
	}

	card, ok := found["modelCard"].(map[string]any)
	if !ok {
		t.Fatalf("the model carries no modelCard — this is the whole reason this "+
			"exporter exists:\n%s", raw)
	}
	params, ok := card["modelParameters"].(map[string]any)
	if !ok {
		t.Fatal("the modelCard carries no modelParameters")
	}
	if params["task"] != "text-generation" {
		t.Errorf("task = %v, want text-generation", params["task"])
	}
	if params["modelArchitecture"] != "LlamaForCausalLM" {
		t.Errorf("modelArchitecture = %v", params["modelArchitecture"])
	}
	if params["datasets"] == nil {
		t.Error("the modelCard names no datasets, though the model has one")
	}
}

// TestTheOperatorsAnswersLandInConsiderationsNotOnlyInProperties.
//
// CycloneDX models exactly what a model is FOR and what it must NOT be used for.
// Burying those in namespaced properties would hide them from every tool that
// reads an ML-BOM properly — which is most of the value of emitting one.
func TestTheOperatorsAnswersLandInConsiderationsNotOnlyInProperties(t *testing.T) {
	raw, err := SerializeMLBOM(sampleMLDocument())
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	text := string(raw)

	for _, want := range []string{
		`"considerations"`, `"useCases"`, "internal support triage only",
		`"technicalLimitations"`, "never for medical advice",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the ML-BOM does not carry %q", want)
		}
	}
}

// TestTheSentinelIsNeverExportedAsAValue.
//
// ⚠ `not-provided` IS HOW *OUR* DOCUMENT MAKES A GAP VISIBLE (invariant 3), and
// exporting it into a CycloneDX file would assert it as the answer to every tool
// that reads one. Absence is how the standard says "not stated".
func TestTheSentinelIsNeverExportedAsAValue(t *testing.T) {
	doc := sampleMLDocument()
	doc.Models[0].Licenses = "not-provided"
	doc.Models[0].IntendedUsage = "not-provided"
	doc.Models[0].Author = "not-provided"
	// ⚠ `task` WAS THE ONE THAT ESCAPED. A live export carried
	// `task: "not-provided"` into the ML-BOM and onward into SPDX 3.0's
	// `typeOfModel`, because this test only covered licence and intended use —
	// the guard was narrower than the rule it was written for.
	doc.Models[0].Task = "not-provided"
	doc.Models[0].Version = "not-provided"
	doc.Models[0].Inputs = "not-provided"

	raw, err := SerializeMLBOM(doc)
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	decoded := decodeMLBOM(t, raw)
	components, _ := decoded["components"].([]any)
	for _, c := range components {
		m, _ := c.(map[string]any)
		if m["type"] != "machine-learning-model" {
			continue
		}
		if m["licenses"] != nil {
			t.Errorf("a `not-provided` licence was exported as a licence: %v", m["licenses"])
		}
		card, _ := m["modelCard"].(map[string]any)
		cons, _ := card["considerations"].(map[string]any)
		// ⚠ THE `useCases` KEY SPECIFICALLY. `considerations` is legitimately
		// present here — the out-of-scope answer is real — and asserting the
		// whole block is absent would pass only by accident.
		if cons["useCases"] != nil {
			t.Errorf("a `not-provided` intended use reached considerations.useCases: %v",
				cons["useCases"])
		}
		if m["authors"] != nil {
			t.Errorf("a `not-provided` developer was exported as an author: %v", m["authors"])
		}
		if m["version"] != nil {
			t.Errorf("a `not-provided` version was exported: %v", m["version"])
		}
		params, _ := card["modelParameters"].(map[string]any)
		if params["task"] != nil {
			t.Errorf("a `not-provided` task was exported as a task: %v", params["task"])
		}
		if params["inputs"] != nil {
			t.Errorf("a `not-provided` input format was exported: %v", params["inputs"])
		}
	}
	// ⚠ AND IT IS STILL IN THE DOCUMENT, on the namespaced property carrying the
	// full Table 10 set — a reader of OUR properties can still see the gap was
	// stated rather than merely absent.
	if !strings.Contains(string(raw), "certin.aibom.11.hardware") {
		t.Error("the full Table 10 field set is not carried on properties")
	}
}

// TestAnInferenceEndpointIsAServiceNotAComponent.
//
// CycloneDX has a `services` array, and `cdxgen -t ai` — the engine that finds
// these — emits them there. A consumer that reads one AI BOM should read both.
func TestAnInferenceEndpointIsAServiceNotAComponent(t *testing.T) {
	raw, err := SerializeMLBOM(sampleMLDocument())
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	doc := decodeMLBOM(t, raw)

	services, _ := doc["services"].([]any)
	if len(services) != 1 {
		t.Fatalf("got %d services, want 1 (the inference endpoint)", len(services))
	}
	svc, _ := services[0].(map[string]any)
	if svc["name"] != "OpenAI API" {
		t.Errorf("service name = %v", svc["name"])
	}

	components, _ := doc["components"].([]any)
	for _, c := range components {
		m, _ := c.(map[string]any)
		if m["name"] == "OpenAI API" {
			t.Error("the inference endpoint was also emitted as a component; " +
				"a consumer would count it twice")
		}
	}
}

// TestTheHonestyFieldsAreExported.
//
// An ML-BOM that says what a model IS without saying how well we know it leaves
// a reviewer nothing to check. `verified` is emitted even when false —
// especially when false.
func TestTheHonestyFieldsAreExported(t *testing.T) {
	doc := sampleMLDocument()
	doc.Models[0].Verified = false

	raw, err := SerializeMLBOM(doc)
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	text := string(raw)

	for _, want := range []string{
		"axebom:aibom:verified", `"false"`,
		"axebom:aibom:found_by", "ai-bom, airom, cdxgen-ai",
		"axebom:aibom:evidence", "src/app.py:17",
		"axebom:aibom:identity_confidence",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the ML-BOM does not carry %q", want)
		}
	}
}

// TestAnEmptyMLBOMIsRefusedRatherThanEmitted.
//
// ⚠ IT WOULD VALIDATE, AND IT WOULD ASSERT THAT THE PROJECT CONTAINS NO AI.
// That is the exact failure the generic AIBOM export already made once, where
// six downloadable artifacts said nothing while conforming perfectly.
func TestAnEmptyMLBOMIsRefusedRatherThanEmitted(t *testing.T) {
	_, err := SerializeMLBOM(MLDocument{DocumentID: "x", ProjectName: "p"})
	if err == nil {
		t.Fatal("an ML-BOM with no models and no assets was serialized")
	}
	if !strings.Contains(err.Error(), "contains no AI") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// TestTheMLBOMIsByteStableAcrossSerializations.
//
// A report is downloaded, diffed and attached to tickets, and ADR-0003 rests on
// re-rendering the same canonical model producing the same bytes. Go randomises
// map iteration, so every map this exporter touches has to be sorted — the same
// trap protobom's shuffled arrays already set for the SPDX/CycloneDX exporter.
func TestTheMLBOMIsByteStableAcrossSerializations(t *testing.T) {
	for i := range 10 {
		first, err := SerializeMLBOM(sampleMLDocument())
		if err != nil {
			t.Fatalf("SerializeMLBOM: %v", err)
		}
		second, err := SerializeMLBOM(sampleMLDocument())
		if err != nil {
			t.Fatalf("SerializeMLBOM: %v", err)
		}
		if string(first) != string(second) {
			t.Fatalf("run %d: two serializations of one document differ", i)
		}
	}
}

// TestOnlyARealPurlReachesTheResolvableField.
//
// ⚠ A MODEL IDENTIFIED AS `api:openai/gpt-4o` HAS NO PACKAGE URL. Minting one
// would put an identifier in the field a consumer RESOLVES, pointing at nothing
// — and the resolution failing later reads as our document being wrong, which it
// would be.
func TestOnlyARealPurlReachesTheResolvableField(t *testing.T) {
	doc := sampleMLDocument()
	doc.Models[0].Purl = "api:openai/gpt-4o"

	raw, err := SerializeMLBOM(doc)
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	decoded := decodeMLBOM(t, raw)
	components, _ := decoded["components"].([]any)
	for _, c := range components {
		m, _ := c.(map[string]any)
		if m["type"] == "machine-learning-model" && m["purl"] != nil {
			t.Errorf("a non-purl identity was exported as a purl: %v", m["purl"])
		}
	}
}

// TestAMalformedSerialNumberIsOmittedRatherThanEmitted.
//
// ⚠ THE OFFICIAL SCHEMA CAUGHT THIS, AND OUR OWN TESTS DID NOT.
//
// CycloneDX pins `serialNumber` to an RFC-4122 URN. The serializer emitted
// `urn:uuid:` + whatever the document id was, so a non-UUID id produced a
// document the spec's own validator rejects. It would have shipped: a report id
// is a UUIDv7 in production, so the field would have been correct on every real
// report and wrong on the first one that was not — which is the worst shape of
// latent defect, and the reason `tools/conformance` validates against the real
// schema rather than against our opinion of it.
func TestAMalformedSerialNumberIsOmittedRatherThanEmitted(t *testing.T) {
	doc := sampleMLDocument()
	doc.DocumentID = "not-a-uuid"

	raw, err := SerializeMLBOM(doc)
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	decoded := decodeMLBOM(t, raw)
	if sn, present := decoded["serialNumber"]; present {
		t.Errorf("a malformed serialNumber was emitted: %v", sn)
	}

	// And a real one still is — omitting it always would trade one defect for
	// another, since the field is how two exports of one report are tied
	// together.
	doc.DocumentID = "01900000-0000-7000-8000-000000000001"
	raw, err = SerializeMLBOM(doc)
	if err != nil {
		t.Fatalf("SerializeMLBOM: %v", err)
	}
	if decodeMLBOM(t, raw)["serialNumber"] != "urn:uuid:01900000-0000-7000-8000-000000000001" {
		t.Error("a valid document id did not become a serialNumber")
	}
}
