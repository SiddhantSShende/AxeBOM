package hbom

import (
	"context"
	"encoding/json"
	"testing"
)

func TestManualProviderWorksWithNoAPIKeyConfigured(t *testing.T) {
	p := ManualProvider{}
	if !p.Configured() {
		t.Fatal("ManualProvider must always report configured")
	}
	got := p.Lookup(context.Background(), []string{"anything"})
	if len(got) != 0 {
		t.Errorf("manual lookup = %v, want empty", got)
	}
}

func TestResolveFallsBackToManualWhenNothingIsConfigured(t *testing.T) {
	p := Resolve(NexarProvider{}, MouserProvider{})
	if p.Name() != "manual" {
		t.Errorf("resolved provider = %q, want manual", p.Name())
	}
}

func TestResolvePrefersAConfiguredProvider(t *testing.T) {
	p := Resolve(NexarProvider{}, MouserProvider{APIKey: "key"})
	if p.Name() != "mouser" {
		t.Errorf("resolved provider = %q, want mouser", p.Name())
	}
}

func TestEnrichmentNeverOverwritesWhatTheCustomerSupplied(t *testing.T) {
	c := &Component{ModelNumber: "ENC-1", ManufacturerName: "Customer-Verified Corp"}
	enrichments := map[string]Enrichment{
		"enc-1": {ManufacturerName: "Distributor Guess", Origin: "Elsewhere", Source: "nexar"},
	}
	Apply(c, enrichments)

	if c.ManufacturerName != "Customer-Verified Corp" {
		t.Errorf("manufacturer name was overwritten: %q", c.ManufacturerName)
	}
	if c.Origin != "Elsewhere" {
		t.Errorf("origin = %q, want filled from the empty field", c.Origin)
	}
	if c.EnrichedFields["origin"] != "nexar" {
		t.Errorf("enriched_fields[origin] = %q, want nexar", c.EnrichedFields["origin"])
	}
	if _, ok := c.EnrichedFields["manufacturer_name"]; ok {
		t.Error("manufacturer_name must not be recorded as enriched — the customer's value stood")
	}
}

func TestEnrichmentUnionsComplianceRatherThanReplacingIt(t *testing.T) {
	c := &Component{ModelNumber: "ENC-1", Compliance: []string{"RoHS"}}
	enrichments := map[string]Enrichment{
		"enc-1": {Compliance: []string{"RoHS", "CE"}, Source: "mouser"},
	}
	Apply(c, enrichments)

	if got, want := c.Compliance, []string{"RoHS", "CE"}; !equal(got, want) {
		t.Errorf("compliance = %v, want %v", got, want)
	}
}

func TestPartNumbersAreDedupedBeforeALookup(t *testing.T) {
	child1 := &Component{ModelNumber: "CAP-1"}
	child2 := &Component{ModelNumber: "cap-1"} // same part, different case
	root := &Component{ModelNumber: "BOARD", Children: []*Component{child1, child2}}

	got := MPNs(root)
	if len(got) != 2 { // BOARD + cap-1 (deduped, case-insensitive)
		t.Errorf("MPNs = %v, want 2 distinct entries", got)
	}
}

func TestNexarParserReadsAResponseWithoutANetwork(t *testing.T) {
	raw := `{
		"data": {
			"supMultiMatch": [{
				"parts": [{
					"mpn": "STM32H753ZI",
					"manufacturer": {"name": "STMicroelectronics"},
					"specs": [{"attribute": {"shortname": "rohsstatus"}, "displayValue": "RoHS Compliant"}],
					"bestDatasheet": {"url": "https://example.com/ds.pdf"}
				}]
			}]
		}
	}`
	var body nexarResponseBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	enrichment := parseNexarResponse(body)
	e, ok := enrichment["stm32h753zi"]
	if !ok {
		t.Fatal("expected an enrichment for stm32h753zi")
	}
	if e.ManufacturerName != "STMicroelectronics" {
		t.Errorf("manufacturer = %q", e.ManufacturerName)
	}
	if len(e.Compliance) != 1 || e.Compliance[0] != "RoHS" {
		t.Errorf("compliance = %v, want [RoHS]", e.Compliance)
	}
}

func TestMouserParserReadsAResponseWithoutANetwork(t *testing.T) {
	raw := `{
		"SearchResults": {
			"Parts": [{
				"ManufacturerPartNumber": "LM2596S-5.0",
				"Manufacturer": "Texas Instruments",
				"ROHSStatus": "RoHS Compliant"
			}]
		}
	}`
	var body mouserResponseBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	enrichment := parseMouserResponse(body)
	e, ok := enrichment["lm2596s-5.0"]
	if !ok {
		t.Fatal("expected an enrichment for lm2596s-5.0")
	}
	if e.ManufacturerName != "Texas Instruments" {
		t.Errorf("manufacturer = %q", e.ManufacturerName)
	}
	if len(e.Compliance) != 1 || e.Compliance[0] != "RoHS" {
		t.Errorf("compliance = %v, want [RoHS]", e.Compliance)
	}
}

func TestProviderParserTreatsAnEmptyResponseAsNoResults(t *testing.T) {
	if got := parseNexarResponse(nexarResponseBody{}); len(got) != 0 {
		t.Errorf("nexar empty response = %v, want empty", got)
	}
	if got := parseMouserResponse(mouserResponseBody{}); len(got) != 0 {
		t.Errorf("mouser empty response = %v, want empty", got)
	}
}
