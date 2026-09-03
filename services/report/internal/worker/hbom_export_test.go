package worker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/report/internal/export"
	"github.com/axebom/axebom/services/report/internal/render"
)

// ---------------------------------------------------------------------------
// HBOM → SPDX and CycloneDX
// ---------------------------------------------------------------------------
//
// ⚠ THIS CLOSES §10.4.1.6, AND BEFORE IT THE HARDWARE BOM COULD NOT LEAVE
// AxeBOM. `b.Hardware` reached the XLSX and DOCX renderers and stopped there;
// a customer who asked for the CycloneDX or SPDX form of their hardware BOM
// got a document with zero components, which validates and says nothing.

func hbomFixture() render.BOM {
	return render.BOM{
		BOMType:     model.BOMTypeHBOM,
		ReportID:    "01900000-0000-7000-8000-0000000000r1",
		ProjectName: "edge-gateway",
		GeneratedAt: "2026-09-03T00:00:00Z",
		ToolName:    "AxeBOM", ToolVersion: "0.1.0",
		Hardware: []render.HardwareComponent{
			{
				ID: "hw-root", Depth: 0, Quantity: 1,
				Name: "ENC-GW-4400", Description: "Edge Gateway",
				ManufacturerName: "Encore Systems", ManufacturerLocation: "Pune, India",
				SupplierInfo: "Bharat Integrators", Origin: "India", Criticality: "critical",
				Compliance: []string{"RoHS", "CE"}, LifecycleStatus: "active",
				SourceEngine: "hbom-ecad",
			},
			{
				ID: "hw-r1", ParentID: "hw-root", Depth: 1, Quantity: 3,
				Name: "RC0402FR-0710KL", ModelNumber: "RC0402FR-0710KL",
				ManufacturerName: "Yageo", ComponentSupplierInfo: "Arrow",
				Designators: []string{"R1", "R4", "R17"}, PackageFootprint: "0402",
				SupplierSKU: "311-10.0KLRCT-ND", PreferredSupplier: "Digi-Key",
				UnitPrice: "0.001800", ExtendedPrice: "0.005400", Currency: "USD",
				AssemblyType: "smt", LifecycleStatus: "active", SourceEngine: "hbom-ecad",
				Alternates: []render.HardwareAlternate{
					{ModelNumber: "ERJ-2RKF1002X", Equivalence: "functional"},
				},
			},
			{
				ID: "hw-fw", ParentID: "hw-root", Depth: 1, Quantity: 1,
				Name: "UEFI BIOS", FirmwareVersion: "N3AET92W",
				ManufacturerName: "Encore Systems", SourceEngine: "hbom-cdxgen-host",
			},
			{
				ID: "hw-tp", ParentID: "hw-root", Depth: 1, Quantity: 1,
				Name: "Test point", ModelNumber: "TP-1", DoNotPopulate: true,
				Designators: []string{"TP1"}, AssemblyType: "tht",
				LifecycleStatus: "obsolete", SourceEngine: "hbom-ecad",
			},
		},
	}
}

func serializeHBOM(t *testing.T, f export.Format) map[string]any {
	t.Helper()
	raw, err := export.Serialize(toExportDocument(hbomFixture()), f)
	if err != nil {
		t.Fatalf("serialize %s: %v", f, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s is not valid JSON: %v", f, err)
	}
	return out
}

// TestHardwareIsTypedAsDeviceNotSoftware.
//
// ⚠ THE SINGLE MOST IMPORTANT ASSERTION IN THIS FILE. A parts list serialized
// with software defaults is a valid document that says something false — a
// consumer reads a gateway's capacitors as libraries it depends on. The
// component TYPE is what makes a hardware BOM a hardware BOM.
func TestHardwareIsTypedAsDeviceNotSoftware(t *testing.T) {
	cdx := serializeHBOM(t, export.CycloneDX16JSON)

	meta, _ := cdx["metadata"].(map[string]any)
	root, _ := meta["component"].(map[string]any)
	if root == nil || root["type"] != "device" {
		t.Errorf("metadata.component.type = %v, want device", root["type"])
	}

	components, _ := cdx["components"].([]any)
	if len(components) != 3 {
		// The root is hoisted into metadata.component, which is correct
		// CycloneDX — the top-level product belongs there, not in the array.
		t.Fatalf("components = %d, want 3 (the root lives in metadata.component)", len(components))
	}
	for _, raw := range components {
		c := raw.(map[string]any)
		switch c["type"] {
		case "device", "firmware":
		default:
			t.Errorf("%v has type %v; a hardware component is device or firmware",
				c["name"], c["type"])
		}
	}

	spdx := serializeHBOM(t, export.SPDX23JSON)
	packages, _ := spdx["packages"].([]any)
	if len(packages) != 4 {
		t.Fatalf("spdx packages = %d, want 4", len(packages))
	}
	for _, raw := range packages {
		p := raw.(map[string]any)
		switch p["primaryPackagePurpose"] {
		case "DEVICE", "FIRMWARE":
		default:
			t.Errorf("%v has primaryPackagePurpose %v", p["name"], p["primaryPackagePurpose"])
		}
	}
}

// TestTheAssemblyRelationshipSurvivesBothStandards.
//
// SPDX carries a real CONTAINS. CycloneDX does not have one in its dependency
// graph and protobom ignores the edge type there, so the same fact is ALSO
// emitted as an explicit property — see export.Dependency.Kind. This pins both
// halves, because the property is the only thing that makes the CycloneDX form
// unambiguous.
func TestTheAssemblyRelationshipSurvivesBothStandards(t *testing.T) {
	spdx := serializeHBOM(t, export.SPDX23JSON)
	contains := 0
	for _, raw := range spdx["relationships"].([]any) {
		if raw.(map[string]any)["relationshipType"] == "CONTAINS" {
			contains++
		}
	}
	if contains != 3 {
		t.Errorf("SPDX CONTAINS relationships = %d, want 3", contains)
	}

	cdx := serializeHBOM(t, export.CycloneDX16JSON)
	for _, raw := range cdx["components"].([]any) {
		c := raw.(map[string]any)
		if props := propertyMap(c); props["axebom:hbom:parent"] != "hw-root" {
			t.Errorf("%v carries no axebom:hbom:parent; the CycloneDX form would leave "+
				"a reader unable to tell containment from a runtime dependency", c["name"])
		}
	}
}

// TestTheManufacturerSurvivesCycloneDX.
//
// ⚠ REGRESSION GUARD FOR A REAL DATA LOSS. protobom's CycloneDX serializer
// reads Suppliers and never reads Originators, so the manufacturer — the field
// §10.2.1 exists for — vanished from every CycloneDX hardware BOM until it was
// also emitted as a property. Found by reading real output, not by reasoning.
func TestTheManufacturerSurvivesCycloneDX(t *testing.T) {
	cdx := serializeHBOM(t, export.CycloneDX16JSON)
	for _, raw := range cdx["components"].([]any) {
		c := raw.(map[string]any)
		if c["name"] != "RC0402FR-0710KL" {
			continue
		}
		if got := propertyMap(c)["certin:hbom:manufacturer"]; got != "Yageo" {
			t.Errorf("certin:hbom:manufacturer = %q, want Yageo", got)
		}
		return
	}
	t.Fatal("the resistor is missing from the CycloneDX document")
}

// TestSuppliersAreOrganisationsNotPeople — SPDX renders an entity as
// `Person: X` or `Organization: X`, and filing STMicroelectronics as a person
// is wrong in a document an auditor reads.
func TestSuppliersAreOrganisationsNotPeople(t *testing.T) {
	spdx := serializeHBOM(t, export.SPDX23JSON)
	for _, raw := range spdx["packages"].([]any) {
		p := raw.(map[string]any)
		for _, field := range []string{"supplier", "originator"} {
			if v, ok := p[field].(string); ok && strings.HasPrefix(v, "Person:") {
				t.Errorf("%v.%s = %q; a company is an Organization", p["name"], field, v)
			}
		}
	}
}

// TestManufacturingPropertiesAreNamespacedByAuthority.
//
// A reader must be able to tell which claims a compliance standard requires
// from which are AxeBOM's own. One flat namespace makes that unrecoverable.
func TestManufacturingPropertiesAreNamespacedByAuthority(t *testing.T) {
	cdx := serializeHBOM(t, export.CycloneDX16JSON)
	for _, raw := range cdx["components"].([]any) {
		c := raw.(map[string]any)
		for name := range propertyMap(c) {
			if !strings.HasPrefix(name, "certin:hbom:") && !strings.HasPrefix(name, "axebom:hbom:") {
				t.Errorf("%v carries un-namespaced property %q", c["name"], name)
			}
		}
	}

	// The DNP flag is written only when true: every fitted part carrying
	// `do_not_populate: false` would bury the one that matters.
	dnp := 0
	for _, raw := range cdx["components"].([]any) {
		if _, ok := propertyMap(raw.(map[string]any))["axebom:hbom:do_not_populate"]; ok {
			dnp++
		}
	}
	if dnp != 1 {
		t.Errorf("do_not_populate appears on %d components, want 1", dnp)
	}
}

// TestHardwareExportIsByteReproducible — ADR-0003. A re-render of a stored
// report must be the same artifact, or a signature over it means nothing.
func TestHardwareExportIsByteReproducible(t *testing.T) {
	for _, f := range []export.Format{export.SPDX23JSON, export.CycloneDX16JSON} {
		doc := toExportDocument(hbomFixture())
		first, err := export.Serialize(doc, f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		second, err := export.Serialize(toExportDocument(hbomFixture()), f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if string(first) != string(second) {
			t.Errorf("%s is not byte-reproducible across two renders of the same model", f)
		}
	}
}

func propertyMap(c map[string]any) map[string]string {
	out := map[string]string{}
	props, _ := c["properties"].([]any)
	for _, raw := range props {
		p := raw.(map[string]any)
		name, _ := p["name"].(string)
		value, _ := p["value"].(string)
		out[name] = value
	}
	return out
}
