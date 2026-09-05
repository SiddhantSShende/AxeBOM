package hbom_test

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/project/internal/hbom"
)

// TestTheComponentFormCoversEveryEditableTable11Element.
//
// ⚠ THE EDITOR EXPOSED SIX FIELDS AND ROUND-TRIPPED THE REST UNTOUCHED, so a
// customer could see a `not-provided` manufacturer on the component sheet and
// had no way to fix it — and the coverage number stayed low for a reason
// nothing on screen explained.
//
// ⚠ NO COUNT IS ASSERTED HERE, deliberately (invariant 2). The assertion is
// that the form covers every element whose canonical path names an editable
// component attribute, whatever that number becomes when CERT-In is revised.
func TestTheComponentFormCoversEveryEditableTable11Element(t *testing.T) {
	fields := hbom.ComponentFormFields()

	got := make(map[string]bool, len(fields))
	for _, f := range fields {
		got[f.FieldID] = true
	}

	for _, f := range model.HBOMFields {
		attr, ok := cutPrefix(f.CanonicalPath, "hardware_component.")
		if !ok || attr == "" {
			continue
		}
		// `children[]` is the tree and `findings[]` is derived; `compliance[]`
		// is a list a person types and must still have an input.
		if strings.HasSuffix(attr, "[]") && attr != "compliance[]" {
			continue
		}
		if !got[f.ID] {
			t.Errorf("%s (%s) is an editable component element with no form input",
				f.ID, f.Name)
		}
	}

	if len(fields) < 15 {
		t.Fatalf("only %d inputs were generated; the profile has far more editable "+
			"elements than that, so the derivation is wrong", len(fields))
	}
}

// TestTheFormSkipsTheTwoElementsThatAreNotTypedIn.
//
// Element 20 IS the tree — edited by adding a row, not by typing into a box —
// and element 24 is derived from CPE matching, so a form asking for it would be
// asking a customer to duplicate a lookup.
func TestTheFormSkipsTheTwoElementsThatAreNotTypedIn(t *testing.T) {
	for _, f := range hbom.ComponentFormFields() {
		switch f.FieldID {
		case model.FieldCertinHbom20SubComponent:
			t.Error("sub_component is the tree; it must not be a text input")
		case model.FieldCertinHbom24Vulnerabilities:
			t.Error("vulnerabilities are derived from CPE matching, not typed in")
		}
	}
}

// TestTheTwoSupplierFieldsAreDisambiguated.
//
// "Supplier" alone is the field somebody fills in with whichever company comes
// to mind, and Table 11 means two different things by them. A form that does
// not say which is which collects the wrong answer — confidently.
func TestTheTwoSupplierFieldsAreDisambiguated(t *testing.T) {
	hints := map[string]string{}
	for _, f := range hbom.ComponentFormFields() {
		hints[f.Attr] = f.Hint
	}
	for _, attr := range []string{"supplier_info", "component_supplier_info"} {
		if hints[attr] == "" {
			t.Errorf("%s has no hint distinguishing it from the other supplier field", attr)
		}
	}
	if hints["supplier_info"] == hints["component_supplier_info"] {
		t.Error("both supplier fields carry the same hint, which disambiguates nothing")
	}
}

func TestCriticalityIsAClosedSetNotFreeText(t *testing.T) {
	for _, f := range hbom.ComponentFormFields() {
		if f.Attr == "criticality" {
			if len(f.Values) == 0 {
				t.Fatal("criticality renders as free text; the column has a CHECK constraint")
			}
			return
		}
	}
	t.Fatal("criticality has no form input at all")
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

// TestTheComponentFormCarriesTheManufacturingElements.
//
// ⚠ THEY WERE AUTHORED, LINTED, SCORED IN PYTHON — AND INVISIBLE IN THE ONLY
// SCREEN WHERE ANYBODY COULD ENTER THEM. docs/reference/hbom-manufacturing-v1.yaml
// defines designators, footprint, quantity, supplier SKU, alternates, lifecycle
// status and the rest. The form is built from the GENERATED model, and
// `axebom profile gen` refused operational profiles outright — so the elements
// existed everywhere except where a customer could fill them in, and a
// manufacturing readiness number was scored against fields no screen offered.
func TestTheComponentFormCarriesTheManufacturingElements(t *testing.T) {
	byAttr := map[string]hbom.ComponentFormField{}
	for _, f := range hbom.ComponentFormFields() {
		byAttr[f.Attr] = f
	}

	// Spot-check across the profile's three groups: engineering, sourcing,
	// assembly. Named individually rather than counted — a count here would be
	// the literal invariant 2 forbids.
	for _, attr := range []string{
		"designators", "package_footprint", "quantity",
		"supplier_sku", "alternates", "assembly_type", "lifecycle_status",
	} {
		if _, ok := byAttr[attr]; !ok {
			t.Errorf("the component form has no input for %q; the manufacturing "+
				"readiness number scores a field nobody can fill in", attr)
		}
	}
}

// TestManufacturingElementsAreNotLabelledAsCERTIn.
//
// ⚠ THE TWO SETS SCORE INTO DIFFERENT NUMBERS AND CONFLATING THEM IS A
// COMPLIANCE DEFECT. hbom-manufacturing-v1.yaml's own header: these may NEVER
// move completeness_pct or declaration_pct. A form that presents a unit-price
// input beside a CERT-In element with no distinction invites a customer to read
// their procurement diligence as compliance coverage.
func TestManufacturingElementsAreNotLabelledAsCERTIn(t *testing.T) {
	for _, f := range hbom.ComponentFormFields() {
		isManufacturing := strings.HasPrefix(f.FieldID, "axebom.hbom.mfg.")
		if isManufacturing && f.CertIn {
			t.Errorf("%q is an AxeBOM operational element but is flagged as CERT-In", f.Attr)
		}
		if !isManufacturing && !f.CertIn {
			t.Errorf("%q is a CERT-In element but is not flagged as one", f.Attr)
		}
	}
}

// TestNoTwoInputsWriteTheSameColumn.
//
// ⚠ `mfg.04.description` DELIBERATELY SHARES CERT-In ELEMENT 3'S COLUMN. The
// profile says so, to avoid splitting one fact in two and halving element 3's
// coverage. Two inputs bound to one column is a form that silently discards
// whichever the customer filled in second.
func TestNoTwoInputsWriteTheSameColumn(t *testing.T) {
	seen := map[string]string{}
	for _, f := range hbom.ComponentFormFields() {
		if prev, dup := seen[f.Attr]; dup {
			t.Errorf("two inputs write %q (%s and %s); one would silently overwrite the other",
				f.Attr, prev, f.FieldID)
		}
		seen[f.Attr] = f.FieldID
	}
}

// A closed value set must reach the form, or a customer types "EOL " into a
// field whose entire value is that it is comparable across parts.
func TestTheOperationalEnumsCarryTheirValues(t *testing.T) {
	for _, f := range hbom.ComponentFormFields() {
		if f.Attr == "assembly_type" || f.Attr == "lifecycle_status" {
			if len(f.Values) == 0 {
				t.Errorf("%q is an enum in the profile but renders as free text", f.Attr)
			}
		}
	}
}

// TestCriticalityComesFromTheProfileAndNowhereElse.
//
// ⚠ ONE CLOSED SET HAD FOUR HAND-WRITTEN COPIES AND TWO OF THEM DISAGREED.
//
//   - hbom.Criticalities (the device form)      {critical, high, medium, low, unknown}
//   - hbom.CriticalityValues (the component validator)  {critical, high, medium, low}
//   - a sentence inside a validation error       "critical, high, medium, low"
//   - workers/hbom/model.py CRITICALITY_VALUES   ("critical","high","medium","low")
//
// The first carried a fifth value beneath a comment reading "⚠ IT MUST MATCH
// normalize.hardware_components.criticality" — a table whose CHECK allows four.
// So a device recorded as `unknown` was storable and unrepresentable in the
// parts table its tree flows into: the comment named the exact invariant the
// line below it broke.
//
// They multiplied because `axebom profile gen` DROPPED the profile's values
// list, leaving every consumer to write its own. The generator emits it now, so
// this asserts the single source rather than the four agreeing by luck.
func TestCriticalityComesFromTheProfileAndNowhereElse(t *testing.T) {
	var want []string
	for _, f := range model.HBOMFields {
		if f.ID == model.FieldCertinHbom23Criticality {
			want = f.Values
		}
	}
	if len(want) == 0 {
		t.Fatal("the profile declares no criticality values; every consumer below " +
			"would fall back to an empty set and accept anything")
	}

	if len(hbom.Criticalities) != len(want) {
		t.Errorf("the device form offers %v, the profile declares %v",
			hbom.Criticalities, want)
	}
	for _, v := range want {
		if !hbom.CriticalityValues[v] {
			t.Errorf("the component validator rejects %q, which the profile allows", v)
		}
	}
	// And nothing extra — the direction that actually broke. `unknown` was
	// accepted here and rejected by normalize.hardware_components' CHECK.
	if len(hbom.CriticalityValues) != len(want) {
		t.Errorf("the component validator accepts %d values, the profile declares %d",
			len(hbom.CriticalityValues), len(want))
	}
}

// TestTheOperationalEnumsComeFromTheProfile.
//
// The same fix, applied where the same mistake was about to be repeated: the
// manufacturing enums were briefly a hand-written Go map for exactly the reason
// criticality was, and are now read from the generated operational set.
func TestTheOperationalEnumsComeFromTheProfile(t *testing.T) {
	fromProfile := map[string][]string{}
	for _, f := range model.HBOMManufacturingFields {
		if len(f.Values) > 0 {
			attr := strings.TrimPrefix(f.CanonicalPath, "hardware_component.")
			fromProfile[attr] = f.Values
		}
	}
	if len(fromProfile) == 0 {
		t.Fatal("the operational profile declares no enum values at all")
	}

	byAttr := map[string]hbom.ComponentFormField{}
	for _, f := range hbom.ComponentFormFields() {
		byAttr[f.Attr] = f
	}
	for attr, want := range fromProfile {
		got := byAttr[attr].Values
		if len(got) != len(want) {
			t.Errorf("%s: the form offers %v, the profile declares %v", attr, got, want)
		}
	}
}
