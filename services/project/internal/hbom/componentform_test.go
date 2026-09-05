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
