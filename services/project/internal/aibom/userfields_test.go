package aibom_test

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/project/internal/aibom"
)

func TestUserSuppliedFormFieldsIsExactlyFour(t *testing.T) {
	fields := aibom.UserSuppliedFormFields()
	if len(fields) != 4 {
		t.Fatalf("UserSuppliedFormFields() len = %d, want 4 — mirrors "+
			"workers/aibom/normalize/ai.py's USER_SUPPLIED_FIELDS", len(fields))
	}

	want := map[string]bool{
		model.FieldCertinAibom12SecurityRequirements: true,
		model.FieldCertinAibom15IntendedUsage:        true,
		model.FieldCertinAibom16OutOfScopeUsage:      true,
		model.FieldCertinAibom19Attestations:         true,
	}
	for _, f := range fields {
		if !want[f.FieldID] {
			t.Errorf("unexpected field in UserSuppliedFormFields: %s", f.FieldID)
		}
		if f.Name == "" || f.CanonicalPath == "" {
			t.Errorf("field %+v missing required metadata", f)
		}
		delete(want, f.FieldID)
	}
	if len(want) != 0 {
		t.Errorf("missing expected fields: %v", want)
	}
}

func TestIsUserSuppliedRejectsADiscoveredField(t *testing.T) {
	// ⚠ model_name (element 1) is discovered, not user-supplied — a caller
	// mistakenly treating it as editable here would let a Go handler accept
	// client input for a field the Python normalizer owns.
	if aibom.IsUserSupplied(model.FieldCertinAibom01ModelName) {
		t.Error("IsUserSupplied(model_name) = true, want false")
	}
	if !aibom.IsUserSupplied(model.FieldCertinAibom15IntendedUsage) {
		t.Error("IsUserSupplied(intended_usage) = false, want true")
	}
}

func TestApplyUserFieldsLeavesOtherEntriesUntouched(t *testing.T) {
	status := map[string]string{
		model.FieldCertinAibom01ModelName:  "provided",
		model.FieldCertinAibom09DataSource: aibom.NotProvided,
	}

	aibom.ApplyUserFields(status, aibom.UserFields{
		SecurityRequirements: "SOC 2 controls apply",
		IntendedUsage:        "",
		OutOfScopeUsage:      "not-provided",
		AttestationSignature: "sig-123",
	})

	if status[model.FieldCertinAibom01ModelName] != "provided" {
		t.Errorf("discovered field status changed: %+v", status)
	}
	if status[model.FieldCertinAibom09DataSource] != aibom.NotProvided {
		t.Errorf("discovered field status changed: %+v", status)
	}
	if status[model.FieldCertinAibom12SecurityRequirements] != "provided" {
		t.Errorf("security_requirements = %q, want provided", status[model.FieldCertinAibom12SecurityRequirements])
	}
	if status[model.FieldCertinAibom15IntendedUsage] != aibom.NotProvided {
		t.Errorf("intended_usage (empty) = %q, want not-provided", status[model.FieldCertinAibom15IntendedUsage])
	}
	// ⚠ A USER WHO TYPES "not-provided" HAS DECLARED THE GAP, AND IT STILL
	// SCORES ZERO — CLAUDE.md invariant 3.
	if status[model.FieldCertinAibom16OutOfScopeUsage] != aibom.NotProvided {
		t.Errorf("out_of_scope_usage (literal not-provided) = %q, want not-provided", status[model.FieldCertinAibom16OutOfScopeUsage])
	}
	if status[model.FieldCertinAibom19Attestations] != "provided" {
		t.Errorf("attestations = %q, want provided", status[model.FieldCertinAibom19Attestations])
	}
}
