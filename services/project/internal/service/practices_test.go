package service_test

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/service"
	"github.com/axebom/axebom/services/project/internal/store"
)

// CERT-In "Practices and Processes" — the commonly-missed minimum element.
//
// "Minimum Elements" is THREE categories, not just the 21 data fields. A tool
// that implements only the data fields and claims CERT-In compliance is
// overstating, and these tests are what stop this product from doing that.

func ptr(s string) *string { return &s }

// ⚠ THE GAP TEST the phase requires.
//
// A project missing practices must report a compliance gap NOW, at registration
// — not surface it as a coverage surprise when a report is generated in Phase 9.
func TestProjectWithNoPracticesReportsEveryGap(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	report, err := f.svc.GetPractices(t.Context(), tenantA, p.ID)
	if err != nil {
		t.Fatalf("get practices: %v", err)
	}

	if report.Complete {
		t.Error("a project with no practices reported as complete")
	}
	if report.Recorded != 0 {
		t.Errorf("recorded = %d, want 0", report.Recorded)
	}
	// The total comes FROM THE PROFILE. Asserting against len(model.PracticeFields)
	// rather than a literal is the point: writing the number here would be the
	// same mistake as hardcoding it in the product.
	if report.Total != len(model.PracticeFields) {
		t.Errorf("total = %d, want %d (from the compliance profile)",
			report.Total, len(model.PracticeFields))
	}
	if len(report.Gaps) != report.Total {
		t.Fatalf("got %d gaps, want one per unrecorded sub-element (%d)",
			len(report.Gaps), report.Total)
	}

	// Every profile sub-element must be named in the gaps, so the UI can point
	// at the specific field rather than saying "something is missing".
	named := map[string]bool{}
	for _, g := range report.Gaps {
		named[g.FieldID] = true
		if g.Name == "" || g.Reason == "" {
			t.Errorf("gap %s has no name or reason: %+v", g.FieldID, g)
		}
	}
	for _, f := range model.PracticeFields {
		if !named[f.ID] {
			t.Errorf("sub-element %s (%s) is not reported as a gap", f.ID, f.Name)
		}
	}
}

// Practices must persist and come back with the project.
func TestPracticesPersistAndRoundTrip(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	in := service.PracticesInput{
		Frequency:     ptr("weekly, every Monday 02:00 UTC"),
		Depth:         ptr("complete"),
		KnownUnknowns: ptr("Firmware blobs in vendor/ are not analysable."),
		Distribution:  ptr("Published to the customer portal on release."),
		AccessControl: ptr("private"),
		ErrataPolicy:  ptr("Corrections re-normalized into a new BOM version."),
	}

	saved, err := f.svc.SetPractices(t.Context(), tenantA, p.ID, in)
	if err != nil {
		t.Fatalf("set practices: %v", err)
	}
	if !saved.Complete {
		t.Errorf("all six recorded but reported incomplete; gaps: %+v", saved.Gaps)
	}
	if saved.Recorded != saved.Total {
		t.Errorf("recorded %d of %d", saved.Recorded, saved.Total)
	}

	read, err := f.svc.GetPractices(t.Context(), tenantA, p.ID)
	if err != nil {
		t.Fatalf("get practices: %v", err)
	}
	if read.Practices.Frequency == nil || *read.Practices.Frequency != *in.Frequency {
		t.Errorf("frequency did not round-trip: %v", read.Practices.Frequency)
	}
	if read.Practices.AccessControl == nil || *read.Practices.AccessControl != "private" {
		t.Errorf("access_control did not round-trip: %v", read.Practices.AccessControl)
	}
	if !read.Complete {
		t.Error("a fully-recorded project read back as incomplete")
	}
}

// ⚠ CLAUDE.md INVARIANT 3.
//
// `not-provided` is REPORTED but never counts as COVERED. Treating a
// declaration as coverage is exactly how a tool ships a misleading 100%.
func TestDeclaredButUnsubstantiveValuesDoNotCountAsCovered(t *testing.T) {
	for _, declared := range []string{
		model.NotProvided, "NOASSERTION", "unknown", "n/a", "", "  ", "[]", "None",
	} {
		t.Run(declared, func(t *testing.T) {
			report := service.EvaluatePractices(store.Practices{
				Frequency:     &declared,
				Depth:         ptr("complete"),
				KnownUnknowns: ptr("real narrative"),
				Distribution:  ptr("real narrative"),
				AccessControl: ptr("private"),
				ErrataPolicy:  ptr("real narrative"),
			})

			if report.Complete {
				t.Errorf("%q was counted as substantive coverage", declared)
			}
			if report.Recorded != report.Total-1 {
				t.Errorf("recorded = %d, want %d — only frequency should fail",
					report.Recorded, report.Total-1)
			}

			var found bool
			for _, g := range report.Gaps {
				if g.FieldID == model.FieldCertinSbomPpFrequency {
					found = true
					if g.Reason == "" {
						t.Error("the gap does not say why the value does not count")
					}
				}
			}
			if !found {
				t.Errorf("%q produced no gap for frequency", declared)
			}
		})
	}
}

// A substantive value must count. The inverse of the test above — without it,
// a bug that scored everything zero would pass the invariant-3 test perfectly.
func TestSubstantiveValuesCount(t *testing.T) {
	report := service.EvaluatePractices(store.Practices{
		Frequency:     ptr("nightly"),
		Depth:         ptr("top_level"),
		KnownUnknowns: ptr("Two ecosystems have no available engine."),
		Distribution:  ptr("Customer portal."),
		AccessControl: ptr("public"),
		ErrataPolicy:  ptr("Re-normalize and re-issue."),
	})
	if !report.Complete {
		t.Errorf("fully-recorded practices reported incomplete; gaps: %+v", report.Gaps)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("gaps on a complete record: %+v", report.Gaps)
	}
}

// Depth is validated against the PROFILE's levels (CERT-In §3.1), never a
// hardcoded list — so a profile revision cannot silently disagree.
func TestDepthIsValidatedAgainstTheProfile(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	for _, level := range model.BOMLevels {
		if _, err := f.svc.SetPractices(t.Context(), tenantA, p.ID,
			service.PracticesInput{Depth: ptr(level)}); err != nil {
			t.Errorf("profile level %q was rejected: %v", level, err)
		}
	}

	_, err := f.svc.SetPractices(t.Context(), tenantA, p.ID,
		service.PracticesInput{Depth: ptr("very_deep")})
	if err == nil {
		t.Error("a depth outside the profile was accepted")
	}
	if !errs.Is(err, errs.ValidationFieldInvalid) {
		t.Errorf("code = %v, want VALIDATION_FIELD_INVALID", err)
	}
}

// CERT-In §5.3.2 requires BOTH a public and a private version be maintainable,
// so this field records which one this project's BOM is. Anything else is a
// value the reports cannot render.
func TestAccessControlAcceptsOnlyPublicOrPrivate(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	for _, v := range []string{"public", "private"} {
		if _, err := f.svc.SetPractices(t.Context(), tenantA, p.ID,
			service.PracticesInput{AccessControl: ptr(v)}); err != nil {
			t.Errorf("%q was rejected: %v", v, err)
		}
	}
	if _, err := f.svc.SetPractices(t.Context(), tenantA, p.ID,
		service.PracticesInput{AccessControl: ptr("internal")}); err == nil {
		t.Error("an access_control value outside the profile was accepted")
	}
}

// Phase 8 auto-populates known_unknowns from engine-coverage gaps, so it starts
// empty rather than being pre-filled with a placeholder that would score as
// covered and hide the very gap it is meant to declare.
func TestKnownUnknownsStartsEmpty(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	report, err := f.svc.GetPractices(t.Context(), tenantA, p.ID)
	if err != nil {
		t.Fatalf("get practices: %v", err)
	}
	if report.Practices.KnownUnknowns != nil {
		t.Errorf("known_unknowns was seeded with %q; Phase 8 populates it from "+
			"engine-coverage gaps, and a placeholder would score as covered",
			*report.Practices.KnownUnknowns)
	}
}

// Partially-recorded practices report exactly the missing ones — the UI needs
// to point at fields, not say "incomplete".
func TestPartialPracticesReportOnlyTheMissingSubElements(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	report, err := f.svc.SetPractices(t.Context(), tenantA, p.ID, service.PracticesInput{
		Frequency: ptr("weekly"),
		Depth:     ptr("complete"),
	})
	if err != nil {
		t.Fatalf("set practices: %v", err)
	}

	if report.Recorded != 2 {
		t.Errorf("recorded = %d, want 2", report.Recorded)
	}
	if report.Complete {
		t.Error("a partially-recorded project reported as complete")
	}
	if len(report.Gaps) != report.Total-2 {
		t.Errorf("got %d gaps, want %d", len(report.Gaps), report.Total-2)
	}
	for _, g := range report.Gaps {
		if g.FieldID == model.FieldCertinSbomPpFrequency ||
			g.FieldID == model.FieldCertinSbomPpDepth {
			t.Errorf("%s is recorded but reported as a gap", g.FieldID)
		}
	}
}

// Every profile sub-element must have a Go binding. A field added to the
// profile with no binding would otherwise be silently skipped in scoring,
// inflating the result after a CERT-In revision.
func TestEveryProfileSubElementHasABinding(t *testing.T) {
	// Fill every field with a substantive value. If a sub-element has no
	// binding, EvaluatePractices reports it as a gap and this fails.
	report := service.EvaluatePractices(store.Practices{
		Frequency:     ptr("nightly"),
		Depth:         ptr("complete"),
		KnownUnknowns: ptr("narrative"),
		Distribution:  ptr("narrative"),
		AccessControl: ptr("private"),
		ErrataPolicy:  ptr("narrative"),
	})

	for _, g := range report.Gaps {
		t.Errorf("profile sub-element %s (%s) has no binding in the product: %s\n"+
			"    Add it to practiceValue() in practices.go, and to the "+
			"project.practices table if it needs a column.",
			g.FieldID, g.Name, g.Reason)
	}
}
