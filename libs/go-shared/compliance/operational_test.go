package compliance

import (
	"path/filepath"
	"strings"
	"testing"
)

func operationalProfilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "docs", "reference", "hbom-manufacturing-v1.yaml")
}

func loadOperationalProfile(t *testing.T) *Profile {
	t.Helper()
	p, err := Load(operationalProfilePath(t))
	if err != nil {
		t.Fatalf("load operational profile: %v", err)
	}
	return p
}

// The operational profile must lint clean under the SAME checker as the
// compliance one. A second field set nothing validates is a second field set
// that drifts.
func TestOperationalProfileLintsClean(t *testing.T) {
	res := Lint(loadOperationalProfile(t))
	for _, p := range res.Problems {
		t.Errorf("%s", p)
	}
	t.Logf("%d fields, %d count assertions matched", res.FieldCount, res.CountsOK)
}

// TestOperationalFieldsNeverReachACertInAccessor is the test the whole
// file-and-key split exists to make possible.
//
// ⚠ IT ASSERTS AN ABSENCE, WHICH IS THE ONLY KIND OF ASSERTION THAT WORKS HERE.
// The danger is not that some code deliberately scores a manufacturing field
// as CERT-In; it is that a future edit widens an accessor and nothing notices,
// because the number it produces still looks plausible. Every accessor that
// feeds completeness_pct, the generated models, the guardrail counts or the
// evidence pack is checked here against BOTH profiles.
func TestOperationalFieldsNeverReachACertInAccessor(t *testing.T) {
	certin := loadProfile(t)
	operational := loadOperationalProfile(t)

	mfgIDs := map[string]bool{}
	for _, f := range operational.HBOMManufacturing.Elements {
		mfgIDs[f.ID] = true
	}
	if len(mfgIDs) == 0 {
		t.Fatal("operational profile defines no fields; this test would pass vacuously")
	}

	for _, p := range []*Profile{certin, operational} {
		for _, bomType := range []string{"SBOM", "QBOM", "AIBOM", "HBOM"} {
			for _, f := range p.FieldsForBOMType(bomType) {
				if mfgIDs[f.ID] {
					t.Errorf("FieldsForBOMType(%q) returned operational field %s — it would "+
						"be scored into completeness_pct and generated into the models",
						bomType, f.ID)
				}
			}
		}

		// ActualCounts feeds the guardrail's "never write a field count"
		// audit. A manufacturing element landing in a CERT-In count would make
		// the guardrail police the wrong number.
		counts := p.ActualCounts()
		if counts["hbom_table11_elements"]+counts["hbom_additional_required_elements"] !=
			counts["hbom_total_elements"] {
			t.Errorf("HBOM counts no longer add up; an operational field may have leaked in")
		}
	}

	// The CERT-In profile must not define the operational section at all, and
	// vice versa — otherwise one file could quietly acquire the other's fields.
	if len(certin.HBOMManufacturing.Elements) != 0 {
		t.Error("certin-v2.0.yaml defines hbom_manufacturing; the compliance profile " +
			"must stay free of AxeBOM operational fields")
	}
	if len(operational.HBOM.Elements) != 0 {
		t.Error("the operational profile defines a CERT-In hbom section; every accessor " +
			"in this package would read those as a standard's requirements")
	}
}

// TestOperationalFieldIDsAreDisjointFromCertIn guards the other direction: an
// id collision would make a duplicate-id lint failure the only warning, and
// only if both files were ever linted together.
func TestOperationalFieldIDsAreDisjointFromCertIn(t *testing.T) {
	certinIDs := map[string]bool{}
	for _, f := range loadProfile(t).AllFields() {
		certinIDs[f.ID] = true
	}
	for _, f := range loadOperationalProfile(t).HBOMManufacturing.Elements {
		if certinIDs[f.ID] {
			t.Errorf("operational field %s collides with a CERT-In field id", f.ID)
		}
		if !strings.HasPrefix(f.ID, "axebom.") {
			t.Errorf("operational field %s must carry the axebom. prefix that marks it "+
				"as ours rather than the standard's", f.ID)
		}
	}
}

// TestAScoredExtensionPassesOnlyInAnOperationalProfile pins the one lint rule
// that INVERTS between the two kinds, in both directions.
//
// A rule that only ever fires one way is a rule whose other branch is
// untested, and this particular other branch is what lets manufacturing
// fields be scored at all.
func TestAScoredExtensionPassesOnlyInAnOperationalProfile(t *testing.T) {
	scored := Field{
		ID: "axebom.test.01.thing", Name: "Thing",
		CanonicalPath: "hardware_component.thing", Weight: 1, Status: "extension",
	}

	operational := loadOperationalProfile(t)
	operational.HBOMManufacturing.Elements = append(operational.HBOMManufacturing.Elements, scored)
	operational.ExpectedCounts = nil // the count assertion is not what is under test
	if problems := problemsMentioning(Lint(operational), "scored: false"); len(problems) > 0 {
		t.Errorf("an operational profile must permit a scored extension; got %v", problems)
	}

	certin := loadProfile(t)
	certin.AIBOM.AxeBOMExtensions = append(certin.AIBOM.AxeBOMExtensions, scored)
	if problems := problemsMentioning(Lint(certin), "scored: false"); len(problems) == 0 {
		t.Error("a compliance profile must still refuse a scored extension; scoring our " +
			"own analysis would move a number a regulator reads")
	}
}

// TestAnOperationalProfileWithACertInSectionFailsLint proves the structural
// guard fires. Without it the separation would rest on nobody ever adding an
// `hbom:` block to the operational file.
func TestAnOperationalProfileWithACertInSectionFailsLint(t *testing.T) {
	p := loadOperationalProfile(t)
	p.HBOM.Elements = []Field{{
		ID: "certin.hbom.01.product_name", Name: "Product Name",
		CanonicalPath: "hardware_component.product_name", Weight: 3, Status: "verified",
	}}
	if problems := problemsMentioning(Lint(p), "must not define CERT-In sections"); len(problems) == 0 {
		t.Error("an operational profile defining a CERT-In section must fail lint; its " +
			"fields would otherwise be read as a standard's by every accessor here")
	}
}

// TestAnOperationalProfileMayNotClaimVerification — all_entries_verified is a
// claim about transcription from a source document. There is no document.
func TestAnOperationalProfileMayNotClaimVerification(t *testing.T) {
	p := loadOperationalProfile(t)
	p.Meta.AllEntriesVerified = true
	if problems := problemsMentioning(Lint(p), "provenance claim"); len(problems) == 0 {
		t.Error("all_entries_verified on a profile with no source document must fail lint")
	}
}

// TestAnOperationalFieldMayNotCiteASourcePage — a page number promises an
// auditor can open it and check.
func TestAnOperationalFieldMayNotCiteASourcePage(t *testing.T) {
	p := loadOperationalProfile(t)
	p.HBOMManufacturing.Elements[0].SourcePage = 61
	if problems := problemsMentioning(Lint(p), "implies a citation nobody can check"); len(problems) == 0 {
		t.Error("a source_page on an operational field must fail lint")
	}
}

// TestKindDefaultsToCompliance — the safe direction. A profile that forgets to
// declare its kind is held to every compliance check rather than escaping them.
func TestKindDefaultsToCompliance(t *testing.T) {
	if !(Meta{}).IsCompliance() {
		t.Error("an undeclared kind must mean compliance; the permissive default would " +
			"let a new profile skip every check by omission")
	}
	if !(Meta{Kind: "compliance"}).IsCompliance() {
		t.Error(`kind "compliance" must be compliance`)
	}
	if (Meta{Kind: "operational"}).IsCompliance() {
		t.Error(`kind "operational" must not be compliance`)
	}
}

func problemsMentioning(res LintResult, substr string) []string {
	var out []string
	for _, p := range res.Problems {
		if strings.Contains(p.String(), substr) {
			out = append(out, p.String())
		}
	}
	return out
}
