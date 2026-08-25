package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// profileWithCounts builds a minimal profile whose counts are known.
func profileWithCounts(t *testing.T) *Profile {
	t.Helper()
	p := &Profile{}
	for range 21 {
		p.SBOM.DataFields = append(p.SBOM.DataFields, Field{})
	}
	for range 19 {
		p.AIBOM.Elements = append(p.AIBOM.Elements, Field{})
	}
	for range 11 {
		p.QBOM.Elements = append(p.QBOM.Elements, Field{})
	}
	for range 20 {
		p.HBOM.Elements = append(p.HBOM.Elements, Field{})
	}
	for range 4 {
		p.HBOM.AdditionalRequiredElements.Elements = append(
			p.HBOM.AdditionalRequiredElements.Elements, Field{})
	}
	return p
}

// audit runs the guardrails over one synthetic file.
func audit(t *testing.T, name, body string) []GuardrailFinding {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "services")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := AuditGeneratedOutput(profileWithCounts(t), root, []string{"services"})
	if err != nil {
		t.Fatal(err)
	}
	return report.Findings
}

// ---------------------------------------------------------------------------
// It catches what it claims to
// ---------------------------------------------------------------------------

// TestAHardcodedFieldCountIsCaught.
//
// ⚠ THIS IS THE CHECK'S REASON TO EXIST. Writing the count means the literal
// stops matching the profile when CERT-In revises the guideline — and nothing
// fails when it does. The report simply states a number that is wrong.
func TestAHardcodedFieldCountIsCaught(t *testing.T) {
	cases := map[string]string{
		"count phrase":     `label := "All 21 data fields are present"`,
		"element phrase":   `note := "19 elements were checked"`,
		"count assignment": `fieldCount := 21`,
		"expected total":   `expectedTotal = 24`,
	}

	for name, line := range cases {
		findings := audit(t, "x.go", "package x\n\nfunc f() {\n\t"+line+"\n}\n")
		if len(findings) == 0 {
			t.Errorf("%s: %q was not caught", name, line)
			continue
		}
		if findings[0].Rule != "hardcoded-field-count" {
			t.Errorf("%s: rule = %q", name, findings[0].Rule)
		}
		if !strings.Contains(findings[0].Why, "len(") {
			t.Errorf("%s: the finding does not say what to do instead", name)
		}
	}
}

// TestAnAssertionOfComplianceIsCaught.
//
// ⚠ AxeBOM REPORTS VIOLATIONS AGAINST A CONFIGURED POLICY. Compliance is a
// determination an auditor makes about an organisation, and a customer will
// quote our word for it — in good faith — to somebody who holds them to it.
func TestAnAssertionOfComplianceIsCaught(t *testing.T) {
	for _, line := range []string{
		`title := "Your SBOM is compliant"`,
		`status := "compliance status: passing"`,
		`return "This report certifies the project is compliant."`,
	} {
		findings := audit(t, "x.go", "package x\n\nfunc f() {\n\t"+line+"\n}\n")
		if len(findings) == 0 {
			t.Errorf("%q was not caught", line)
			continue
		}
		if findings[0].Rule != "asserts-compliance" {
			t.Errorf("%q produced rule %q", line, findings[0].Rule)
		}
	}
}

// ---------------------------------------------------------------------------
// It does not cry wolf — every case here was a real false positive
// ---------------------------------------------------------------------------

// TestOrdinalsAreNotCounts.
//
// ⚠ "§4.2 field 21" NAMES THE UNIQUE IDENTIFIER. It is CERT-In's own numbering,
// it is correct, and rewriting it would be wrong. An earlier version of this
// check flagged eight of these plus every `Ordinal:` in the generated profile —
// nine findings, nine false positives, which is exactly how a check gets
// switched off and its absence becomes invisible.
func TestOrdinalsAreNotCounts(t *testing.T) {
	for _, line := range []string{
		`note := "CERT-In §4.2 field 21 writes the qualifier separator differently"`,
		`hint := "Table 11 records both supplier relationships"`,
		`f := ProfileField{Ordinal: 21, Name: "Unique Identifier"}`,
		`f := ProfileField{Ordinal: 19, Name: "Archive Property"}`,
	} {
		if findings := audit(t, "x.go", "package x\n\nfunc f() {\n\t"+line+"\n}\n"); len(findings) > 0 {
			t.Errorf("an ordinal was flagged as a count: %q\n  %s", line, findings[0])
		}
	}
}

// TestUnrelatedNumbersAreNotCounts — every one of these was a real false
// positive from the first version.
func TestUnrelatedNumbersAreNotCounts(t *testing.T) {
	for _, line := range []string{
		`pageWidth = 210.0`,
		`cacheTTL := 24 * 3600`,
		`components := 21`,
		`port := 8021`,
		`if status == 419 {`,
	} {
		if findings := audit(t, "x.go", "package x\n\nfunc f() {\n\t"+line+"\n}\n"); len(findings) > 0 {
			t.Errorf("an unrelated number was flagged: %q\n  %s", line, findings[0])
		}
	}
}

// TestDerivingTheCountFromTheProfileIsTheCorrectForm.
func TestDerivingTheCountFromTheProfileIsTheCorrectForm(t *testing.T) {
	body := "package x\n\nfunc f() {\n\t" +
		`msg := fmt.Sprintf("%d data fields", len(model.SBOMFields))` + "\n}\n"
	if findings := audit(t, "x.go", body); len(findings) > 0 {
		t.Errorf("the correct form was flagged: %s", findings[0])
	}
}

// TestCommentsExplainingTheRuleAreNotViolationsOfIt.
//
// ⚠ THE FIRST VERSION FLAGGED ITS OWN DOCUMENTATION, including two comments
// describing these rules. A check that flags the explanation of itself is
// unenforceable, so somebody deletes it.
func TestCommentsExplainingTheRuleAreNotViolationsOfIt(t *testing.T) {
	body := `package x

// The profile has 21 data fields today. Never write that number: render it
// from len(model.SBOMFields), because a literal stops matching when CERT-In
// revises the guideline and nothing fails when it does.

/*
 * A report must never say the project is compliant. We report violations
 * against a configured policy; compliance is an auditor's determination.
 */

func f() {}
`
	if findings := audit(t, "x.go", body); len(findings) > 0 {
		t.Errorf("a comment explaining the rule was flagged: %s", findings[0])
	}
}

func TestPythonDocstringsAreNotViolations(t *testing.T) {
	body := `"""A module docstring.

It mentions 21 data fields, and says a report must never call a project
compliant, because both are the rules this module enforces.
"""


def f():
    pass
`
	if findings := audit(t, "x.py", body); len(findings) > 0 {
		t.Errorf("a docstring was flagged: %s", findings[0])
	}
}

func TestAThirdPartyMarkingIsNotOurClaim(t *testing.T) {
	// RoHS and CE are a manufacturer's assertion about a part, carried verbatim
	// from a datasheet. Ours to report; not ours to make.
	for _, line := range []string{
		`compliance := []string{"RoHS compliant"}`,
		`label := "CE-compliant per the manufacturer's datasheet"`,
	} {
		if findings := audit(t, "x.go", "package x\n\nfunc f() {\n\t"+line+"\n}\n"); len(findings) > 0 {
			t.Errorf("a third-party marking was flagged: %q", line)
		}
	}
}

func TestAnIdentifierIsNotAClaim(t *testing.T) {
	// `complianceProfile` is a variable name, not something a customer reads.
	body := "package x\n\nfunc f() {\n\tcomplianceProfile := load()\n\t_ = complianceProfile\n}\n"
	if findings := audit(t, "x.go", body); len(findings) > 0 {
		t.Errorf("an identifier was flagged: %s", findings[0])
	}
}

// ---------------------------------------------------------------------------
// The audit cannot pass vacuously
// ---------------------------------------------------------------------------

// TestAnEmptyAuditIsAnError.
//
// ⚠ A CHECK THAT SCANNED NOTHING PASSES, and a passing check that proves
// nothing is worse than no check — it is a green tick that somebody trusts.
func TestAnEmptyAuditIsAnError(t *testing.T) {
	_, err := AuditGeneratedOutput(profileWithCounts(t), t.TempDir(), []string{"nowhere"})
	if err == nil {
		t.Fatal("auditing zero files reported success")
	}
	if !strings.Contains(err.Error(), "proves nothing") {
		t.Errorf("the error does not say why it matters: %v", err)
	}
}

func TestTestFilesAreNotAudited(t *testing.T) {
	// They necessarily contain the literals and phrases the rules forbid, in
	// order to assert that production code does not — this file being the case
	// in point.
	root := t.TempDir()
	dir := filepath.Join(root, "services")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// ⚠ A REAL FILE ALONGSIDE THE TEST FILE. Auditing only a test file scans
	// zero files and trips the empty-audit guard — which is that guard working
	// correctly, and would make this test pass for entirely the wrong reason.
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	offending := "package x\n\nfunc f() {\n\tlabel := \"All 21 data fields present and compliant\"\n\t_ = label\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(offending), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := AuditGeneratedOutput(profileWithCounts(t), root, []string{"services"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 {
		t.Fatalf("scanned %d files, want 1 — the test file must be skipped", report.Scanned)
	}
	if len(report.Findings) > 0 {
		t.Errorf("a test file was audited: %s", report.Findings[0])
	}
}

func TestEveryBOMTypesCountIsChecked(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "services")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := AuditGeneratedOutput(profileWithCounts(t), root, []string{"services"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bomType := range []string{"SBOM", "AIBOM", "QBOM", "HBOM"} {
		if report.CountsChecked[bomType] == 0 {
			t.Errorf("%s's count is not being checked", bomType)
		}
	}
	if report.CountsChecked["HBOM"] != 24 {
		t.Errorf("HBOM count = %d; Table 11's 20 plus §10.4.1.4's 4 is 24",
			report.CountsChecked["HBOM"])
	}
}
