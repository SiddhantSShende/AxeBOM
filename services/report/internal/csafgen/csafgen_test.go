package csafgen_test

import (
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/vex"
	"github.com/axebom/axebom/services/report/internal/csafgen"
)

func baseInput(status vex.Status) csafgen.Input {
	return csafgen.Input{
		Statement: vex.Statement{
			Status:        status,
			Scope:         vex.ScopeComponent,
			Justification: "component_not_present",
			Remediation:   "upgrade to 2.1.0",
		},
		TenantName:       "Acme Corp",
		ClusterDisplayID: "CVE-2024-12345",
		ClusterAliases:   []string{"GHSA-xxxx-yyyy-zzzz"},
		ComponentName:    "left-pad",
		ComponentPURL:    "pkg:npm/left-pad@1.3.0",
		TrackingID:       "AXEBOM-VEX-TEST-1",
		Now:              time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
	}
}

// TestGenerateAlwaysProducesAValidDocument — the one property this package
// exists to guarantee, for every status the four-value CERT-In enum allows.
func TestGenerateAlwaysProducesAValidDocument(t *testing.T) {
	for _, status := range vex.Statuses() {
		t.Run(string(status), func(t *testing.T) {
			doc := csafgen.Generate(baseInput(status))
			if problems := doc.Validate(); len(problems) > 0 {
				t.Fatalf("Generate(%s) produced an invalid document: %v", status, problems)
			}
		})
	}
}

// TestGenerateForAProjectScopedStatementStillValidates — no ComponentName,
// the case vex.Statement's own doc comment says is legitimate for a
// project-scoped statement (ComponentKey, and therefore ComponentName, is
// empty).
func TestGenerateForAProjectScopedStatementStillValidates(t *testing.T) {
	in := baseInput(vex.StatusAffected)
	in.ComponentName = ""
	in.ComponentPURL = ""

	doc := csafgen.Generate(in)
	if problems := doc.Validate(); len(problems) > 0 {
		t.Fatalf("project-scoped Generate produced an invalid document: %v", problems)
	}
}

// TestKnownNotAffectedAlwaysCarriesTheImpactStatement — Validate refuses a
// known_not_affected declaration with no impact statement; vex.Validate
// separately refuses a not_affected VEX statement with no justification, so
// Generate must always have one to carry forward. Proven directly rather
// than trusted, since the two refusals living in two different packages is
// exactly the kind of invariant that silently breaks if one side changes.
func TestKnownNotAffectedAlwaysCarriesTheImpactStatement(t *testing.T) {
	doc := csafgen.Generate(baseInput(vex.StatusNotAffected))
	if len(doc.Vulns) != 1 || len(doc.Vulns[0].Threats) == 0 {
		t.Fatalf("known_not_affected document has no threats/impact statement: %+v", doc.Vulns)
	}
	if doc.Vulns[0].Threats[0].Details == "" {
		t.Error("the impact statement is empty")
	}
}

// TestPublisherIsTheTenantNeverAxeBOM — CSAF's publisher is who ISSUES the
// advisory (the customer), not the tool that generated it.
func TestPublisherIsTheTenantNeverAxeBOM(t *testing.T) {
	doc := csafgen.Generate(baseInput(vex.StatusAffected))
	if doc.DocumentMeta.Publisher.Name != "Acme Corp" {
		t.Errorf("publisher.name = %q, want the tenant's own name", doc.DocumentMeta.Publisher.Name)
	}
}

// TestCVEIsExtractedOnlyWhenTheDisplayIDLooksLikeOne — a GHSA-only cluster
// (no CVE assigned) must not be misrepresented as one.
func TestCVEIsExtractedOnlyWhenTheDisplayIDLooksLikeOne(t *testing.T) {
	in := baseInput(vex.StatusAffected)
	in.ClusterDisplayID = "GHSA-xxxx-yyyy-zzzz"
	in.ClusterAliases = nil

	doc := csafgen.Generate(in)
	if doc.Vulns[0].CVE != "" {
		t.Errorf("CVE = %q, want empty for a GHSA-only cluster", doc.Vulns[0].CVE)
	}
	if len(doc.Vulns[0].IDs) == 0 {
		t.Error("the GHSA id must still be carried as an id, not silently dropped")
	}
	if problems := doc.Validate(); len(problems) > 0 {
		t.Fatalf("GHSA-only document is invalid: %v", problems)
	}
}
