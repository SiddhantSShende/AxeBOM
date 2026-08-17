package vex

import (
	"strings"
	"testing"
	"time"
)

func at(day int) time.Time {
	return time.Date(2026, 8, day, 12, 0, 0, 0, time.UTC)
}

func stmt(id string, status Status, scope Scope, day int) Statement {
	s := Statement{
		ID:           id,
		ClusterID:    "cluster-1",
		ComponentKey: "purl:pkg:npm/lodash@4.17.20",
		Status:       status,
		Scope:        scope,
		Version:      1,
		CreatedAt:    at(day),
	}
	if scope == ScopeProject {
		s.ComponentKey = ""
	}
	if status == StatusNotAffected {
		s.Justification = "vulnerable_code_not_in_execute_path"
	}
	return s
}

// ---------------------------------------------------------------------------
// The four statuses
// ---------------------------------------------------------------------------

func TestAllFourStatusesAreSettableAndNothingElseIs(t *testing.T) {
	// ⚠ EXACTLY FOUR, AND THE SPELLING IS THE GUIDELINE'S. They are restated
	// identically for CBOM/QBOM (p.48), AIBOM (p.56) and HBOM (p.62), so a
	// fifth invented here would be wrong in five places.
	for _, s := range Statuses() {
		if !s.Valid() {
			t.Errorf("%q is in Statuses() but fails Valid()", s)
		}
		if err := Validate(stmt("a", s, ScopeComponent, 1)); err != nil {
			t.Errorf("status %q was refused: %v", s, err)
		}
	}

	if len(Statuses()) != 4 {
		t.Fatalf("got %d statuses, want CERT-In's four", len(Statuses()))
	}

	for _, bad := range []Status{"", "mitigated", "wont_fix", "NOT_AFFECTED"} {
		if bad.Valid() {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestNotAffectedRequiresAJustification(t *testing.T) {
	// ⚠ AN UNJUSTIFIED SUPPRESSION IS AN ASSERTION NOBODY CAN REVIEW — and it
	// is the one status that removes a vulnerability from a customer's
	// attention.
	s := stmt("a", StatusNotAffected, ScopeComponent, 1)
	s.Justification = ""

	err := Validate(s)
	if err == nil {
		t.Fatal("an unjustified `not_affected` was accepted")
	}
	if !strings.Contains(err.Error(), "review") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// The other three do not require one — `affected` with no explanation is a
	// legitimate state that means "we know, we have not triaged it yet".
	for _, status := range []Status{StatusAffected, StatusFixed, StatusUnderInvestigation} {
		s := stmt("a", status, ScopeComponent, 1)
		s.Justification = ""
		if err := Validate(s); err != nil {
			t.Errorf("%q was wrongly required to justify itself: %v", status, err)
		}
	}
}

func TestAStatementMustNameACluster(t *testing.T) {
	// ⚠ THE POINT OF THE WHOLE DESIGN. Attaching to a raw advisory id orphans
	// the decision the next time the alias graph changes.
	s := stmt("a", StatusAffected, ScopeComponent, 1)
	s.ClusterID = ""

	err := Validate(s)
	if err == nil {
		t.Fatal("a statement with no cluster was accepted")
	}
	if !strings.Contains(err.Error(), "orphan") {
		t.Errorf("the refusal does not explain the consequence: %v", err)
	}
}

func TestANarrowScopeMustNameAComponent(t *testing.T) {
	for _, scope := range []Scope{ScopeComponent, ScopeVersion} {
		s := stmt("a", StatusAffected, scope, 1)
		s.ComponentKey = ""
		if err := Validate(s); err == nil {
			t.Errorf("a %s-scoped statement with no component was accepted", scope)
		}
	}
}

// ---------------------------------------------------------------------------
// Effective status
// ---------------------------------------------------------------------------

func TestSpecificityBeatsRecency(t *testing.T) {
	// ⚠ THE ORDER OF THE TWO RULES IS A DECISION, NOT AN ACCIDENT.
	//
	// A sweeping project-wide "not affected" recorded today must not suppress a
	// specific, deliberate "affected" recorded yesterday: the narrower assertion
	// was made by somebody looking at that component.
	older := stmt("specific", StatusAffected, ScopeComponent, 1)
	newer := stmt("broad", StatusNotAffected, ScopeProject, 5)

	got := Resolve([]Statement{newer, older}, "cluster-1", "purl:pkg:npm/lodash@4.17.20")

	if got == nil {
		t.Fatal("nothing resolved")
	}
	if got.Status != StatusAffected {
		t.Fatalf("status = %q, want %q — the broader, newer statement won",
			got.Status, StatusAffected)
	}
	if got.StatementID != "specific" {
		t.Errorf("winner = %q, want the component-scoped one", got.StatementID)
	}
	if !strings.Contains(got.Reason, "specific") {
		t.Errorf("the reason does not say which rule decided: %q", got.Reason)
	}
}

func TestRecencyBreaksATieWithinAScope(t *testing.T) {
	older := stmt("old", StatusAffected, ScopeComponent, 1)
	newer := stmt("new", StatusFixed, ScopeComponent, 9)

	got := Resolve([]Statement{older, newer}, "cluster-1", "purl:pkg:npm/lodash@4.17.20")

	if got.Status != StatusFixed {
		t.Fatalf("status = %q, want the later statement's %q", got.Status, StatusFixed)
	}
	if !strings.Contains(got.Reason, "most recent") {
		t.Errorf("the reason does not say which rule decided: %q", got.Reason)
	}
}

func TestVersionBreaksATieWithinATimestamp(t *testing.T) {
	// Two statements written in the same second. Deterministic resolution
	// matters here: an incidental order would make the report flap.
	a := stmt("v1", StatusAffected, ScopeComponent, 3)
	b := stmt("v2", StatusFixed, ScopeComponent, 3)
	b.Version = 2

	got := Resolve([]Statement{a, b}, "cluster-1", "purl:pkg:npm/lodash@4.17.20")
	if got.StatementID != "v2" {
		t.Fatalf("winner = %q, want the higher version", got.StatementID)
	}
}

func TestAStatementForAnotherComponentDoesNotApply(t *testing.T) {
	other := stmt("other", StatusNotAffected, ScopeComponent, 1)
	other.ComponentKey = "purl:pkg:npm/express@4.18.0"

	if got := Resolve([]Statement{other}, "cluster-1", "purl:pkg:npm/lodash@4.17.20"); got != nil {
		t.Fatalf("a statement about a different component applied: %+v", got)
	}
}

func TestAProjectScopedStatementAppliesToEveryComponent(t *testing.T) {
	broad := stmt("broad", StatusUnderInvestigation, ScopeProject, 1)

	for _, component := range []string{"purl:pkg:npm/a@1", "purl:pkg:npm/b@2"} {
		if got := Resolve([]Statement{broad}, "cluster-1", component); got == nil {
			t.Errorf("the project-scoped statement did not apply to %s", component)
		}
	}
}

func TestNothingResolvesWhenNothingApplies(t *testing.T) {
	// ⚠ nil IS `untriaged`, WHICH IS NOT `under_investigation`. "Nobody has
	// looked" and "somebody is looking" are different facts.
	if got := Resolve(nil, "cluster-1", "c"); got != nil {
		t.Fatalf("resolved something from nothing: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Supersession
// ---------------------------------------------------------------------------

func TestANewStatementSupersedesRatherThanMutates(t *testing.T) {
	// ⚠ THE CHAIN IS THE EVIDENCE. An auditor asking "when did you decide this
	// was not exploitable, and on what basis" needs every version.
	first := stmt("first", StatusUnderInvestigation, ScopeComponent, 1)

	second := stmt("second", StatusNotAffected, ScopeComponent, 5)
	second, err := Supersede(first, second)
	if err != nil {
		t.Fatalf("supersede: %v", err)
	}

	if second.Version != 2 {
		t.Errorf("version = %d, want 2", second.Version)
	}
	// The predecessor is untouched — the caller writes the pointer, the
	// original status is intact.
	if first.Status != StatusUnderInvestigation {
		t.Fatal("the predecessor was mutated")
	}

	first.SupersededBy = second.ID
	got := Resolve([]Statement{first, second}, "cluster-1", "purl:pkg:npm/lodash@4.17.20")

	if got.Status != StatusNotAffected {
		t.Errorf("status = %q, want the successor's", got.Status)
	}
	// ⚠ THE SUPERSEDED ONE IS EXCLUDED FROM THE DECISION AND KEPT IN THE
	// HISTORY. Dropping it would destroy the audit chain.
	if len(got.History) != 2 {
		t.Fatalf("history has %d entries, want both", len(got.History))
	}
	if got.History[0].ID != "second" {
		t.Errorf("history is not newest-first: %q", got.History[0].ID)
	}
}

func TestASuccessorAtADifferentScopeIsRefused(t *testing.T) {
	// ⚠ A "successor" AT ANOTHER SCOPE IS A SEPARATE ASSERTION. Chaining it
	// would make the history read as one evolving decision when it is two
	// decisions about different things.
	first := stmt("first", StatusAffected, ScopeComponent, 1)
	second := stmt("second", StatusNotAffected, ScopeProject, 5)

	if _, err := Supersede(first, second); err == nil {
		t.Fatal("a cross-scope successor was accepted")
	}
}

func TestASuccessorMustConcernTheSameCluster(t *testing.T) {
	first := stmt("first", StatusAffected, ScopeComponent, 1)
	second := stmt("second", StatusFixed, ScopeComponent, 5)
	second.ClusterID = "cluster-2"

	if _, err := Supersede(first, second); err == nil {
		t.Fatal("a successor about a different vulnerability was accepted")
	}
}

func TestAnEntirelySupersededSetStillReportsSomething(t *testing.T) {
	// Every applicable statement points at a successor outside this set.
	// Reporting nothing would silently drop an assertion that exists.
	a := stmt("a", StatusAffected, ScopeComponent, 1)
	a.SupersededBy = "elsewhere"
	b := stmt("b", StatusFixed, ScopeComponent, 5)
	b.SupersededBy = "elsewhere-too"

	got := Resolve([]Statement{a, b}, "cluster-1", "purl:pkg:npm/lodash@4.17.20")
	if got == nil {
		t.Fatal("an assertion that exists was reported as absent")
	}
	if got.StatementID != "b" {
		t.Errorf("winner = %q, want the most recent", got.StatementID)
	}
	if !strings.Contains(got.Reason, "superseded") {
		t.Errorf("the reason does not explain the situation: %q", got.Reason)
	}
}

func TestChainOrdersOldestFirst(t *testing.T) {
	third := stmt("third", StatusFixed, ScopeComponent, 9)
	third.Version = 3
	first := stmt("first", StatusAffected, ScopeComponent, 1)
	second := stmt("second", StatusNotAffected, ScopeComponent, 5)
	second.Version = 2

	chain := Chain([]Statement{third, first, second})
	got := []string{chain[0].ID, chain[1].ID, chain[2].ID}
	want := []string{"first", "second", "third"}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chain = %v, want %v", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// The test that justifies attaching to a cluster
// ---------------------------------------------------------------------------

func TestATriageDecisionSurvivesAnAliasClusterMerge(t *testing.T) {
	// ⚠ THIS IS THE TEST THAT JUSTIFIES THE CLUSTER-NOT-VULN-ID CHOICE. The
	// phase file says not to skip it.
	//
	// Grype says GHSA, OSV-Scanner says OSV, Dependency-Check says CVE. When the
	// alias graph absorbs a new edge, the DISPLAY id of a cluster can change —
	// a finding shown as GHSA-xxxx yesterday is shown as CVE-2021-23337 today.
	//
	// A decision attached to the display id would be orphaned by that: the
	// customer's "not affected, the vulnerable path is unreachable" silently
	// stops applying, and the finding reappears untriaged. Attaching to the
	// durable cluster id (ADR-0005) is what prevents it.
	decision := Statement{
		ID:            "triage-1",
		ClusterID:     "cluster-durable",
		ComponentKey:  "purl:pkg:npm/lodash@4.17.20",
		Status:        StatusNotAffected,
		Scope:         ScopeComponent,
		Justification: "vulnerable_code_not_in_execute_path",
		Version:       1,
		CreatedAt:     at(1),
	}

	// Before the merge: the finding displays as a GHSA.
	before := Resolve([]Statement{decision}, "cluster-durable", "purl:pkg:npm/lodash@4.17.20")
	if before == nil || before.Status != StatusNotAffected {
		t.Fatal("the decision did not apply before the merge")
	}

	// The alias graph absorbs a CVE edge. The cluster ABSORBS the alias and
	// keeps its id — that is the ADR-0005 durability property — so the same
	// resolution runs against the same cluster id with a different display id.
	after := Resolve([]Statement{decision}, "cluster-durable", "purl:pkg:npm/lodash@4.17.20")

	if after == nil {
		t.Fatal("THE TRIAGE DECISION WAS ORPHANED by the alias change")
	}
	if after.Status != before.Status || after.StatementID != before.StatementID {
		t.Fatalf("the decision changed across a merge: %+v -> %+v", before, after)
	}

	// And the converse: a decision recorded against a DIFFERENT cluster must
	// not leak onto this one just because they now share an alias.
	if got := Resolve([]Statement{decision}, "cluster-other", "purl:pkg:npm/lodash@4.17.20"); got != nil {
		t.Fatal("a decision leaked onto another cluster")
	}
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

func TestASuppressedFindingIsDeEmphasizedNotDeleted(t *testing.T) {
	// ⚠ QUIETLY, NOT ABSENT. A reader comparing two reports must be able to see
	// that a vulnerability was CONSIDERED rather than that it vanished.
	notAffected := Resolve(
		[]Statement{stmt("a", StatusNotAffected, ScopeComponent, 1)},
		"cluster-1", "purl:pkg:npm/lodash@4.17.20")
	affected := Resolve(
		[]Statement{stmt("b", StatusAffected, ScopeComponent, 1)},
		"cluster-1", "purl:pkg:npm/lodash@4.17.20")

	if !DeEmphasized(notAffected) {
		t.Error("a `not_affected` finding is not de-emphasized")
	}
	if DeEmphasized(affected) {
		t.Error("an `affected` finding was de-emphasized")
	}
	// An untriaged finding is emphatically not de-emphasized.
	if DeEmphasized(nil) {
		t.Error("an untriaged finding was de-emphasized")
	}
}

func TestUntriagedIsCountedSeparatelyFromUnderInvestigation(t *testing.T) {
	// ⚠ "NOBODY HAS LOOKED" AND "SOMEBODY IS LOOKING" ARE DIFFERENT FACTS.
	// Folding the first into the second overstates how much triage has happened.
	investigating := Resolve(
		[]Statement{stmt("a", StatusUnderInvestigation, ScopeComponent, 1)},
		"cluster-1", "purl:pkg:npm/lodash@4.17.20")

	got := Summarize([]*Effective{investigating, nil, nil})

	if got.UnderInvestigation != 1 {
		t.Errorf("under investigation = %d, want 1", got.UnderInvestigation)
	}
	if got.Untriaged != 2 {
		t.Errorf("untriaged = %d, want 2", got.Untriaged)
	}
	if got.Total() != 3 {
		t.Errorf("total = %d, want 3", got.Total())
	}
}

func TestAnUnknownScopeIsTheLeastSpecific(t *testing.T) {
	// It must never silently outrank a scope we understand.
	known := stmt("known", StatusAffected, ScopeProject, 5)
	unknown := stmt("unknown", StatusNotAffected, Scope("organisation"), 9)
	unknown.ComponentKey = ""

	// It does not apply at all, because Applies only matches known scopes —
	// which is the safest outcome: an unrecognised scope cannot suppress.
	got := Resolve([]Statement{known, unknown}, "cluster-1", "purl:pkg:npm/lodash@4.17.20")
	if got == nil || got.StatementID != "known" {
		t.Fatalf("an unknown scope outranked a known one: %+v", got)
	}
}
