package orchestr_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/axebom/axebom/libs/go-shared/vex"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// Against real Postgres, via newFixture (orchestrator_test.go) — the
// properties under test (RLS isolation, automatic supersession, the
// append-only guarantee) are properties of the database and of
// libs/go-shared/vex's contract with its caller, not of a mock.

func vexInput(clusterID string, status vex.Status, scope vex.Scope) orchestr.VEXStatementInput {
	return orchestr.VEXStatementInput{
		ProjectID:     projectA,
		ComponentKey:  "purl:pkg:npm/left@1",
		ClusterID:     clusterID,
		Status:        status,
		Scope:         scope,
		Justification: "component_not_present",
		AuthorUserID:  userA,
	}
}

func TestCreateVEXStatementRefusesAnUnjustifiedNotAffected(t *testing.T) {
	f := newFixture(t)
	clusterID := uuid.NewString()

	in := vexInput(clusterID, vex.StatusNotAffected, vex.ScopeComponent)
	in.Justification = ""
	_, err := f.store.CreateVEXStatement(t.Context(), tenantA, in)
	if err == nil {
		t.Fatal("expected an error for an unjustified not_affected statement")
	}
}

func TestASecondStatementAtTheSameScopeSupersedesTheFirst(t *testing.T) {
	f := newFixture(t)
	clusterID := uuid.NewString()

	first, err := f.store.CreateVEXStatement(t.Context(), tenantA,
		vexInput(clusterID, vex.StatusUnderInvestigation, vex.ScopeComponent))
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	if first.Version != 1 {
		t.Errorf("first.Version = %d, want 1", first.Version)
	}

	second, err := f.store.CreateVEXStatement(t.Context(), tenantA,
		vexInput(clusterID, vex.StatusNotAffected, vex.ScopeComponent))
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	if second.Version != 2 {
		t.Errorf("second.Version = %d, want 2 (supersession increments version)", second.Version)
	}

	// ⚠ THE FIRST ROW IS NEVER MUTATED IN PLACE — only superseded_by is set.
	// Everything else about it, including its own status, must survive
	// unchanged in the history.
	history, err := f.store.GetVEXHistory(t.Context(), tenantA, projectA, clusterID, "purl:pkg:npm/left@1")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history has %d entries, want 2", len(history))
	}
	if history[0].ID != first.ID || history[0].Status != vex.StatusUnderInvestigation {
		t.Errorf("history[0] = %+v, want the original under_investigation statement unchanged", history[0])
	}
	if history[0].SupersededBy != second.ID {
		t.Errorf("history[0].SupersededBy = %q, want %q", history[0].SupersededBy, second.ID)
	}
	if history[1].ID != second.ID || history[1].Status != vex.StatusNotAffected {
		t.Errorf("history[1] = %+v, want the new not_affected statement", history[1])
	}
}

func TestDifferentScopesDoNotSupersedeEachOther(t *testing.T) {
	f := newFixture(t)
	clusterID := uuid.NewString()

	componentScoped, err := f.store.CreateVEXStatement(t.Context(), tenantA,
		vexInput(clusterID, vex.StatusAffected, vex.ScopeComponent))
	if err != nil {
		t.Fatalf("create component-scoped: %v", err)
	}

	projectInput := vexInput(clusterID, vex.StatusNotAffected, vex.ScopeProject)
	projectInput.ComponentKey = ""
	projectScoped, err := f.store.CreateVEXStatement(t.Context(), tenantA, projectInput)
	if err != nil {
		t.Fatalf("create project-scoped: %v", err)
	}

	// ⚠ BOTH LIVE SIMULTANEOUSLY. vex.Resolve, not this store, decides which
	// one governs a given finding — this store's only job is to record what
	// was asserted, at whatever scope it was asserted.
	if componentScoped.Version != 1 || projectScoped.Version != 1 {
		t.Errorf("expected two independent version-1 statements, got %d and %d",
			componentScoped.Version, projectScoped.Version)
	}

	all, err := f.store.ListVEXStatements(t.Context(), tenantA, projectA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var live int
	for _, st := range all {
		if st.ClusterID == clusterID && st.SupersededBy == "" {
			live++
		}
	}
	if live != 2 {
		t.Errorf("live statements for this cluster = %d, want 2 (neither superseded the other)", live)
	}
}

func TestListVEXStatementsIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	clusterID := uuid.NewString()

	if _, err := f.store.CreateVEXStatement(t.Context(), tenantA,
		vexInput(clusterID, vex.StatusAffected, vex.ScopeComponent)); err != nil {
		t.Fatalf("create: %v", err)
	}

	fromB, err := f.store.ListVEXStatements(t.Context(), tenantB, projectA)
	if err != nil {
		t.Fatalf("list as tenant B: %v", err)
	}
	for _, st := range fromB {
		if st.ClusterID == clusterID {
			t.Fatalf("tenant B can see tenant A's VEX statement: %+v", st)
		}
	}
}

func TestEffectiveStatusResolvesFromRealStoredStatements(t *testing.T) {
	f := newFixture(t)
	clusterID := uuid.NewString()

	if _, err := f.store.CreateVEXStatement(t.Context(), tenantA,
		vexInput(clusterID, vex.StatusAffected, vex.ScopeComponent)); err != nil {
		t.Fatalf("create: %v", err)
	}

	all, err := f.store.ListVEXStatements(t.Context(), tenantA, projectA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	effective := vex.Resolve(all, clusterID, "purl:pkg:npm/left@1")
	if effective == nil {
		t.Fatal("expected an effective status, got nil")
	}
	if effective.Status != vex.StatusAffected {
		t.Errorf("effective.Status = %q, want affected", effective.Status)
	}

	if got := vex.Resolve(all, clusterID, "purl:pkg:npm/unrelated@1"); got != nil {
		t.Errorf("a component-scoped statement applied to an unrelated component: %+v", got)
	}
}
