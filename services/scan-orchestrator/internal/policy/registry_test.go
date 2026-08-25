package policy_test

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/policy"
)

// TestResolveAppliesTenantOverride is the pure-function half of "configurable
// tool management" — no DB needed, since Resolve only ever consumes a plain
// map. handler.Create is what builds that map from policy.Store; this proves
// the registry actually honours it once built.
func TestResolveAppliesTenantOverride(t *testing.T) {
	reg := policy.DefaultRegistry()

	res := reg.Resolve([]events.Family{events.FamilySBOM}, events.SourceGit,
		map[events.Family][]string{events.FamilySBOM: {"syft"}})

	if len(res.Engines) != 1 || res.Engines[0].ID != "syft" {
		t.Fatalf("engines = %v, want exactly [syft]", res.Engines)
	}
}

// TestResolveOverrideOfEmptySliceRunsNothing is the "disabled" case
// policy.Store.OverridesForTenant produces for a disabled row — Resolve must
// not treat an explicit empty override as "no override given" and fall back
// to the built-in default, which would silently re-enable a family a tenant
// turned off.
func TestResolveOverrideOfEmptySliceRunsNothing(t *testing.T) {
	reg := policy.DefaultRegistry()

	res := reg.Resolve([]events.Family{events.FamilyAIBOM}, events.SourceGit,
		map[events.Family][]string{events.FamilyAIBOM: {}})

	if len(res.Engines) != 0 {
		t.Fatalf("engines = %v, want none (family disabled)", res.Engines)
	}
}

// TestResolveWithNoOverrideUsesDefault is the control: an ABSENT key (the
// shape of a tenant who has never customised this family) must still resolve
// to the built-in default set, not nothing.
func TestResolveWithNoOverrideUsesDefault(t *testing.T) {
	reg := policy.DefaultRegistry()

	res := reg.Resolve([]events.Family{events.FamilySBOM}, events.SourceGit, nil)

	if len(res.Engines) == 0 {
		t.Fatal("engines is empty, want the built-in SBOM default set")
	}
}
