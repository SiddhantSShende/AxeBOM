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

// TestGitHubDependencyGraphIsOfferedForGitOnly pins the one real constraint on
// this engine: GitHub's Dependency Graph API has no meaning for an upload or a
// bare image, so it must never be silently offered — and therefore silently
// fail — for either.
func TestGitHubDependencyGraphIsOfferedForGitOnly(t *testing.T) {
	reg := policy.DefaultRegistry()

	git := reg.Resolve([]events.Family{events.FamilySBOM}, events.SourceGit, nil)
	if !containsEngine(git.Engines, "github-dependency-graph-sbom") {
		t.Fatal("github-dependency-graph-sbom was not offered for a git-sourced scan")
	}

	for _, kind := range []events.SourceKind{events.SourceUpload, events.SourceImage} {
		res := reg.Resolve([]events.Family{events.FamilySBOM}, kind, nil)
		if containsEngine(res.Engines, "github-dependency-graph-sbom") {
			t.Errorf("github-dependency-graph-sbom was offered for a %s-sourced scan, "+
				"which the fetcher can never produce a Dependency Graph document for", kind)
		}
	}
}

// TestGitHubDependencyGraphCarriesTheHonestLabels pins the two flags a reader
// of Engine Coverage depends on: RequiresImport (this is not discovery — see
// docs/04-OSINT-INTEGRATION.md) and ConsumesNativeSBOM (the dispatch-time
// signal FanOut uses to wire Workspace.NativeSBOMRef into this engine's job).
func TestGitHubDependencyGraphCarriesTheHonestLabels(t *testing.T) {
	reg := policy.DefaultRegistry()

	e, ok := reg.Get("github-dependency-graph-sbom")
	if !ok {
		t.Fatal("github-dependency-graph-sbom is not registered")
	}
	if !e.RequiresImport {
		t.Error("RequiresImport is false: this engine imports a document, it does not scan")
	}
	if !e.ConsumesNativeSBOM {
		t.Error("ConsumesNativeSBOM is false: FanOut would never populate its job's " +
			"Workspace.NativeSBOMRef, and the adapter would always report unavailable")
	}
	if e.Mode != "internal" {
		t.Errorf("Mode = %q, want %q", e.Mode, "internal")
	}
	if !containsSourceKind(e.SourceKinds, events.SourceGit) || len(e.SourceKinds) != 1 {
		t.Errorf("SourceKinds = %v, want exactly [git]", e.SourceKinds)
	}
}

// TestWebreconFingerprintCarriesTheHonestLabels is
// TestGitHubDependencyGraphCarriesTheHonestLabels's sibling for the other
// engine that consumes a producer-staged native document. Unlike
// github-dependency-graph-sbom this one is NOT RequiresImport: it performs
// real discovery (subfinder + JS fingerprinting via services/webrecon), just
// not inside a sandboxed container job of its own.
func TestWebreconFingerprintCarriesTheHonestLabels(t *testing.T) {
	reg := policy.DefaultRegistry()

	e, ok := reg.Get("webrecon-fingerprint")
	if !ok {
		t.Fatal("webrecon-fingerprint is not registered")
	}
	if e.RequiresImport {
		t.Error("RequiresImport is true: this engine performs real discovery, it does not import a foreign document")
	}
	if !e.ConsumesNativeSBOM {
		t.Error("ConsumesNativeSBOM is false: FanOut would never populate its job's " +
			"Workspace.NativeSBOMRef, and the adapter would always report unavailable")
	}
	if e.Mode != "internal" {
		t.Errorf("Mode = %q, want %q", e.Mode, "internal")
	}
	if !containsSourceKind(e.SourceKinds, events.SourceURL) || len(e.SourceKinds) != 1 {
		t.Errorf("SourceKinds = %v, want exactly [url]", e.SourceKinds)
	}
}

// TestAtMostOneConsumesNativeSBOMPerSourceKind is the invariant
// nativeSBOMRefFor's single scan-wide ref actually depends on: FanOut wires
// ONE ref into EVERY engine that sets ConsumesNativeSBOM, so two such engines
// sharing a SourceKind would both receive the same document — correct for at
// most one of them. github-dependency-graph-sbom (git) and
// webrecon-fingerprint (url) are safe together only because their
// SourceKinds never overlap; this test is what keeps that true as the
// registry grows.
func TestAtMostOneConsumesNativeSBOMPerSourceKind(t *testing.T) {
	reg := policy.DefaultRegistry()

	perKind := map[events.SourceKind][]string{}
	for _, e := range reg.ForFamily(events.FamilySBOM) {
		if !e.ConsumesNativeSBOM {
			continue
		}
		for _, k := range e.SourceKinds {
			perKind[k] = append(perKind[k], e.ID)
		}
	}
	for kind, ids := range perKind {
		if len(ids) > 1 {
			t.Errorf("source kind %q has %d engines consuming a native document (%v); "+
				"FanOut can only wire one ref per scan", kind, len(ids), ids)
		}
	}
}

func containsSourceKind(kinds []events.SourceKind, want events.SourceKind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

func containsEngine(engines []policy.Engine, id string) bool {
	for _, e := range engines {
		if e.ID == id {
			return true
		}
	}
	return false
}
