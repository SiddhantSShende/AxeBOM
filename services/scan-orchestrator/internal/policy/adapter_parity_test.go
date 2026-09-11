package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
)

// ⚠ EVERY GIT-SOURCED CBOM SCAN WAS `completed_with_errors`, AND NOTHING FAILED.
//
// `cbomkit` sat in this registry neither Disabled nor Scaffold, so ForFamily put
// it in the default CBOM set for a git source and FanOut published a job for
// it. workers/cbom/runner.py has no adapter for it, so the worker answered
// `skipped`/ENGINE_NOT_IMPLEMENTED on every scan, and DeriveScanStatus degraded
// every one of them even when cbomkit-theia succeeded. The manifest said
// `enabled: false` all along; the registry and the worker never met in a test.
//
// The registry is Go and the adapters are Python, so the compiler cannot make
// this join. These tests make it the same way
// libs/go-shared/model/generated_agreement_test.go joins the generated models:
// by reading the Python source.

var (
	pyAdaptersBlock = regexp.MustCompile(`(?s)\nADAPTERS: dict\[[^\n]*\] = \{(.*?)\n\}`)
	pyAdapterKey    = regexp.MustCompile(`(?m)^\s*"([a-z0-9][a-z0-9-]*)"\s*:`)
)

// familyWorker names the worker whose ADAPTERS map serves `scan.job.<family>`.
// QBOM has no worker: its only engine is Derived.
var familyWorker = map[events.Family]string{
	events.FamilySBOM:  "sbom",
	events.FamilyCBOM:  "cbom",
	events.FamilyAIBOM: "aibom",
	events.FamilyHBOM:  "hbom",
}

func workerAdapters(t *testing.T, worker string) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "workers", worker, "runner.py")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block := pyAdaptersBlock.FindSubmatch(data)
	if block == nil {
		t.Fatalf("%s has no `ADAPTERS: dict[...] = {` block this test can read", path)
	}
	ids := map[string]bool{}
	for _, m := range pyAdapterKey.FindAllSubmatch(block[1], -1) {
		ids[string(m[1])] = true
	}
	if len(ids) == 0 {
		t.Fatalf("%s: ADAPTERS parsed as empty — the regex no longer matches the file", path)
	}
	return ids
}

// notOnAFamilyWorker says why an engine is never consumed from
// `scan.job.<family>` by that family's worker, or "" when it is.
func notOnAFamilyWorker(e Engine) string {
	switch {
	case e.Disabled:
		return "disabled"
	case e.Scaffold:
		return "scaffold"
	case e.Derived:
		return "derived, never dispatched"
	case e.JobSubject != "":
		return "consumed from its own subject " + e.JobSubject
	case len(e.SourceKinds) == 0:
		return "reads no source kind"
	}
	return ""
}

func TestEveryDispatchableEngineHasAWorkerAdapter(t *testing.T) {
	reg := DefaultRegistry()
	adapters := map[string]map[string]bool{}
	for _, worker := range familyWorker {
		adapters[worker] = workerAdapters(t, worker)
	}

	ids := reg.IDs()
	sort.Strings(ids)
	for _, id := range ids {
		e, _ := reg.Get(id)
		if reason := notOnAFamilyWorker(e); reason != "" {
			continue
		}
		for _, family := range e.Families {
			worker, ok := familyWorker[family]
			if !ok {
				t.Errorf("%s is dispatchable to family %s, which has no worker", id, family)
				continue
			}
			if !adapters[worker][id] {
				t.Errorf("%s is dispatchable to scan.job.%s but workers/%s/runner.py has no "+
					"adapter for it: every run would be `skipped`/ENGINE_NOT_IMPLEMENTED and "+
					"every scan that includes it `completed_with_errors`. Implement it, or mark "+
					"it Disabled with a DisabledReason.", id, family, worker)
			}
		}
	}
}

func TestEveryWorkerAdapterIsARegistryEngineInItsFamily(t *testing.T) {
	reg := DefaultRegistry()
	for family, worker := range familyWorker {
		for id := range workerAdapters(t, worker) {
			e, ok := reg.Get(id)
			if !ok {
				t.Errorf("workers/%s/runner.py implements %q, which the registry does not "+
					"know: it can never be dispatched", worker, id)
				continue
			}
			if !e.InFamily(family) {
				t.Errorf("workers/%s/runner.py implements %q, but the registry does not "+
					"put it in family %s", worker, id, family)
			}
		}
	}
}

// The disabled engine that started this is still disabled, with its reason.
func TestCbomkitIsRegisteredButNeverDispatched(t *testing.T) {
	reg := DefaultRegistry()
	e, ok := reg.Get("cbomkit")
	if !ok {
		t.Fatal("cbomkit is no longer registered; the engine list would stop explaining why it is not run")
	}
	if !e.Disabled || e.DisabledReason == "" {
		t.Fatalf("cbomkit must be Disabled with a reason, got Disabled=%v reason=%q", e.Disabled, e.DisabledReason)
	}
	for _, got := range reg.ForFamily(events.FamilyCBOM) {
		if got.ID == "cbomkit" {
			t.Fatal("ForFamily(CBOM) still offers cbomkit; a git CBOM scan would dispatch it again")
		}
	}
}
