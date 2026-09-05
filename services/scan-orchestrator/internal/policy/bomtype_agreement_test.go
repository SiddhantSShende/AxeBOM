package policy

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/model"
)

// TestBOMTypeFactsAgreeWithTheEngineRegistry.
//
// ⚠ model.BOMType.RequiresImport() SAID "HBOM" FOR MONTHS AFTER hbom-ecad MADE
// HBOM SCANNABLE, AND THE REGISTRATION SCREEN RENDERED IT AS AN "import only"
// CHIP. A user picking classifications was told, at the moment of the decision,
// that a path which works does not exist.
//
// The reason it went stale is structural, not careless: whether a family can be
// scanned is a property of the ENGINE REGISTRY, and `libs/go-shared/model`
// cannot import a service (depguard, ADR-0001 mitigation 3). So the fact was
// transcribed into a hardcoded identity and the two drifted the moment an
// engine was added — exactly the failure mode invariant 1 describes.
//
// This test is the join the compiler cannot make. It lives here because this is
// the side that is allowed to see both.
//
// The same shape as libs/go-shared/model/generated_agreement_test.go, which
// already holds the Go and Python field lists to each other.
func TestBOMTypeFactsAgreeWithTheEngineRegistry(t *testing.T) {
	reg := DefaultRegistry()

	for _, bt := range model.AllBOMTypes() {
		family, ok := familyFor(bt)
		if !ok {
			t.Fatalf("no scan family maps to BOM type %s; this test cannot see it", bt)
		}

		engines := reg.ForFamily(family)
		if len(engines) == 0 {
			t.Fatalf("the registry has no engine at all for family %s", family)
		}

		// ⚠ "NOT SCANNABLE" AND "IMPORT-ONLY" ARE NOT THE SAME FACT, AND THIS
		// TEST CAUGHT ME CONFLATING THEM ON ITS FIRST RUN.
		//
		// rejectNonScannableFamilies refuses a family when every engine is
		// `RequiresImport || Derived` — that is one predicate covering two
		// different reasons a scan cannot run. The UI renders them as two
		// different chips, because they tell a user to do two different things:
		//
		//   derived      → "run a CBOM scan and this appears"
		//   import-only  → "there is nothing to run; upload or type it in"
		//
		// QBOM is derived. Calling it import-only would tell someone to go and
		// find a file that does not exist.
		notScannable, derived := true, true
		for _, e := range engines {
			if !e.RequiresImport && !e.Derived {
				notScannable = false
			}
			if !e.Derived {
				derived = false
			}
		}
		importOnly := notScannable && !derived

		if got := bt.RequiresImport(); got != importOnly {
			t.Errorf(
				"%s.RequiresImport() = %v, but the registry says %v.\n"+
					"  The engines registered for %s are: %s.\n"+
					"  Fix model.importOnlyTypes, not this test — the registry is "+
					"the fact and the model is the transcription.",
				bt, got, importOnly, family, engineIDs(engines))
		}

		if got := bt.IsDerived(); got != derived {
			t.Errorf(
				"%s.IsDerived() = %v, but every engine for %s being derived is %v "+
					"(engines: %s)",
				bt, got, family, derived, engineIDs(engines))
		}
	}
}

// familyFor maps a BOM type onto the scan family its engines are registered
// under. They are spelled differently — model.BOMTypeSBOM is "SBOM",
// events.FamilySBOM is "sbom" — and nothing else in the codebase needs the
// mapping, so it lives with its only caller.
func familyFor(bt model.BOMType) (events.Family, bool) {
	switch bt {
	case model.BOMTypeSBOM:
		return events.FamilySBOM, true
	case model.BOMTypeCBOM:
		return events.FamilyCBOM, true
	case model.BOMTypeQBOM:
		return events.FamilyQBOM, true
	case model.BOMTypeAIBOM:
		return events.FamilyAIBOM, true
	case model.BOMTypeHBOM:
		return events.FamilyHBOM, true
	default:
		return "", false
	}
}

func engineIDs(engines []Engine) string {
	out := ""
	for i, e := range engines {
		if i > 0 {
			out += ", "
		}
		out += e.ID
	}
	return out
}
