package policy

import (
	"sort"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/model"
)

// TestRegistrationSourcesAgreeWithTheEngineRegistry.
//
// ⚠ THE JOIN THE COMPILER CANNOT MAKE. model.RegistrationSources states which
// project source types each BOM type can be registered from, because the
// project service needs that fact and `libs/go-shared/model` may not import a
// service (depguard, ADR-0001). The AUTHORITY for it is this registry: an
// engine's SourceKinds is what it can actually read. Transcription without this
// test is how model.RequiresImport() came to claim HBOM was import-only for
// months after hbom-ecad made it scannable.
//
// The two vocabularies differ on purpose and this test owns the mapping:
//   - the registry says `git`; a project's source_type names the PROVIDER, so
//     `git` corresponds to github, gitlab and bitbucket together.
//   - `manual` is not an engine source kind at all — no engine runs on that
//     path — so it is excluded here and asserted separately below.
func TestRegistrationSourcesAgreeWithTheEngineRegistry(t *testing.T) {
	reg := DefaultRegistry()

	for _, bt := range model.AllBOMTypes() {
		family, ok := familyFor(bt)
		if !ok {
			t.Fatalf("no scan family maps to BOM type %s; this test cannot see it", bt)
		}

		// What the engines for this family can actually read.
		readable := map[events.SourceKind]bool{}
		for _, e := range reg.ForFamily(family) {
			for _, k := range e.SourceKinds {
				readable[k] = true
			}
		}
		if len(readable) == 0 {
			t.Fatalf("the registry has no engine reading any source for family %s", family)
		}

		declared := map[string]bool{}
		for _, s := range model.RegistrationSources(bt) {
			declared[s] = true
		}
		if len(declared) == 0 {
			t.Errorf("%s can be registered from nothing at all; a BOM type with no "+
				"registration source cannot be created by any customer", bt)
			continue
		}

		// Every declared source must be one an engine can read — or `manual`.
		for source := range declared {
			if source == model.ManualSource {
				continue
			}
			kind := sourceKindFor(source)
			if kind == "" {
				t.Errorf("%s declares source %q, which maps to no engine source kind "+
					"at all — the mapping in this test does not know it", bt, source)
				continue
			}
			if !readable[kind] {
				t.Errorf("%s is offered for registration from %q, but no %s engine "+
					"reads a %s source. A project registered that way produces an "+
					"empty %s and nothing says so.", bt, source, family, kind, bt)
			}
		}

		// And every source an engine CAN read must be offered, or a working
		// path is hidden from the customer at the moment of the decision —
		// which is the exact harm TestBOMTypeFactsAgreeWithTheEngineRegistry
		// was written about.
		for kind := range readable {
			offered := false
			for _, source := range sourceTypesFor(kind) {
				if declared[source] {
					offered = true
					break
				}
			}
			if !offered {
				t.Errorf("a %s engine reads a %s source, but %s is not offered for "+
					"registration from it — a path that works is hidden from the "+
					"customer choosing classifications", family, kind, bt)
			}
		}
	}
}

// TestManualRegistrationIsOfferedOnlyWhereItProducesADocument.
//
// ⚠ `manual` CANNOT BE CHECKED AGAINST THE REGISTRY, BECAUSE NO ENGINE RUNS ON
// IT. That makes it the one entry in the table with no authority behind it, so
// it gets its own assertion rather than silently passing the loop above.
//
// A manual project is only honest where a form or import actually produces a
// document: HBOM (device, parts tree, CSV/XLSX import) and QBOM (Table 8's
// device metadata form). SBOM, CBOM and AIBOM have no hand-entry path that
// yields an inventory, so offering `manual` there would register a project that
// produces nothing — the silent no-op the whole table exists to prevent.
func TestManualRegistrationIsOfferedOnlyWhereItProducesADocument(t *testing.T) {
	wantManual := map[model.BOMType]bool{
		model.BOMTypeHBOM: true,
		model.BOMTypeQBOM: true,
	}

	for _, bt := range model.AllBOMTypes() {
		got := model.SupportsRegistrationSource(bt, model.ManualSource)
		if got != wantManual[bt] {
			t.Errorf("%s offers manual registration = %v, want %v", bt, got, wantManual[bt])
		}
	}
}

// sourceKindFor maps a project source_type onto the registry's source kind.
func sourceKindFor(sourceType string) events.SourceKind {
	for _, p := range model.GitProviders() {
		if p == sourceType {
			return events.SourceGit
		}
	}
	switch sourceType {
	case "upload":
		return events.SourceUpload
	case "image":
		return events.SourceImage
	case "url":
		return events.SourceURL
	default:
		return ""
	}
}

// sourceTypesFor is the inverse: every project source_type that satisfies one
// engine source kind.
func sourceTypesFor(kind events.SourceKind) []string {
	switch kind {
	case events.SourceGit:
		out := model.GitProviders()
		sort.Strings(out)
		return out
	case events.SourceUpload:
		return []string{"upload"}
	case events.SourceImage:
		return []string{"image"}
	case events.SourceURL:
		return []string{"url"}
	default:
		return nil
	}
}
