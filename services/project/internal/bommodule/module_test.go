package bommodule

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// TestEveryBOMTypeHasAModule is the reason the registry exists.
//
// ⚠ THE FAILURE THIS PREVENTS IS THE ONE THAT ALREADY HAPPENED. Five BOM types
// shared one registration path and one set of project endpoints because nothing
// ever required a type to state its own needs. A sixth type added to
// model.AllBOMTypes would inherit SBOM's assumptions in exactly the same way,
// silently, and the first sign would be a customer registering it from a source
// no engine reads.
func TestEveryBOMTypeHasAModule(t *testing.T) {
	r := Default()
	for _, bt := range model.AllBOMTypes() {
		m, ok := r.For(bt)
		if !ok {
			t.Errorf("%s has no module: it would inherit another type's "+
				"registration rules rather than stating its own", bt)
			continue
		}
		if m.Type() != bt {
			t.Errorf("the module registered for %s reports its type as %s", bt, m.Type())
		}
		if strings.TrimSpace(m.Noun()) == "" {
			t.Errorf("%s has no noun; refusing an operation on it would produce "+
				"an error sentence with a hole in it", bt)
		}
		if len(m.Sources()) == 0 {
			t.Errorf("%s can be registered from nothing at all", bt)
		}
	}

	if got, want := len(r.Types()), len(model.AllBOMTypes()); got != want {
		t.Errorf("the registry serves %d types, model defines %d", got, want)
	}
}

// TestAModuleDoesNotInventItsOwnSourceList.
//
// Sources() must be the profile-and-registry-backed answer, not a second copy.
// A module that hand-wrote its list would pass every test in this package and
// escape TestRegistrationSourcesAgreeWithTheEngineRegistry entirely, which is
// the only thing holding the answer to the engines that must read it.
func TestAModuleDoesNotInventItsOwnSourceList(t *testing.T) {
	r := Default()
	for _, bt := range model.AllBOMTypes() {
		m, ok := r.For(bt)
		if !ok {
			continue
		}
		want := model.RegistrationSources(bt)
		got := m.Sources()
		if len(got) != len(want) {
			t.Errorf("%s: module lists %v, model lists %v", bt, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: module lists %v, model lists %v", bt, got, want)
				break
			}
		}
	}
}

func TestRequireClassifiedAcceptsAProjectThatHasTheType(t *testing.T) {
	r := Default()
	err := r.RequireClassified(
		[]model.BOMType{model.BOMTypeSBOM, model.BOMTypeHBOM}, model.BOMTypeHBOM)
	if err != nil {
		t.Fatalf("a project classified for HBOM was refused a hardware operation: %v", err)
	}
}

// TestRequireClassifiedRefusesADeviceOnAnSBOMOnlyProject is the defect this
// milestone was named for.
func TestRequireClassifiedRefusesADeviceOnAnSBOMOnlyProject(t *testing.T) {
	r := Default()
	err := r.RequireClassified([]model.BOMType{model.BOMTypeSBOM}, model.BOMTypeHBOM)
	if err == nil {
		t.Fatal("a hardware device was accepted against an SBOM-only project")
	}
	if !errs.Is(err, errs.ProjectNotClassified) {
		t.Errorf("code = %s, want %s", errs.From(err).Code, errs.ProjectNotClassified)
	}

	msg := err.Error()
	// The message must say what the caller was doing, what the project is, and
	// what to do about it — an error that says only "not classified" makes the
	// customer guess which of the two things to change.
	for _, want := range []string{"hardware device", "HBOM", "SBOM"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q: %s", want, msg)
		}
	}
}

// A project with no classifications at all is the shape the store's own test
// helper creates, and the shape that made this bug invisible.
func TestRequireClassifiedRefusesAProjectClassifiedForNothing(t *testing.T) {
	r := Default()
	err := r.RequireClassified(nil, model.BOMTypeQBOM)
	if err == nil {
		t.Fatal("an unclassified project accepted a QBOM operation")
	}
	if !strings.Contains(err.Error(), "nothing") {
		t.Errorf("the refusal does not say the project is classified for nothing: %v", err)
	}
}

func TestRequireSourceRefusesASourceNoEngineCanRead(t *testing.T) {
	r := Default()

	// The combination the dev database actually contains.
	err := r.RequireSource(model.BOMTypeAIBOM, "url")
	if err == nil {
		t.Fatal("an AIBOM project was accepted from a url source, which no AIBOM engine reads")
	}
	if !errs.Is(err, errs.ValidationFieldInvalid) {
		t.Errorf("code = %s, want %s", errs.From(err).Code, errs.ValidationFieldInvalid)
	}
	// It must name the sources that DO work, or the customer is left guessing.
	if !strings.Contains(err.Error(), "upload") {
		t.Errorf("the refusal does not name a source that works: %v", err)
	}

	if err := r.RequireSource(model.BOMTypeSBOM, "url"); err != nil {
		t.Errorf("SBOM from a url source was refused, but webrecon reads exactly that: %v", err)
	}
	if err := r.RequireSource(model.BOMTypeHBOM, "manual"); err != nil {
		t.Errorf("HBOM from a manual source was refused, and manual is its first-class path: %v", err)
	}
	if err := r.RequireSource(model.BOMTypeSBOM, "manual"); err == nil {
		t.Error("SBOM was accepted from a manual source; there is no form that produces a component inventory")
	}
}
