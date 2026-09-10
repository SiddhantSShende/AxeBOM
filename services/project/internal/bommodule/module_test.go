package bommodule

import (
	"regexp"
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

// TestQBOMWithoutCBOMIsNamedAsADerivationWithNothingToDeriveFrom.
//
// ⚠ THE PRODUCT ALREADY KNEW THIS AND NEVER SAID IT. model.BOMType.IsDerived's
// own comment: a project classified QBOM without CBOM "will produce device
// metadata and no crypto assets — worth warning about at registration rather
// than at report time". The registration screen showed a "derived from CBOM"
// chip, which states the relationship and not the consequence of ignoring it.
func TestQBOMWithoutCBOMIsNamedAsADerivationWithNothingToDeriveFrom(t *testing.T) {
	r := Default()

	missing := r.MissingDependencies([]model.BOMType{model.BOMTypeSBOM, model.BOMTypeQBOM})
	deps, ok := missing[model.BOMTypeQBOM]
	if !ok {
		t.Fatal("QBOM selected without CBOM was not flagged")
	}
	if len(deps) != 1 || deps[0] != model.BOMTypeCBOM {
		t.Errorf("missing = %v, want [CBOM]", deps)
	}
}

// Selecting both is the whole point of the warning, and must be silent.
func TestQBOMWithCBOMIsNotFlagged(t *testing.T) {
	r := Default()
	if got := r.MissingDependencies([]model.BOMType{model.BOMTypeCBOM, model.BOMTypeQBOM}); len(got) != 0 {
		t.Errorf("a complete selection was flagged: %v", got)
	}
}

// TestOnlyTheTypesThatNeedSomethingCarryRequirements.
//
// An empty list is an answer. If SBOM ever grows a checklist item, it should be
// because something real changed — not because five types were made to look
// symmetrical.
func TestOnlyTheTypesThatNeedSomethingCarryRequirements(t *testing.T) {
	r := Default()
	want := map[model.BOMType]bool{
		model.BOMTypeQBOM:  true,
		model.BOMTypeAIBOM: true,
		model.BOMTypeHBOM:  true,
	}

	for _, bt := range model.AllBOMTypes() {
		m, ok := r.For(bt)
		if !ok {
			continue
		}
		reqs := m.Requirements()
		if got := len(reqs) > 0; got != want[bt] {
			t.Errorf("%s has requirements = %v, want %v", bt, got, want[bt])
		}
		for _, req := range reqs {
			if req.ID == "" || req.Title == "" || req.Detail == "" {
				t.Errorf("%s: a requirement is missing id, title or detail: %+v", bt, req)
			}
			// A checklist item that does not say the consequence reads as
			// optional, which is the opposite of what Required means here.
			if req.Required && len(req.Detail) < 40 {
				t.Errorf("%s: requirement %q is required but does not explain why",
					bt, req.ID)
			}
		}
	}
}

// TestNoRequirementWritesAFieldCount is invariant 2, applied to copy that ships.
//
// ⚠ THE AIBOM REQUIREMENT NAMES A COUNT, AND IT MUST COME FROM THE PROFILE.
// "four Table 10 elements" typed into a string is exactly how a product ships a
// false compliance claim the day the guideline is revised.
//
// ⚠ IT MATCHES A NUMBER NEXT TO A FIELD NOUN, NOT EVERY NUMBER WORD. The first
// version banned the words outright and flagged "the one part of a QBOM that no
// scan can produce" and "until one of those exists" — ordinary English, no
// count in sight. A guard that cries wolf on prose gets the assertion deleted
// rather than the prose fixed, so it looks for the shape invariant 2 is
// actually about: a quantity immediately qualifying elements or fields.
func TestNoRequirementWritesAFieldCount(t *testing.T) {
	r := Default()

	// "<number word> [up to two words] element(s)/field(s)".
	countOfFields := regexp.MustCompile(
		`\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|` +
			`thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|` +
			`twenty|twenty-one|twenty-four|\d+)\b(\s+\S+){0,2}\s+(element|field)s?\b`)

	for _, bt := range model.AllBOMTypes() {
		m, ok := r.For(bt)
		if !ok {
			continue
		}
		for _, req := range m.Requirements() {
			text := strings.ToLower(req.Title + " " + req.Detail)
			// %d rendered from the profile at runtime is the CORRECT form, so
			// the literal source text is what must be checked — not the output.
			// These strings are built with fmt.Sprintf from len(profile fields),
			// which is why this test reads them after formatting and still
			// passes: the digits it sees came from the profile, not a keyboard.
			if match := countOfFields.FindString(text); match != "" && !renderedFromProfile(bt, req.ID) {
				t.Errorf("%s requirement %q writes a field count as a literal (%q); "+
					"render it from the profile", bt, req.ID, match)
			}
		}
	}
}

// renderedFromProfile names the requirements whose counts are produced by
// fmt.Sprintf from a profile-derived length rather than typed.
//
// ⚠ AN ALLOWLIST IS A LIABILITY AND THIS ONE IS DELIBERATELY TINY. It exists
// because the test can only read the FORMATTED string, where a profile-rendered
// count and a typed one look identical. Each entry is a claim that the source
// uses len() on a profile list — check modules.go before adding to it.
func renderedFromProfile(bt model.BOMType, id string) bool {
	return bt == model.BOMTypeAIBOM && id == "aibom.user_fields"
}

// TestOnlyWhatTheWizardCanActuallyCollectIsMarkedAtRegistration.
//
// ⚠ THE DIVIDING LINE IS SHAPE, NOT IMPORTANCE. All three requirements are
// Required; only two of them can be asked for while somebody is registering.
//
//	QBOM  Table 8 is per-PROJECT and derives from nothing that must exist
//	      first, so every fact is available in the wizard.
//	HBOM  a device is per-project too — and on a `manual` project it is the
//	      only thing that will ever produce a document.
//	AIBOM Table 10's user-supplied elements are per-MODEL, and no model exists
//	      until a scan has found one. A registration form for them would have
//	      no rows to attach to.
//
// Flipping AIBOM to true would put a form in the wizard that cannot know what
// it is describing; flipping either of the others to false is what made
// registration ask all five types the same questions.
func TestOnlyWhatTheWizardCanActuallyCollectIsMarkedAtRegistration(t *testing.T) {
	r := Default()
	want := map[string]bool{
		"qbom.device_metadata": true,
		"hbom.device":          true,
		"aibom.user_fields":    false,
	}

	seen := map[string]bool{}
	for _, bt := range model.AllBOMTypes() {
		m, ok := r.For(bt)
		if !ok {
			continue
		}
		for _, req := range m.Requirements() {
			expected, known := want[req.ID]
			if !known {
				t.Errorf("%s: requirement %q is new — decide whether the wizard can "+
					"collect it and add it here", bt, req.ID)
				continue
			}
			seen[req.ID] = true
			if req.AtRegistration != expected {
				t.Errorf("%s: requirement %q AtRegistration = %v, want %v",
					bt, req.ID, req.AtRegistration, expected)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("requirement %q was expected and no module produced it", id)
		}
	}
}
