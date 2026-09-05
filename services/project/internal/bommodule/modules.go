package bommodule

import (
	"fmt"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/services/project/internal/aibom"
)

// The five modules.
//
// ⚠ EACH IS DELIBERATELY THIN, AND THAT IS THE DESIGN RATHER THAN AN UNFINISHED
// EDGE. A module states what is TRUE OF ITS BOM TYPE that the generic project
// layer cannot know. It does not hold the type's field list (that is the
// profile), its engines (that is the scan orchestrator's registry), or its
// storage (that is the store). Everything a module could grow into already has
// an owner, and duplicating any of it here is the drift invariant 1 forbids.
//
// Sources() delegates to model.RegistrationSources in every module rather than
// each answering for itself: the answer is held to the engine registry by
// TestRegistrationSourcesAgreeWithTheEngineRegistry, and a module that
// hand-wrote its own list would escape that check.

type sbomModule struct{}

func (sbomModule) Type() model.BOMType { return model.BOMTypeSBOM }
func (sbomModule) Noun() string        { return "a software component" }
func (sbomModule) Sources() []string   { return model.RegistrationSources(model.BOMTypeSBOM) }

func (sbomModule) DependsOn() []model.BOMType { return nil }

// ⚠ NOTHING, AND THAT IS THE HONEST ANSWER. An SBOM needs a source its engines
// can read and nothing else; the engines do the rest. Inventing a checklist
// item here to make the five types look symmetrical would put a task in front
// of a customer that they cannot act on.
func (sbomModule) Requirements() []Requirement { return nil }

type cbomModule struct{}

func (cbomModule) Type() model.BOMType { return model.BOMTypeCBOM }
func (cbomModule) Noun() string        { return "a cryptographic asset" }
func (cbomModule) Sources() []string   { return model.RegistrationSources(model.BOMTypeCBOM) }

func (cbomModule) DependsOn() []model.BOMType  { return nil }
func (cbomModule) Requirements() []Requirement { return nil }

type qbomModule struct{}

func (qbomModule) Type() model.BOMType { return model.BOMTypeQBOM }

// ⚠ "QUANTUM DEVICE METADATA", NOT "A QUANTUM DEVICE". CLAUDE.md's honest
// labels are explicit that QBOM is largely a derivation: the readiness half
// comes from CBOM discovery, and only Table 8's device metadata is separately
// captured. A noun claiming we inventory quantum devices would be the kind of
// overstatement those labels exist to stop, and it would appear in an error
// message the customer reads.
func (qbomModule) Noun() string      { return "quantum device metadata" }
func (qbomModule) Sources() []string { return model.RegistrationSources(model.BOMTypeQBOM) }

// ⚠ THE DEPENDENCY THE PRODUCT KNEW ABOUT AND NEVER SURFACED. A QBOM's
// readiness half IS the project's CBOM crypto assets with quantum-vulnerability
// rules applied (CLAUDE.md honest labels: "QBOM is largely a derivation"). A
// project classified QBOM but not CBOM registers cleanly, produces Table 8
// device metadata, and reports no crypto assets at all — forever, and with
// nothing anywhere saying why.
func (qbomModule) DependsOn() []model.BOMType { return []model.BOMType{model.BOMTypeCBOM} }

func (qbomModule) Requirements() []Requirement {
	return []Requirement{{
		ID:    "qbom.device_metadata",
		Title: "Record the quantum device metadata",
		Detail: "CERT-In Table 8's device elements are the one part of a QBOM " +
			"that no scan can produce — there is no quantum-hardware scanner. " +
			"Until the form is filled, this project has no QBOM document at all.",
		Required: true,
	}}
}

type aibomModule struct{}

func (aibomModule) Type() model.BOMType { return model.BOMTypeAIBOM }
func (aibomModule) Noun() string        { return "an AI model record" }
func (aibomModule) Sources() []string   { return model.RegistrationSources(model.BOMTypeAIBOM) }

func (aibomModule) DependsOn() []model.BOMType { return nil }

func (aibomModule) Requirements() []Requirement {
	// ⚠ THE COUNT IS RENDERED FROM THE PROFILE, NEVER TYPED (invariant 2). A
	// CERT-In revision that adds a user-supplied Table 10 element changes this
	// sentence with no Go change; writing "four" here is exactly how a product
	// ships a false claim when the guideline is revised.
	n := len(aibom.UserSuppliedFormFields())
	return []Requirement{{
		ID:    "aibom.user_fields",
		Title: "Complete the Table 10 elements no tool reports",
		Detail: fmt.Sprintf(
			"%d of CERT-In Table 10's elements describe intent and governance "+
				"rather than the model file, so no scanner can supply them. They "+
				"are recorded per model, on the model itself, once a scan has "+
				"found it. Until then they count as not-provided and reduce "+
				"completeness.", n),
		Required: true,
	}}
}

type hbomModule struct{}

func (hbomModule) Type() model.BOMType { return model.BOMTypeHBOM }

// ⚠ "A HARDWARE DEVICE AND ITS PARTS" — a record, not an inspection. Nothing in
// AxeBOM examines hardware (CLAUDE.md honest labels); a device reaches the
// product as a registration, an upload or a collector file the operator ran.
// This string ends up in an error a customer reads, so it is held to the same
// standard as report copy.
func (hbomModule) Noun() string      { return "a hardware device and its parts" }
func (hbomModule) Sources() []string { return model.RegistrationSources(model.BOMTypeHBOM) }

func (hbomModule) DependsOn() []model.BOMType { return nil }

func (hbomModule) Requirements() []Requirement {
	return []Requirement{{
		ID:    "hbom.device",
		Title: "Register a device, or import its parts",
		Detail: "Nothing in AxeBOM examines hardware. An HBOM is built from a " +
			"device you register, a parts file you import, design files in the " +
			"repository, or a collector you ran on the machine yourself — so " +
			"until one of those exists this project has no hardware to report.",
		Required: true,
	}}
}
