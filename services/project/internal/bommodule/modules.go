package bommodule

import "github.com/axebom/axebom/libs/go-shared/model"

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

type cbomModule struct{}

func (cbomModule) Type() model.BOMType { return model.BOMTypeCBOM }
func (cbomModule) Noun() string        { return "a cryptographic asset" }
func (cbomModule) Sources() []string   { return model.RegistrationSources(model.BOMTypeCBOM) }

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

type aibomModule struct{}

func (aibomModule) Type() model.BOMType { return model.BOMTypeAIBOM }
func (aibomModule) Noun() string        { return "an AI model record" }
func (aibomModule) Sources() []string   { return model.RegistrationSources(model.BOMTypeAIBOM) }

type hbomModule struct{}

func (hbomModule) Type() model.BOMType { return model.BOMTypeHBOM }

// ⚠ "A HARDWARE DEVICE AND ITS PARTS" — a record, not an inspection. Nothing in
// AxeBOM examines hardware (CLAUDE.md honest labels); a device reaches the
// product as a registration, an upload or a collector file the operator ran.
// This string ends up in an error a customer reads, so it is held to the same
// standard as report copy.
func (hbomModule) Noun() string      { return "a hardware device and its parts" }
func (hbomModule) Sources() []string { return model.RegistrationSources(model.BOMTypeHBOM) }
