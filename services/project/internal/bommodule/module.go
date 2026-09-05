// Package bommodule is the seam between the generic project service and the
// five BOM types it serves.
//
// # Why this exists
//
// The customer's complaint was exact: "our projects are still the same for all
// BOMs". They were. `Create` validated one flat set of source types for every
// classification, and every BOM-type-specific endpoint — hardware devices,
// hardware components, CSV import, Table 8 quantum metadata, AI model fields —
// took a project id and never asked what the project was FOR. A hardware device
// could be registered against a project that produces only an SBOM; the row was
// written, the device appeared on a screen, and no report would ever contain
// it.
//
// # Why a module and not a service
//
// Five microservices was the alternative considered and rejected. Every one of
// them would need the same tenancy, the same RLS wrapper, the same project
// lookup and the same audit trail, and they would share a database schema —
// which is a distributed monolith, not five services. A module is the same
// separation with none of that: the compiler enforces the seam, `Registry`
// enforces completeness, and any module can still be lifted into a service
// later precisely because its dependencies point one way.
//
// # What a module is NOT allowed to be
//
// ⚠ A MODULE IS NOT A PLACE TO RESTATE THE PROFILE. Field lists, counts and
// names come from `docs/reference/certin-v2.0.yaml` through `libs/go-shared/model`
// (invariants 1 and 2). A module says what its BOM type NEEDS — sources, the
// operations that belong to it — never what CERT-In says it contains.
//
// # What is deliberately not here yet
//
// ⚠ NO RegistrationFields() METHOD, ON PURPOSE. Three per-type form generators
// already exist (hbom.DeviceFormFields, qbom.FormFields,
// aibom.UserSuppliedFormFields) with three different shapes, each correct for
// its own screen. Unifying them needs a consumer to be right about, and that
// consumer is the BOM-type-first registration flow. Declaring the method now
// and implementing it three incompatible ways would be the drift invariant 1
// warns about, in the one package built to prevent it.
package bommodule

import (
	"fmt"
	"sort"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Module is what one BOM type contributes to the otherwise generic project
// service.
type Module interface {
	// Type is the BOM type this module serves.
	Type() model.BOMType

	// Noun names what the type inventories, as a phrase that completes
	// "… belongs to a project classified for X". Used when refusing an
	// operation, so the message says what the caller was actually doing.
	Noun() string

	// Sources are the project source types this BOM type can be registered
	// from. Delegated to model.RegistrationSources, which the engine registry's
	// agreement test holds honest — a module must not invent its own answer.
	Sources() []string
}

// Registry holds one module per BOM type.
//
// ⚠ COMPLETENESS IS THE POINT. A sixth BOM type added to model.AllBOMTypes
// without a module fails TestEveryBOMTypeHasAModule rather than silently
// inheriting SBOM's assumptions about sources and operations — which is exactly
// how the five types came to share one registration path.
type Registry struct {
	modules map[model.BOMType]Module
}

// Default is the registry the project service runs with.
func Default() *Registry {
	mods := []Module{
		sbomModule{}, cbomModule{}, qbomModule{}, aibomModule{}, hbomModule{},
	}
	r := &Registry{modules: make(map[model.BOMType]Module, len(mods))}
	for _, m := range mods {
		r.modules[m.Type()] = m
	}
	return r
}

// For returns the module serving a BOM type.
func (r *Registry) For(t model.BOMType) (Module, bool) {
	m, ok := r.modules[t]
	return m, ok
}

// Types lists every BOM type the registry serves, in CERT-In's order.
func (r *Registry) Types() []model.BOMType {
	out := make([]model.BOMType, 0, len(r.modules))
	for _, t := range model.AllBOMTypes() {
		if _, ok := r.modules[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

// RequireClassified refuses an operation belonging to one BOM type on a project
// not classified for it.
//
// ⚠ NOTHING CHECKED THIS ANYWHERE, FOR ANY TYPE. Devices, hardware components,
// CSV imports, Table 8 quantum metadata and AI model fields all took a project
// id and wrote against it. The store's own test helper creates projects with NO
// classifications at all and the device tests passed, which is the proof: the
// data was accepted by a path that had no opinion about whether it made sense.
//
// The project's classification list is the caller's to supply — it comes from
// the project the caller already loaded, so this adds no query and cannot be
// skipped by forgetting one.
func (r *Registry) RequireClassified(classifications []model.BOMType, want model.BOMType) error {
	for _, c := range classifications {
		if c == want {
			return nil
		}
	}

	m, ok := r.For(want)
	if !ok {
		// A type with no module cannot be reasoned about, and guessing is how
		// this class of bug started. Refuse rather than allow.
		return errs.Newf(errs.ProjectNotClassified,
			"this project is not classified for %s", want)
	}

	have := "nothing"
	if len(classifications) > 0 {
		names := make([]string, 0, len(classifications))
		for _, c := range classifications {
			names = append(names, string(c))
		}
		sort.Strings(names)
		have = joinWithAnd(names)
	}

	return errs.Newf(errs.ProjectNotClassified,
		"%s belongs to a project classified for %s, and this project is "+
			"classified for %s. Add %s to the project's classifications, or "+
			"use a project that already has it — otherwise this would be "+
			"stored against a project whose reports can never contain it.",
		m.Noun(), want, have, want)
}

// RequireSource refuses a registration whose source type no engine for that BOM
// type can read.
func (r *Registry) RequireSource(t model.BOMType, sourceType string) error {
	if model.SupportsRegistrationSource(t, sourceType) {
		return nil
	}

	allowed := model.RegistrationSources(t)
	if len(allowed) == 0 {
		return errs.Newf(errs.ValidationFieldInvalid,
			"%s cannot be registered from any source", t)
	}

	return errs.Newf(errs.ValidationFieldInvalid,
		"a %s project cannot be registered from %q. %s can be registered from "+
			"%s. A project registered from a source its engines cannot read "+
			"produces an empty %s and nothing says so.",
		t, sourceType, t, joinWithAnd(allowed), t)
}

// joinWithAnd renders a list the way a sentence needs it.
func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	out := ""
	for i, s := range items[:len(items)-1] {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return fmt.Sprintf("%s and %s", out, items[len(items)-1])
}
