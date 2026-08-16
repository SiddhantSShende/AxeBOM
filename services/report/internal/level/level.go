// Package level projects a canonical BOM onto one of CERT-In's BOM levels.
//
// The guideline (§3.1) defines five: Top-Level, n-Level, Delivery, Transitive
// and Complete. Two are load-bearing for a report:
//
//	Top-Level  depth <= 1 from the root set  — direct dependencies
//	Complete   everything, orphans included and FLAGGED
//
// ⚠ AN ORPHAN CAN NEVER SATISFY TOP-LEVEL, AND THAT IS THE HONEST ANSWER.
//
// An orphan is a component no root reaches. We do not know whether it is a
// direct dependency, a transitive one, or dead code. Including it in a
// Top-Level report would assert a position in the tree that was never
// established; excluding it silently would hide it entirely. So it is excluded
// from Top-Level, included in Complete, and COUNTED in both — the count is what
// stops the exclusion from becoming a disappearance.
//
// See docs/03-NORMALIZER-SPEC.md §4.3.
package level

import (
	"fmt"
	"sort"
)

// Level is a CERT-In BOM level.
type Level string

const (
	// TopLevel is depth <= 1 from the root set.
	TopLevel Level = "top-level"
	// Complete is everything, including flagged orphans.
	Complete Level = "complete"
)

// Valid reports whether a level string is one this projection implements.
//
// n-Level, Delivery and Transitive are defined by the guideline but not yet
// produced; an explicit "not implemented" is better than silently rendering a
// Complete BOM under a label the customer chose for something narrower.
func Valid(l Level) bool {
	return l == TopLevel || l == Complete
}

// Component is the subset of the canonical model this projection needs.
type Component struct {
	Key string
	// Depth is nil for an orphan. ⚠ Not zero, not one — nil. A number here
	// would assert a tree position that was never established.
	Depth    *int
	IsDirect bool
	IsOrphan bool
	Scope    string
}

// Projection is a BOM narrowed to one level, plus what the narrowing removed.
type Projection struct {
	Level      Level
	Components []Component

	// ⚠ Everything excluded is COUNTED, never silently dropped. A Top-Level
	// report that says "42 components" without saying it omitted 900 is
	// indistinguishable from a project that genuinely has 42.
	ExcludedTransitive int
	ExcludedOrphans    int
	ExcludedByScope    int

	// Note is rendered into the report whenever anything was excluded.
	Note string
}

// Total is the component count the report displays for this level.
func (p Projection) Total() int { return len(p.Components) }

// ExcludedTotal is how many components the level omitted.
func (p Projection) ExcludedTotal() int {
	return p.ExcludedTransitive + p.ExcludedOrphans + p.ExcludedByScope
}

// Project narrows a component set to the requested level.
func Project(components []Component, l Level) (Projection, error) {
	if !Valid(l) {
		return Projection{}, fmt.Errorf(
			"level %q is not implemented; CERT-In §3.1 also defines n-Level, "+
				"Delivery and Transitive, and rendering one of those as Complete "+
				"would mislabel the report", l)
	}

	out := Projection{Level: l}

	for _, c := range components {
		// ⚠ `excluded` scope is dropped from BOTH levels but still counted.
		// It is in the BOM because something observed it; it is out of the
		// report because the operator scoped it out. Those are different
		// statements and the count keeps them distinguishable.
		if c.Scope == "excluded" {
			out.ExcludedByScope++
			continue
		}

		if l == Complete {
			out.Components = append(out.Components, c)
			continue
		}

		// Top-Level.
		if c.IsOrphan || c.Depth == nil {
			out.ExcludedOrphans++
			continue
		}
		if *c.Depth > 1 {
			out.ExcludedTransitive++
			continue
		}
		out.Components = append(out.Components, c)
	}

	sort.Slice(out.Components, func(i, j int) bool {
		return out.Components[i].Key < out.Components[j].Key
	})

	out.Note = note(out)
	return out, nil
}

// note explains what the level left out, in the report's own words.
//
// ⚠ RENDERED WHENEVER ANYTHING WAS EXCLUDED. A narrowed report that does not
// say it was narrowed is the same failure as an SBOM that silently omits an
// ecosystem: it converts a known limitation into an unknown the reader will not
// think to ask about.
func note(p Projection) string {
	if p.ExcludedTotal() == 0 {
		return ""
	}

	switch p.Level {
	case TopLevel:
		s := fmt.Sprintf(
			"This is a Top-Level BOM: it lists %d direct dependencies and omits "+
				"%d transitive ones.", p.Total(), p.ExcludedTransitive)
		if p.ExcludedOrphans > 0 {
			s += fmt.Sprintf(
				" A further %d component(s) could not be placed in the dependency "+
					"tree and are omitted here; they appear in the Complete BOM.",
				p.ExcludedOrphans)
		}
		if p.ExcludedByScope > 0 {
			s += fmt.Sprintf(" %d component(s) are out of the configured scope.",
				p.ExcludedByScope)
		}
		return s
	default:
		s := fmt.Sprintf("This is a Complete BOM listing %d components.", p.Total())
		if p.ExcludedByScope > 0 {
			s += fmt.Sprintf(" %d component(s) are out of the configured scope and "+
				"are not listed.", p.ExcludedByScope)
		}
		return s
	}
}

// OrphanNote describes the orphans inside a Complete BOM.
//
// They ARE listed there, but flagged: a reader comparing the direct-dependency
// count against the total needs to know some components have no known position
// rather than assuming they are all transitive.
func OrphanNote(components []Component) string {
	orphans := 0
	for _, c := range components {
		if c.IsOrphan || c.Depth == nil {
			orphans++
		}
	}
	if orphans == 0 {
		return ""
	}
	return fmt.Sprintf(
		"%d component(s) are not reachable from any dependency root. They are "+
			"listed with an unknown depth rather than assumed to be direct "+
			"dependencies, which would overstate the direct-dependency count.",
		orphans)
}
