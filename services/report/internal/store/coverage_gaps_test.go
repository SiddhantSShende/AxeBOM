package store

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/services/report/internal/render"
)

// ⚠ A CBOM HAS NO COMPONENTS, so the component-derived gaps are empty for it
// and the gaps its engines reported are the only ones it has. Both lists reach
// the report, once each, in order.
func TestReportedGapsJoinTheComponentDerivedOnes(t *testing.T) {
	cases := []struct {
		name              string
		derived, reported []string
		want              string
	}{
		{"a cbom: engine-reported only", nil, []string{"go-source", "c-cpp-source"}, "c-cpp-source,go-source"},
		{"an sbom: component-derived only", []string{"cargo"}, nil, "cargo"},
		{"both, overlapping", []string{"cargo", "go-source"}, []string{"go-source", "rust-source"}, "cargo,go-source,rust-source"},
		{"neither", nil, nil, ""},
	}
	for _, c := range cases {
		got := strings.Join(unionSorted(c.derived, c.reported), ",")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// The component-derived half still works on its own: a component catalogued
// in an ecosystem no engine covered.
func TestAComponentInAnUncoveredEcosystemIsStillAGap(t *testing.T) {
	b := &render.BOM{
		Engines:    []render.EngineCoverage{{EngineID: "syft", Ecosystems: []string{"npm"}}},
		Components: []render.Component{{Ecosystem: "npm"}, {Ecosystem: "cargo"}},
	}
	if got := strings.Join(ecosystemsWithNoEngine(b), ","); got != "cargo" {
		t.Errorf("got %q, want cargo", got)
	}
}
