package store

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/services/report/internal/render"
)

// TestATopLevelHardwareBOMOmitsSubComponentsAndSaysSo.
//
// ⚠ BEFORE THIS, "Top-Level" WAS A LABEL THE HARDWARE SHEETS IGNORED.
// level.Project walks software components; nothing applied the same rule to
// the hardware tree, so a customer who chose a Top-Level hardware BOM got all
// 900 parts under a heading promising the top level only.
func TestATopLevelHardwareBOMOmitsSubComponentsAndSaysSo(t *testing.T) {
	out := render.BOM{
		Level: "top_level",
		Hardware: []render.HardwareComponent{
			{ID: "p", Depth: 0, Name: "gateway"},
			{ID: "a", ParentID: "p", Depth: 1, Name: "mainboard"},
			{ID: "b", ParentID: "a", Depth: 2, Name: "mcu"},
			{ID: "c", ParentID: "b", Depth: 3, Name: "die"},
		},
	}
	applyLevel(&out)

	if len(out.Hardware) != 2 {
		t.Fatalf("kept %d rows, want 2 (the product and its sub-assemblies)", len(out.Hardware))
	}
	for _, h := range out.Hardware {
		if h.Depth > 1 {
			t.Errorf("%q at depth %d survived a Top-Level projection", h.Name, h.Depth)
		}
	}
	// ⚠ COUNTED AND STATED. A report saying "2 components" without "and 2
	// omitted" is indistinguishable from a product that genuinely has 2 parts.
	if !strings.Contains(out.LevelNote, "2 sub-component(s)") {
		t.Errorf("the omission is not stated in the level note: %q", out.LevelNote)
	}
}

// A Complete BOM keeps everything, and says nothing extra about hardware.
func TestACompleteHardwareBOMKeepsTheWholeTree(t *testing.T) {
	out := render.BOM{
		Level: "complete",
		Hardware: []render.HardwareComponent{
			{ID: "p", Depth: 0}, {ID: "a", Depth: 1}, {ID: "b", Depth: 2},
		},
	}
	applyLevel(&out)

	if len(out.Hardware) != 3 {
		t.Errorf("a Complete BOM dropped %d hardware rows", 3-len(out.Hardware))
	}
}

// A flat parts list is unaffected, and must not gain a note claiming an
// omission that did not happen.
func TestAFlatHardwareBOMGainsNoOmissionNote(t *testing.T) {
	out := render.BOM{
		Level:    "top_level",
		Hardware: []render.HardwareComponent{{ID: "p", Depth: 0}, {ID: "a", Depth: 1}},
	}
	applyLevel(&out)

	if len(out.Hardware) != 2 {
		t.Errorf("a flat list lost rows: %d", len(out.Hardware))
	}
	if strings.Contains(out.LevelNote, "omitted") {
		t.Errorf("a note claims an omission that did not happen: %q", out.LevelNote)
	}
}
