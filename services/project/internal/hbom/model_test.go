package hbom

import "testing"

func TestNormalizeDropsAnUnrecognisedCriticality(t *testing.T) {
	c := &Component{ProductName: " Widget ", Criticality: "URGENT"}
	Normalize(c)
	if c.Criticality != "" {
		t.Errorf("criticality = %q, want dropped rather than coerced", c.Criticality)
	}
	if c.ProductName != "Widget" {
		t.Errorf("product name = %q, want trimmed", c.ProductName)
	}
}

func TestNormalizeLowercasesAndKeepsAValidCriticality(t *testing.T) {
	c := &Component{ProductName: "Widget", Criticality: " Critical "}
	Normalize(c)
	if c.Criticality != "critical" {
		t.Errorf("criticality = %q, want critical", c.Criticality)
	}
}

func TestNormalizeIsRecursive(t *testing.T) {
	child := &Component{ProductName: " Child ", Criticality: "bogus"}
	root := &Component{ProductName: "Root", Children: []*Component{child}}
	Normalize(root)
	if root.Children[0].ProductName != "Child" {
		t.Errorf("child product name = %q, want trimmed", root.Children[0].ProductName)
	}
	if root.Children[0].Criticality != "" {
		t.Errorf("child criticality = %q, want dropped", root.Children[0].Criticality)
	}
}

func TestNormalizeDropsEmptyComplianceEntries(t *testing.T) {
	c := &Component{ProductName: "Widget", Compliance: []string{" RoHS ", "", "  ", "CE"}}
	Normalize(c)
	if got, want := c.Compliance, []string{"RoHS", "CE"}; !equal(got, want) {
		t.Errorf("compliance = %v, want %v", got, want)
	}
}

func TestWalkVisitsParentsBeforeChildren(t *testing.T) {
	grandchild := &Component{ProductName: "GC"}
	child := &Component{ProductName: "C", Children: []*Component{grandchild}}
	root := &Component{ProductName: "R", Children: []*Component{child}}

	var order []string
	root.Walk(0, func(_ int, n *Component) { order = append(order, n.ProductName) })

	if got, want := order, []string{"R", "C", "GC"}; !equal(got, want) {
		t.Errorf("walk order = %v, want %v", got, want)
	}
}

func TestWalkStopsAtMaxDepth(t *testing.T) {
	// Build a chain deeper than MaxDepth and confirm Walk does not recurse
	// past it — mirrors the depth cap workers/hbom/model.py enforces.
	leaf := &Component{ProductName: "leaf"}
	node := leaf
	for i := 0; i < MaxDepth+5; i++ {
		node = &Component{ProductName: "n", Children: []*Component{node}}
	}

	count := 0
	node.Walk(0, func(int, *Component) { count++ })
	if count > MaxDepth+1 {
		t.Errorf("Walk visited %d nodes, want at most %d (MaxDepth+1)", count, MaxDepth+1)
	}
}
