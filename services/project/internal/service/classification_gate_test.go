package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// bomModuleFiles are the per-BOM-type service files. A BOM type that gains its
// own file belongs in this list.
// ⚠ `ai_models.go` LEFT THIS LIST WHEN THE AI WRITE PATH LEFT THIS SERVICE.
// It moved to services/aibom, which carries its own copy of this guard
// (`services/aibom/classification_gate_test.go`) over its own store — the rule
// travelled with the code rather than being quietly dropped with it.
var bomModuleFiles = []string{"hbom.go", "qbom.go"}

// creationPrefixes name the methods that bring NEW data into existence.
//
// Update and Delete are absent on purpose: requireClassified's own comment
// explains that gating them would trap data a customer must still be able to
// correct or remove after changing a project's classifications.
var creationPrefixes = []string{"Create", "Save", "Import"}

// exemptionMarker is how a creation path opts out, in writing, where a reviewer
// reading the function will see it.
const exemptionMarker = "DELIBERATELY NOT CLASSIFICATION-GATED"

// TestEveryBOMTypeSpecificCreationPathIsGated.
//
// ⚠ THE GATE IS ONLY WORTH ANYTHING IF IT IS ON EVERY PATH, AND A HAND-APPLIED
// RULE IS EXACTLY THE KIND THAT GETS FORGOTTEN ON THE SIXTH ONE. That is not
// hypothetical here: before this milestone the rule was on ZERO of them —
// devices, hardware components, CSV imports and Table 8 quantum metadata all
// wrote against any project id they were handed.
//
// This reads the source rather than the behaviour because there is nothing to
// call: whether a method is gated is a property of what it was written to do,
// and a unit test per method would be the same hand-applied rule one level up.
// The same reasoning as libs/go-shared/compliance's source guards.
func TestEveryBOMTypeSpecificCreationPathIsGated(t *testing.T) {
	fset := token.NewFileSet()
	total := 0

	for _, name := range bomModuleFiles {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		checked := 0
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !isCreationMethod(fn.Name.Name) {
				continue
			}
			checked++

			doc := fn.Doc.Text()
			if strings.Contains(doc, exemptionMarker) {
				// An exemption must say why, not merely claim one. A bare
				// marker with no reasoning is how an exemption becomes the
				// default.
				if len(strings.TrimSpace(doc)) < len(exemptionMarker)+80 {
					t.Errorf("%s.%s claims an exemption without explaining it",
						name, fn.Name.Name)
				}
				continue
			}

			if !callsRequireClassified(fn) {
				t.Errorf("%s.%s creates BOM-type-specific data without calling "+
					"requireClassified, and without an explicit %q comment "+
					"explaining why it is safe. Data written this way can be "+
					"stored against a project whose reports can never contain it.",
					name, fn.Name.Name, exemptionMarker)
			}
		}

		total += checked
	}

	// ⚠ THE STALENESS CHECK IS GLOBAL, NOT PER FILE, AND THE DIFFERENCE IS REAL.
	// A per-file "must have at least one" fired on ai_models.go, which
	// legitimately has NO creation path — an AI model row exists only because a
	// scan produced it, and the sole write edits fields on a row that already
	// exists. Zero creation paths in one module is a fact about that BOM type;
	// zero across ALL of them would mean these prefixes stopped matching
	// anything and this test had quietly become a no-op, which is the failure
	// worth catching.
	if total == 0 {
		t.Fatalf("no %v method exists in any of %v — the prefixes this test "+
			"matches on are stale and it is now guarding nothing",
			creationPrefixes, bomModuleFiles)
	}
}

func isCreationMethod(name string) bool {
	if !ast.IsExported(name) {
		return false
	}
	for _, p := range creationPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func callsRequireClassified(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "requireClassified" {
			found = true
			return false
		}
		return true
	})
	return found
}
