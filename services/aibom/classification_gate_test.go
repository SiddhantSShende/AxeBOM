package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestEveryWritePathIsClassificationGated.
//
// ⚠ THE RULE TRAVELLED WITH THE CODE. `services/project` has carried this guard
// over its own BOM-type write paths since the classification gate was added,
// and the AI write path used to be one of them. Moving that path to this
// service without moving the guard would have quietly dropped it — the exact
// shape of loss a refactor produces and nothing catches.
//
// ⚠ AND THE THING IT PREVENTS IS SILENT. A person fills in what a model is FOR,
// on a project classified SBOM only. The answer saves, the screen says saved,
// and no AIBOM is ever generated to render it. The customer finds out at report
// time, if at all.
//
// This reads the source rather than the behaviour because there is nothing to
// call: whether a method is gated is a property of what it was written to do,
// and a unit test per method would be the same hand-applied rule one level up.
func TestEveryWritePathIsClassificationGated(t *testing.T) {
	const gate = "requireAIBOMClassified"
	// Every method on the store that brings NEW data into existence. Reads are
	// absent on purpose: refusing to SHOW a project's AI data because somebody
	// changed a classification would hide data the customer must still be able
	// to see and correct.
	writePrefixes := []string{"Save", "Set", "Record"}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/store/store.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse store.go: %v", err)
	}

	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		isWrite := false
		for _, prefix := range writePrefixes {
			if strings.HasPrefix(fn.Name.Name, prefix) {
				isWrite = true
			}
		}
		if !isWrite {
			continue
		}
		checked++

		if !callsGate(fn, gate) {
			t.Errorf("Store.%s writes AI data without calling %s. Data written "+
				"this way is stored against a project whose reports can never "+
				"contain it, and nothing tells the customer.", fn.Name.Name, gate)
		}
	}

	// ⚠ THE STALENESS CHECK. A rename that made every method invisible to the
	// prefix list above would leave a green test proving nothing — the exact
	// failure mode this codebase has hit before.
	if checked == 0 {
		t.Fatal("no write methods were found at all; this guard is checking nothing")
	}
	t.Logf("%d write paths checked", checked)
}

func callsGate(fn *ast.FuncDecl, gate string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == gate {
			found = true
		}
		return true
	})
	return found
}
