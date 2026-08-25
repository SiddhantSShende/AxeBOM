package store

import (
	"path/filepath"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/schemacheck"
)

// TestEveryColumnThisPackageQueriesExists.
//
// ⚠ THE REPORT STORE INVENTED FOUR COLUMN NAMES BEFORE THIS CHECK EXISTED, and
// the scan store invented one in Phase 6 that left fan-out publishing zero jobs
// silently. Both compiled. Both passed review. Neither could fail until a real
// database was in front of them, which on this project is rarer than a commit.
//
// See libs/go-shared/schemacheck for what the check does and why it is static.
func TestEveryColumnThisPackageQueriesExists(t *testing.T) {
	idx, err := schemacheck.Load(filepath.Join("..", "..", "..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := schemacheck.Check(".", idx, schemacheck.Options{
		Schemas: []string{"campaign", "project", "scan"},
		Allow: map[string]bool{
			// Table names the alias pattern picks up.
			"due_campaigns": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		t.Errorf("%s %s", f.File, f.Message)
	}
}

// TestTheSchedulerCallsAFunctionThatExists.
//
// ⚠ THE ONE QUERY IN THIS SERVICE THAT RUNS OUTSIDE RLS. If its name is wrong
// the scheduler fails on every tick — which is a silent product failure, not a
// loud one: campaigns simply never fire, and the only symptom is an absence
// nobody is watching for.
func TestTheSchedulerCallsAFunctionThatExists(t *testing.T) {
	idx, err := schemacheck.Load(filepath.Join("..", "..", "..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if !idx.Functions["campaign.due_campaigns"] {
		t.Fatalf("campaign.due_campaigns is not defined in migrations/; known functions: %v",
			idx.Functions)
	}
}
