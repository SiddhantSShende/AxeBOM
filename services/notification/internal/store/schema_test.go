package store

import (
	"path/filepath"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/schemacheck"
)

// TestEveryColumnThisPackageQueriesExists.
//
// See libs/go-shared/schemacheck: the report store invented four column names
// and the scan store one, all of which compiled and passed review. The check is
// static because the database is not always up, and a check that only runs when
// Docker is running is a check that does not run.
func TestEveryColumnThisPackageQueriesExists(t *testing.T) {
	idx, err := schemacheck.Load(filepath.Join("..", "..", "..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := schemacheck.Check(".", idx, schemacheck.Options{
		Schemas: []string{"notify"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("%s %s", f.File, f.Message)
	}
}
