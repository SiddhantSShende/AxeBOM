package store

import (
	"path/filepath"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/schemacheck"
)

// TestEveryColumnThisPackageQueriesExists.
//
// ⚠ THIS PACKAGE INVENTED FOUR COLUMN NAMES BEFORE THIS TEST EXISTED.
//
// It read `project.project_practices` (the table is `project.practices`),
// `p.distribution_delivery` (the column is `distribution`), and
// `parent_component_id` / `child_component_id` (they are `from_` and `to_`).
// Every one of them compiles, passes review, and fails at runtime against a
// real database — the same defect Phase 6 hit in the scan store, where a store
// that invented columns left fan-out publishing zero jobs silently.
//
// The parser moved to libs/go-shared/schemacheck once the campaign store needed
// the same check; see that package for what it does and why it is static.
func TestEveryColumnThisPackageQueriesExists(t *testing.T) {
	idx, err := schemacheck.Load(filepath.Join("..", "..", "..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := schemacheck.Check(".", idx, schemacheck.Options{
		Schemas: []string{"report", "normalize", "scan", "project", "auth"},
		Allow: map[string]bool{
			// Table names the alias pattern picks up as if they were columns.
			"share_links": true, "share_access_log": true, "bom_documents": true,
			"component_dependencies": true, "engine_runs": true, "raw_findings": true,
			"vuln_clusters": true, "vuln_ids": true, "vuln_alias_edges": true,
			"component_locations": true, "component_provenance": true,
			"project_classifications": true, "repository_connections": true,
			"crypto_assets": true, "quantum_components": true, "ai_models": true,
			"ai_datasets": true, "hardware_components": true, "vex_statements": true,
			"csaf_documents": true, "vuln_cluster_merges": true, "license_refs": true,
			"component_candidate_identities": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		t.Errorf("%s %s", f.File, f.Message)
	}
}

// TestTheAnonymousPathCallsFunctionsThatExist.
//
// ⚠ THE SHARE-LINK ROUTE IS THE ONLY UNAUTHENTICATED DATA PATH IN THE PRODUCT,
// and it reaches the database through two SECURITY DEFINER functions called by
// name. A typo there is exactly as invisible at compile time as a wrong column,
// on the one route that serves data with no identity attached.
func TestTheAnonymousPathCallsFunctionsThatExist(t *testing.T) {
	idx, err := schemacheck.Load(filepath.Join("..", "..", "..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"report.claim_share_download"} {
		if !idx.Functions[fn] {
			t.Errorf("%s is not defined in migrations/", fn)
		}
	}
}
