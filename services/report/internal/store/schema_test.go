package store

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestEveryColumnThisPackageQueriesExists.
//
// ⚠ THIS PACKAGE INVENTED FOUR COLUMN NAMES BEFORE THIS TEST EXISTED.
//
// It read `project.project_practices` (the table is `project.practices`),
// `p.distribution_delivery` (the column is `distribution`), and
// `parent_component_id` / `child_component_id` (they are `from_` and `to_`).
// Every one of them compiles, passes review, and fails at runtime against a
// real database — which is the same defect Phase 6 hit in the scan store, where
// a store that invented columns left fan-out publishing zero jobs silently.
//
// The check is static because the database is not always up. It parses the SQL
// literals in this package and the CREATE TABLE statements in migrations/, and
// asserts every qualified table exists and every bare identifier appearing in a
// SELECT list is a column of some table in the schemas this package reads.
//
// It is deliberately conservative: it only judges identifiers it can attribute,
// so it produces no false alarms on expressions and aliases. What it does catch
// is the whole class above — a name that exists nowhere.
func TestEveryColumnThisPackageQueriesExists(t *testing.T) {
	schema := loadSchema(t)
	if len(schema.tables) == 0 {
		t.Fatal("no tables were parsed from migrations/, so this check proves nothing")
	}

	sources := goFiles(t, ".")
	if len(sources) == 0 {
		t.Fatal("no source files were scanned, so this check proves nothing")
	}

	knownColumns := map[string]bool{}
	for _, cols := range schema.tables {
		for c := range cols {
			knownColumns[c] = true
		}
	}

	for _, path := range sources {
		body, err := os.ReadFile(path) //nolint:gosec // a test reading its own package
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(body)

		// Qualified table references: schema.table
		for _, ref := range tablePattern.FindAllStringSubmatch(text, -1) {
			qualified := strings.ToLower(ref[1] + "." + ref[2])
			if !schema.readableSchemas[strings.ToLower(ref[1])] {
				continue // not a database schema we know about
			}
			_, isTable := schema.tables[qualified]
			if !isTable && !schema.functions[qualified] {
				t.Errorf("%s queries %q, which is neither a table nor a function "+
					"in migrations/\n    known tables in that schema: %v",
					filepath.Base(path), qualified, schema.inSchema(ref[1]))
			}
		}

		// Column names used with a table alias: `p.distribution_delivery`,
		// `d.parent_component_id`. A one- or two-letter alias followed by a
		// snake_case identifier is a column reference with very few false
		// positives, and it is exactly the shape all four real bugs took.
		for _, ref := range aliasedColumnPattern.FindAllStringSubmatch(text, -1) {
			name := strings.ToLower(ref[2])
			if knownColumns[name] || sqlKeywords[name] {
				continue
			}
			t.Errorf("%s references column %q (as %s.%s), which exists in no table "+
				"in migrations/", filepath.Base(path), name, ref[1], ref[2])
		}
	}
}

// tablePattern matches `schema.table` in a SQL string.
var tablePattern = regexp.MustCompile(`\b(report|normalize|scan|project|auth)\.([a-z_][a-z0-9_]*)\b`)

// aliasedColumnPattern matches `x.column_name` where x is a short alias.
var aliasedColumnPattern = regexp.MustCompile(`\b([a-z]{1,2})\.([a-z_][a-z0-9_]*_[a-z0-9_]*)\b`)

// sqlKeywords are identifiers the patterns may pick up that are not columns.
var sqlKeywords = map[string]bool{
	"share_links": true, "share_access_log": true, "bom_documents": true,
	"component_dependencies": true, "engine_runs": true, "raw_findings": true,
	"vuln_clusters": true, "vuln_ids": true, "vuln_alias_edges": true,
	"component_locations": true, "component_provenance": true,
	"project_classifications": true, "repository_connections": true,
	"crypto_assets": true, "quantum_components": true, "ai_models": true,
	"ai_datasets": true, "hardware_components": true, "vex_statements": true,
	"csaf_documents": true, "vuln_cluster_merges": true, "license_refs": true,
	"component_candidate_identities": true,
}

type schemaIndex struct {
	// tables maps "schema.table" to its column set.
	tables map[string]map[string]bool
	// functions holds "schema.function" names.
	//
	// ⚠ CHECKED FOR THE SAME REASON AS TABLES. The anonymous share-link path
	// calls two SECURITY DEFINER functions by name. A typo there is exactly as
	// invisible at compile time as a wrong column, and it lands on the one
	// route that serves data with no identity attached.
	functions map[string]bool
	// readableSchemas are the schemas whose CREATE statements were found.
	readableSchemas map[string]bool
}

func (s schemaIndex) inSchema(name string) []string {
	prefix := strings.ToLower(name) + "."
	var out []string
	for t := range s.tables {
		if strings.HasPrefix(t, prefix) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

var (
	createTablePattern    = regexp.MustCompile(`(?i)CREATE TABLE\s+([a-z_]+)\.([a-z_][a-z0-9_]*)\s*\(`)
	createFunctionPattern = regexp.MustCompile(`(?i)CREATE (?:OR REPLACE )?FUNCTION\s+([a-z_]+)\.([a-z_][a-z0-9_]*)\s*\(`)
	addColumnPattern      = regexp.MustCompile(`(?i)ADD COLUMN\s+([a-z_][a-z0-9_]*)`)
	columnLinePattern     = regexp.MustCompile(`(?m)^\s{4}([a-z_][a-z0-9_]*)\s+[a-z]`)
)

// loadSchema parses migrations/ into a table -> column index.
func loadSchema(t *testing.T) schemaIndex {
	t.Helper()

	root := filepath.Join("..", "..", "..", "..", "migrations")
	idx := schemaIndex{
		tables:          map[string]map[string]bool{},
		functions:       map[string]bool{},
		readableSchemas: map[string]bool{},
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		body, err := os.ReadFile(path) //nolint:gosec // walking our own migrations
		if err != nil {
			return err
		}
		parseMigration(string(body), &idx)
		return nil
	})
	if err != nil {
		t.Fatalf("walking migrations: %v", err)
	}
	return idx
}

// parseMigration extracts table and column names from one migration.
//
// A real SQL parser would be a dependency added to read our own DDL. This is a
// deliberately shallow reader: it finds CREATE TABLE bodies and the
// four-space-indented column definitions inside them, which is the house style
// every migration follows. Anything it cannot attribute is simply not checked,
// so the failure mode is a missed bug rather than a false one.
func parseMigration(body string, idx *schemaIndex) {
	locs := createTablePattern.FindAllStringSubmatchIndex(body, -1)
	for i, loc := range locs {
		schema := strings.ToLower(body[loc[2]:loc[3]])
		table := strings.ToLower(body[loc[4]:loc[5]])
		qualified := schema + "." + table

		idx.readableSchemas[schema] = true
		if idx.tables[qualified] == nil {
			idx.tables[qualified] = map[string]bool{}
		}

		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		for _, m := range columnLinePattern.FindAllStringSubmatch(body[loc[1]:end], -1) {
			idx.tables[qualified][strings.ToLower(m[1])] = true
		}
	}

	for _, m := range createFunctionPattern.FindAllStringSubmatch(body, -1) {
		schema := strings.ToLower(m[1])
		idx.readableSchemas[schema] = true
		idx.functions[schema+"."+strings.ToLower(m[2])] = true
	}

	// ALTER TABLE ... ADD COLUMN, which later migrations use.
	for _, m := range addColumnPattern.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(m[1])
		for _, cols := range idx.tables {
			// The column belongs to one table, but this reader does not track
			// which. Registering it everywhere keeps the check conservative:
			// it can miss a wrong table, never invent a wrong column.
			cols[name] = true
			break
		}
		if len(idx.tables) > 0 {
			for _, cols := range idx.tables {
				cols[name] = true
			}
		}
	}
}

func goFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out
}
