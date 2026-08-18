// Package schemacheck statically validates SQL literals against migrations/.
//
// ⚠ THIS EXISTS BECAUSE A STORE INVENTED FOUR COLUMN NAMES AND NOTHING NOTICED.
//
// The report store read `project.project_practices` (the table is
// `project.practices`), `p.distribution_delivery` (the column is
// `distribution`), and `parent_component_id` / `child_component_id` (they are
// `from_` and `to_`). Every one of them compiles, passes review, and fails at
// runtime against a real database. The same defect hit the scan store in
// Phase 6, where a query naming a column that did not exist left fan-out
// publishing zero jobs — silently.
//
// The check is STATIC because the database is not always up, and a check that
// only runs when Docker is running is a check that does not run. It parses the
// SQL string literals in a package and the CREATE TABLE / CREATE FUNCTION
// statements in migrations/, then asserts every qualified name exists and every
// aliased column reference is a column of some table.
//
// It is deliberately conservative: it judges only identifiers it can attribute,
// so its failure mode is a missed bug rather than a false alarm. What it does
// catch is the whole class above — a name that exists nowhere.
package schemacheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Index is a parsed view of migrations/.
type Index struct {
	// Tables maps "schema.table" to its column set.
	Tables map[string]map[string]bool
	// Functions holds "schema.function" names.
	//
	// ⚠ CHECKED FOR THE SAME REASON AS TABLES. The SECURITY DEFINER functions
	// are called by name from Go, and a typo there is exactly as invisible at
	// compile time as a wrong column — while landing on the paths that run
	// outside RLS, which are the ones least able to absorb a mistake.
	Functions map[string]bool
	// Schemas are the schemas whose CREATE statements were found.
	Schemas map[string]bool
}

// Columns is the union of every table's columns.
func (i Index) Columns() map[string]bool {
	out := map[string]bool{}
	for _, cols := range i.Tables {
		for c := range cols {
			out[c] = true
		}
	}
	return out
}

// TablesIn lists the known tables in one schema, for an error message.
func (i Index) TablesIn(schema string) []string {
	prefix := strings.ToLower(schema) + "."
	var out []string
	for t := range i.Tables {
		if strings.HasPrefix(t, prefix) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

var (
	createTablePattern    = regexp.MustCompile(`(?i)CREATE TABLE\s+(?:IF NOT EXISTS\s+)?([a-z_]+)\.([a-z_][a-z0-9_]*)\s*\(`)
	createFunctionPattern = regexp.MustCompile(`(?i)CREATE (?:OR REPLACE )?FUNCTION\s+([a-z_]+)\.([a-z_][a-z0-9_]*)\s*\(`)
	addColumnPattern      = regexp.MustCompile(`(?i)ADD COLUMN\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	columnLinePattern     = regexp.MustCompile(`(?m)^\s{4}([a-z_][a-z0-9_]*)\s+[a-z]`)
	// returnsTablePattern picks up the column names a SECURITY DEFINER function
	// projects. Go scans those names, and they are as easy to mistype as a real
	// column while belonging to no table.
	returnsTablePattern = regexp.MustCompile(`(?is)RETURNS TABLE\s*\((.*?)\)\s*(?:LANGUAGE|AS)`)
	returnsColumnLine   = regexp.MustCompile(`(?m)^\s+([a-z_][a-z0-9_]*)\s+[a-z]`)
)

// Load parses every .sql file under root.
func Load(root string) (Index, error) {
	idx := Index{
		Tables:    map[string]map[string]bool{},
		Functions: map[string]bool{},
		Schemas:   map[string]bool{},
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		body, err := os.ReadFile(path) //nolint:gosec // walking our own migrations
		if err != nil {
			return err
		}
		parse(string(body), &idx)
		return nil
	})
	if err != nil {
		return Index{}, fmt.Errorf("walking %s: %w", root, err)
	}
	return idx, nil
}

// parse extracts table, column and function names from one migration.
//
// A real SQL parser would be a dependency added to read our own DDL. This is a
// deliberately shallow reader: it finds CREATE TABLE bodies and the
// four-space-indented column definitions inside them, which is the house style
// every migration follows.
func parse(body string, idx *Index) {
	locs := createTablePattern.FindAllStringSubmatchIndex(body, -1)
	for i, loc := range locs {
		schema := strings.ToLower(body[loc[2]:loc[3]])
		table := strings.ToLower(body[loc[4]:loc[5]])
		qualified := schema + "." + table

		idx.Schemas[schema] = true
		if idx.Tables[qualified] == nil {
			idx.Tables[qualified] = map[string]bool{}
		}

		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		for _, m := range columnLinePattern.FindAllStringSubmatch(body[loc[1]:end], -1) {
			idx.Tables[qualified][strings.ToLower(m[1])] = true
		}
	}

	for _, m := range createFunctionPattern.FindAllStringSubmatch(body, -1) {
		schema := strings.ToLower(m[1])
		idx.Schemas[schema] = true
		idx.Functions[schema+"."+strings.ToLower(m[2])] = true
	}

	// A function's projected columns count as known names.
	for _, m := range returnsTablePattern.FindAllStringSubmatch(body, -1) {
		for _, col := range returnsColumnLine.FindAllStringSubmatch(m[1], -1) {
			name := strings.ToLower(col[1])
			for _, cols := range idx.Tables {
				cols[name] = true
			}
		}
	}

	// ALTER TABLE ... ADD COLUMN, which later migrations use.
	//
	// The column belongs to one table, but this reader does not track which.
	// Registering it against every table keeps the check conservative: it can
	// miss a column attached to the wrong table, never invent one.
	for _, m := range addColumnPattern.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(m[1])
		for _, cols := range idx.Tables {
			cols[name] = true
		}
	}
}

// Finding is one problem in one file.
type Finding struct {
	File    string
	Message string
}

// Options configure a check.
type Options struct {
	// Schemas the package is allowed to reference. A name qualified by any
	// other schema prefix is ignored rather than reported, because it is
	// probably not SQL at all.
	//
	// ⚠ THIS IS NOT THE CROSS-SCHEMA JOIN CHECK. Listing a schema here says
	// "resolve names against it", not "joining to it is allowed". The
	// no-cross-schema-JOIN invariant is enforced by the boundary lint.
	Schemas []string
	// Allow are identifiers the patterns pick up that are not columns —
	// table names appearing after a schema alias, mostly.
	Allow map[string]bool
}

// Check reads every non-test .go file in dir and validates its SQL literals.
func Check(dir string, idx Index, opts Options) ([]Finding, error) {
	if len(idx.Tables) == 0 {
		return nil, fmt.Errorf("no tables were parsed, so this check would prove nothing")
	}

	files, err := goFiles(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no source files in %s, so this check would prove nothing", dir)
	}

	allowed := map[string]bool{}
	for _, s := range opts.Schemas {
		allowed[strings.ToLower(s)] = true
	}
	tablePattern := regexp.MustCompile(
		`\b(` + strings.Join(opts.Schemas, "|") + `)\.([a-z_][a-z0-9_]*)\b`)
	// A one- or two-letter alias followed by a snake_case identifier is a
	// column reference with very few false positives, and it is exactly the
	// shape all four real bugs took.
	aliasedColumn := regexp.MustCompile(`\b([a-z]{1,2})\.([a-z_][a-z0-9_]*_[a-z0-9_]*)\b`)

	known := idx.Columns()
	var findings []Finding

	for _, path := range files {
		body, err := os.ReadFile(path) //nolint:gosec // reading our own package
		if err != nil {
			return nil, err
		}
		text := string(body)
		base := filepath.Base(path)

		for _, ref := range tablePattern.FindAllStringSubmatch(text, -1) {
			schema := strings.ToLower(ref[1])
			if !allowed[schema] || !idx.Schemas[schema] {
				continue
			}
			qualified := schema + "." + strings.ToLower(ref[2])
			if _, isTable := idx.Tables[qualified]; isTable {
				continue
			}
			if idx.Functions[qualified] {
				continue
			}
			findings = append(findings, Finding{
				File: base,
				Message: fmt.Sprintf(
					"queries %q, which is neither a table nor a function in migrations/\n"+
						"    known tables in that schema: %v", qualified, idx.TablesIn(schema)),
			})
		}

		for _, ref := range aliasedColumn.FindAllStringSubmatch(text, -1) {
			name := strings.ToLower(ref[2])
			if known[name] || opts.Allow[name] {
				continue
			}
			findings = append(findings, Finding{
				File: base,
				Message: fmt.Sprintf(
					"references column %q (as %s.%s), which exists in no table in migrations/",
					name, ref[1], ref[2]),
			})
		}

		findings = append(findings, checkWrites(text, base, idx, allowed)...)
	}

	return findings, nil
}

var (
	insertPattern = regexp.MustCompile(
		`(?is)INSERT\s+INTO\s+([a-z_]+)\.([a-z_][a-z0-9_]*)\s*\(([^)]*)\)`)
	updatePattern = regexp.MustCompile(
		`(?is)UPDATE\s+([a-z_]+)\.([a-z_][a-z0-9_]*)\s+SET\s+(.*?)\s+WHERE\b`)
	setAssignment = regexp.MustCompile(`(?m)(?:^|,)\s*([a-z_][a-z0-9_]*)\s*=`)
)

// checkWrites validates INSERT column lists and UPDATE SET clauses.
//
// ⚠ THE READ-PATH CHECKS ABOVE DO NOT COVER THESE, AND THE WRITE PATH IS WHERE
// AN INVENTED COLUMN HURTS MOST. A SELECT naming a column that does not exist
// fails on the first request; an INSERT naming one fails only when that write
// path runs, which for a scheduler is at 02:30 on somebody else's Tuesday.
//
// These are checked against THE SPECIFIC TABLE rather than the union of all
// columns, because the write statement names its own table — so this catches a
// column that exists somewhere else, which the union check by construction
// cannot.
func checkWrites(text, base string, idx Index, allowed map[string]bool) []Finding {
	var findings []Finding

	check := func(schema, table, list string, columns []string) {
		schema, table = strings.ToLower(schema), strings.ToLower(table)
		if !allowed[schema] {
			return
		}
		cols, ok := idx.Tables[schema+"."+table]
		if !ok {
			return // the table itself is reported by the read-path check
		}
		for _, c := range columns {
			name := strings.ToLower(strings.TrimSpace(c))
			if name == "" || cols[name] {
				continue
			}
			findings = append(findings, Finding{
				File: base,
				Message: fmt.Sprintf(
					"writes column %q to %s.%s, which has no such column\n"+
						"    in: %s", name, schema, table, strings.TrimSpace(list)),
			})
		}
	}

	for _, m := range insertPattern.FindAllStringSubmatch(text, -1) {
		check(m[1], m[2], m[3], strings.Split(m[3], ","))
	}

	for _, m := range updatePattern.FindAllStringSubmatch(text, -1) {
		var names []string
		for _, a := range setAssignment.FindAllStringSubmatch(m[3], -1) {
			names = append(names, a[1])
		}
		check(m[1], m[2], m[3], names)
	}

	return findings
}

func goFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out, nil
}
