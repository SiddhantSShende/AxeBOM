package service

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestTheRenderableFormatsMatchTheDatabaseConstraint.
//
// ⚠ THEY DID NOT, AND THE SYMPTOM WAS A 500 FROM A REQUEST THE API HAD JUST
// VALIDATED.
//
// `report.reports` carries `CHECK (format IN (…))`. Adding `mlbom` to
// `parseFormat` and not to the constraint produced an endpoint that accepted the
// format, rendered nothing, and failed at INSERT with a check violation — so the
// customer saw INTERNAL_UNEXPECTED for a request that was entirely well-formed.
//
// A closed set in Go and a closed set in SQL are two statements of one rule.
// This reads the migrations as TEXT rather than needing a live database, for the
// same reason `libs/go-shared/schemacheck` does: the check has to run on every
// machine, not only where Postgres happens to be up.
func TestTheRenderableFormatsMatchTheDatabaseConstraint(t *testing.T) {
	constraint := latestFormatConstraint(t)

	got := slices.Clone(Formats)
	sort.Strings(got)
	sort.Strings(constraint)

	if !slices.Equal(got, constraint) {
		t.Errorf("service.Formats and the database CHECK disagree.\n"+
			"  Go:  %v\n  SQL: %v\n"+
			"Adding a format needs BOTH — a migration under migrations/report/ "+
			"and this slice — or the API accepts a format the insert refuses.",
			got, constraint)
	}
}

// latestFormatConstraint reads the newest `reports_format_check` from the
// migrations, which is the one actually in force.
//
// ⚠ THE NEWEST, NOT THE FIRST. Every format so far arrived by dropping and
// re-adding the constraint, so the file that defines the current rule is the
// highest-numbered one that mentions it — reading `0001` would compare against a
// constraint that has not existed for three migrations.
func latestFormatConstraint(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "..", "migrations", "report")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	// ⚠ ONLY THE `Up` HALF. Every one of these migrations restores the PREVIOUS
	// set in its `Down`, so scanning the whole file finds the constraint being
	// rolled back and compares against a set that is deliberately one behind.
	pattern := regexp.MustCompile(`(?s)ADD CONSTRAINT reports_format_check\s*\n?\s*CHECK \(format IN \(([^)]*)\)\)`)
	var found []string
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		up, _, _ := strings.Cut(string(body), "-- +goose Down")
		for _, m := range pattern.FindAllStringSubmatch(up, -1) {
			found = parseQuoted(m[1])
		}
	}
	if len(found) == 0 {
		t.Fatal("no reports_format_check constraint found in migrations/report/ — " +
			"this guard is checking nothing")
	}
	return found
}

func parseQuoted(list string) []string {
	var out []string
	for _, part := range strings.Split(list, ",") {
		if v := strings.Trim(strings.TrimSpace(part), "'"); v != "" {
			out = append(out, v)
		}
	}
	return out
}
