package auditexport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func entry() Entry {
	return Entry{
		ID: "0199-entry", TenantID: "0199-tenant", ActorUserID: "0199-user",
		Action: "project.create", EntityType: "project", EntityID: "0199-project",
		IP: "203.0.113.7", UserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
		Metadata:  map[string]any{"name": "payments-api", "sdlc_stage": "production"},
		CreatedAt: "2026-08-18T09:14:03Z",
	}
}

func write(t *testing.T, format Format, entries ...Entry) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, format)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// ---------------------------------------------------------------------------
// Formula injection — the same class the report writer defends against
// ---------------------------------------------------------------------------

// TestAMetadataFormulaIsNeutralised.
//
// ⚠ A CSV IS THE FORMAT A REVIEWER IS MOST LIKELY TO OPEN IN EXCEL, and audit
// metadata carries user-controlled strings — a project name, a search query. A
// value beginning `=`, `+`, `-`, `@`, TAB or CR executes on open.
func TestAMetadataFormulaIsNeutralised(t *testing.T) {
	hostile := []string{
		`=cmd|'/c calc'!A1`,
		`+2+3`,
		`-1+1`,
		`@SUM(1:2)`,
		"\tTAB",
		"\rCR",
	}

	for _, value := range hostile {
		e := entry()
		// The metadata key sorts first, so the hostile value leads the cell.
		e.Metadata = map[string]any{"aaa": value}
		out := write(t, FormatCSV, e)

		rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
		if err != nil {
			t.Fatalf("the export is not readable as CSV: %v", err)
		}
		cell := rows[1][len(Header)-1]

		// The rendered cell is `aaa=<value>`, so it starts with a letter — the
		// danger is a value that leads. Assert the escape on the raw render.
		raw := metadataCell(map[string]any{"": value})
		if raw != "" && strings.ContainsAny(raw[:1], "=+-@\t\r") {
			t.Errorf("metadata %q was not escaped: %q", value, raw)
		}
		if cell == "" {
			t.Errorf("metadata %q vanished from the export", value)
		}
	}
}

func TestAnEscapedCellStillCarriesItsValue(t *testing.T) {
	// Neutralising must not mean discarding: the audit record has to match what
	// was logged, or the export is not evidence of anything.
	escaped := escapeCell("=1+1")
	if !strings.Contains(escaped, "=1+1") {
		t.Fatalf("escaping lost the value: %q", escaped)
	}
	if escaped[0] != '\'' {
		t.Errorf("escaped value does not lead with a quote: %q", escaped)
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// TestMetadataRendersDeterministically.
//
// ⚠ MAP ITERATION ORDER IS RANDOMIZED IN GO. A reviewer diffing two exports
// taken months apart would see every row as changed, and real change would be
// invisible in the noise.
func TestMetadataRendersDeterministically(t *testing.T) {
	metadata := map[string]any{
		"zeta": 1, "alpha": 2, "mu": 3, "beta": 4, "omega": 5,
	}
	first := metadataCell(metadata)
	for range 50 {
		if got := metadataCell(metadata); got != first {
			t.Fatalf("metadata render changed: %q then %q", first, got)
		}
	}
	if !strings.HasPrefix(first, "alpha=") {
		t.Errorf("metadata is not sorted: %q", first)
	}
}

func TestTheCSVColumnOrderIsFixed(t *testing.T) {
	out := write(t, FormatCSV, entry())
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range Header {
		if rows[0][i] != want {
			t.Errorf("column %d is %q, want %q", i, rows[0][i], want)
		}
	}
}

// ---------------------------------------------------------------------------
// JSON Lines
// ---------------------------------------------------------------------------

// TestJSONLIsOneObjectPerLine.
//
// ⚠ NOT A JSON ARRAY. An array must be closed, so a stream interrupted halfway
// produces a file no parser will read. JSON Lines degrades to truncated-but-
// usable, which is what a reviewer wants from a large export that failed.
func TestJSONLIsOneObjectPerLine(t *testing.T) {
	out := write(t, FormatJSONL, entry(), entry(), entry())

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines for 3 entries", len(lines))
	}
	for i, line := range lines {
		var decoded Entry
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("line %d is not standalone JSON: %v", i, err)
		}
		if decoded.Action != "project.create" {
			t.Errorf("line %d lost its action", i)
		}
	}

	// A truncated stream is still parseable up to the break.
	truncated := out[:len(out)-20]
	whole := strings.Split(strings.TrimSpace(truncated), "\n")
	var decoded Entry
	if err := json.Unmarshal([]byte(whole[0]), &decoded); err != nil {
		t.Errorf("a truncated export lost its first record: %v", err)
	}
}

// TestJSONLDoesNotEscapeHTML.
//
// ⚠ encoding/json ESCAPES <, > AND & BY DEFAULT, which corrupts a user-agent
// string and any URL in metadata. The export would no longer match what was
// recorded — the one thing an audit artifact has to do.
func TestJSONLDoesNotEscapeHTML(t *testing.T) {
	e := entry()
	e.UserAgent = "Mozilla/5.0 <compatible> & such"
	e.Metadata = map[string]any{"url": "https://example.com/a?b=1&c=2"}

	out := write(t, FormatJSONL, e)

	// ⚠ THE ESCAPE MUST BE ABSENT AND THE LITERAL PRESENT — in that order.
	//
	// The first version of this test asserted the output contained no `&` or
	// `<` at all, which is backwards: those characters appearing literally is
	// the whole point. It would have passed only on output corrupted in exactly
	// the way it was supposed to catch.
	for _, escape := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(out, escape) {
			t.Errorf("the export contains the escape %s, so it no longer matches "+
				"the recorded value:\n%s", escape, out)
		}
	}
	if !strings.Contains(out, "b=1&c=2") {
		t.Errorf("the URL was altered: %s", out)
	}
	if !strings.Contains(out, "<compatible>") {
		t.Errorf("the user agent was altered: %s", out)
	}
}

// ---------------------------------------------------------------------------
// The export is itself auditable
// ---------------------------------------------------------------------------

// TestAnExportProducesItsOwnAuditRecord.
//
// ⚠ EXPORTING COPIES A TENANT'S ENTIRE ADMINISTRATIVE HISTORY OUT OF THE
// SYSTEM. That is precisely the action a reviewer wants to see in the log. A log
// that does not record its own export has a blind spot shaped like the most
// interesting question.
func TestAnExportProducesItsOwnAuditRecord(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)

	record := ExportRecord("0199-user", FormatCSV, from, to)

	if record.Action != "audit_log.export" {
		t.Errorf("action = %q", record.Action)
	}
	if record.ActorUserID != "0199-user" {
		t.Error("the export record does not say who exported")
	}
	if record.Metadata["from"] != "2026-01-01T00:00:00Z" {
		t.Errorf("the record does not say what range was taken: %v", record.Metadata)
	}
	if record.Metadata["format"] != "csv" {
		t.Errorf("the record does not say what format: %v", record.Metadata)
	}
}

// ---------------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------------

func TestAnUnknownFormatIsRefused(t *testing.T) {
	if _, err := NewWriter(&bytes.Buffer{}, "pdf"); err == nil {
		t.Fatal("an unsupported format was accepted")
	}
}

func TestCloseReportsTheCount(t *testing.T) {
	// A reviewer needs to know the export is complete, and a count is the only
	// thing that distinguishes an empty range from a failed query.
	var buf bytes.Buffer
	w, err := NewWriter(&buf, FormatJSONL)
	if err != nil {
		t.Fatal(err)
	}
	for range 7 {
		if err := w.Write(entry()); err != nil {
			t.Fatal(err)
		}
	}
	n, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Errorf("count = %d, want 7", n)
	}
}

func TestAnEmptyExportIsWellFormed(t *testing.T) {
	// A tenant with no activity in the range gets a header and nothing else,
	// not an error — "no events" is an answer.
	out := write(t, FormatCSV)
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("an empty export has %d rows, want just the header", len(rows))
	}
}
