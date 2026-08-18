// Package auditexport renders the audit log for review.
//
// ⚠ CERT-In §5.3.6 ASKS FOR REVIEW. EXPORT IS WHAT MAKES REVIEW PRACTICAL.
//
// An audit log nobody can get out of the database is an audit log nobody reads,
// and an unread log is indistinguishable from no log at the moment it matters.
// A reviewer needs it in something they can filter, sort and hand to somebody
// else — which means JSON Lines for a pipeline and CSV for a person.
//
// ⚠ THE EXPORT IS ITSELF AN AUDITED EVENT.
//
// Exporting the log copies a tenant's entire administrative history out of the
// system. That is exactly the action a reviewer would want to see in the log,
// so the caller records it before streaming. A log that does not record its own
// export has a blind spot shaped like the most interesting question.
package auditexport

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Format is an output encoding.
type Format string

const (
	// FormatJSONL is one JSON object per line — for a pipeline.
	//
	// ⚠ NOT A JSON ARRAY. An array must be closed, so a stream interrupted
	// halfway produces a file no parser will read; JSON Lines degrades to a
	// truncated-but-usable file, which is what a reviewer actually wants from a
	// large export that failed.
	FormatJSONL Format = "jsonl"
	// FormatCSV is for a person with a spreadsheet.
	FormatCSV Format = "csv"
)

// Formats returns every supported encoding.
func Formats() []Format { return []Format{FormatJSONL, FormatCSV} }

// Valid reports whether f is supported.
func (f Format) Valid() bool {
	for _, known := range Formats() {
		if f == known {
			return true
		}
	}
	return false
}

// Entry is one audit-log row.
type Entry struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	ActorUserID string         `json:"actor_user_id,omitempty"`
	Action      string         `json:"action"`
	EntityType  string         `json:"entity_type,omitempty"`
	EntityID    string         `json:"entity_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	IP          string         `json:"ip,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	// CreatedAt is RFC3339 UTC with a literal Z.
	CreatedAt string `json:"created_at"`
}

// Header is the CSV column order.
//
// ⚠ FIXED AND EXPLICIT. A reviewer diffs two exports taken months apart, and a
// column order derived from map iteration would make every export differ from
// every other for no reason.
var Header = []string{
	"id", "created_at", "tenant_id", "actor_user_id",
	"action", "entity_type", "entity_id", "ip", "user_agent", "metadata",
}

// Writer streams entries in one format.
type Writer struct {
	format Format
	out    io.Writer
	csv    *csv.Writer
	count  int
}

// NewWriter builds a writer and emits any preamble.
func NewWriter(out io.Writer, format Format) (*Writer, error) {
	if !format.Valid() {
		return nil, fmt.Errorf("auditexport: %q is not a supported format", format)
	}

	w := &Writer{format: format, out: out}
	if format == FormatCSV {
		w.csv = csv.NewWriter(out)
		if err := w.csv.Write(Header); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Write emits one entry.
func (w *Writer) Write(e Entry) error {
	w.count++

	switch w.format {
	case FormatJSONL:
		// ⚠ NO HTML ESCAPING. encoding/json escapes <, > and & by default,
		// which corrupts a user-agent string and any URL in metadata — the
		// export would no longer match what was recorded, which for an audit
		// artifact is the one thing it must do.
		enc := json.NewEncoder(w.out)
		enc.SetEscapeHTML(false)
		return enc.Encode(e)

	case FormatCSV:
		return w.csv.Write([]string{
			e.ID, e.CreatedAt, e.TenantID, e.ActorUserID,
			e.Action, e.EntityType, e.EntityID, e.IP, e.UserAgent,
			metadataCell(e.Metadata),
		})
	}
	return fmt.Errorf("auditexport: unsupported format %q", w.format)
}

// Close flushes and returns how many entries were written.
func (w *Writer) Close() (int, error) {
	if w.csv != nil {
		w.csv.Flush()
		if err := w.csv.Error(); err != nil {
			return w.count, err
		}
	}
	return w.count, nil
}

// metadataCell renders metadata deterministically and safely.
//
// ⚠ TWO SEPARATE HAZARDS, AND BOTH MATTER HERE.
//
//  1. Map iteration order is randomized in Go, so an unsorted render makes two
//     exports of identical data differ — and a reviewer diffing them sees noise
//     instead of change.
//  2. A metadata value beginning `=`, `+`, `-`, `@`, TAB or CR EXECUTES when the
//     CSV is opened in Excel. Audit metadata contains user-controlled strings
//     (a project name, a search query), so this is the same formula-injection
//     class the report writer defends against, in a file a reviewer is
//     especially likely to open in a spreadsheet.
func metadataCell(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}

	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%v", k, metadata[k]))
	}
	return escapeCell(strings.Join(pairs, "; "))
}

// escapeCell neutralises a spreadsheet formula.
//
// A single leading quote is what Excel and LibreOffice both read as "this is
// text". The value is unchanged for every other reader.
func escapeCell(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

// ExportRecord is the audit entry describing an export.
//
// ⚠ WRITTEN BEFORE THE STREAM STARTS, not after. An export that fails halfway
// still copied rows out of the system, and the log has to show the attempt —
// recording only completed exports means the interesting case is the one that
// leaves no trace.
func ExportRecord(actorUserID string, format Format, from, to time.Time) Entry {
	return Entry{
		ActorUserID: actorUserID,
		Action:      "audit_log.export",
		EntityType:  "audit_log",
		Metadata: map[string]any{
			"format": string(format),
			"from":   from.UTC().Format(time.RFC3339),
			"to":     to.UTC().Format(time.RFC3339),
		},
	}
}
