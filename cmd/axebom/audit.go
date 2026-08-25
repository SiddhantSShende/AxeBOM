package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/auditexport"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
)

// runAudit is the operator-facing audit-log export.
//
// ⚠ THIS CONNECTS AS THE DATABASE OWNER, NOT axebom_app — SAME AS `db seed`
// AND `db reset`. RLS is what stops the application asking for another
// tenant's rows; this is a local operator tool run outside the application
// path entirely, for the incident-response case where nobody has (or should
// need) a browser session — so it filters by tenant EXPLICITLY, by hand,
// which is the one place in this codebase CLAUDE.md's "never write
// `WHERE tenant_id = ?`" rule does not apply: that rule exists to stop RLS
// from ever being the only thing standing between two tenants' data in
// APPLICATION code. There is no RLS here to lean on, so the explicit filter
// is the only thing standing between two tenants' data, and it is written
// once, in this one place, on purpose.
func runAudit(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return fmt.Errorf("usage: axebom audit export --tenant <id> [--format jsonl|csv] [--out <file>] [--from RFC3339] [--to RFC3339]")
	}

	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	tenantID := fs.String("tenant", "", "tenant id to export (required)")
	format := fs.String("format", string(auditexport.FormatJSONL), "jsonl or csv")
	outPath := fs.String("out", "", "output file (default: stdout)")
	fromRaw := fs.String("from", "", "only rows at or after this RFC3339 timestamp")
	toRaw := fs.String("to", "", "only rows at or before this RFC3339 timestamp")
	operator := fs.String("actor", "", "who is running this export, for the audit trail (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *operator == "" {
		return fmt.Errorf("--actor is required: this export is itself an audited event " +
			"(auditexport's whole reason to exist), and an unattributed one defeats the point")
	}
	if *tenantID == "" {
		return fmt.Errorf("--tenant is required")
	}
	f := auditexport.Format(*format)
	if !f.Valid() {
		return fmt.Errorf("--format %q is not supported; want jsonl or csv", *format)
	}
	from, err := parseOptionalRFC3339(*fromRaw)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	to, err := parseOptionalRFC3339(*toRaw)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}

	cfg, err := config.LoadService("gateway") // any service's Postgres config works
	if err != nil {
		return err
	}

	conn, err := pgx.Connect(ctx, cfg.Postgres.AdminDSN())
	if err != nil {
		return fmt.Errorf("connect as owner (%s): %w", cfg.Postgres.Redacted(), err)
	}
	defer func() { _ = conn.Close(ctx) }()

	out := os.Stdout
	if *outPath != "" {
		file, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open %s: %w", *outPath, err)
		}
		defer func() { _ = file.Close() }()
		out = file
	}

	w, err := auditexport.NewWriter(out, f)
	if err != nil {
		return err
	}

	// ⚠ RECORDED BEFORE THE STREAM STARTS, LIKE THE HTTP PATH. See
	// auditexport.ExportRecord's own doc comment. p_actor stays NULL — an
	// operator running this tool is not necessarily a row in auth.users —
	// and the free-text name goes into metadata instead, where it belongs
	// next to the row count an interactive session's export doesn't have
	// (that one streams the response instead of buffering it).
	rangeFrom, rangeTo := time.Time{}, time.Now()
	if from != nil {
		rangeFrom = *from
	}
	if to != nil {
		rangeTo = *to
	}
	rec := auditexport.ExportRecord("", f, rangeFrom, rangeTo)
	rec.Metadata["operator"] = *operator
	if _, err := conn.Exec(ctx, `SELECT auth.record_auth_event($1, $2, $3, $4, $5, $6)`,
		*tenantID, nil, rec.Action, rec.Metadata, nil, ""); err != nil {
		return fmt.Errorf("record export event: %w", err)
	}

	rows, err := conn.Query(ctx, `
		SELECT id, tenant_id, COALESCE(actor_user_id::text, ''), action,
		       COALESCE(entity_type, ''), COALESCE(entity_id::text, ''),
		       metadata, COALESCE(host(ip), ''), COALESCE(user_agent, ''),
		       created_at
		  FROM auth.audit_log
		 WHERE tenant_id = $1
		   AND ($2::timestamptz IS NULL OR created_at >= $2)
		   AND ($3::timestamptz IS NULL OR created_at <= $3)
		 ORDER BY created_at`, *tenantID, from, to)
	if err != nil {
		return fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			e           auditexport.Entry
			metadataRaw []byte
			createdAt   time.Time
		)
		if err := rows.Scan(&e.ID, &e.TenantID, &e.ActorUserID, &e.Action,
			&e.EntityType, &e.EntityID, &metadataRaw, &e.IP, &e.UserAgent,
			&createdAt); err != nil {
			return fmt.Errorf("scan audit entry: %w", err)
		}
		e.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if len(metadataRaw) > 0 {
			_ = json.Unmarshal(metadataRaw, &e.Metadata) //nolint:errcheck // best-effort, see auditexport.Store
		}
		if err := w.Write(e); err != nil {
			return fmt.Errorf("write entry: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	n, err := w.Close()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "exported %d row(s)\n", n)
	return nil
}

func parseOptionalRFC3339(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil //nolint:nilnil // absent is a valid, distinct answer from "invalid"
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	utc := t.UTC()
	return &utc, nil
}
