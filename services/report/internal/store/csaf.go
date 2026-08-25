package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/vex"
	"github.com/axebom/axebom/services/report/internal/csafgen"
)

// ---------------------------------------------------------------------------
// CSAF advisories — normalize.csaf_advisories, read/write cross-schema.
//
// ⚠ THIS SERVICE IS THE CSAF WRITE AUTHORITY, NOT scan-orchestrator. CSAF
// "follows VEX in the sequence" (libs/go-shared/csaf's own doc) — it is the
// PUBLISHED form of a decision scan-orchestrator's VEX store already
// recorded, so this service only ever READS normalize.vex_statements (never
// writes it) and OWNS normalize.csaf_advisories (never scan-orchestrator).
// ---------------------------------------------------------------------------

// CSAFAdvisory is one row of normalize.csaf_advisories.
type CSAFAdvisory struct {
	ID             string
	VEXStatementID string
	TrackingID     string
	Description    string
	Severity       string
	MitigationStep string
	PublishedAt    string
	Document       json.RawMessage
	CreatedAt      string
}

// ErrVEXStatementNotFound is returned when the request names a VEX
// statement that does not exist, or does not belong to the caller's tenant
// (RLS makes the two cases the same query result — CLAUDE.md invariant 6:
// 404, never 403).
var ErrVEXStatementNotFound = errors.New("no such VEX statement")

// GenerateCSAFAdvisoryInput carries the display context a caller already
// has (its own findings table already shows this to the user) alongside the
// vex_statement_id whose actual status/justification/scope this function
// looks up itself, server-side, rather than trusting a client-supplied copy.
//
// ⚠ A DELIBERATE SCOPE DECISION, STATED RATHER THAN HIDDEN: ClusterDisplayID,
// ClusterAliases, ComponentName and ComponentPURL are accepted from the
// caller instead of re-derived here via a second cross-schema resolution
// (cluster -> aliases, component_key -> the project's current SBOM
// component). They describe already-public vulnerability/component facts
// the caller's own UI is already displaying, not anything security-
// sensitive — the SECURITY-relevant fact (which statement says what, and
// whether it belongs to this tenant) is always resolved server-side below,
// never accepted from the request. A future revision that adds real
// server-side resolution should replace these fields, not add a second
// source of truth alongside them.
type GenerateCSAFAdvisoryInput struct {
	VEXStatementID   string
	ClusterDisplayID string
	ClusterAliases   []string
	ComponentName    string
	ComponentPURL    string
}

// GenerateAndStoreCSAFAdvisory looks up the named VEX statement (refusing if
// it does not belong to this tenant/project), builds a document via gen, and
// stores it.
//
// ⚠ IDEMPOTENT PER VEX STATEMENT. A second call for the same
// vex_statement_id returns the EXISTING advisory rather than creating a
// duplicate — clicking "generate" twice must not clutter
// normalize.csaf_advisories with two documents describing the same
// decision. Regenerating a genuinely NEW document (because the VEX
// statement itself was superseded) means generating for the NEW statement's
// id, which is a different row entirely.
func (s *Store) GenerateAndStoreCSAFAdvisory(
	ctx context.Context, tenantID, projectID string, in GenerateCSAFAdvisoryInput, now time.Time,
) (*CSAFAdvisory, error) {
	var out *CSAFAdvisory
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		statement, err := loadOneVEXStatement(ctx, tx, projectID, in.VEXStatementID)
		if err != nil {
			return err
		}

		// ⚠ A SEPARATE QUERY AGAINST auth.tenants, joined in Go — the CSAF
		// publisher is the CUSTOMER'S organisation (csafgen.Input's own doc
		// comment), which lives in a schema this service otherwise never
		// touches.
		tenantName, err := resolveTenantName(ctx, tx, tenantID)
		if err != nil {
			return err
		}

		if existing, err := loadCSAFAdvisoryByStatement(ctx, tx, statement.ID); err != nil {
			return err
		} else if existing != nil {
			out = existing
			return nil
		}

		trackingID := "AXEBOM-VEX-" + statement.ID
		doc := csafgen.Generate(csafgen.Input{
			Statement: *statement, TenantName: tenantName,
			ClusterDisplayID: in.ClusterDisplayID, ClusterAliases: in.ClusterAliases,
			ComponentName: in.ComponentName, ComponentPURL: in.ComponentPURL,
			TrackingID: trackingID, Now: now,
		})

		docJSON, err := doc.Marshal()
		if err != nil {
			return fmt.Errorf("marshal csaf document: %w", err)
		}

		var severity string
		if len(doc.Vulns) > 0 && len(doc.Vulns[0].Scores) > 0 {
			severity = "" // no CVSS score generated today — see csafgen's own scope note
		}

		var mitigation string
		if len(doc.Vulns) > 0 && len(doc.Vulns[0].Remediations) > 0 {
			mitigation = doc.Vulns[0].Remediations[0].Details
		}

		advisory := CSAFAdvisory{
			VEXStatementID: statement.ID,
			TrackingID:     trackingID,
			Description:    doc.DocumentMeta.Title,
			Severity:       severity,
			MitigationStep: mitigation,
			PublishedAt:    now.UTC().Format(time.RFC3339),
			Document:       docJSON,
		}

		id, createdAt, err := insertCSAFAdvisory(ctx, tx, tenantID, advisory)
		if err != nil {
			return err
		}
		advisory.ID = id
		advisory.CreatedAt = createdAt
		out = &advisory
		return nil
	})
	return out, err
}

// ListCSAFAdvisories returns every CSAF advisory for a project's VEX
// statements — a project-wide view, not scoped to one report, matching how
// VEX statements themselves are project-scoped rather than report-scoped.
func (s *Store) ListCSAFAdvisories(ctx context.Context, tenantID, projectID string) ([]CSAFAdvisory, error) {
	var out []CSAFAdvisory
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT a.id, a.vex_statement_id, a.tracking_id, COALESCE(a.description,''),
			       COALESCE(a.severity,''), COALESCE(a.mitigation_steps,''),
			       COALESCE(a.published_at::text,''), a.document, a.created_at
			  FROM normalize.csaf_advisories a
			  JOIN normalize.vex_statements v ON v.id = a.vex_statement_id
			 WHERE v.project_id = $1
			 ORDER BY a.created_at DESC`, projectID)
		if err != nil {
			return fmt.Errorf("list csaf advisories: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var a CSAFAdvisory
			var createdAt time.Time
			if err := rows.Scan(&a.ID, &a.VEXStatementID, &a.TrackingID, &a.Description,
				&a.Severity, &a.MitigationStep, &a.PublishedAt, &a.Document, &createdAt); err != nil {
				return fmt.Errorf("scan csaf advisory: %w", err)
			}
			a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func resolveTenantName(ctx context.Context, tx db.Tx, tenantID string) (string, error) {
	var name string
	err := tx.QueryRow(ctx, `SELECT name FROM auth.tenants WHERE id = $1`, tenantID).Scan(&name)
	if err != nil {
		return "", fmt.Errorf("resolve tenant name: %w", err)
	}
	return name, nil
}

func loadOneVEXStatement(ctx context.Context, tx db.Tx, projectID, statementID string) (*vex.Statement, error) {
	var st vex.Statement
	var status, scope string
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, project_id, COALESCE(component_key,''), cluster_id,
		       status, COALESCE(justification,''), COALESCE(remediation,''),
		       COALESCE(workarounds,''), COALESCE(downtime,''), scope, version,
		       COALESCE(superseded_by::text,''), COALESCE(author_user_id::text,''), created_at
		  FROM normalize.vex_statements
		 WHERE id = $1 AND project_id = $2`, statementID, projectID).Scan(
		&st.ID, &st.TenantID, &st.ProjectID, &st.ComponentKey, &st.ClusterID,
		&status, &st.Justification, &st.Remediation, &st.Workarounds, &st.Downtime,
		&scope, &st.Version, &st.SupersededBy, &st.AuthorUserID, &st.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrVEXStatementNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load vex statement: %w", err)
	}
	st.Status = vex.Status(status)
	st.Scope = vex.Scope(scope)
	return &st, nil
}

func loadCSAFAdvisoryByStatement(ctx context.Context, tx db.Tx, vexStatementID string) (*CSAFAdvisory, error) {
	var a CSAFAdvisory
	var createdAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, vex_statement_id, tracking_id, COALESCE(description,''),
		       COALESCE(severity,''), COALESCE(mitigation_steps,''),
		       COALESCE(published_at::text,''), document, created_at
		  FROM normalize.csaf_advisories
		 WHERE vex_statement_id = $1`, vexStatementID).Scan(
		&a.ID, &a.VEXStatementID, &a.TrackingID, &a.Description,
		&a.Severity, &a.MitigationStep, &a.PublishedAt, &a.Document, &createdAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load existing csaf advisory: %w", err)
	}
	a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	return &a, nil
}

func insertCSAFAdvisory(ctx context.Context, tx db.Tx, tenantID string, a CSAFAdvisory) (id, createdAt string, err error) {
	var created time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO normalize.csaf_advisories
			(tenant_id, vex_statement_id, tracking_id, description, severity,
			 mitigation_steps, published_at, document)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, created_at`,
		tenantID, a.VEXStatementID, a.TrackingID, nullIfEmpty(a.Description),
		nullIfEmpty(a.Severity), nullIfEmpty(a.MitigationStep), a.PublishedAt, a.Document,
	).Scan(&id, &created)
	if err != nil {
		return "", "", fmt.Errorf("insert csaf advisory: %w", err)
	}
	return id, created.UTC().Format(time.RFC3339), nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
