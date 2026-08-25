package orchestr

import (
	"context"
	"fmt"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/vex"
)

// ---------------------------------------------------------------------------
// VEX statements — normalize.vex_statements.
//
// ⚠ THIS FILE OWNS THE WRITE PATH. vex.Validate/vex.Resolve/vex.Supersede are
// the pure logic (libs/go-shared/vex); this file is the storage that calls
// them, the same split store.go/findings.go already draw between "touches
// scan.*" and "touches normalize.*" in this same package.
//
// ⚠ NO project.projects EXISTENCE CHECK, DELIBERATELY, MATCHING
// CreateScan's OWN PRECEDENT (orchestrator.go). This service accepts a
// caller-supplied project_id as given everywhere else in its store layer —
// RLS already makes a cross-tenant project_id resolve to nothing, and
// introducing a check here that CreateScan itself does not have would be a
// new, inconsistent discipline rather than a real gap being closed.
// ---------------------------------------------------------------------------

// VEXStatementInput is what a caller supplies to record a triage decision.
// AuthorUserID and CreatedAt are not caller-supplied — the author comes from
// the authenticated request, the timestamp from Postgres.
type VEXStatementInput struct {
	ProjectID    string
	ComponentKey string
	ClusterID    string
	Status       vex.Status
	Scope        vex.Scope

	Justification string
	Remediation   string
	Workarounds   string
	Downtime      string

	AuthorUserID string
}

// CreateVEXStatement records a triage decision as a new statement.
//
// ⚠ SUPERSESSION IS AUTOMATIC, NEVER CALLER-SPECIFIED. The caller states what
// is true now for (project, cluster, component, scope); this function finds
// whichever statement is CURRENTLY in force for that exact tuple (if any) and
// supersedes it via vex.Supersede. A caller-supplied "supersedes this id"
// parameter would let a stale or wrong id silently fork the history — the
// database, not the client, is the source of truth for what "current" means.
func (s *Store) CreateVEXStatement(ctx context.Context, tenantID string, in VEXStatementInput) (*vex.Statement, error) {
	next := vex.Statement{
		TenantID:      tenantID,
		ProjectID:     in.ProjectID,
		ComponentKey:  in.ComponentKey,
		ClusterID:     in.ClusterID,
		Status:        in.Status,
		Scope:         in.Scope,
		Justification: in.Justification,
		Remediation:   in.Remediation,
		Workarounds:   in.Workarounds,
		Downtime:      in.Downtime,
		AuthorUserID:  in.AuthorUserID,
		Version:       1,
	}

	var out *vex.Statement
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		previous, err := currentVEXStatement(ctx, tx, in.ProjectID, in.ClusterID, in.ComponentKey, in.Scope)
		if err != nil {
			return err
		}

		if previous != nil {
			superseded, err := vex.Supersede(*previous, next)
			if err != nil {
				return err
			}
			next = superseded
		} else if err := vex.Validate(next); err != nil {
			return err
		}

		id, createdAt, err := insertVEXStatement(ctx, tx, next)
		if err != nil {
			return err
		}
		next.ID = id
		next.CreatedAt = createdAt

		if previous != nil {
			if _, err := tx.Exec(ctx, `
				UPDATE normalize.vex_statements SET superseded_by = $1 WHERE id = $2`,
				id, previous.ID,
			); err != nil {
				return fmt.Errorf("mark statement superseded: %w", err)
			}
		}

		out = &next
		return nil
	})
	return out, err
}

// currentVEXStatement finds the statement (if any) presently in force for an
// exact (cluster, component, scope) tuple — the one vex.Supersede requires
// as its "previous" argument. Not the same question as vex.Resolve, which
// answers "what applies to this finding across every scope"; this answers
// "is there already a live assertion at THIS scope to supersede."
func currentVEXStatement(
	ctx context.Context, tx db.Tx, projectID, clusterID, componentKey string, scope vex.Scope,
) (*vex.Statement, error) {
	statements, err := listVEXStatementsForCluster(ctx, tx, projectID, clusterID)
	if err != nil {
		return nil, err
	}
	for _, st := range statements {
		if st.SupersededBy == "" && st.Scope == scope && st.ComponentKey == componentKey {
			s := st
			return &s, nil
		}
	}
	return nil, nil
}

func insertVEXStatement(ctx context.Context, tx db.Tx, st vex.Statement) (id string, createdAt time.Time, err error) {
	err = tx.QueryRow(ctx, `
		INSERT INTO normalize.vex_statements
			(tenant_id, project_id, component_key, cluster_id, status, justification,
			 remediation, workarounds, downtime, scope, version, author_user_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at`,
		st.TenantID, st.ProjectID, nullIfEmpty(st.ComponentKey), st.ClusterID,
		string(st.Status), nullIfEmpty(st.Justification), nullIfEmpty(st.Remediation),
		nullIfEmpty(st.Workarounds), nullIfEmpty(st.Downtime), string(st.Scope),
		st.Version, nullIfEmpty(st.AuthorUserID),
	).Scan(&id, &createdAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("insert vex statement: %w", err)
	}
	return id, createdAt, nil
}

// ListVEXStatements returns every statement for a project, including
// superseded ones — the full raw material vex.Resolve/vex.Chain need.
func (s *Store) ListVEXStatements(ctx context.Context, tenantID, projectID string) ([]vex.Statement, error) {
	var out []vex.Statement
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := listVEXStatementRows(ctx, tx, `WHERE project_id = $1`, projectID)
		if err != nil {
			return err
		}
		out = rows
		return nil
	})
	return out, err
}

// GetVEXHistory returns the full supersession chain for one (cluster,
// component) pair, oldest first (vex.Chain).
func (s *Store) GetVEXHistory(ctx context.Context, tenantID, projectID, clusterID, componentKey string) ([]vex.Statement, error) {
	all, err := s.ListVEXStatements(ctx, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	var matching []vex.Statement
	for _, st := range all {
		if st.ClusterID == clusterID && st.ComponentKey == componentKey {
			matching = append(matching, st)
		}
	}
	return vex.Chain(matching), nil
}

func listVEXStatementsForCluster(ctx context.Context, tx db.Tx, projectID, clusterID string) ([]vex.Statement, error) {
	return listVEXStatementRows(ctx, tx, `WHERE project_id = $1 AND cluster_id = $2`, projectID, clusterID)
}

func listVEXStatementRows(ctx context.Context, tx db.Tx, where string, args ...any) ([]vex.Statement, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, project_id, COALESCE(component_key,''), cluster_id,
		       status, COALESCE(justification,''), COALESCE(remediation,''),
		       COALESCE(workarounds,''), COALESCE(downtime,''), scope, version,
		       COALESCE(superseded_by::text,''), COALESCE(author_user_id::text,''), created_at
		  FROM normalize.vex_statements
		 `+where+`
		 ORDER BY created_at`, args...)
	if err != nil {
		return nil, fmt.Errorf("list vex statements: %w", err)
	}
	defer rows.Close()

	var out []vex.Statement
	for rows.Next() {
		var st vex.Statement
		var status, scope string
		if err := rows.Scan(
			&st.ID, &st.TenantID, &st.ProjectID, &st.ComponentKey, &st.ClusterID,
			&status, &st.Justification, &st.Remediation, &st.Workarounds, &st.Downtime,
			&scope, &st.Version, &st.SupersededBy, &st.AuthorUserID, &st.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan vex statement: %w", err)
		}
		st.Status = vex.Status(status)
		st.Scope = vex.Scope(scope)
		out = append(out, st)
	}
	return out, rows.Err()
}
