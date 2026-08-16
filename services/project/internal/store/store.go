// Package store is the project service's persistence layer.
//
// EVERY query here goes through db.WithTenant, without exception. Unlike auth,
// this service has no pre-tenant operation: a project only ever exists inside a
// tenant, so there is no legitimate reason to reach for pool.Raw() and no
// SECURITY DEFINER function to bypass RLS with.
//
// That is why cross-tenant access returns 404 rather than 403 for free: RLS
// filters the row out, the query finds nothing, and "not found" is the honest
// answer. A 403 would confirm the id exists.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/encorebom/encorebom/libs/go-shared/model"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
)

// ErrNotFound is returned when a row does not exist FOR THIS TENANT.
//
// The two cases — absent, and belonging to somebody else — are deliberately
// indistinguishable here, because RLS makes them indistinguishable at the
// database. Handlers turn this into a 404.
var ErrNotFound = errors.New("not found")

// ErrNameTaken is returned when a tenant already has a project with that name.
var ErrNameTaken = errors.New("a project with this name already exists")

type Store struct{ pool *db.Pool }

func New(pool *db.Pool) *Store { return &Store{pool: pool} }

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Project mirrors project.projects plus its classifications.
type Project struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	SourceType  string
	SDLCStage   string

	ValidityStart *time.Time
	ValidityEnd   *time.Time

	Owner Owner

	Classifications []model.BOMType

	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Owner is the point of contact CERT-In reports name.
//
// Its own struct rather than four loose fields: these travel together into
// every generated report, and a report with a contact block half-filled is
// worse than one that declares the whole block absent.
type Owner struct {
	Name   string
	Email  string
	GitHub string
	Phone  string
}

// Practices are the six CERT-In Table 5 category-3 sub-elements.
//
// Pointers, not strings: "" and "not recorded" are different states, and
// collapsing them would make an unset field indistinguishable from one the user
// deliberately cleared. Coverage scoring depends on that distinction —
// CLAUDE.md invariant 3.
type Practices struct {
	ProjectID string

	Frequency     *string
	Depth         *string
	KnownUnknowns *string
	Distribution  *string
	AccessControl *string
	ErrataPolicy  *string

	UpdatedAt *time.Time
}

// RepoConnection mirrors project.repository_connections.
//
// Note what is ABSENT: there is no token field. CredentialRef is a Vault path,
// and the token itself never enters this process except in transit to Vault.
type RepoConnection struct {
	ID       string
	TenantID string

	ProjectID      string
	Provider       string
	RepoURL        string
	RepoExternalID string
	DefaultBranch  string
	CredentialRef  string

	LastSyncedAt *time.Time
	CreatedAt    time.Time
}

// Upload mirrors project.uploads.
type Upload struct {
	ID               string
	TenantID         string
	ProjectID        string
	Kind             string
	StorageRef       string
	SHA256           string
	SizeBytes        int64
	OriginalFilename string
	UploadedBy       string
	CreatedAt        time.Time
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// CreateProject inserts a project and its classifications in one transaction.
//
// One transaction because a project without its classifications is not a
// half-created project — it is a project that will silently scan for nothing.
func (s *Store) CreateProject(ctx context.Context, p Project) (Project, error) {
	var out Project
	err := s.pool.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO project.projects
				(tenant_id, name, description, source_type, sdlc_stage,
				 validity_start, validity_end,
				 owner_name, owner_email, owner_github, owner_phone, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			RETURNING id, created_at, updated_at`,
			p.TenantID, p.Name, nullIfEmpty(p.Description), p.SourceType, p.SDLCStage,
			p.ValidityStart, p.ValidityEnd,
			nullIfEmpty(p.Owner.Name), nullIfEmpty(p.Owner.Email),
			nullIfEmpty(p.Owner.GitHub), nullIfEmpty(p.Owner.Phone),
			p.CreatedBy,
		).Scan(&out.ID, &out.CreatedAt, &out.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err, "projects_tenant_id_name_key") {
				return ErrNameTaken
			}
			return fmt.Errorf("insert project: %w", err)
		}

		return insertClassifications(ctx, tx, p.TenantID, out.ID, p.Classifications)
	})
	if err != nil {
		return Project{}, err
	}

	out.TenantID = p.TenantID
	out.Name = p.Name
	out.Description = p.Description
	out.SourceType = p.SourceType
	out.SDLCStage = p.SDLCStage
	out.ValidityStart = p.ValidityStart
	out.ValidityEnd = p.ValidityEnd
	out.Owner = p.Owner
	out.Classifications = p.Classifications
	out.CreatedBy = p.CreatedBy
	return out, nil
}

func insertClassifications(ctx context.Context, tx db.Tx,
	tenantID, projectID string, types []model.BOMType,
) error {
	for _, t := range types {
		if _, err := tx.Exec(ctx, `
			INSERT INTO project.project_classifications (project_id, tenant_id, bom_type)
			VALUES ($1, $2, $3)
			ON CONFLICT (project_id, bom_type) DO NOTHING`,
			projectID, tenantID, string(t)); err != nil {
			return fmt.Errorf("insert classification %s: %w", t, err)
		}
	}
	return nil
}

// GetProject reads one project with its classifications.
func (s *Store) GetProject(ctx context.Context, tenantID, projectID string) (Project, error) {
	var p Project
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := scanProject(tx.QueryRow(ctx, projectColumns+`
			  FROM project.projects
			 WHERE id = $1 AND deleted_at IS NULL`, projectID), &p); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("get project: %w", err)
		}

		types, err := loadClassifications(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		p.Classifications = types
		return nil
	})
	if err != nil {
		return Project{}, err
	}
	return p, nil
}

const projectColumns = `
	SELECT id, tenant_id, name, COALESCE(description,''), source_type, sdlc_stage,
	       validity_start, validity_end,
	       COALESCE(owner_name,''), COALESCE(owner_email,''),
	       COALESCE(owner_github,''), COALESCE(owner_phone,''),
	       created_by, created_at, updated_at`

func scanProject(row pgx.Row, p *Project) error {
	return row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.SourceType, &p.SDLCStage,
		&p.ValidityStart, &p.ValidityEnd,
		&p.Owner.Name, &p.Owner.Email, &p.Owner.GitHub, &p.Owner.Phone,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
}

func loadClassifications(ctx context.Context, tx db.Tx, projectID string) ([]model.BOMType, error) {
	rows, err := tx.Query(ctx, `
		SELECT bom_type FROM project.project_classifications
		 WHERE project_id = $1 ORDER BY bom_type`, projectID)
	if err != nil {
		return nil, fmt.Errorf("load classifications: %w", err)
	}
	defer rows.Close()

	var out []model.BOMType
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, model.BOMType(t))
	}
	return out, rows.Err()
}

// ListProjects returns a tenant's projects, newest first.
//
// UUIDv7 ids are time-ordered, so `ORDER BY id DESC` is chronological AND a
// stable keyset-pagination cursor — unlike created_at, which ties.
func (s *Store) ListProjects(ctx context.Context, tenantID string, limit int, cursor string) ([]Project, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var out []Project
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		sql := projectColumns + `
			  FROM project.projects
			 WHERE deleted_at IS NULL`
		args := []any{}
		if cursor != "" {
			sql += ` AND id < $1`
			args = append(args, cursor)
		}
		sql += fmt.Sprintf(` ORDER BY id DESC LIMIT %d`, limit)

		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		defer rows.Close()

		ids := make([]string, 0, limit)
		for rows.Next() {
			var p Project
			if err := scanProject(rows, &p); err != nil {
				return err
			}
			out = append(out, p)
			ids = append(ids, p.ID)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}

		// One query for every project's classifications rather than one per
		// project: a list of 50 would otherwise be 51 round trips.
		byProject, err := loadClassificationsFor(ctx, tx, ids)
		if err != nil {
			return err
		}
		for i := range out {
			out[i].Classifications = byProject[out[i].ID]
		}
		return nil
	})
	return out, err
}

func loadClassificationsFor(ctx context.Context, tx db.Tx, projectIDs []string) (map[string][]model.BOMType, error) {
	rows, err := tx.Query(ctx, `
		SELECT project_id, bom_type FROM project.project_classifications
		 WHERE project_id = ANY($1) ORDER BY project_id, bom_type`, projectIDs)
	if err != nil {
		return nil, fmt.Errorf("load classifications: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]model.BOMType, len(projectIDs))
	for rows.Next() {
		var id, t string
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = append(out[id], model.BOMType(t))
	}
	return out, rows.Err()
}

// UpdateProject changes the mutable fields and replaces the classification set.
func (s *Store) UpdateProject(ctx context.Context, p Project) (Project, error) {
	err := s.pool.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE project.projects
			   SET name = $2, description = $3, sdlc_stage = $4,
			       validity_start = $5, validity_end = $6,
			       owner_name = $7, owner_email = $8,
			       owner_github = $9, owner_phone = $10
			 WHERE id = $1 AND deleted_at IS NULL`,
			p.ID, p.Name, nullIfEmpty(p.Description), p.SDLCStage,
			p.ValidityStart, p.ValidityEnd,
			nullIfEmpty(p.Owner.Name), nullIfEmpty(p.Owner.Email),
			nullIfEmpty(p.Owner.GitHub), nullIfEmpty(p.Owner.Phone))
		if err != nil {
			if isUniqueViolation(err, "projects_tenant_id_name_key") {
				return ErrNameTaken
			}
			return fmt.Errorf("update project: %w", err)
		}
		// Zero rows means RLS filtered it out or it does not exist. Same
		// answer either way — see the note on ErrNotFound.
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}

		// Replace rather than merge: the client sent the full set, and a merge
		// would make deselecting a BOM type impossible.
		if _, err := tx.Exec(ctx,
			`DELETE FROM project.project_classifications WHERE project_id = $1`, p.ID); err != nil {
			return fmt.Errorf("clear classifications: %w", err)
		}
		return insertClassifications(ctx, tx, p.TenantID, p.ID, p.Classifications)
	})
	if err != nil {
		return Project{}, err
	}
	return s.GetProject(ctx, p.TenantID, p.ID)
}

// DeleteProject soft-deletes.
//
// Soft, because scans, reports and findings reference it, and a hard delete
// would either cascade away a customer's compliance history or fail on a
// foreign key. Phase 16 owns retention and purge.
func (s *Store) DeleteProject(ctx context.Context, tenantID, projectID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE project.projects SET deleted_at = now()
			 WHERE id = $1 AND deleted_at IS NULL`, projectID)
		if err != nil {
			return fmt.Errorf("delete project: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Practices
// ---------------------------------------------------------------------------

// GetPractices reads a project's practices.
//
// Returns a zero-valued Practices with no error when the row is absent: "no
// practices recorded" is a legitimate state that the compliance gap report is
// built to describe, not an error to propagate.
func (s *Store) GetPractices(ctx context.Context, tenantID, projectID string) (Practices, error) {
	p := Practices{ProjectID: projectID}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT frequency, depth, known_unknowns, distribution,
			       access_control, errata_policy, updated_at
			  FROM project.practices WHERE project_id = $1`, projectID).
			Scan(&p.Frequency, &p.Depth, &p.KnownUnknowns, &p.Distribution,
				&p.AccessControl, &p.ErrataPolicy, &p.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return p, err
}

// UpsertPractices writes a project's practices.
func (s *Store) UpsertPractices(ctx context.Context, tenantID string, p Practices) (Practices, error) {
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		// Confirm the project is visible in this tenant BEFORE writing. Without
		// it, practices for a nonexistent project fail on the foreign key with
		// a message that says nothing useful.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM project.projects WHERE id = $1 AND deleted_at IS NULL`,
			p.ProjectID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO project.practices
				(project_id, tenant_id, frequency, depth, known_unknowns,
				 distribution, access_control, errata_policy)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (project_id) DO UPDATE SET
				frequency      = EXCLUDED.frequency,
				depth          = EXCLUDED.depth,
				known_unknowns = EXCLUDED.known_unknowns,
				distribution   = EXCLUDED.distribution,
				access_control = EXCLUDED.access_control,
				errata_policy  = EXCLUDED.errata_policy`,
			p.ProjectID, tenantID, p.Frequency, p.Depth, p.KnownUnknowns,
			p.Distribution, p.AccessControl, p.ErrataPolicy)
		if err != nil {
			return fmt.Errorf("upsert practices: %w", err)
		}
		return nil
	})
	if err != nil {
		return Practices{}, err
	}
	return s.GetPractices(ctx, tenantID, p.ProjectID)
}

// ---------------------------------------------------------------------------
// Repository connections
// ---------------------------------------------------------------------------

// CreateConnection stores a repository connection.
//
// credentialRef is a VAULT PATH. If a caller ever passes a token here it lands
// in a database column, so the service layer writes to Vault first and passes
// only what Vault returned.
func (s *Store) CreateConnection(ctx context.Context, c RepoConnection) (RepoConnection, error) {
	var out RepoConnection
	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM project.projects WHERE id = $1 AND deleted_at IS NULL`,
			c.ProjectID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		return tx.QueryRow(ctx, `
			INSERT INTO project.repository_connections
				(tenant_id, project_id, provider, repo_url, repo_external_id,
				 default_branch, credential_ref)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (project_id, repo_url) DO UPDATE SET
				repo_external_id = EXCLUDED.repo_external_id,
				default_branch   = EXCLUDED.default_branch,
				credential_ref   = EXCLUDED.credential_ref
			RETURNING id, created_at`,
			c.TenantID, c.ProjectID, c.Provider, c.RepoURL,
			nullIfEmpty(c.RepoExternalID), nullIfEmpty(c.DefaultBranch),
			nullIfEmpty(c.CredentialRef)).
			Scan(&out.ID, &out.CreatedAt)
	})
	if err != nil {
		return RepoConnection{}, err
	}
	out.TenantID = c.TenantID
	out.ProjectID = c.ProjectID
	out.Provider = c.Provider
	out.RepoURL = c.RepoURL
	out.RepoExternalID = c.RepoExternalID
	out.DefaultBranch = c.DefaultBranch
	out.CredentialRef = c.CredentialRef
	return out, nil
}

// ListConnections returns a project's repository connections.
func (s *Store) ListConnections(ctx context.Context, tenantID, projectID string) ([]RepoConnection, error) {
	var out []RepoConnection
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, project_id, provider, repo_url,
			       COALESCE(repo_external_id,''), COALESCE(default_branch,''),
			       COALESCE(credential_ref,''), last_synced_at, created_at
			  FROM project.repository_connections
			 WHERE project_id = $1 ORDER BY created_at`, projectID)
		if err != nil {
			return fmt.Errorf("list connections: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var c RepoConnection
			if err := rows.Scan(&c.ID, &c.TenantID, &c.ProjectID, &c.Provider, &c.RepoURL,
				&c.RepoExternalID, &c.DefaultBranch, &c.CredentialRef,
				&c.LastSyncedAt, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

// CreateUpload records a stored upload.
//
// The bytes are already in object storage; this is the row that points at them.
// Note the order the service uses: store bytes, then record. A crash between
// the two leaves an orphaned object, which is cheap. The reverse leaves a row
// pointing at nothing, which breaks every later scan.
func (s *Store) CreateUpload(ctx context.Context, u Upload) (Upload, error) {
	var out Upload
	err := s.pool.WithTenant(ctx, u.TenantID, func(ctx context.Context, tx db.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM project.projects WHERE id = $1 AND deleted_at IS NULL`,
			u.ProjectID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		return tx.QueryRow(ctx, `
			INSERT INTO project.uploads
				(tenant_id, project_id, kind, storage_ref, sha256, size_bytes,
				 original_filename, uploaded_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING id, created_at`,
			u.TenantID, u.ProjectID, u.Kind, u.StorageRef, u.SHA256, u.SizeBytes,
			nullIfEmpty(u.OriginalFilename), u.UploadedBy).
			Scan(&out.ID, &out.CreatedAt)
	})
	if err != nil {
		return Upload{}, err
	}
	out.TenantID = u.TenantID
	out.ProjectID = u.ProjectID
	out.Kind = u.Kind
	out.StorageRef = u.StorageRef
	out.SHA256 = u.SHA256
	out.SizeBytes = u.SizeBytes
	out.OriginalFilename = u.OriginalFilename
	out.UploadedBy = u.UploadedBy
	return out, nil
}

// ListUploads returns a project's uploads, newest first.
func (s *Store) ListUploads(ctx context.Context, tenantID, projectID string) ([]Upload, error) {
	var out []Upload
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, project_id, kind, storage_ref, sha256, size_bytes,
			       COALESCE(original_filename,''), uploaded_by, created_at
			  FROM project.uploads
			 WHERE project_id = $1 ORDER BY id DESC`, projectID)
		if err != nil {
			return fmt.Errorf("list uploads: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var u Upload
			if err := rows.Scan(&u.ID, &u.TenantID, &u.ProjectID, &u.Kind, &u.StorageRef,
				&u.SHA256, &u.SizeBytes, &u.OriginalFilename, &u.UploadedBy,
				&u.CreatedAt); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nullIfEmpty maps "" to SQL NULL.
//
// The columns are nullable and the difference matters: NULL means "not
// recorded", "" would mean "recorded as empty". Coverage scoring reads them
// differently (CLAUDE.md invariant 3).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// isUniqueViolation reports whether err is a unique violation on a named
// constraint, so a duplicate name becomes a clear message rather than a 500.
//
// Matches on the STRUCTURED error, never the message text: Postgres error
// strings are localized by lc_messages, so a server running under a different
// locale would silently stop matching and every duplicate name would become a
// 500 that nobody could reproduce.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}
