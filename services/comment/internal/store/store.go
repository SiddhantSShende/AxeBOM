// Package store is the comment service's persistence layer.
//
// Every query goes through db.WithTenant — comment.comments is tenant-scoped
// and RLS-enabled (migrations/comment/0001_init.sql), so cross-tenant access
// is filtered at the database before it ever reaches Go, exactly like every
// other service's store (CLAUDE.md invariant 6).
//
// ⚠ OWNERSHIP IS CHECKED HERE, NOT BY THE AUTHZ MATRIX.
//
// libs/go-shared/authz/matrix.go grants comment:update and comment:delete to
// every Viewer — "own comments; ownership checked by the handler" — because
// the matrix has no concept of row ownership, only role. Update and Delete
// below are what actually enforces "own": they read the row's user_id inside
// the same transaction and refuse with ErrNotOwner when it does not match the
// caller, before ever writing. The handler turns that into a 403
// (errs.PermCommentNotOwner) — a genuine same-tenant permission failure, not
// the cross-tenant 404 case invariant 6 otherwise mandates.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// MaxDepth is the deepest a reply may nest — 0 is a top-level comment, 5 is a
// reply to a reply five levels deep. Mirrors the CHECK constraint on
// comment.comments.depth (migrations/comment/0001_init.sql), so a bug here
// surfaces as a database error rather than a report with unreadable nesting
// or an unbounded recursive query.
const MaxDepth = 5

// Sentinel errors. Handlers map these to the taxonomy in
// libs/go-shared/platform/errs — never a bare string (CLAUDE.md conventions).
var (
	// ErrNotFound means the comment does not exist FOR THIS TENANT. Absent and
	// belonging-to-another-tenant are indistinguishable, because RLS makes them
	// indistinguishable at the database (CLAUDE.md invariant 6). A comment that
	// exists but has already been soft-deleted answers the same way: there is
	// nothing left for Update or Delete to act on.
	ErrNotFound = errors.New("comment not found")

	// ErrNotOwner means the comment exists, is visible to this tenant, and is
	// simply not this caller's. See the package doc.
	ErrNotOwner = errors.New("not the comment's author")

	// ErrParentNotFound means parent_id was supplied but does not resolve to a
	// comment this tenant can see.
	ErrParentNotFound = errors.New("parent comment not found")

	// ErrParentCrossReport means parent_id resolves to a real comment, but one
	// attached to a different report. A comment can only be threaded onto
	// another comment on the SAME report — otherwise a thread could straddle
	// two reports' discussions, which makes "delete this report's comments"
	// and "who can see this reply" both ambiguous.
	ErrParentCrossReport = errors.New("parent comment belongs to a different report")

	// ErrDepthExceeded means the parent is already at MaxDepth; one more level
	// would exceed the CHECK constraint and make the thread unreadable.
	ErrDepthExceeded = errors.New("comment thread has reached its maximum depth")
)

// Comment mirrors comment.comments.
//
// ParentID is "" for a top-level comment — Go's zero value for a nullable
// column that has no natural zero of its own, matching the idiom the rest of
// this codebase uses for optional foreign keys (e.g. store.RepoConnection).
type Comment struct {
	ID       string
	TenantID string
	ReportID string
	UserID   string
	ParentID string
	Depth    int

	// Body is the RAW text, always. A soft-deleted comment's body is preserved
	// here — never overwritten — so the row itself is the audit trail the
	// guideline in docs/phases/PHASE-13 asks for ("edits and deletes are
	// audited"). Masking it into a "[deleted]" placeholder for display is the
	// HANDLER's job (internal/handler.toCommentResponse), not the store's: a
	// future admin or export path may legitimately need the real text, and the
	// store must not be the place that decides who gets to see it.
	Body string

	EditedAt  *time.Time
	DeletedAt *time.Time
	CreatedAt time.Time
}

// Store is the comment service's persistence layer.
type Store struct{ pool *db.Pool }

// NewStore builds a store over a pool.
func NewStore(pool *db.Pool) *Store { return &Store{pool: pool} }

const commentColumns = `
	SELECT id, tenant_id, report_id, user_id, COALESCE(parent_id::text, ''),
	       depth, body, edited_at, deleted_at, created_at`

func scanComment(row pgx.Row) (Comment, error) {
	var c Comment
	err := row.Scan(&c.ID, &c.TenantID, &c.ReportID, &c.UserID, &c.ParentID,
		&c.Depth, &c.Body, &c.EditedAt, &c.DeletedAt, &c.CreatedAt)
	return c, err
}

// Create inserts a comment, computing depth server-side from the parent.
//
// ⚠ DEPTH IS NEVER TRUSTED FROM THE CALLER. It is derived from the parent's
// stored depth inside this transaction, so a client cannot forge a shallow
// depth to bypass the nesting cap.
func (s *Store) Create(
	ctx context.Context, tenantID, reportID, userID, parentID, body string,
) (Comment, error) {
	var out Comment
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		depth := 0

		if parentID != "" {
			var parentReportID string
			var parentDepth int
			err := tx.QueryRow(ctx,
				`SELECT report_id, depth FROM comment.comments WHERE id = $1`,
				parentID,
			).Scan(&parentReportID, &parentDepth)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrParentNotFound
			}
			if err != nil {
				return fmt.Errorf("look up parent comment: %w", err)
			}
			if parentReportID != reportID {
				return ErrParentCrossReport
			}
			if parentDepth >= MaxDepth {
				return ErrDepthExceeded
			}
			depth = parentDepth + 1
		}

		var parentArg any
		if parentID != "" {
			parentArg = parentID
		}

		var err error
		out, err = scanComment(tx.QueryRow(ctx, `
			INSERT INTO comment.comments (tenant_id, report_id, user_id, parent_id, depth, body)
			VALUES ($1,$2,$3,$4,$5,$6)
			RETURNING id, tenant_id, report_id, user_id, COALESCE(parent_id::text, ''),
			          depth, body, edited_at, deleted_at, created_at`,
			tenantID, reportID, userID, parentArg, depth, body))
		return err
	})
	if err != nil {
		return Comment{}, err
	}
	return out, nil
}

// List returns EVERY comment on a report, including soft-deleted ones.
//
// ⚠ SOFT-DELETED ROWS ARE RETURNED, NOT FILTERED OUT. A deleted comment with
// live replies is rendered by the handler as a "[deleted]" placeholder rather
// than vanishing — omitting it here would orphan its children in the client's
// tree view (docs/phases/PHASE-13's own requirement). Ordered oldest-first so
// a client can build the reply tree by a single pass over parent_id.
func (s *Store) List(ctx context.Context, tenantID, reportID string) ([]Comment, error) {
	var out []Comment
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, commentColumns+`
			  FROM comment.comments
			 WHERE report_id = $1
			 ORDER BY created_at ASC`, reportID)
		if err != nil {
			return fmt.Errorf("list comments: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			c, err := scanComment(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Update rewrites a comment's body and stamps edited_at.
//
// Refuses with ErrNotOwner if userID does not match the row's author, and
// with ErrNotFound if the comment does not exist for this tenant OR has
// already been soft-deleted — editing something already gone is not a
// permission question, there is simply nothing left to edit.
func (s *Store) Update(ctx context.Context, tenantID, commentID, userID, body string) (Comment, error) {
	var out Comment
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var ownerID string
		var deletedAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT user_id, deleted_at FROM comment.comments WHERE id = $1`,
			commentID,
		).Scan(&ownerID, &deletedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("look up comment: %w", err)
		}
		if deletedAt != nil {
			return ErrNotFound
		}
		if ownerID != userID {
			return ErrNotOwner
		}

		out, err = scanComment(tx.QueryRow(ctx, `
			UPDATE comment.comments SET body = $2, edited_at = now()
			 WHERE id = $1
			 RETURNING id, tenant_id, report_id, user_id, COALESCE(parent_id::text, ''),
			           depth, body, edited_at, deleted_at, created_at`,
			commentID, body))
		return err
	})
	if err != nil {
		return Comment{}, err
	}
	return out, nil
}

// Delete soft-deletes a comment — deleted_at is stamped, body is retained.
//
// Same ownership rule as Update. A comment already deleted answers
// ErrNotFound rather than silently succeeding a second time: idempotent
// deletion is convenient for clients but would mask a bug where a client
// deletes the same id twice believing each is a distinct action.
func (s *Store) Delete(ctx context.Context, tenantID, commentID, userID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var ownerID string
		var deletedAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT user_id, deleted_at FROM comment.comments WHERE id = $1`,
			commentID,
		).Scan(&ownerID, &deletedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("look up comment: %w", err)
		}
		if deletedAt != nil {
			return ErrNotFound
		}
		if ownerID != userID {
			return ErrNotOwner
		}

		_, err = tx.Exec(ctx,
			`UPDATE comment.comments SET deleted_at = now() WHERE id = $1`, commentID)
		if err != nil {
			return fmt.Errorf("delete comment: %w", err)
		}
		return nil
	})
}
