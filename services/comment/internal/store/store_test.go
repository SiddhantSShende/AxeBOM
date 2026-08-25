package store_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/comment/internal/store"
)

// Against real Postgres — the properties under test (RLS isolation, the
// depth cap, cross-report parent rejection, ownership) are properties of the
// database and the transaction, not of Go alone. SKIPS without one; CI always
// has one. Same harness services/project/internal/store/hbom_test.go uses.

const (
	tenantA = "01900000-0000-7000-8000-00000000000a"
	tenantB = "01900000-0000-7000-8000-00000000000b"
	userA   = "01900000-0000-7000-8000-0000000000a1"
	userB   = "01900000-0000-7000-8000-0000000000b1"
)

func openPool(t *testing.T) *db.Pool {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("comment")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pool, err := db.Open(t.Context(), cfg.Postgres)
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev && task db:reset`", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestCreateTopLevelCommentHasDepthZero(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	c, err := st.Create(t.Context(), tenantA, reportID, userA, "", "first comment")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.Depth != 0 {
		t.Errorf("depth = %d, want 0", c.Depth)
	}
	if c.ParentID != "" {
		t.Errorf("parent_id = %q, want empty", c.ParentID)
	}
	if c.Body != "first comment" {
		t.Errorf("body = %q", c.Body)
	}
}

func TestCreateReplyInheritsParentDepthPlusOne(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	root, err := st.Create(t.Context(), tenantA, reportID, userA, "", "root")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	reply, err := st.Create(t.Context(), tenantA, reportID, userB, root.ID, "a reply")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	if reply.Depth != 1 {
		t.Errorf("depth = %d, want 1", reply.Depth)
	}
	if reply.ParentID != root.ID {
		t.Errorf("parent_id = %q, want %q", reply.ParentID, root.ID)
	}
}

func TestCreateRefusesBeyondMaxDepth(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	parentID := ""
	for i := 0; i <= store.MaxDepth; i++ {
		c, err := st.Create(t.Context(), tenantA, reportID, userA, parentID, "level")
		if err != nil {
			t.Fatalf("create at level %d: %v", i, err)
		}
		if c.Depth != i {
			t.Fatalf("level %d: depth = %d, want %d", i, c.Depth, i)
		}
		parentID = c.ID
	}

	// parentID now points at a comment at MaxDepth; one more reply would be
	// MaxDepth+1, which the CHECK constraint forbids and Create must refuse
	// itself rather than surface as a raw constraint-violation error.
	_, err := st.Create(t.Context(), tenantA, reportID, userA, parentID, "too deep")
	if !errors.Is(err, store.ErrDepthExceeded) {
		t.Fatalf("err = %v, want ErrDepthExceeded", err)
	}
}

func TestCreateRefusesParentFromAnotherReport(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportA := mustReportUUID(t, pool, tenantA)
	reportB := mustReportUUID(t, pool, tenantA)

	root, err := st.Create(t.Context(), tenantA, reportA, userA, "", "on report A")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}

	_, err = st.Create(t.Context(), tenantA, reportB, userA, root.ID, "threaded onto the wrong report")
	if !errors.Is(err, store.ErrParentCrossReport) {
		t.Fatalf("err = %v, want ErrParentCrossReport", err)
	}
}

func TestCreateRefusesUnknownParent(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	_, err := st.Create(t.Context(), tenantA, reportID, userA,
		"00000000-0000-7000-8000-000000000000", "orphan reply")
	if !errors.Is(err, store.ErrParentNotFound) {
		t.Fatalf("err = %v, want ErrParentNotFound", err)
	}
}

func TestListReturnsSoftDeletedCommentsAsPlaceholderCandidates(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	root, err := st.Create(t.Context(), tenantA, reportID, userA, "", "will be deleted")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	reply, err := st.Create(t.Context(), tenantA, reportID, userB, root.ID, "a live reply")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}

	if err := st.Delete(t.Context(), tenantA, root.ID, userA); err != nil {
		t.Fatalf("delete root: %v", err)
	}

	comments, err := st.List(t.Context(), tenantA, reportID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var sawRoot, sawReply bool
	for _, c := range comments {
		switch c.ID {
		case root.ID:
			sawRoot = true
			if c.DeletedAt == nil {
				t.Error("deleted root: DeletedAt is nil")
			}
			// ⚠ THE RAW BODY IS STILL HERE. Masking to "[deleted]" is the
			// handler's job (the audit trail), not the store's — see the
			// package doc on Comment.Body.
			if c.Body != "will be deleted" {
				t.Errorf("deleted root body = %q, want the original text preserved", c.Body)
			}
		case reply.ID:
			sawReply = true
			if c.DeletedAt != nil {
				t.Error("live reply: DeletedAt is set")
			}
			if c.ParentID != root.ID {
				t.Errorf("reply parent_id = %q, want %q (must not be orphaned)", c.ParentID, root.ID)
			}
		}
	}
	if !sawRoot {
		t.Error("List omitted the soft-deleted root — it would orphan its live reply")
	}
	if !sawReply {
		t.Error("List omitted the live reply")
	}
}

func TestUpdateByNonAuthorIsRefused(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	c, err := st.Create(t.Context(), tenantA, reportID, userA, "", "mine")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = st.Update(t.Context(), tenantA, c.ID, userB, "edited by somebody else")
	if !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("err = %v, want ErrNotOwner", err)
	}

	// The author himself can, and edited_at is stamped.
	updated, err := st.Update(t.Context(), tenantA, c.ID, userA, "edited by the author")
	if err != nil {
		t.Fatalf("update by author: %v", err)
	}
	if updated.EditedAt == nil {
		t.Error("EditedAt is nil after a successful edit")
	}
	if updated.Body != "edited by the author" {
		t.Errorf("body = %q", updated.Body)
	}
}

func TestDeleteByNonAuthorIsRefused(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	c, err := st.Create(t.Context(), tenantA, reportID, userA, "", "mine")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := st.Delete(t.Context(), tenantA, c.ID, userB); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("err = %v, want ErrNotOwner", err)
	}
	if err := st.Delete(t.Context(), tenantA, c.ID, userA); err != nil {
		t.Fatalf("delete by author: %v", err)
	}
}

func TestUpdateAndDeleteOfAlreadyDeletedCommentIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	c, err := st.Create(t.Context(), tenantA, reportID, userA, "", "mine")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.Delete(t.Context(), tenantA, c.ID, userA); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := st.Update(t.Context(), tenantA, c.ID, userA, "too late"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update after delete: err = %v, want ErrNotFound", err)
	}
	if err := st.Delete(t.Context(), tenantA, c.ID, userA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: err = %v, want ErrNotFound (not silently idempotent)", err)
	}
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation — CLAUDE.md invariant 6, RLS-backed.
// ---------------------------------------------------------------------------

func TestListIsScopedToTenant(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	if _, err := st.Create(t.Context(), tenantA, reportID, userA, "", "tenant A's comment"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Same report id, other tenant: RLS filters tenant A's row out entirely.
	// There is nothing to compare it against because the id space is shared —
	// this is exactly the property that makes cross-tenant indistinguishable
	// from nonexistent (ErrNotFound's own doc comment).
	comments, err := st.List(t.Context(), tenantB, reportID)
	if err != nil {
		t.Fatalf("list as tenant B: %v", err)
	}
	if len(comments) != 0 {
		t.Errorf("tenant B saw %d comments belonging to tenant A", len(comments))
	}
}

func TestCrossTenantUpdateAndDeleteAreNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	c, err := st.Create(t.Context(), tenantA, reportID, userA, "", "tenant A's comment")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Tenant B, even naming the SAME user id and comment id, sees nothing: RLS
	// scopes the lookup itself. This must answer ErrNotFound, never
	// ErrNotOwner — a 403 here would confirm the row exists to a caller in the
	// wrong tenant entirely, which is the exact leak CLAUDE.md invariant 6
	// forbids.
	if _, err := st.Update(t.Context(), tenantB, c.ID, userA, "hijacked"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant update: err = %v, want ErrNotFound", err)
	}
	if err := st.Delete(t.Context(), tenantB, c.ID, userA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete: err = %v, want ErrNotFound", err)
	}

	// And it is genuinely untouched.
	comments, err := st.List(t.Context(), tenantA, reportID)
	if err != nil {
		t.Fatalf("list as tenant A: %v", err)
	}
	if len(comments) != 1 || comments[0].DeletedAt != nil || comments[0].Body != "tenant A's comment" {
		t.Fatalf("tenant A's comment was modified by a cross-tenant call: %+v", comments)
	}
}

func TestCreateRefusesParentFromAnotherTenant(t *testing.T) {
	pool := openPool(t)
	st := store.NewStore(pool)
	reportID := mustReportUUID(t, pool, tenantA)

	root, err := st.Create(t.Context(), tenantA, reportID, userA, "", "tenant A's root")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}

	// Tenant B cannot see tenant A's comment at all — RLS makes the parent
	// lookup itself come back empty, which Create must report the same way it
	// would report a parent id that never existed.
	_, err = st.Create(t.Context(), tenantB, reportID, userA, root.ID, "reply from the wrong tenant")
	if !errors.Is(err, store.ErrParentNotFound) {
		t.Fatalf("err = %v, want ErrParentNotFound", err)
	}
}

// mustReportUUID mints a fresh UUID via Postgres to stand in for a
// report.reports.id. comment.comments has no FK across the schema boundary
// (CLAUDE.md invariant 11), so no report row needs to exist for these tests —
// exactly like production, where the comment service never queries the
// report schema.
func mustReportUUID(t *testing.T, pool *db.Pool, tenantID string) string {
	t.Helper()
	var id string
	err := pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT app.uuid_v7()`).Scan(&id)
	})
	if err != nil {
		t.Fatalf("mint report uuid: %v", err)
	}
	return id
}
