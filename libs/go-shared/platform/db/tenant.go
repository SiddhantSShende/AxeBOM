package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
)

// Tx is the only handle domain code gets. It is a transaction that already has
// app.current_tenant_id set, so every statement is filtered by RLS.
type Tx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconnCommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error)
}

// pgconnCommandTag aliases the pgx command tag so callers need not import
// pgconn directly.
type pgconnCommandTag = interface {
	RowsAffected() int64
	String() string
	Insert() bool
	Update() bool
	Delete() bool
	Select() bool
}

// ErrNoTenant means a tenant-scoped operation was attempted without a tenant.
var ErrNoTenant = errors.New("no tenant in context")

// WithTenant runs fn inside a transaction scoped to tenantID.
//
// SET LOCAL, NOT SET — this is the whole point.
//
// SET would persist on the pooled connection after the transaction ends, and
// the next request to borrow that connection would inherit the previous
// tenant's scope. That is a cross-tenant read with no code change and no error
// message. SET LOCAL is reverted at COMMIT or ROLLBACK, so the leak cannot
// happen. There is an explicit test for it.
//
// The transaction commits if fn returns nil and rolls back otherwise.
func (p *Pool) WithTenant(ctx context.Context, tenantID string, fn func(context.Context, Tx) error) error {
	if tenantID == "" {
		return ErrNoTenant
	}

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	// Parameterized: tenantID reaches here from a verified JWT, but
	// interpolating it into SQL would make any future path that forgets to
	// validate it an injection point.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant scope: %w", err)
	}

	if err := fn(ctx, txWrapper{tx}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// WithTenantFromContext takes the tenant from the request context.
//
// The tenant reaches the context from a verified JWT and nowhere else — never
// a header, query parameter, or body field (docs/05-SECURITY-MODEL.md §2).
func (p *Pool) WithTenantFromContext(ctx context.Context, fn func(context.Context, Tx) error) error {
	tenantID, ok := ctxkey.TenantID(ctx)
	if !ok || tenantID == "" {
		// A missing tenant here means the request bypassed auth middleware.
		// Surface it loudly rather than defaulting to anything.
		return ErrNoTenant
	}
	return p.WithTenant(ctx, tenantID, fn)
}

// txWrapper adapts pgx.Tx to the Tx interface.
type txWrapper struct{ tx pgx.Tx }

func (w txWrapper) Exec(ctx context.Context, sql string, args ...any) (pgconnCommandTag, error) {
	return w.tx.Exec(ctx, sql, args...)
}

func (w txWrapper) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return w.tx.Query(ctx, sql, args...)
}

func (w txWrapper) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return w.tx.QueryRow(ctx, sql, args...)
}

func (w txWrapper) CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error) {
	// Bulk path for the normalizer: 50k+ components per scan makes row-by-row
	// INSERT untenable. RLS still applies to COPY.
	return w.tx.CopyFrom(ctx, table, cols, src)
}
