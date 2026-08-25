package middleware

import (
	"context"
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Tenant scoping.
//
// PHASE-03 step 7 states the property to aim for: "a handler must not be able
// to get an unscoped connection — that is the property to design for, not
// merely to test."
//
// The design that achieves it is in platform/db, not here:
//
//   - db.Pool exposes NO query methods. There is no pool.Query, no pool.Exec.
//     The only way to reach a query is WithTenant / WithTenantFromContext.
//   - Both take a callback and hand it a db.Tx — a transaction that has
//     already issued SET LOCAL app.current_tenant_id. Every statement inside
//     is filtered by RLS.
//   - WithTenantFromContext refuses to run at all when the context has no
//     verified tenant, so a handler reached without auth middleware fails
//     closed rather than querying globally.
//
// So "forgetting to scope" is not a discipline anyone has to remember: the
// unscoped call does not exist to be written. pool.Raw() is the one escape
// hatch, it is named to be conspicuous in review, and RLS still applies to it
// because the application role is neither superuser nor BYPASSRLS.
//
// This middleware's own job is therefore small: verify the tenant is present
// and usable before the handler runs, so a failure surfaces as a clear 401
// rather than a confusing Postgres error deep in a query.

// RequireTenantScope rejects any request that reached a tenant-scoped route
// without a verified tenant.
//
// It is defence in depth. RLS already fails closed — current_setting raises
// when app.current_tenant_id is unset — but that error reads as a database
// problem. This turns it into a statement about authentication.
func RequireTenantScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := ctxkey.TenantID(r.Context())
		if !ok || tenantID == "" {
			errs.Write(w, r, errs.New(errs.AuthTenantContextMiss,
				"no tenant in context; the route is missing the Authenticate middleware"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WithTenantTx runs fn inside a transaction scoped to the request's tenant.
//
// Handlers should call this rather than reaching for the pool, so the scope
// always comes from the verified token in the context and never from an
// argument a handler could compute.
func WithTenantTx(ctx context.Context, pool *db.Pool, fn func(context.Context, db.Tx) error) error {
	return pool.WithTenantFromContext(ctx, fn)
}
