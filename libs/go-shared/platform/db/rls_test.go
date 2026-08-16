package db

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
)

// Tenancy tests. These are the acceptance criteria of Phase 1 and the reason
// ADR-0006 exists.
//
// They require a live database (`task dev`), and they SKIP rather than fail
// when one is absent — a developer without Docker running should not see a red
// suite they cannot fix. CI always has the database, so the checks always run
// there.

// Seeded tenant ids from migrations/seed/0001_dev_tenants.sql.
const (
	tenantA = "01900000-0000-7000-8000-00000000000a" // Acme Industries
	tenantB = "01900000-0000-7000-8000-00000000000b" // Beta Corp

	// Both tenants have a project named "payments-api" on purpose: a
	// cross-tenant leak then shows up as duplicate rows rather than as nothing.
	projectA = "01900000-0000-7000-8000-0000000000f1"
	projectB = "01900000-0000-7000-8000-0000000000f3"
)

func testConfig() config.Postgres {
	cfg, err := config.LoadService("gateway")
	if err != nil {
		panic(err)
	}
	return cfg.Postgres
}

// openTestPool connects as the APPLICATION role, which is the whole point:
// connecting as the owner would bypass FORCE RLS and every test below would
// pass while proving nothing.
func openTestPool(t *testing.T) *Pool {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	pool, err := Open(t.Context(), testConfig())
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev && task db:reset`", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

// TestRLSCoverage enumerates every table in the tenant schemas.
//
// A table added without a policy is not a style problem: it is a table any
// tenant can read in full. This test is what makes "we always add the policy"
// a fact rather than an intention.
func TestRLSCoverage(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	m, err := NewMigrator(testConfig())
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev`", err)
	}
	defer func() { _ = m.Close() }()

	report, err := m.VerifyRLS(t.Context())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	t.Logf("%d tables checked: %d protected, %d exempt, %d gaps",
		report.Checked, len(report.Covered), len(report.Exempt), len(report.Gaps))

	for _, gap := range report.Gaps {
		t.Errorf("NO ROW-LEVEL SECURITY: %s — %s", gap.Table, gap.Reason)
	}

	// A suite that reports zero covered tables is broken, not clean.
	if len(report.Covered) == 0 {
		t.Fatal("no protected tables found — migrations have probably not run")
	}
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation — the negative suite
// ---------------------------------------------------------------------------

func TestCrossTenantSelectReturnsNothing(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	// Sanity: tenant A can see its own project. Without this, the negative
	// assertions below could pass because nothing exists at all.
	var name string
	err := pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		return tx.QueryRow(ctx,
			`SELECT name FROM project.projects WHERE id = $1`, projectA).Scan(&name)
	})
	if err != nil {
		t.Fatalf("tenant A cannot read its own project: %v (did `task db:seed` run?)", err)
	}
	if name != "payments-api" {
		t.Fatalf("unexpected project name %q", name)
	}

	// The actual test: tenant A asks for tenant B's project BY ID.
	err = pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		return tx.QueryRow(ctx,
			`SELECT name FROM project.projects WHERE id = $1`, projectB).Scan(&name)
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant A read tenant B's project — RLS IS NOT WORKING. err=%v name=%q", err, name)
	}
}

func TestCrossTenantCountIsScoped(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	count := func(tenant string) int {
		var n int
		if err := pool.WithTenant(ctx, tenant, func(ctx context.Context, tx Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM project.projects`).Scan(&n)
		}); err != nil {
			t.Fatalf("count for %s: %v", tenant, err)
		}
		return n
	}

	a, b := count(tenantA), count(tenantB)
	t.Logf("tenant A sees %d projects, tenant B sees %d", a, b)

	// Seed: A has two projects, B has one. If either sees three, the policy is
	// not filtering — and because both tenants have a project called
	// "payments-api", that shows up as an obvious duplicate.
	if a != 2 {
		t.Errorf("tenant A should see exactly its own 2 projects, saw %d", a)
	}
	if b != 1 {
		t.Errorf("tenant B should see exactly its own 1 project, saw %d", b)
	}
}

func TestCrossTenantUpdateAffectsNothing(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	var affected int64
	err := pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE project.projects SET description = 'compromised' WHERE id = $1`, projectB)
		if err != nil {
			return err
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if affected != 0 {
		t.Fatalf("tenant A modified %d of tenant B's rows — RLS IS NOT WORKING", affected)
	}

	// And confirm B's row is intact, viewed from B.
	var desc string
	if err := pool.WithTenant(ctx, tenantB, func(ctx context.Context, tx Tx) error {
		return tx.QueryRow(ctx,
			`SELECT description FROM project.projects WHERE id = $1`, projectB).Scan(&desc)
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if desc == "compromised" {
		t.Fatal("tenant B's data was modified by tenant A")
	}
}

// WITH CHECK is the half of the policy people forget. Without it a tenant can
// INSERT rows attributed to another tenant — writing into their data rather
// than reading it.
func TestCrossTenantInsertViolatesWithCheck(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	err := pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO project.projects
				(tenant_id, name, source_type, sdlc_stage, created_by)
			VALUES ($1, 'smuggled', 'manual', 'source', $2)`,
			tenantB, "01900000-0000-7000-8000-0000000000a1")
		return err
	})

	if err == nil {
		t.Fatal("tenant A inserted a row attributed to tenant B — WITH CHECK IS MISSING")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
		t.Errorf("expected an RLS violation, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed
// ---------------------------------------------------------------------------

// A query issued outside WithTenant must FAIL, not return everything.
//
// current_setting('app.current_tenant_id') raises when unset, which is exactly
// the desired behaviour — the alternative is a query that silently returns
// every tenant's rows.
func TestQueryOutsideWithTenantFailsClosed(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	var n int
	err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM project.projects`).Scan(&n)

	if err == nil {
		t.Fatalf("an unscoped query SUCCEEDED and returned %d rows — it must fail closed", n)
	}
	if !strings.Contains(err.Error(), "app.current_tenant_id") {
		t.Errorf("expected a missing-setting error, got: %v", err)
	}
	t.Logf("unscoped query correctly failed: %v", err)
}

func TestWithTenantRejectsEmptyTenant(t *testing.T) {
	pool := openTestPool(t)
	err := pool.WithTenant(t.Context(), "", func(context.Context, Tx) error {
		t.Fatal("callback must not run without a tenant")
		return nil
	})
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("got %v, want ErrNoTenant", err)
	}
}

// THE REASON FOR `SET LOCAL` RATHER THAN `SET`.
//
// SET persists on the pooled connection after the transaction ends, so the
// next request to borrow that connection inherits the previous tenant's scope.
// That is a cross-tenant read with no code change and no error message.
//
// This test hammers the pool from both tenants concurrently: if scope leaked,
// one of them would see the other's row count.
func TestPoolReuseDoesNotLeakTenantScope(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	const iterations = 60
	var wg sync.WaitGroup
	errCh := make(chan error, iterations*2)

	check := func(tenant string, want int) {
		defer wg.Done()
		var n int
		if err := pool.WithTenant(ctx, tenant, func(ctx context.Context, tx Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM project.projects`).Scan(&n)
		}); err != nil {
			errCh <- err
			return
		}
		if n != want {
			errCh <- errors.New("TENANT SCOPE LEAKED ACROSS POOLED CONNECTIONS: tenant " +
				tenant + " saw the wrong row count")
		}
	}

	for i := 0; i < iterations; i++ {
		wg.Add(2)
		go check(tenantA, 2)
		go check(tenantB, 1)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

// After a WithTenant transaction commits, the setting must be gone. If it
// survived, the very next unscoped query on that connection would succeed —
// which is precisely the leak.
func TestSettingIsRevertedAfterTransaction(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	if err := pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM project.projects`).Scan(&n)
	}); err != nil {
		t.Fatalf("scoped query: %v", err)
	}

	// Exhaust the pool so we are very likely to reuse the same connection.
	for i := 0; i < 30; i++ {
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM project.projects`).Scan(&n); err == nil {
			t.Fatalf("unscoped query succeeded after a scoped transaction (saw %d rows) — "+
				"the tenant setting survived the transaction", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Role privileges
// ---------------------------------------------------------------------------

// RLS is only a boundary if the connecting role cannot bypass it. A later
// GRANT can reintroduce the problem long after the migration that got it
// right, so this is asserted on every connection, not once at provisioning.
func TestAppRoleCannotBypassRLS(t *testing.T) {
	pool := openTestPool(t)

	var role string
	var superuser, bypassRLS bool
	err := pool.Raw().QueryRow(t.Context(), `
		SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&role, &superuser, &bypassRLS)
	if err != nil {
		t.Fatalf("read role: %v", err)
	}

	t.Logf("connected as %q", role)
	if superuser {
		t.Error("the application role is SUPERUSER — every RLS policy is disabled")
	}
	if bypassRLS {
		t.Error("the application role has BYPASSRLS — every RLS policy is disabled")
	}
	if role == "postgres" || role == testConfig().User {
		t.Errorf("connected as the OWNER (%q) rather than the application role; "+
			"FORCE RLS applies to the owner but this is still the wrong identity", role)
	}
}

// The audit log is append-only BY GRANT, not by convention — a convention is
// something an ORM will cheerfully ignore.
func TestAuditLogIsAppendOnly(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	err := pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM auth.audit_log WHERE tenant_id = $1`, tenantA)
		return err
	})
	if err == nil {
		t.Fatal("DELETE on auth.audit_log succeeded — it must be append-only")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Errorf("expected permission denied, got: %v", err)
	}
}

// Raw scan artifacts are the evidence behind every report and what makes
// normalization replayable (ADR-0003). Immutable by grant.
func TestRawArtifactsAreImmutable(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	err := pool.WithTenant(ctx, tenantA, func(ctx context.Context, tx Tx) error {
		_, err := tx.Exec(ctx, `UPDATE scan.raw_artifacts SET storage_ref = 'x'`)
		return err
	})
	if err == nil {
		t.Fatal("UPDATE on scan.raw_artifacts succeeded — raw artifacts must be immutable")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Errorf("expected permission denied, got: %v", err)
	}
}
