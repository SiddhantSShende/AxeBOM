package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver, required by goose
	"github.com/pressly/goose/v3"

	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/migrations"
)

// MigrationOrder is dependency order, not alphabetical.
//
// bootstrap MUST run first: it creates the schemas, the non-superuser
// application role, and the RLS helper functions every later migration calls.
//
// Each schema gets its OWN goose version table, so schemas version
// independently and a future service extraction takes its migration history
// with it (ADR-0001 mitigation 2).
var MigrationOrder = []string{
	"bootstrap",
	"auth",
	"project",
	"scan",
	"normalize",
	"report",
	"campaign",
	"comment",
	"notify",
}

// Migrator runs migrations as the database OWNER.
//
// Deliberately separate from Pool, which connects as the application role.
// Migrations create objects and need privileges the application must never
// have; sharing one connection would mean the application ran with the
// owner's rights.
type Migrator struct {
	db  *sql.DB
	cfg config.Postgres
}

// NewMigrator connects as the owner.
//
// The connectivity check is bounded: an unreachable host would otherwise hang
// the CLI with no output, which reads as a freeze rather than a config error.
func NewMigrator(cfg config.Postgres) (*Migrator, error) {
	sqlDB, err := sql.Open("pgx", cfg.AdminDSN())
	if err != nil {
		return nil, fmt.Errorf("open admin connection: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping as owner (%s): %w", cfg.Redacted(), err)
	}
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, fmt.Errorf("goose dialect: %w", err)
	}
	return &Migrator{db: sqlDB, cfg: cfg}, nil
}

func (m *Migrator) Close() error { return m.db.Close() }

// Up applies all pending migrations in dependency order.
func (m *Migrator) Up(ctx context.Context) error {
	for _, schema := range MigrationOrder {
		if err := m.upOne(ctx, schema); err != nil {
			return fmt.Errorf("migrate %s: %w", schema, err)
		}
	}
	slog.Info("migrations applied", "schemas", len(MigrationOrder))
	return nil
}

func (m *Migrator) upOne(ctx context.Context, schema string) error {
	if err := m.setVersionTable(ctx, schema); err != nil {
		return err
	}
	dir := schema
	before, _ := goose.GetDBVersionContext(ctx, m.db)
	if err := goose.UpContext(ctx, m.db, dir); err != nil {
		return err
	}
	after, _ := goose.GetDBVersionContext(ctx, m.db)
	if after != before {
		slog.Info("schema migrated", "schema", schema, "from", before, "to", after)
	}
	return nil
}

// Down rolls back ONE migration per schema, in reverse dependency order.
//
// Development only. Production is forward-only: a rollback that drops a table
// destroys data, and the additive-first discipline (docs/08-OPERATIONS.md §3)
// means a code rollback never requires a schema one.
//
// BOOTSTRAP IS EXCLUDED, deliberately. Its Down drops every schema and the RLS
// helper functions — it is a full teardown, not a step. Including it here
// would attempt to drop app.touch_updated_at() while triggers on
// still-existing tables depend on it, and fail with a dependency error that
// reads like a bug rather than a category mistake. Use Reset for a teardown.
func (m *Migrator) Down(ctx context.Context) error {
	for i := len(MigrationOrder) - 1; i >= 0; i-- {
		schema := MigrationOrder[i]
		if schema == "bootstrap" {
			continue
		}
		if err := m.setVersionTable(ctx, schema); err != nil {
			return err
		}
		if err := goose.DownContext(ctx, m.db, schema); err != nil {
			return fmt.Errorf("rollback %s: %w", schema, err)
		}
		slog.Info("schema rolled back one step", "schema", schema)
	}
	slog.Info("rolled back one migration per schema",
		"note", "goose Down is a single step; normalize has several migrations. "+
			"Use `db reset` for a full teardown.")
	return nil
}

// DownAll rolls every schema back to zero, in reverse dependency order.
//
// Development only. This is what makes "up, down, up is clean" a real check
// rather than a partial one: a Down that stops after one step leaves tables
// behind and the following Up is a no-op that proves nothing.
func (m *Migrator) DownAll(ctx context.Context) error {
	if err := m.refuseNonLocal("roll back all migrations in"); err != nil {
		return err
	}
	for i := len(MigrationOrder) - 1; i >= 0; i-- {
		schema := MigrationOrder[i]
		if schema == "bootstrap" {
			continue // dropped last, after every dependent object is gone
		}
		if err := m.setVersionTable(ctx, schema); err != nil {
			return err
		}
		if err := goose.DownToContext(ctx, m.db, schema, 0); err != nil {
			return fmt.Errorf("roll back %s to zero: %w", schema, err)
		}
		slog.Info("schema rolled back to zero", "schema", schema)
	}

	// Bootstrap last: its Down drops the schemas and helper functions that
	// everything above depended on.
	if err := m.setVersionTable(ctx, "bootstrap"); err != nil {
		return err
	}
	if err := goose.DownToContext(ctx, m.db, "bootstrap", 0); err != nil {
		return fmt.Errorf("roll back bootstrap: %w", err)
	}
	slog.Info("all migrations rolled back")
	return nil
}

// Status prints the applied/pending state per schema.
func (m *Migrator) Status(ctx context.Context) error {
	for _, schema := range MigrationOrder {
		if err := m.setVersionTable(ctx, schema); err != nil {
			return err
		}
		fmt.Printf("\n--- %s ---\n", schema)
		if err := goose.StatusContext(ctx, m.db, schema); err != nil {
			return err
		}
	}
	return nil
}

// Reset drops every schema and re-applies from scratch. Development only.
func (m *Migrator) Reset(ctx context.Context) error {
	if m.cfg.Host != "localhost" && m.cfg.Host != "127.0.0.1" {
		// A guard, not a permission system — but it turns one specific
		// catastrophe (running reset against staging) into an error message.
		return fmt.Errorf("refusing to reset a non-local database at %q; "+
			"drop it manually if that is genuinely what you want", m.cfg.Host)
	}

	slog.Warn("dropping all schemas", "host", m.cfg.Host, "database", m.cfg.Database)
	for i := len(MigrationOrder) - 1; i >= 0; i-- {
		schema := MigrationOrder[i]
		if schema == "bootstrap" {
			continue // handled below, along with the helper schema
		}
		if _, err := m.db.ExecContext(ctx,
			fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema)); err != nil {
			return fmt.Errorf("drop schema %s: %w", schema, err)
		}
	}
	if _, err := m.db.ExecContext(ctx, "DROP SCHEMA IF EXISTS app CASCADE"); err != nil {
		return fmt.Errorf("drop app schema: %w", err)
	}
	return m.Up(ctx)
}

// setVersionTable points goose at this schema's own version table.
//
// The schema must exist first, so bootstrap keeps its table in `public`.
func (m *Migrator) setVersionTable(ctx context.Context, schema string) error {
	if schema == "bootstrap" {
		goose.SetTableName("public.goose_bootstrap_version")
		return nil
	}
	if _, err := m.db.ExecContext(ctx,
		fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
		return fmt.Errorf("ensure schema %s: %w", schema, err)
	}
	goose.SetTableName(schema + ".goose_db_version")
	return nil
}
