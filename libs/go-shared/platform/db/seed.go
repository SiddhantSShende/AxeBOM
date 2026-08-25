package db

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/migrations"
)

// Seed loads development fixtures.
//
// Runs as the OWNER, deliberately. Seed data spans two tenants, and inserting
// tenant B's rows through a connection scoped to tenant A would violate the
// very WITH CHECK constraint the seed exists to exercise. This is one of the
// few legitimate uses of an unscoped connection — and it is why Seed refuses
// to run anywhere but a local database.
func (m *Migrator) Seed(ctx context.Context) error {
	if err := m.refuseNonLocal("seed"); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrations.SeedFS, "seed")
	if err != nil {
		return fmt.Errorf("read seed directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // numeric prefixes give deterministic order

	for _, name := range names {
		content, err := fs.ReadFile(migrations.SeedFS, "seed/"+name)
		if err != nil {
			return fmt.Errorf("read seed %s: %w", name, err)
		}
		if _, err := m.db.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("apply seed %s: %w", name, err)
		}
		slog.Info("seed applied", "file", name)
	}

	slog.Info("development seed loaded",
		"files", len(names),
		"tenants", 2,
		"note", "two tenants share project names on purpose — a cross-tenant leak shows as duplicates")
	return nil
}

// refuseNonLocal is a guard, not a permission system.
//
// It cannot stop a determined operator, and is not meant to. It turns one
// specific catastrophe — running `db reset` or `db seed` against staging
// because a shell had the wrong env loaded — into an error message.
func (m *Migrator) refuseNonLocal(op string) error {
	if m.cfg.Host == "localhost" || m.cfg.Host == "127.0.0.1" || m.cfg.Host == "postgres" {
		return nil
	}
	return fmt.Errorf(
		"refusing to %s a non-local database at %q: this destroys or fabricates data. "+
			"If that is genuinely intended, do it deliberately by hand", op, m.cfg.Host)
}

// Config exposes the connection settings, for tests that need a second
// connection as a different role.
func (m *Migrator) Config() config.Postgres { return m.cfg }
