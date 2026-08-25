package main

import (
	"context"
	"fmt"
	"os"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/obs"
)

func runDB(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: axebom db <migrate|down|down-all|status|reset|seed|verify-rls>")
	}

	obs.InitLogger(obs.LogConfig{Service: "axebom-db", Level: "info", Format: "text"})

	cfg, err := config.LoadService("gateway")
	if err != nil {
		return err
	}

	switch args[0] {
	case "migrate", "up":
		return withMigrator(cfg.Postgres, func(m *db.Migrator) error { return m.Up(ctx) })
	case "down":
		return withMigrator(cfg.Postgres, func(m *db.Migrator) error { return m.Down(ctx) })
	case "down-all":
		return withMigrator(cfg.Postgres, func(m *db.Migrator) error { return m.DownAll(ctx) })
	case "status":
		return withMigrator(cfg.Postgres, func(m *db.Migrator) error { return m.Status(ctx) })
	case "reset":
		return withMigrator(cfg.Postgres, func(m *db.Migrator) error { return m.Reset(ctx) })
	case "seed":
		return withMigrator(cfg.Postgres, func(m *db.Migrator) error { return m.Seed(ctx) })
	case "verify-rls":
		return verifyRLS(ctx, cfg.Postgres)
	default:
		return fmt.Errorf("unknown db subcommand %q", args[0])
	}
}

func withMigrator(pg config.Postgres, fn func(*db.Migrator) error) error {
	m, err := db.NewMigrator(pg)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()
	return fn(m)
}

// verifyRLS is the operator-facing form of TestRLSCoverage.
//
// The test guards development; this guards a deployed database, where the
// question "is RLS actually on right now" has a different weight. It reports
// every tenant-scoped table's state and exits non-zero on any gap.
func verifyRLS(ctx context.Context, pg config.Postgres) error {
	m, err := db.NewMigrator(pg)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	report, err := m.VerifyRLS(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("RLS coverage: %d tables checked\n\n", report.Checked)
	for _, t := range report.Exempt {
		fmt.Printf("  exempt  %-46s %s\n", t.Table, t.Reason)
	}
	for _, t := range report.Covered {
		fmt.Printf("  ok      %-46s policy=%s\n", t.Table, t.Policy)
	}
	if len(report.Gaps) > 0 {
		fmt.Fprintf(os.Stderr, "\n")
		for _, g := range report.Gaps {
			fmt.Fprintf(os.Stderr, "  GAP     %-46s %s\n", g.Table, g.Reason)
		}
		return fmt.Errorf("%d table(s) without row-level security", len(report.Gaps))
	}

	fmt.Printf("\nAll %d tenant-scoped tables have FORCE row-level security and a policy.\n",
		len(report.Covered))
	return nil
}
