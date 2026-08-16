// Package db owns database access.
//
// Its entire purpose is to make the tenancy boundary (ADR-0006) impossible to
// bypass by accident. Two rules follow from that, and both are enforced here
// rather than left to discipline:
//
//   - There is no exported way to get a connection without a tenant. Callers
//     go through WithTenant, which issues SET LOCAL app.current_tenant_id at
//     the start of every transaction. A query outside it FAILS CLOSED, because
//     current_setting() raises when the setting is unset.
//
//   - The application role is asserted non-superuser and non-BYPASSRLS at
//     startup. Either privilege silently disables every policy in the
//     database: the queries keep working, the rows keep coming back, and
//     nothing looks wrong until it is a breach.
//
// See docs/05-SECURITY-MODEL.md §2.
package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
)

// Pool wraps a pgxpool and refuses to hand out an unscoped connection.
type Pool struct {
	pool *pgxpool.Pool
	cfg  config.Postgres
}

// Open connects as the APPLICATION role and verifies its privileges.
//
// It deliberately does not accept a role name: connecting as anything other
// than the non-superuser app role would defeat the whole design, so the caller
// cannot choose.
func Open(ctx context.Context, cfg config.Postgres) (*Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.AppDSN())
	if err != nil {
		return nil, fmt.Errorf("parse app dsn: %w", err)
	}

	pc.MaxConns = int32(cfg.MaxConns) //nolint:gosec // bounded by config validation
	pc.MinConns = 2
	pc.MaxConnLifetime = time.Hour
	pc.MaxConnIdleTime = 15 * time.Minute
	pc.HealthCheckPeriod = 30 * time.Second

	// Every pooled connection is reset before reuse. SET LOCAL is already
	// transaction-scoped, so this is belt-and-braces against a stray SET.
	pc.AfterRelease = func(c *pgx.Conn) bool {
		_, err := c.Exec(context.Background(), "RESET ALL")
		return err == nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	p := &Pool{pool: pool, cfg: cfg}

	if err := p.assertRolePrivileges(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	slog.Info("database connected",
		"dsn", cfg.Redacted(),
		"role", cfg.AppRole,
		"max_conns", cfg.MaxConns)
	return p, nil
}

// ErrPrivilegedRole means the application connected with a role that can
// bypass Row-Level Security.
var ErrPrivilegedRole = errors.New("application role can bypass row-level security")

// assertRolePrivileges refuses to start if the connected role can bypass RLS.
//
// This runs on every boot, not just once at provisioning, because a later
// GRANT can reintroduce the problem long after the migration that got it
// right. Failing to start is the correct response: a service that runs with
// RLS silently disabled is worse than one that does not run.
func (p *Pool) assertRolePrivileges(ctx context.Context) error {
	var (
		role      string
		superuser bool
		bypassRLS bool
	)
	err := p.pool.QueryRow(ctx, `
		SELECT rolname, rolsuper, rolbypassrls
		  FROM pg_roles
		 WHERE rolname = current_user`).Scan(&role, &superuser, &bypassRLS)
	if err != nil {
		return fmt.Errorf("read role privileges: %w", err)
	}

	if superuser || bypassRLS {
		return fmt.Errorf("%w: role %q has superuser=%v bypassrls=%v; "+
			"row-level security is the only tenancy boundary and both privileges "+
			"disable it silently. Fix: ALTER ROLE %s NOSUPERUSER NOBYPASSRLS",
			ErrPrivilegedRole, role, superuser, bypassRLS, role)
	}

	slog.Debug("role privileges verified", "role", role, "superuser", false, "bypassrls", false)
	return nil
}

// Ping is the readiness probe.
func (p *Pool) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return p.pool.Ping(ctx)
}

// Close releases the pool.
func (p *Pool) Close() { p.pool.Close() }

// Stat exposes pool statistics for metrics.
func (p *Pool) Stat() *pgxpool.Stat { return p.pool.Stat() }

// Raw returns the underlying pool.
//
// ⚠ THIS BYPASSES TENANT SCOPING. It exists for migrations, health checks and
// genuinely cross-tenant platform queries (the global alias graph, scheduler
// leader election). Every use is a decision: if the query touches a
// tenant-scoped table, use WithTenant instead.
//
// RLS still applies — the role cannot bypass it — so a tenant-scoped query
// issued here fails closed rather than returning everything. That is the
// safety net, not the plan.
func (p *Pool) Raw() *pgxpool.Pool { return p.pool }
