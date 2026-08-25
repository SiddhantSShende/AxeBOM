package orchestr

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// The deadline reaper.
//
// ⚠ WITHOUT IT, A LOST JOB IS INVISIBLE FOREVER.
//
// A worker that dies between picking up a job and publishing its result leaves
// an engine run in `running` with nothing to move it. JetStream redelivers, but
// after max_deliver the message is gone and the row is still there. The reaper
// is what turns "we never heard back" into a reported `timeout` — a scan stuck
// at 60% with no explanation is the failure mode this prevents.
//
// LEADER-ELECTED VIA A POSTGRES ADVISORY LOCK. No etcd, no Consul: the database
// is already a hard dependency and already gives us exactly-one-holder
// semantics. Adding a coordination service to run one loop would be a second
// thing to operate for no benefit.

// reaperLockID is the advisory-lock key.
//
// An arbitrary but FIXED constant. Postgres advisory locks are a single global
// namespace, so this number must not collide with another subsystem's — hence
// the registry comment below rather than a bare literal.
//
//	1 axebom deadline reaper
//	(next subsystem takes 2)
const reaperLockID int64 = 1

// Reaper marks overdue jobs as timed out.
type Reaper struct {
	pool  *db.Pool
	store *Store
	log   *slog.Logger

	interval time.Duration
	now      func() time.Time
}

// ReaperConfig configures the reaper.
type ReaperConfig struct {
	Pool  *db.Pool
	Store *Store
	Log   *slog.Logger
	// Interval is how often to sweep. The contract requires a job past its
	// deadline to be reaped within a minute, so this must be well under that.
	Interval time.Duration
	Now      func() time.Time
}

func NewReaper(cfg ReaperConfig) *Reaper {
	if cfg.Interval <= 0 {
		cfg.Interval = 20 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Reaper{
		pool: cfg.Pool, store: cfg.Store, log: cfg.Log,
		interval: cfg.Interval, now: cfg.Now,
	}
}

// Run sweeps until the context is cancelled.
//
// Every instance runs this; only the lock holder does work. That is deliberate
// — there is no separate "reaper deployment" to forget to deploy, and if the
// leader dies another instance takes the lock on its next tick.
func (r *Reaper) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.sweepIfLeader(ctx); err != nil {
				// Logged, not fatal. A reaper that exits on a transient
				// database error is a reaper that is not running when the
				// database recovers.
				r.log.Error("reaper sweep failed", "cause", err.Error())
			}
		}
	}
}

// sweepIfLeader takes the advisory lock and sweeps, or returns immediately.
func (r *Reaper) sweepIfLeader(ctx context.Context) error {
	conn, err := r.pool.Raw().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// pg_try_advisory_lock, NOT pg_advisory_lock: try-and-move-on. The blocking
	// form would queue every instance behind the leader, and on leader death
	// they would all wake at once.
	//
	// The lock is SESSION-scoped and held on this specific connection, which is
	// why the connection is acquired explicitly rather than using the pool: a
	// pooled statement could take the lock on one connection and release it on
	// another, which silently does nothing.
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, reaperLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("try advisory lock: %w", err)
	}
	if !acquired {
		// Another instance is the leader. Not an error.
		return nil
	}
	defer func() {
		// Released explicitly. A session lock survives until the connection
		// closes, so leaking it would make this instance the permanent leader
		// even after it stopped sweeping.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, reaperLockID)
	}()

	return r.sweep(ctx)
}

// ReapResult reports what one sweep did.
type ReapResult struct {
	JobsTimedOut  int
	ScansAffected []string
}

// sweep marks overdue runs as timed out and recomputes their scans.
func (r *Reaper) sweep(ctx context.Context) error {
	res, err := r.Sweep(ctx)
	if err != nil {
		return err
	}
	if res.JobsTimedOut > 0 {
		r.log.Warn("reaped overdue engine runs",
			"jobs", res.JobsTimedOut, "scans", len(res.ScansAffected))
	}
	return nil
}

// Sweep is the reaping pass, exported so tests can drive it directly rather
// than waiting on a ticker.
//
// ⚠ IT GOES THROUGH SECURITY DEFINER FUNCTIONS, NOT A RAW QUERY.
//
// The reaper must cover EVERY tenant, but scan.engine_runs has FORCE RLS keyed
// on app.current_tenant_id, so an unscoped query raises
// `unrecognized configuration parameter` — RLS failing closed, correctly.
//
// The alternatives were all worse: BYPASSRLS disables every policy in the
// database for that role; connecting as the owner is the same with extra steps;
// enumerating tenants needs a forbidden cross-schema read and misses a tenant
// added mid-sweep. So: narrow functions that take no parameters, write one
// status transition, and return only ids (migrations/scan/0005).
func (r *Reaper) Sweep(ctx context.Context) (ReapResult, error) {
	var res ReapResult

	rows, err := r.pool.Raw().Query(ctx, `SELECT * FROM scan.reap_overdue_runs()`)
	if err != nil {
		return res, fmt.Errorf("reap overdue runs: %w", err)
	}

	type affected struct{ scanID, tenantID string }
	var list []affected

	for rows.Next() {
		var scanID, tenantID, jobID, engineID string
		if err := rows.Scan(&scanID, &tenantID, &jobID, &engineID); err != nil {
			rows.Close()
			return res, err
		}
		res.JobsTimedOut++
		list = append(list, affected{scanID, tenantID})
		r.log.Warn("engine run timed out",
			"scan_id", scanID, "engine", engineID, "job_id", jobID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	// Recompute each affected scan. A timeout may have been the last
	// outstanding run, in which case the scan becomes terminal — and the whole
	// point of the reaper is that it becomes terminal rather than staying at
	// 60% forever.
	seen := map[string]bool{}
	for _, a := range list {
		if seen[a.scanID] {
			continue
		}
		seen[a.scanID] = true
		res.ScansAffected = append(res.ScansAffected, a.scanID)

		statuses, err := r.terminalStatuses(ctx, a.scanID)
		if err != nil {
			r.log.Error("could not read statuses after reaping",
				"scan_id", a.scanID, "cause", err.Error())
			continue
		}
		// ⚠ DO NOT DERIVE WHILE ANYTHING IS STILL RUNNING.
		//
		// DeriveScanStatus treats `queued` and `running` as not-succeeded, so
		// deriving early would mark a scan FAILED while half its engines were
		// still working — and that status is what a report prints.
		if anyStillRunning(statuses) {
			continue
		}

		// The derivation stays in Go, in ONE place. Duplicating it in SQL would
		// give two copies that drift, and the one that drifts is the one that
		// prints a status into a compliance document.
		derived := events.DeriveScanStatus(statuses)
		terminal := derived == events.ScanCompleted ||
			derived == events.ScanCompletedWithErrors ||
			derived == events.ScanFailed

		if _, err := r.pool.Raw().Exec(ctx,
			`SELECT scan.set_scan_status($1, $2, $3)`,
			a.scanID, string(derived), terminal); err != nil {
			r.log.Error("could not update scan status after reaping",
				"scan_id", a.scanID, "cause", err.Error())
		}
	}

	return res, nil
}

// terminalStatuses reads a scan's per-engine statuses without a tenant scope.
func (r *Reaper) terminalStatuses(ctx context.Context, scanID string) ([]events.EngineStatus, error) {
	rows, err := r.pool.Raw().Query(ctx,
		`SELECT status FROM scan.terminal_statuses_for($1)`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []events.EngineStatus
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, events.EngineStatus(s))
	}
	return out, rows.Err()
}

// anyStillRunning reports whether a scan has work outstanding.
//
// `queued` and `running` are not in events.EngineStatus — they are orchestrator
// states, not results — so they are compared as strings here rather than being
// added to the result enum, where a worker could publish them.
func anyStillRunning(statuses []events.EngineStatus) bool {
	for _, s := range statuses {
		if string(s) == statusQueued || string(s) == "running" {
			return true
		}
	}
	return false
}
