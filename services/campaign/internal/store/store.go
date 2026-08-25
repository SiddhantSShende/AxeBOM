// Package store is the campaign service's persistence layer.
//
// Every tenant-scoped query goes through db.WithTenant. There is exactly ONE
// exception, and it is deliberate: DueCampaigns, which a background tick calls
// with no tenant to scope by. It uses the narrow SECURITY DEFINER function from
// migrations/campaign/0002 — scheduling columns only — and never pool.Raw().
//
// Cross-tenant access returns ErrNotFound for free: RLS filters the row out,
// the query finds nothing, and "not found" is the honest answer. A 403 would
// confirm the id exists.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/campaign/internal/schedule"
	"github.com/axebom/axebom/services/campaign/internal/scheduler"
)

// ErrNotFound is returned when a row does not exist FOR THIS TENANT.
var ErrNotFound = errors.New("not found")

// Store is the campaign service's database access.
type Store struct{ pool *db.Pool }

// New builds a store over a pool.
func New(pool *db.Pool) *Store { return &Store{pool: pool} }

// Campaign mirrors campaign.campaigns.
type Campaign struct {
	ID       string
	TenantID string
	Name     string

	ProjectIDs []string

	CronExpr string
	// Timezone is an IANA name. Never an offset: an offset is wrong for half
	// the year, and which half depends on the zone.
	Timezone string

	BOMTypes     []string
	ReportLevels []string
	Standards    []string
	Formats      []string

	Enabled   bool
	NextRunAt *time.Time
	LastRunAt *time.Time

	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Run mirrors campaign.runs.
type Run struct {
	ID           string
	TenantID     string
	CampaignID   string
	ScheduledFor time.Time
	StartedAt    *time.Time
	FinishedAt   *time.Time
	Status       string
	SkipReason   string
	ScanIDs      []string
	Error        string
	CreatedAt    time.Time
}

const campaignColumns = `
	SELECT id, tenant_id, name, project_ids, cron_expr, timezone,
	       bom_types, report_levels, standards, formats,
	       enabled, next_run_at, last_run_at, created_by, created_at, updated_at
	FROM campaign.campaigns`

func scanCampaign(row pgx.Row) (Campaign, error) {
	var c Campaign
	err := row.Scan(
		&c.ID, &c.TenantID, &c.Name, &c.ProjectIDs, &c.CronExpr, &c.Timezone,
		&c.BOMTypes, &c.ReportLevels, &c.Standards, &c.Formats,
		&c.Enabled, &c.NextRunAt, &c.LastRunAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

// Create inserts a campaign and computes its first occurrence.
func (s *Store) Create(ctx context.Context, tenantID string, c Campaign) (Campaign, error) {
	var out Campaign
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO campaign.campaigns
			    (tenant_id, name, project_ids, cron_expr, timezone,
			     bom_types, report_levels, standards, formats,
			     enabled, next_run_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			RETURNING id, tenant_id, name, project_ids, cron_expr, timezone,
			          bom_types, report_levels, standards, formats,
			          enabled, next_run_at, last_run_at, created_by, created_at, updated_at`,
			tenantID, c.Name, c.ProjectIDs, c.CronExpr, c.Timezone,
			c.BOMTypes, c.ReportLevels, c.Standards, c.Formats,
			c.Enabled, c.NextRunAt, c.CreatedBy)

		var err error
		out, err = scanCampaign(row)
		return err
	})
	if err != nil {
		return Campaign{}, fmt.Errorf("create campaign: %w", err)
	}
	return out, nil
}

// Get reads one campaign.
func (s *Store) Get(ctx context.Context, tenantID, id string) (Campaign, error) {
	var out Campaign
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var err error
		out, err = scanCampaign(tx.QueryRow(ctx, campaignColumns+` WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Campaign{}, ErrNotFound
	}
	if err != nil {
		return Campaign{}, fmt.Errorf("get campaign: %w", err)
	}
	return out, nil
}

// List returns a tenant's campaigns, newest first.
func (s *Store) List(ctx context.Context, tenantID string, limit int) ([]Campaign, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []Campaign
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, campaignColumns+` ORDER BY created_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			c, err := scanCampaign(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list campaigns: %w", err)
	}
	return out, nil
}

// Update changes a campaign's definition and recomputes its cursor.
//
// ⚠ THE CURSOR IS RECOMPUTED FROM `now`, NOT PRESERVED. Editing a cron from
// daily to hourly while keeping a cursor from three days ago would make the
// next tick see 72 missed occurrences — and the missed-run policy would
// dutifully record 71 skips for a schedule that never existed.
func (s *Store) Update(ctx context.Context, tenantID, id string, c Campaign, now time.Time) (Campaign, error) {
	next, err := firstOccurrence(c.CronExpr, c.Timezone, now)
	if err != nil {
		return Campaign{}, err
	}

	var out Campaign
	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE campaign.campaigns
			SET name = $2, project_ids = $3, cron_expr = $4, timezone = $5,
			    bom_types = $6, report_levels = $7, standards = $8, formats = $9,
			    next_run_at = CASE WHEN enabled THEN $10::timestamptz ELSE NULL END
			WHERE id = $1
			RETURNING id, tenant_id, name, project_ids, cron_expr, timezone,
			          bom_types, report_levels, standards, formats,
			          enabled, next_run_at, last_run_at, created_by, created_at, updated_at`,
			id, c.Name, c.ProjectIDs, c.CronExpr, c.Timezone,
			c.BOMTypes, c.ReportLevels, c.Standards, c.Formats, next)

		var err error
		out, err = scanCampaign(row)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Campaign{}, ErrNotFound
	}
	if err != nil {
		return Campaign{}, fmt.Errorf("update campaign: %w", err)
	}
	return out, nil
}

// SetEnabled turns a campaign on or off.
//
// ⚠ ENABLING SETS THE CURSOR TO THE NEXT FUTURE OCCURRENCE, AND THAT IS THE
// WHOLE NO-BACKFILL RULE. A campaign paused for a month and switched back on
// must not fire a month of missed scans; because the cursor moves forward,
// there is nothing behind it to catch up on. The alternative — an `enabled_at`
// column and a comparison in the scheduler — is a rule somebody can forget to
// apply, in a code path that only runs when a customer un-pauses something.
//
// Disabling nulls the cursor, so a disabled campaign is not merely filtered out
// of the due query but has no due time at all.
func (s *Store) SetEnabled(ctx context.Context, tenantID, id string, enabled bool, now time.Time) (Campaign, error) {
	var out Campaign

	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		current, err := scanCampaign(tx.QueryRow(ctx, campaignColumns+` WHERE id = $1`, id))
		if err != nil {
			return err
		}

		var next *time.Time
		if enabled {
			at, err := firstOccurrence(current.CronExpr, current.Timezone, now)
			if err != nil {
				return err
			}
			next = &at
		}

		out, err = scanCampaign(tx.QueryRow(ctx, `
			UPDATE campaign.campaigns
			SET enabled = $2, next_run_at = $3
			WHERE id = $1
			RETURNING id, tenant_id, name, project_ids, cron_expr, timezone,
			          bom_types, report_levels, standards, formats,
			          enabled, next_run_at, last_run_at, created_by, created_at, updated_at`,
			id, enabled, next))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Campaign{}, ErrNotFound
	}
	if err != nil {
		return Campaign{}, fmt.Errorf("set campaign enabled: %w", err)
	}
	return out, nil
}

// Delete removes a campaign. Runs cascade.
func (s *Store) Delete(ctx context.Context, tenantID, id string) error {
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM campaign.campaigns WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return fmt.Errorf("delete campaign: %w", err)
	}
	return nil
}

// ListRuns returns a campaign's run history, newest first.
func (s *Store) ListRuns(ctx context.Context, tenantID, campaignID string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []Run
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, campaign_id, scheduled_for, started_at, finished_at,
			       status, COALESCE(skip_reason, ''), scan_ids, COALESCE(error, ''), created_at
			FROM campaign.runs
			WHERE campaign_id = $1
			ORDER BY scheduled_for DESC
			LIMIT $2`, campaignID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var r Run
			if err := rows.Scan(
				&r.ID, &r.TenantID, &r.CampaignID, &r.ScheduledFor, &r.StartedAt, &r.FinishedAt,
				&r.Status, &r.SkipReason, &r.ScanIDs, &r.Error, &r.CreatedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list campaign runs: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// scheduler.Store
// ---------------------------------------------------------------------------

// DueCampaigns returns enabled campaigns whose cursor has passed, across all
// tenants.
//
// ⚠ THE ONE CROSS-TENANT READ IN THIS SERVICE, and the reason it is a narrow
// SECURITY DEFINER function rather than BYPASSRLS is written out in
// migrations/campaign/0002_scheduler.sql. The columns it can return are fixed
// by the function signature: no component, no finding, no report.
func (s *Store) DueCampaigns(ctx context.Context, now time.Time, limit int) ([]scheduler.Campaign, error) {
	rows, err := s.pool.Raw().Query(ctx,
		`SELECT id, tenant_id, name, cron_expr, timezone,
		        project_ids, bom_types, report_levels, standards, formats, next_run_at
		 FROM campaign.due_campaigns($1, $2)`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("due campaigns: %w", err)
	}
	defer rows.Close()

	var out []scheduler.Campaign
	for rows.Next() {
		var c scheduler.Campaign
		if err := rows.Scan(
			&c.ID, &c.TenantID, &c.Name, &c.CronExpr, &c.Timezone,
			&c.ProjectIDs, &c.BOMTypes, &c.ReportLevels, &c.Standards, &c.Formats,
			&c.Cursor); err != nil {
			return nil, fmt.Errorf("scan due campaign: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClaimRun inserts the run row for one occurrence.
//
// ⚠ `ON CONFLICT DO NOTHING` RATHER THAN CATCHING 23505, and the difference is
// not stylistic. A unique violation ABORTS the surrounding transaction: every
// statement after it fails with "current transaction is aborted" until a
// rollback, so a loop over several occurrences would poison itself on the first
// already-claimed one. ON CONFLICT resolves in the statement, returns zero
// rows, and leaves the transaction usable.
//
// Zero rows means another instance claimed this occurrence first. That is the
// idempotency mechanism working — SUCCESS, not an error.
func (s *Store) ClaimRun(ctx context.Context, c scheduler.Campaign, at time.Time) (string, bool, error) {
	var runID string
	claimed := false

	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO campaign.runs (tenant_id, campaign_id, scheduled_for, status)
			VALUES ($1, $2, $3, 'pending')
			ON CONFLICT (campaign_id, scheduled_for) DO NOTHING
			RETURNING id`, c.TenantID, c.ID, at).Scan(&runID)

		if errors.Is(err, pgx.ErrNoRows) {
			return nil // claimed elsewhere
		}
		if err != nil {
			return err
		}
		claimed = true
		return nil
	})
	if err != nil {
		return "", false, fmt.Errorf("claim run: %w", err)
	}
	return runID, claimed, nil
}

// RecordSkipped writes a missed occurrence to run history.
//
// The same ON CONFLICT: two instances catching up after the same downtime both
// try to record the same skips, and the second one's no-op is correct.
func (s *Store) RecordSkipped(ctx context.Context, c scheduler.Campaign, at time.Time, reason string) error {
	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO campaign.runs
			    (tenant_id, campaign_id, scheduled_for, status, skip_reason, finished_at)
			VALUES ($1, $2, $3, 'skipped', $4, now())
			ON CONFLICT (campaign_id, scheduled_for) DO NOTHING`,
			c.TenantID, c.ID, at, reason)
		return err
	})
	if err != nil {
		return fmt.Errorf("record skipped run: %w", err)
	}
	return nil
}

// StartRun marks a claimed run as running with the scans it produced.
func (s *Store) StartRun(ctx context.Context, c scheduler.Campaign, runID string, scanIDs []string) error {
	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE campaign.runs
			SET status = 'running', started_at = now(), scan_ids = $2
			WHERE id = $1`, runID, scanIDs)
		return err
	})
	if err != nil {
		return fmt.Errorf("start run: %w", err)
	}
	return nil
}

// FailRun records a run that could not be dispatched.
func (s *Store) FailRun(ctx context.Context, c scheduler.Campaign, runID, cause string) error {
	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE campaign.runs
			SET status = 'failed', finished_at = now(), error = $2
			WHERE id = $1`, runID, cause)
		return err
	})
	if err != nil {
		return fmt.Errorf("fail run: %w", err)
	}
	return nil
}

// AdvanceCursor moves the campaign to its next occurrence.
func (s *Store) AdvanceCursor(ctx context.Context, c scheduler.Campaign, next, lastRun time.Time) error {
	var last *time.Time
	if !lastRun.IsZero() {
		last = &lastRun
	}

	err := s.pool.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE campaign.campaigns
			SET next_run_at = $2,
			    last_run_at = COALESCE($3::timestamptz, last_run_at)
			WHERE id = $1`, c.ID, next, last)
		return err
	})
	if err != nil {
		return fmt.Errorf("advance campaign cursor: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// firstOccurrence computes the next run strictly after `now`.
func firstOccurrence(cronExpr, timezone string, now time.Time) (time.Time, error) {
	spec, err := schedule.Parse(cronExpr)
	if err != nil {
		return time.Time{}, fmt.Errorf("cron %q: %w", cronExpr, err)
	}

	loc := time.UTC
	if timezone != "" {
		loc, err = time.LoadLocation(timezone)
		if err != nil {
			return time.Time{}, fmt.Errorf(
				"timezone %q is not in this host's zone database: %w", timezone, err)
		}
	}

	next, err := schedule.Next(spec, now, loc)
	if err != nil {
		return time.Time{}, err
	}
	return next.UTC(), nil
}

// FirstOccurrence is firstOccurrence for callers outside this package (the
// handler validates a schedule before writing it, so a customer gets a 400
// naming the field rather than a 500 from the scheduler eight hours later).
func FirstOccurrence(cronExpr, timezone string, now time.Time) (time.Time, error) {
	return firstOccurrence(cronExpr, timezone, now)
}
