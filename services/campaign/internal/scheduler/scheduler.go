// Package scheduler fires due campaigns.
//
// ⚠ THE ADVISORY LOCK IS NOT WHAT PREVENTS A DOUBLE FIRE.
//
// It is tempting to read "leader election via a Postgres advisory lock" as the
// safety mechanism and stop there. It is not, and building on that belief
// produces a scheduler that duplicates scans in exactly the situations that
// matter most.
//
// A lock held over a network connection is a LEASE, and a lease can be believed
// by a holder who no longer has it. The leader stops the world for a GC pause,
// or its host is partitioned, or its TCP connection is reset by a middlebox and
// nobody notices for thirty seconds. Postgres drops the session, releases the
// advisory lock, and a second instance acquires it — legitimately. Now two
// processes each believe they are the leader, and the first one is about to
// wake up and dispatch. No amount of checking "am I still the leader?" fixes
// this: the check and the dispatch cannot be made atomic across a network.
//
// So the lock is a POLLING OPTIMISATION. It keeps eight replicas from each
// running the same query every thirty seconds. What actually prevents a
// duplicate scan is one line of DDL:
//
//	UNIQUE (campaign_id, scheduled_for)
//
// Dispatch inserts a run row first and acts only if the insert won. Two
// instances racing produce one row and one scan; the loser's conflict means
// "somebody else already claimed this occurrence", which is SUCCESS, not an
// error, and is counted as such rather than logged as a failure.
//
// The consequence worth stating plainly: this scheduler is CORRECT WITH THE
// LOCK REMOVED ENTIRELY. It would just do more redundant work. That is the
// property to preserve — if a future change makes correctness depend on
// leadership, the change is wrong.
//
// docs/phases/PHASE-14-campaigns-notifications.md, docs/01-DATA-MODEL.md §9
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/encorebom/encorebom/services/campaign/internal/schedule"
)

// TickInterval is how often the leader looks for due campaigns.
//
// Thirty seconds bounds how late a run can be. It is not a precision timer and
// must not be treated as one: a campaign scheduled for 02:30 fires somewhere in
// [02:30, 02:30:30), and `scheduled_for` records the SLOT rather than the
// firing instant so run history stays comparable across restarts.
const TickInterval = 30 * time.Second

// Campaign is the scheduling view of a campaign row.
//
// Deliberately narrow: the scheduler reads what it needs to decide WHEN, and
// the dimensions it passes through to the scan. It never reads report content,
// which is what lets the cross-tenant lookup in Store be a narrow function
// rather than a privilege escalation.
type Campaign struct {
	ID       string
	TenantID string
	Name     string

	CronExpr string
	// Timezone is an IANA name. An offset would be wrong twice a year.
	Timezone string

	ProjectIDs   []string
	BOMTypes     []string
	ReportLevels []string
	Standards    []string
	Formats      []string

	// Cursor is the point the schedule has been advanced to: the next
	// occurrence this campaign owes.
	//
	// ⚠ IT IS ALSO THE BACKFILL FLOOR, AND THAT IS DELIBERATE. Re-enabling a
	// campaign that was off for a month must not fire a month of missed runs.
	// Enabling sets the cursor to the next future occurrence, so there is
	// nothing behind it to catch up on — the rule falls out of the data instead
	// of needing an `enabled_at` column and a comparison somebody can forget.
	Cursor time.Time
}

// Location resolves the campaign's timezone.
//
// An unknown zone is an error, never a silent fall back to UTC: a campaign a
// customer set for 02:00 Asia/Kolkata that quietly runs at 02:00 UTC is off by
// five and a half hours, and nothing in the product would say so.
func (c Campaign) Location() (*time.Location, error) {
	if c.Timezone == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return nil, fmt.Errorf(
			"campaign %s has timezone %q, which this host's zone database does not know: %w",
			c.ID, c.Timezone, err)
	}
	return loc, nil
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

// Store is the scheduler's persistence.
type Store interface {
	// DueCampaigns returns enabled campaigns whose cursor has passed.
	//
	// ⚠ THE ONE CROSS-TENANT READ IN THIS SERVICE. A background scheduler has
	// no tenant to scope by — the same pre-tenant problem login and share links
	// have — and gets the same answer: one narrow SECURITY DEFINER function
	// returning scheduling columns only, never BYPASSRLS. Everything after this
	// call runs inside WithTenant.
	DueCampaigns(ctx context.Context, now time.Time, limit int) ([]Campaign, error)

	// ClaimRun inserts the run row for one occurrence.
	//
	// ⚠ claimed=false IS NOT AN ERROR. It means another instance inserted the
	// same (campaign_id, scheduled_for) first, which is the idempotency
	// mechanism working. Returning an error here would fill the log with
	// alarming lines describing correct behaviour, and an operator who learns
	// to ignore those will ignore a real one.
	ClaimRun(ctx context.Context, c Campaign, scheduledFor time.Time) (runID string, claimed bool, err error)

	// RecordSkipped writes a missed occurrence to run history.
	RecordSkipped(ctx context.Context, c Campaign, scheduledFor time.Time, reason string) error

	// StartRun marks a claimed run as running with the scans it produced.
	StartRun(ctx context.Context, c Campaign, runID string, scanIDs []string) error

	// FailRun records a run that could not be dispatched.
	FailRun(ctx context.Context, c Campaign, runID string, cause string) error

	// AdvanceCursor moves the campaign to its next occurrence.
	AdvanceCursor(ctx context.Context, c Campaign, next time.Time, lastRun time.Time) error
}

// Trigger starts the scans for one run.
type Trigger interface {
	Trigger(ctx context.Context, c Campaign, runID string, scheduledFor time.Time) ([]string, error)
}

// Lock is leader election.
//
// See the package comment: this is a polling optimisation. Acquire returning
// false must never be the only reason a correct dispatch does not happen.
type Lock interface {
	Acquire(ctx context.Context) (bool, error)
	Release(ctx context.Context) error
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

// Scheduler dispatches due campaigns.
type Scheduler struct {
	store   Store
	trigger Trigger
	lock    Lock
	log     *slog.Logger

	// batch bounds one tick. A tick that tries to dispatch ten thousand
	// campaigns holds the leader lock for minutes and delays everything behind
	// it; the remainder is simply picked up by the next tick thirty seconds
	// later, because the cursor was not advanced for them.
	batch int
}

// Options configures a Scheduler.
type Options struct {
	Store   Store
	Trigger Trigger
	Lock    Lock
	Logger  *slog.Logger
	Batch   int
}

// New builds a Scheduler.
func New(opts Options) (*Scheduler, error) {
	if opts.Store == nil {
		return nil, errors.New("scheduler needs a store")
	}
	if opts.Trigger == nil {
		return nil, errors.New("scheduler needs a trigger")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Batch <= 0 {
		opts.Batch = 200
	}
	return &Scheduler{
		store:   opts.Store,
		trigger: opts.Trigger,
		lock:    opts.Lock,
		log:     opts.Logger,
		batch:   opts.Batch,
	}, nil
}

// Result is what one tick did.
type Result struct {
	// Leader is false when another instance held the lock.
	Leader bool
	// Dispatched counts occurrences this instance actually fired.
	Dispatched int
	// Claimed counts occurrences another instance had already claimed. Not an
	// error; reported so the number is visible rather than invisible.
	Claimed int
	// Skipped counts missed occurrences recorded but not fired.
	Skipped int
	// Failed counts campaigns whose dispatch errored.
	Failed int
}

// Tick runs one scheduling pass.
//
// `now` is a parameter rather than a call to time.Now so that a test can place
// the clock on a real DST transition, and so a tick is a pure decision over an
// instant instead of something that drifts while it runs.
func (s *Scheduler) Tick(ctx context.Context, now time.Time) (Result, error) {
	var out Result

	if s.lock != nil {
		held, err := s.lock.Acquire(ctx)
		if err != nil {
			return out, fmt.Errorf("acquire leader lock: %w", err)
		}
		if !held {
			// Another instance is polling. Nothing to do, and NOT an error —
			// this is the expected state for every replica but one.
			return out, nil
		}
	}
	out.Leader = true

	campaigns, err := s.store.DueCampaigns(ctx, now, s.batch)
	if err != nil {
		return out, fmt.Errorf("find due campaigns: %w", err)
	}

	for _, c := range campaigns {
		res, err := s.dispatch(ctx, c, now)
		out.Dispatched += res.Dispatched
		out.Claimed += res.Claimed
		out.Skipped += res.Skipped

		if err != nil {
			// ⚠ ONE CAMPAIGN'S FAILURE DOES NOT ABANDON THE REST. A campaign
			// with an unparseable cron or a timezone this host does not know
			// would otherwise stop every other tenant's schedule — a
			// single-tenant data error becoming a platform outage.
			out.Failed++
			s.log.Error("campaign dispatch failed",
				"campaign_id", c.ID, "tenant_id", c.TenantID, "cause", err.Error())
			continue
		}
	}

	return out, nil
}

// dispatch handles one campaign's due occurrences.
func (s *Scheduler) dispatch(ctx context.Context, c Campaign, now time.Time) (Result, error) {
	var out Result

	spec, err := schedule.Parse(c.CronExpr)
	if err != nil {
		return out, fmt.Errorf("cron %q: %w", c.CronExpr, err)
	}
	loc, err := c.Location()
	if err != nil {
		return out, err
	}

	// CatchUp decides the whole missed-run policy: fire the most recent, record
	// the rest. See schedule.CatchUp for why neither "fire all" nor "fire none"
	// is acceptable.
	occurrences, err := schedule.CatchUp(spec, c.Cursor, now, loc)
	if err != nil {
		return out, fmt.Errorf("compute occurrences: %w", err)
	}
	if len(occurrences) == 0 {
		return out, nil
	}

	var lastFired time.Time

	for _, occ := range occurrences {
		if occ.Skipped {
			// ⚠ RECORDED, NOT DROPPED. The gap has to be visible in run
			// history — a compliance customer discovering at audit that two
			// days have no scan, with nothing in the product saying why, is the
			// failure this row prevents.
			if err := s.store.RecordSkipped(ctx, c, occ.ScheduledFor, occ.Reason); err != nil {
				return out, fmt.Errorf("record skipped occurrence: %w", err)
			}
			out.Skipped++
			continue
		}

		runID, claimed, err := s.store.ClaimRun(ctx, c, occ.ScheduledFor)
		if err != nil {
			return out, fmt.Errorf("claim run: %w", err)
		}
		if !claimed {
			// Another instance got there first. Correct behaviour.
			out.Claimed++
			lastFired = occ.ScheduledFor
			continue
		}

		scanIDs, err := s.trigger.Trigger(ctx, c, runID, occ.ScheduledFor)
		if err != nil {
			// ⚠ THE RUN ROW STAYS, MARKED FAILED. Deleting it would make the
			// occurrence claimable again, and the next tick would retry a
			// campaign that may have already started scans before erroring —
			// which is the duplicate the UNIQUE constraint exists to prevent.
			// A visible failed run is better than an invisible retry loop.
			if ferr := s.store.FailRun(ctx, c, runID, err.Error()); ferr != nil {
				s.log.Error("could not record a failed run",
					"campaign_id", c.ID, "run_id", runID, "cause", ferr.Error())
			}
			return out, fmt.Errorf("trigger scans: %w", err)
		}

		if err := s.store.StartRun(ctx, c, runID, scanIDs); err != nil {
			return out, fmt.Errorf("start run: %w", err)
		}
		out.Dispatched++
		lastFired = occ.ScheduledFor
	}

	// Advance the cursor past everything considered, fired or skipped.
	//
	// ⚠ FROM THE LAST OCCURRENCE, NOT FROM `now`. Advancing from the wall clock
	// would silently swallow any occurrence between the last slot and this
	// instant — on a slow tick, a minutely campaign would lose runs with no
	// trace. Advancing from the slot means the next tick sees them.
	final := occurrences[len(occurrences)-1].ScheduledFor
	next, err := schedule.Next(spec, final, loc)
	if err != nil {
		return out, fmt.Errorf("compute next occurrence: %w", err)
	}
	if err := s.store.AdvanceCursor(ctx, c, next, lastFired); err != nil {
		return out, fmt.Errorf("advance cursor: %w", err)
	}

	return out, nil
}

// Run ticks until the context is cancelled.
//
// The lock is released on the way out so a rolling deploy hands leadership over
// in milliseconds instead of waiting for a TCP timeout.
func (s *Scheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(TickInterval)
	defer ticker.Stop()

	defer func() {
		if s.lock == nil {
			return
		}
		// A fresh context: ctx is already cancelled by the time this runs, and
		// releasing the lock is exactly the work that must still happen.
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.lock.Release(releaseCtx); err != nil {
			s.log.Warn("could not release the leader lock; it will expire with the session",
				"cause", err.Error())
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			// ⚠ A TICK FAILURE IS LOGGED, NOT RETURNED. Returning would stop
			// the scheduler for the life of the process over one bad database
			// round trip; the next tick is thirty seconds away and will try
			// again.
			res, err := s.Tick(ctx, now.UTC())
			if err != nil {
				s.log.Error("scheduler tick failed", "cause", err.Error())
				continue
			}
			if res.Dispatched > 0 || res.Skipped > 0 || res.Failed > 0 {
				s.log.Info("scheduler tick",
					"dispatched", res.Dispatched,
					"claimed_elsewhere", res.Claimed,
					"skipped", res.Skipped,
					"failed", res.Failed)
			}
		}
	}
}
