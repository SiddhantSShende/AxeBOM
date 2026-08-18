package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/libs/go-shared/platform/leader"
	"github.com/encorebom/encorebom/services/campaign/internal/handler"
	"github.com/encorebom/encorebom/services/campaign/internal/scheduler"
	"github.com/encorebom/encorebom/services/campaign/internal/store"
	"github.com/encorebom/encorebom/services/campaign/internal/trigger"
)

// deps holds this service's constructed dependencies.
//
// One place where every dependency is built and one place where each is torn
// down. main.go calls buildDeps exactly once and hands the result to both
// registerHealthChecks and registerRoutes, so a service can never end up with
// two connection pools or a route holding a handle nothing closes.
//
// Return an error rather than exiting: a service that cannot reach its database
// must fail to START, not start and serve 500s while passing liveness.
type deps struct {
	cfg     *config.Service
	pool    *db.Pool
	issuer  *auth.Issuer
	store   *store.Store
	handler *handler.Handler

	// scheduler ticks alongside the HTTP server. Every instance runs it; only
	// the advisory-lock holder polls. That is deliberate — there is no separate
	// "scheduler deployment" to forget to deploy, and if the leader dies
	// another instance takes over on its next tick.
	scheduler *scheduler.Scheduler
	lock      *leader.Lock
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte(cfg.Auth.JWTSigningKey.Reveal()),
		Issuer:     cfg.Auth.JWTIssuer,
		AccessTTL:  cfg.Auth.AccessTTL,
		RefreshTTL: cfg.Auth.RefreshTTL,
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build token issuer: %w", err)
	}

	campaignStore := store.New(pool)

	scanTrigger, err := trigger.New(trigger.Options{
		BaseURL: cfg.Services.ScanOrchestrator,
		Token: func(_ context.Context, tenantID string) (string, error) {
			return issuer.MintService(serviceName, tenantID)
		},
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build scan trigger: %w", err)
	}

	lock, err := leader.NewLock(pool, leader.CampaignScheduler)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build leader lock: %w", err)
	}

	sched, err := scheduler.New(scheduler.Options{
		Store:   campaignStore,
		Trigger: scanTrigger,
		Lock:    lock,
		Logger:  slog.Default(),
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build scheduler: %w", err)
	}

	return &deps{
		cfg:       cfg,
		pool:      pool,
		issuer:    issuer,
		store:     campaignStore,
		handler:   handler.New(campaignStore, runNowAdapter{campaignStore, scanTrigger}, time.Now),
		scheduler: sched,
		lock:      lock,
	}, nil
}

// runNowAdapter turns a manual trigger into the same claim-then-dispatch path a
// scheduled run takes.
//
// ⚠ IT GOES THROUGH ClaimRun, NOT STRAIGHT TO THE SCAN SERVICE. A manual
// trigger that bypassed the run table would produce scans with no run row —
// invisible in run history, and un-deduplicated against a tick landing on the
// same instant.
type runNowAdapter struct {
	store   *store.Store
	trigger *trigger.Trigger
}

func (a runNowAdapter) RunNow(
	ctx context.Context, tenantID, campaignID string, at time.Time,
) (string, []string, error) {
	c, err := a.store.Get(ctx, tenantID, campaignID)
	if err != nil {
		return "", nil, err
	}

	sc := scheduler.Campaign{
		ID: c.ID, TenantID: c.TenantID, Name: c.Name,
		CronExpr: c.CronExpr, Timezone: c.Timezone,
		ProjectIDs: c.ProjectIDs, BOMTypes: c.BOMTypes,
		ReportLevels: c.ReportLevels, Standards: c.Standards, Formats: c.Formats,
	}

	// The occurrence is the current instant truncated to the second, so two
	// clicks in the same second produce one run rather than two.
	occurrence := at.UTC().Truncate(time.Second)

	runID, claimed, err := a.store.ClaimRun(ctx, sc, occurrence)
	if err != nil {
		return "", nil, err
	}
	if !claimed {
		return "", nil, fmt.Errorf("this campaign was already triggered for %s",
			occurrence.Format(time.RFC3339))
	}

	scanIDs, err := a.trigger.Trigger(ctx, sc, runID, occurrence)
	if err != nil {
		// The started scans are recorded before the failure is reported: they
		// are running regardless of what this call returns.
		if len(scanIDs) > 0 {
			_ = a.store.StartRun(ctx, sc, runID, scanIDs)
		}
		_ = a.store.FailRun(ctx, sc, runID, err.Error())
		return runID, scanIDs, err
	}

	if err := a.store.StartRun(ctx, sc, runID, scanIDs); err != nil {
		return runID, scanIDs, err
	}
	return runID, scanIDs, nil
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
	if d.lock != nil {
		// ⚠ RELEASED BEFORE THE POOL CLOSES. The advisory lock lives on a
		// connection borrowed from that pool; closing the pool first would drop
		// the lock anyway, but noisily, and a rolling deploy would hand
		// leadership over on a TCP timeout instead of immediately.
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.lock.Release(releaseCtx); err != nil {
			slog.Warn("could not release the scheduler lock", "cause", err.Error())
		}
	}
	if d.pool != nil {
		d.pool.Close()
	}
}

// serviceMiddleware returns middleware specific to this service, appended
// after the shared chain and therefore running inside it.
func serviceMiddleware(d *deps) []httpx.Middleware {
	_ = d
	return nil
}
