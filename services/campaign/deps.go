package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/libs/go-shared/platform/leader"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
	"github.com/axebom/axebom/services/campaign/internal/handler"
	"github.com/axebom/axebom/services/campaign/internal/scheduler"
	"github.com/axebom/axebom/services/campaign/internal/store"
	"github.com/axebom/axebom/services/campaign/internal/trigger"
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
	cfg      *config.Service
	pool     *db.Pool
	bus      *bus.Bus
	identity *oidcauth.Guard
	store    *store.Store
	handler  *handler.Handler

	// tokens mints this service's own credential for calling the scan service.
	// Separate from identity: verifying an inbound token and presenting an
	// outbound one are different capabilities, and only two services in the
	// fleet need the second.
	tokens *oidcauth.ServiceTokenSource

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

	// Identity: ZITADEL access tokens are verified against the published key
	// set and resolved to a local tenant UUID. See oidcauth.Guard.
	identity, err := oidcauth.Open(cfg.OIDC, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}

	// NATS is REQUIRED. Without it a campaign.failed notification is simply
	// never published — no different, correctness-wise, than the reaper's own
	// event stream being advisory (docs/02-CONTRACTS.md §2), but a service
	// that silently started without the broker it needs would fail every
	// notification instead of failing loudly once at startup.
	msgBus, err := bus.Connect(ctx, bus.Config{
		URL:  cfg.NATS.URL,
		Name: cfg.Name,
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect nats: %w", err)
	}

	tokens, err := oidcauth.NewServiceTokenSource(oidcauth.ServiceTokenConfig{
		KeyPath:   cfg.OIDC.ServiceKeyPath,
		BaseURL:   cfg.OIDC.InternalURL,
		Issuer:    cfg.OIDC.Issuer,
		ProjectID: cfg.OIDC.ProjectID,
	})
	if err != nil {
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("service credential: %w", err)
	}

	campaignStore := store.New(pool)

	// The campaign cannot assert a project's source kind and must not guess
	// it — CreateScan accepts only git/upload/image/url, and this request used
	// to carry none. projectsource is the shared client the fetcher and
	// webrecon already resolve through.
	sourceResolver, err := projectsource.New(projectsource.Options{
		BaseURL: cfg.Services.Project,
		Token:   tokens.Token,
	})
	if err != nil {
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("source resolver: %w", err)
	}

	scanTrigger, err := trigger.New(trigger.Options{
		BaseURL:  cfg.Services.ScanOrchestrator,
		Token:    tokens.Token,
		Resolver: sourceResolver,
	})
	if err != nil {
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("build scan trigger: %w", err)
	}

	lock, err := leader.NewLock(pool, leader.CampaignScheduler)
	if err != nil {
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("build leader lock: %w", err)
	}

	sched, err := scheduler.New(scheduler.Options{
		Store:       campaignStore,
		Trigger:     scanTrigger,
		Lock:        lock,
		Logger:      slog.Default(),
		Notifier:    busNotifier{msgBus},
		FrontendURL: cfg.Auth.FrontendURL,
	})
	if err != nil {
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("build scheduler: %w", err)
	}

	return &deps{
		cfg:       cfg,
		pool:      pool,
		bus:       msgBus,
		identity:  identity,
		tokens:    tokens,
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
	if d.bus != nil {
		_ = d.bus.Close()
	}
	if d.pool != nil {
		d.pool.Close()
	}
}

// busNotifier adapts bus.Bus to scheduler.Notifier.
type busNotifier struct{ bus *bus.Bus }

func (n busNotifier) Publish(ctx context.Context, dedupKey string, evt events.NotifyEventV1) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("encode notify event: %w", err)
	}
	return n.bus.Publish(ctx, evt.Subject(), dedupKey, body)
}

// serviceMiddleware returns middleware specific to this service, appended
// after the shared chain and therefore running inside it.
func serviceMiddleware(d *deps) []httpx.Middleware {
	_ = d
	return nil
}

// startBackground launches this service's long-running background workers.
//
// GENERATED SCAFFOLD, then hand-edited. Written only if absent.
//
// Called after buildDeps and before the HTTP server starts. Implementations
// launch their own goroutines and RETURN — this must not block, or the service
// never begins serving. ctx is cancelled on shutdown.
//
// A worker's failure belongs in a log, not in an exit: an instance that can
// still serve HTTP is worth more than one that dies because NATS blinked.
func startBackground(ctx context.Context, d *deps) {
	// ⚠ EVERY INSTANCE RUNS THE SCHEDULER; ONLY THE LOCK HOLDER POLLS.
	//
	// The alternative — a separate "scheduler" deployment — is one more thing to
	// deploy, one more thing to forget to deploy, and a single point of failure
	// with no automatic successor. Here, if the leader dies another instance
	// takes the advisory lock on its next tick.
	//
	// Its failure is LOGGED rather than fatal: an instance that can still serve
	// campaign CRUD is worth more than one that exits because a tick failed, and
	// leadership moves to a healthy instance either way.
	go func() {
		if err := d.scheduler.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("the campaign scheduler stopped; due campaigns will not fire "+
				"from this instance", "error", err)
		}
	}()
}
