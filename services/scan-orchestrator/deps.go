package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/bus"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/handler"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/orchestr"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/policy"
)

// deps holds this service's constructed dependencies.
//
// GENERATED SCAFFOLD, then hand-edited. Written only if absent.
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
	bus     *bus.Bus
	store   *orchestr.Store
	orch    *orchestr.Orchestrator
	reaper  *orchestr.Reaper
	issuer  *auth.Issuer
	handler *handler.Handler
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// NATS is REQUIRED. This service's entire job is publishing and consuming
	// jobs; starting without it would accept scans it can never dispatch.
	b, err := bus.Connect(ctx, bus.Config{URL: cfg.NATS.URL, Name: cfg.Name})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}

	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte(cfg.Auth.JWTSigningKey.Reveal()),
		Issuer:     cfg.Auth.JWTIssuer,
		AccessTTL:  cfg.Auth.AccessTTL,
		RefreshTTL: cfg.Auth.RefreshTTL,
	})
	if err != nil {
		_ = b.Close()
		pool.Close()
		return nil, fmt.Errorf("token issuer: %w", err)
	}

	registry := policy.DefaultRegistry()
	store := orchestr.NewStore(pool)
	orch := orchestr.New(orchestr.Config{
		Store: store, Bus: b, Registry: registry,
		ArtifactPrefix: "s3://" + cfg.S3.Bucket,
	})

	reaper := orchestr.NewReaper(orchestr.ReaperConfig{
		Pool: pool, Store: store, Log: slog.Default(),
	})

	return &deps{
		cfg: cfg, pool: pool, bus: b, store: store, orch: orch,
		reaper: reaper, issuer: issuer,
		handler: handler.New(orch, store, b, registry),
	}, nil
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
	if d.bus != nil {
		// Drain rather than close, so in-flight publishes complete. A dropped
		// job publish means a scan that was accepted and never dispatched.
		_ = d.bus.Close()
	}
	if d.pool != nil {
		d.pool.Close()
	}
}

// StartBackground launches this service's long-running loops.
//
// Called from registerRoutes, which is the preserved hook that runs once at
// startup — main.go is regenerated and must not be hand-edited.
//
// The reaper runs in EVERY instance and does work only when it holds the
// advisory lock. That is deliberate: there is no separate reaper deployment to
// forget to deploy, and if the leader dies another instance picks the lock up
// on its next tick.
func (d *deps) StartBackground(ctx context.Context) {
	go func() {
		if err := d.reaper.Run(ctx); err != nil {
			slog.Error("reaper stopped", "cause", err.Error())
		}
	}()

	// The result loop: fetch results fan out, engine results aggregate.
	go func() {
		if err := d.orch.ConsumeResults(ctx); err != nil {
			slog.Error("result consumer stopped", "cause", err.Error())
		}
	}()
}

// serviceMiddleware returns middleware specific to this service, appended
// after the shared chain and therefore running inside it.
//
// Most services need none: authentication and authorization are mounted PER
// ROUTE in routes.go, so the permission is declared next to the handler it
// guards rather than inferred from a chain somebody has to remember to read.
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
	_, _ = ctx, d
}
