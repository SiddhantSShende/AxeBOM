package main

import (
	"context"
	"fmt"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/services/comment/internal/handler"
	"github.com/axebom/axebom/services/comment/internal/store"
)

// deps holds this service's constructed dependencies.
//
// Just Postgres and identity — no Vault (comments hold no secret) and no NATS
// bus (nothing downstream needs to react to a comment being posted; Phase 14
// owns notification delivery). This is deliberately the simplest deps.go of
// any service that talks to a database — see services/notification/deps.go
// for what this would look like WITH the extra machinery a webhook-delivering
// service needs, none of which applies here.
//
// Return an error rather than exiting: a service that cannot reach its database
// must fail to START, not start and serve 500s while passing liveness.
type deps struct {
	cfg      *config.Service
	pool     *db.Pool
	identity *oidcauth.Guard
	handler  *handler.Handler
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Identity: ZITADEL access tokens are verified against the published
	// key set and resolved to a local tenant UUID. See oidcauth.Guard.
	identity, err := oidcauth.Open(cfg.OIDC, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}

	commentStore := store.NewStore(pool)

	return &deps{
		cfg:      cfg,
		pool:     pool,
		identity: identity,
		handler:  handler.New(commentStore),
	}, nil
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
	if d.pool != nil {
		d.pool.Close()
	}
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
// Nothing to start: this service has no consumer, no scheduler, no reaper.
// ctx is cancelled on shutdown; the no-op is deliberate, not a placeholder
// waiting for a later phase.
func startBackground(ctx context.Context, d *deps) {
	_, _ = ctx, d
}
