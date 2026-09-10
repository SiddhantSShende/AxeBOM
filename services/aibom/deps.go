package main

import (
	"context"
	"fmt"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/services/aibom/internal/handler"
	"github.com/axebom/axebom/services/aibom/internal/store"
)

// deps holds this service's constructed dependencies.
//
// Postgres and identity, and nothing else. No Vault: this service holds no
// secret — the two consent switches it records are decisions, not credentials,
// and turning one on grants no access to anything today. No NATS: nothing
// downstream reacts to a person classifying a model, and the normalize consumer
// reads `aibom.model_user_values` directly at write time rather than being told.
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

	identity, err := oidcauth.Open(cfg.OIDC, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}

	return &deps{
		cfg:      cfg,
		pool:     pool,
		identity: identity,
		handler:  handler.New(store.NewStore(pool)),
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
// None: authentication and authorization are mounted PER ROUTE in routes.go, so
// the permission is declared next to the handler it guards rather than inferred
// from a chain somebody has to remember to read.
func serviceMiddleware(d *deps) []httpx.Middleware {
	_ = d
	return nil
}

// startBackground launches this service's long-running background workers.
//
// None. Every one of this service's writes is a person pressing a button.
func startBackground(ctx context.Context, d *deps) {
	_, _ = ctx, d
}
