package main

import (
	"context"

	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
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
	cfg *config.Service
}

// buildDeps constructs everything this service needs.
// once it opens a pool, and changing the signature later would touch main.go
// in all eight services at once.
//
//nolint:unparam // the error is the CONTRACT: every service returns a real one
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	// Phase 9 adds: pool, err := db.Open(ctx, cfg.Postgres)
	_ = ctx
	return &deps{cfg: cfg}, nil
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
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
