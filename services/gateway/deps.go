package main

import (
	"context"
	"fmt"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/services/gateway/internal/middleware"
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
//
// The gateway deliberately has NO database pool. It verifies tokens, limits
// rates and proxies; giving it a pool would invite domain logic to accumulate
// in the one component every request passes through.
type deps struct {
	cfg     *config.Service
	issuer  *auth.Issuer
	limiter *middleware.Limiter
}

// buildDeps constructs everything this service needs.
func buildDeps(_ context.Context, cfg *config.Service) (*deps, error) {
	// The gateway VERIFIES tokens; auth mints them. Both need the same key,
	// which is why it is in the shared config section. NewIssuer enforces the
	// minimum key length, so a too-short key stops the process here rather
	// than yielding brute-forceable tokens.
	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte(cfg.Auth.JWTSigningKey.Reveal()),
		Issuer:     cfg.Auth.JWTIssuer,
		AccessTTL:  cfg.Auth.AccessTTL,
		RefreshTTL: cfg.Auth.RefreshTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("token issuer: %w", err)
	}

	// TrustedProxyHeader is left EMPTY by default. Honouring X-Forwarded-For
	// on a directly-exposed gateway would let any client pick its own limiter
	// bucket — that is, opt out of rate limiting. Set it only once a proxy
	// that overwrites the header is actually in front.
	limiter := middleware.NewLimiter(middleware.RateLimitConfig{})

	return &deps{cfg: cfg, issuer: issuer, limiter: limiter}, nil
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
}

// serviceMiddleware returns the gateway's chain additions.
//
// RATE LIMITING RUNS BEFORE AUTHENTICATION, deliberately. Login is the
// endpoint most worth brute-forcing and it is unauthenticated by definition —
// a limiter placed after auth would never see the attempts it exists to stop.
func serviceMiddleware(d *deps) []httpx.Middleware {
	return []httpx.Middleware{middleware.RateLimit(d.limiter)}
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
