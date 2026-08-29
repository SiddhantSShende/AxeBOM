package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/services/auth/internal/handler"
	"github.com/axebom/axebom/services/auth/internal/service"
	"github.com/axebom/axebom/services/auth/internal/store"
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
	issuer  *auth.Issuer
	handler *handler.Handler
	// identity guards the API-key management routes (routes.go), which are
	// authenticated the ZITADEL way like every other service — unlike issuer
	// above, which still backs this service's OWN pre-ZITADEL local-login
	// surface (register/login/refresh/invitations).
	identity *oidcauth.Guard
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	// db.Open refuses to return a pool if the role is a superuser or holds
	// BYPASSRLS — either would silently disable tenant isolation for every
	// query in the process.
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
		return nil, fmt.Errorf("token issuer: %w", err)
	}

	st := store.New(pool)
	svc := service.New(service.Config{
		Store:  st,
		Issuer: issuer,
		Argon:  auth.DefaultArgon2Params(),
	})

	gh := service.NewGitHubClient(service.GitHubConfig{
		ClientID:     cfg.Auth.GitHubClientID,
		ClientSecret: cfg.Auth.GitHubClientSecret.Reveal(),
	})
	if !gh.Enabled() {
		// Loud, not silent. A missing GitHub app is a legitimate configuration
		// for a self-hosted install, but it must never be discovered by a user
		// clicking a button that does nothing.
		slog.Warn("github sign-in is disabled: no client id/secret configured")
	}

	// Development is the ONLY place cookies drop Secure. A Secure cookie is
	// not sent over plain http, so local development on http://localhost could
	// not log in at all — but shipping cookies without Secure to anything
	// network-reachable puts the refresh token on the wire.
	insecureCookies := cfg.Env == config.EnvDevelopment

	h := handler.New(svc, gh, handler.Config{
		AllowInsecureCookies:     insecureCookies,
		FrontendURL:              cfg.Auth.FrontendURL,
		RefreshTTL:               cfg.Auth.RefreshTTL,
		GitHubRedirectURL:        cfg.Auth.GitHubRedirectURL,
		GitHubConnectRedirectURL: cfg.Auth.GitHubConnectRedirectURL,
	})

	// ⚠ A SIXTH SERVICE GAINS oidcauth. The other five replaced their own
	// local-JWT middleware with it (docs/STATE.md); this one keeps both,
	// side by side, because its existing routes still run on the local
	// issuer above and nothing here migrates them. Only the new API-key
	// routes (routes.go) use this guard.
	identity, err := oidcauth.Open(cfg.OIDC, pool)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("identity: %w", err)
	}

	return &deps{cfg: cfg, pool: pool, issuer: issuer, handler: h, identity: identity}, nil
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
	if d.pool != nil {
		// Give in-flight transactions a moment rather than cutting them off:
		// an interrupted audit write loses compliance evidence.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.pool.Ping(ctx)
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
