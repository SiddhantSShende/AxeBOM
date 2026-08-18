package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/platform/blob"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/libs/go-shared/vault"
	"github.com/encorebom/encorebom/services/project/internal/github"
	"github.com/encorebom/encorebom/services/project/internal/handler"
	"github.com/encorebom/encorebom/services/project/internal/service"
	"github.com/encorebom/encorebom/services/project/internal/store"
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
	blob    *blob.Store
	vault   *vault.Client
	issuer  *auth.Issuer
	handler *handler.Handler
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Object storage is REQUIRED, not optional. Uploads are one of the two
	// registration paths, and a service that starts without storage would
	// accept a project and then fail every upload against it.
	blobStore, err := blob.Open(ctx, cfg.S3)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open object storage: %w", err)
	}

	// Vault is likewise required: a private repository connection cannot be
	// created without somewhere safe to put the token, and the one thing this
	// service must never do is fall back to storing it in Postgres.
	vaultClient, err := vault.New(vault.Config{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token.Reveal(),
		Mount:   cfg.Vault.Mount,
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("vault client: %w", err)
	}
	if err := vaultClient.Ping(ctx); err != nil {
		// Warn rather than refuse to start: PUBLIC repositories and uploads
		// work without Vault, and taking the whole service down would turn a
		// credential-store outage into a total outage. Connecting a PRIVATE
		// repository fails loudly at the point of use.
		slog.Warn("vault is not reachable; connecting private repositories will fail",
			"cause", err.Error(), "address", cfg.Vault.Address)
	}

	// The project service VERIFIES access tokens; auth mints them.
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

	svc := service.New(service.Config{
		Store: store.New(pool),
		Blob:  blobStore,
		Vault: vaultClient,
	})

	return &deps{
		cfg: cfg, pool: pool, blob: blobStore, vault: vaultClient, issuer: issuer,
		handler: handler.New(svc, github.New(github.Config{})),
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
