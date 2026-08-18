package main

import (
	"context"
	"fmt"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/libs/go-shared/vault"
	"github.com/encorebom/encorebom/services/notification/internal/delivery"
	"github.com/encorebom/encorebom/services/notification/internal/handler"
	"github.com/encorebom/encorebom/services/notification/internal/store"
)

// deps holds this service's constructed dependencies.
//
// Return an error rather than exiting: a service that cannot reach its database
// must fail to START, not start and serve 500s while passing liveness.
type deps struct {
	cfg     *config.Service
	pool    *db.Pool
	issuer  *auth.Issuer
	vault   *vault.Client
	store   *store.Store
	handler *handler.Handler

	// delivery posts webhooks. It holds no secret: each delivery resolves one
	// from Vault moments before use.
	delivery *delivery.Client
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

	// ⚠ VAULT IS REQUIRED, NOT OPTIONAL. Every webhook signing secret lives
	// there. A service that started without it would accept subscriptions,
	// store them, and fail every delivery — after telling the customer their
	// webhook was configured.
	vaultClient, err := vault.New(vault.Config{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token.Reveal(),
		Mount:   cfg.Vault.Mount,
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open vault: %w", err)
	}

	notifyStore := store.New(pool)

	deliveryClient, err := delivery.New(delivery.Options{
		Secrets: vaultSecrets{vaultClient},
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build delivery client: %w", err)
	}

	return &deps{
		cfg:      cfg,
		pool:     pool,
		issuer:   issuer,
		vault:    vaultClient,
		store:    notifyStore,
		handler:  handler.New(notifyStore, vaultClient, time.Now),
		delivery: deliveryClient,
	}, nil
}

// vaultSecrets adapts the Vault client to delivery.Secrets.
//
// ⚠ THE REF IS RECONSTRUCTED FROM THE STORED PATH, NOT TRUSTED AS ONE. The
// vault client's Get re-derives the correct path from (tenant, kind, id) and
// compares — so a secret_ref that was tampered with in the database points at
// nothing rather than at another tenant's key.
type vaultSecrets struct{ client *vault.Client }

func (v vaultSecrets) Resolve(
	ctx context.Context, tenantID, subscriptionID, storedRef string,
) ([]byte, error) {
	data, err := v.client.Get(ctx, vault.Ref{
		TenantID: tenantID, Kind: vault.KindWebhookSecret, ID: subscriptionID,
	}, storedRef)
	if err != nil {
		return nil, err
	}
	secret, ok := data["secret"]
	if !ok {
		return nil, fmt.Errorf("the vault entry for subscription %s has no secret field", subscriptionID)
	}
	return []byte(secret), nil
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

// serviceMiddleware returns middleware specific to this service.
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
