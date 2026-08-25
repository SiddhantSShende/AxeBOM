package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/notification/internal/delivery"
	"github.com/axebom/axebom/services/notification/internal/handler"
	"github.com/axebom/axebom/services/notification/internal/mail"
	"github.com/axebom/axebom/services/notification/internal/store"
	"github.com/axebom/axebom/services/notification/internal/worker"
)

// deps holds this service's constructed dependencies.
//
// Return an error rather than exiting: a service that cannot reach its database
// must fail to START, not start and serve 500s while passing liveness.
type deps struct {
	cfg      *config.Service
	pool     *db.Pool
	bus      *bus.Bus
	identity *oidcauth.Guard
	vault    *vault.Client
	store    *store.Store
	handler  *handler.Handler

	// delivery posts webhooks. It holds no secret: each delivery resolves one
	// from Vault moments before use.
	delivery *delivery.Client
	mail     *mail.Sender

	consumer *worker.Consumer
	poller   *worker.Poller
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

	// NATS is REQUIRED. Every notify.> event this service will ever act on
	// arrives over it — a service that started without a broker would accept
	// subscriptions and deliver nothing, silently, forever.
	msgBus, err := bus.Connect(ctx, bus.Config{
		URL:  cfg.NATS.URL,
		Name: cfg.Name,
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect nats: %w", err)
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
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("open vault: %w", err)
	}

	notifyStore := store.New(pool)

	deliveryClient, err := delivery.New(delivery.Options{
		Secrets: vaultSecrets{vaultClient},
	})
	if err != nil {
		_ = msgBus.Close()
		pool.Close()
		return nil, fmt.Errorf("build delivery client: %w", err)
	}

	mailSender := mail.New(mail.Config{
		Host:     cfg.SMTP.Host,
		Port:     cfg.SMTP.Port,
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password.Reveal(),
		From:     cfg.SMTP.From,
	}, nil)

	attempter := worker.NewAttempter(notifyStore, deliveryClient, mailSender, nil, slog.Default())

	return &deps{
		cfg:      cfg,
		pool:     pool,
		bus:      msgBus,
		identity: identity,
		vault:    vaultClient,
		mail:     mailSender,
		consumer: worker.NewConsumer(msgBus, notifyStore, attempter, slog.Default()),
		poller:   worker.NewPoller(notifyStore, attempter, nil, slog.Default()),
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
	if d.bus != nil {
		_ = d.bus.Close()
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
	// ⚠ TWO WORKERS, ONE PROCESS. The consumer fans a notify.> event out to
	// its first delivery attempts; the poller retries whatever that left
	// pending, on its own clock — see internal/worker's package doc for why
	// they are not one mechanism. Both are started BEFORE the server so a
	// backlog begins draining at once, and both log rather than exit: an
	// instance that can still serve subscription CRUD is worth more than one
	// that dies because NATS or Postgres blinked.
	go func() {
		if err := d.consumer.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("the notification consumer stopped; events will not be delivered",
				"error", err)
		}
	}()
	go d.poller.Run(ctx)
}
