package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/libs/go-shared/platform/ratelimit"
	"github.com/axebom/axebom/libs/go-shared/reportsig"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/report/internal/handler"
	"github.com/axebom/axebom/services/report/internal/service"
	"github.com/axebom/axebom/services/report/internal/store"
	"github.com/axebom/axebom/services/report/internal/worker"
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
	cfg      *config.Service
	pool     *db.Pool
	blob     *blob.Store
	bus      *bus.Bus
	identity *oidcauth.Guard
	handler  *handler.Handler

	// consumer drains render jobs. main.go runs it alongside the HTTP server:
	// the same binary serves the API and renders, because a render is
	// in-process work and a separate deployment would double the operational
	// surface for no isolation gain.
	consumer *worker.Consumer

	// signer is nil when no signing key is configured. Reports still render;
	// they are stored unsigned and say so.
	signer *reportsig.VaultSigner

	sharedBuckets *ratelimit.Buckets
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	pool, err := db.Open(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Object storage is REQUIRED. Every rendered artifact lives there, so a
	// service that started without it would accept render requests and fail
	// every one of them at the last step, after doing all the work.
	blobStore, err := blob.Open(ctx, cfg.S3)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open object storage: %w", err)
	}

	// Identity: ZITADEL access tokens are verified against the published
	// key set and resolved to a local tenant UUID. See oidcauth.Guard.
	identity, err := oidcauth.Open(cfg.OIDC, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}

	// NATS is REQUIRED. Rendering is async by contract, so a service that
	// started without a broker would accept every render request and queue none
	// — the customer sees `queued` forever, which looks like a slow worker.
	msgBus, err := bus.Connect(ctx, bus.Config{
		URL:  cfg.NATS.URL,
		Name: cfg.Name,
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect nats: %w", err)
	}

	signer := buildSigner(ctx, cfg)

	st := store.New(pool)
	svc := service.New(st, blobStore, worker.NewPublisher(msgBus, nil), slog.Default())

	var renderSigner worker.Signer
	if signer != nil {
		renderSigner = signer
	}

	return &deps{
		cfg:      cfg,
		pool:     pool,
		blob:     blobStore,
		bus:      msgBus,
		identity: identity,
		handler:  handler.New(svc, nil),
		signer:   signer,
		consumer: worker.NewConsumer(msgBus, worker.New(
			svc, st, blobStore, renderSigner,
			busNotifier{msgBus}, cfg.Auth.FrontendURL, slog.Default(),
		), slog.Default()),
		sharedBuckets: ratelimit.New(nil),
	}, nil
}

// busNotifier adapts bus.Bus to worker.Notifier.
type busNotifier struct{ bus *bus.Bus }

// Publish sends a notify.> event with the report id as the dedup key — a
// report row transitions to `ready` exactly once, so a crash-retry that
// re-runs Worker.Render for an already-finished report must not fan the
// same notification out twice.
func (n busNotifier) Publish(ctx context.Context, evt events.NotifyEventV1) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("encode notify event: %w", err)
	}
	return n.bus.Publish(ctx, evt.Subject(), evt.ReportID, body)
}

// buildSigner wires Vault Transit, or returns nil.
//
// ⚠ A MISSING SIGNING KEY DEGRADES LOUDLY AND NEVER SILENTLY.
//
// Refusing to start would turn a signing-key misconfiguration into a total
// reporting outage, and reports are useful unsigned. But an unsigned report
// that looks signed is worse than either, so the degradation is: WARN at
// startup, `signing_key_id` empty on the row, and no signature endpoint for
// that report. Nothing ever fabricates a local key in production — see
// reportsig.LocalSigner, whose key id carries `insecure-local:` precisely so a
// development signature cannot be mistaken for this.
func buildSigner(ctx context.Context, cfg *config.Service) *reportsig.VaultSigner {
	keyName := cfg.Report.SigningKey
	if keyName == "" {
		slog.Warn("no report signing key configured; reports will be stored unsigned",
			"hint", "set REPORT_SIGNING_KEY to a Vault Transit ed25519 key name")
		return nil
	}

	transit, err := vault.NewTransit(vault.TransitConfig{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token.Reveal(),
		Mount:   cfg.Report.TransitMount,
	})
	if err != nil {
		slog.Warn("vault transit is not configured; reports will be stored unsigned",
			"cause", err.Error())
		return nil
	}

	signer, err := reportsig.NewVaultSigner(ctx, transit, keyName)
	if err != nil {
		slog.Warn("the report signer could not be built; reports will be stored unsigned",
			"cause", err.Error())
		return nil
	}

	// ⚠ THE KEY IS READ AT STARTUP, and a wrong TYPE is fatal to signing.
	//
	// A transit mount can hold RSA and ECDSA keys. Pointing the report signer at
	// one produces signatures nothing in the published verification procedure
	// can check — and we would not find out until a customer ran
	// `axebom verify`. Better to know now and store unsigned.
	if _, _, err := signer.PublicKey(); err != nil {
		slog.Warn("the configured signing key is unusable; reports will be stored unsigned",
			"key", keyName, "cause", err.Error())
		return nil
	}

	return signer
}

// PublicKey returns the published verification key, or nil.
func (d *deps) PublicKey() (ed25519.PublicKey, string, error) {
	if d.signer == nil {
		return nil, "", fmt.Errorf("no signing key is configured")
	}
	return d.signer.PublicKey()
}

// sharedLimiter rate-limits the one unauthenticated route by client address.
//
// ⚠ EVERY OTHER ROUTE IS BOUNDED BY A TOKEN THAT HAD TO BE ISSUED. This one is
// reachable by anyone with the URL, so without a limit it is a free oracle: a
// stranger can probe tokens as fast as the network allows, and each probe costs
// us a database round trip and an audit row.
//
// The limit does not make a 256-bit token guessable — nothing does. What it
// does is stop the endpoint being an amplifier and bound the audit-log volume a
// stranger can force us to write.
//
// The budget is deliberately generous per address: a legitimate holder may open
// the link, retry a failed download and share it with a colleague behind the
// same NAT.
func (d *deps) sharedLimiter(next http.Handler) http.Handler {
	const (
		rate  = 1.0 // sustained requests per second, per address
		burst = 20
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "shared|" + httpx.ClientIP(r)
		ok, wait := d.sharedBuckets.Allow(key, rate, burst)
		if !ok {
			// Retry-After is required: without it a client backs off by
			// guessing, and one that guesses badly looks like an attacker.
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
			w.Header().Set("Cache-Control", "no-store")
			errs.Write(w, r, errs.Newf(errs.RateLimitExceeded,
				"too many requests; retry in %d seconds", int(wait.Seconds())))
			return
		}
		next.ServeHTTP(w, r)
	})
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
	// ⚠ THE RENDER CONSUMER RUNS ALONGSIDE THE HTTP SERVER, IN THIS PROCESS.
	//
	// A render is in-process work of seconds, not a sandboxed container, so a
	// separate deployment would double the operational surface for no isolation
	// gain — and would need its own copy of the store, the blob client and the
	// signer.
	//
	// It is started BEFORE the server so a queued backlog begins draining at
	// once, and its failure is LOGGED rather than fatal: an instance that can
	// still serve downloads and metadata is worth more than one that exits
	// because NATS blinked. The reaper-style consequence — reports sitting at
	// `queued` — is visible on the row, which is where an operator looks.
	go func() {
		if err := d.consumer.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("the render consumer stopped; queued reports will not render",
				"error", err)
		}
	}()
}
