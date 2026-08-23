package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/bus"
	"github.com/encorebom/encorebom/libs/go-shared/platform/blob"
	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/libs/go-shared/sandbox"
	"github.com/encorebom/encorebom/libs/go-shared/vault"
	"github.com/encorebom/encorebom/services/fetcher/internal/source"
	"github.com/encorebom/encorebom/services/fetcher/internal/work"
)

// deps holds this service's constructed dependencies.
//
// ⚠ THIS IS THE ONLY SERVICE THAT HOLDS A GIT CREDENTIAL (ADR-0008).
//
// It therefore has the widest dependency set in the fleet — Vault, object
// storage, a Docker runner and the bus — and, deliberately, NO HTTP surface
// beyond health. Nothing routes to it from the gateway: work arrives only over
// a queue. A service holding repository tokens should not also be reachable
// from a browser.
//
// It has no database pool either. The repository connection belongs to the
// project service's schema and is read over its service-only source endpoint,
// so this process cannot read (or corrupt) another service's tables.
type deps struct {
	cfg      *config.Service
	bus      *bus.Bus
	runner   *sandbox.DockerRunner
	store    *blob.Store
	vault    *vault.Client
	resolver *source.Client
	worker   *work.Worker
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	// NATS is REQUIRED. Every scan begins with a fetch job, so a fetcher that
	// starts without the bus is a fetcher that silently stalls every scan.
	b, err := bus.Connect(ctx, bus.Config{URL: cfg.NATS.URL, Name: cfg.Name})
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}

	// The clone runs in a container. Same policy as any engine except that it
	// MUST reach the network — see fetcher.FetcherPolicy, which names that
	// exception rather than quietly relaxing the whole policy.
	runner, err := sandbox.NewDockerRunner(slog.Default())
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	if err := runner.Ping(ctx); err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("docker is unreachable, so no clone can run: %w", err)
	}

	store, err := blob.Open(ctx, cfg.S3)
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("open object storage: %w", err)
	}

	vaultClient, err := vault.New(vault.Config{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token.Reveal(),
		Mount:   cfg.Vault.Mount,
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("vault client: %w", err)
	}

	// Mints its own service token per request. Two minutes, per tenant: a
	// long-lived shared token would be a standing credential in the one process
	// that must not leak one.
	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte(cfg.Auth.JWTSigningKey.Reveal()),
		Issuer:     cfg.Auth.JWTIssuer,
		AccessTTL:  cfg.Auth.AccessTTL,
		RefreshTTL: cfg.Auth.RefreshTTL,
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("token issuer: %w", err)
	}

	resolver, err := source.New(source.Options{
		BaseURL: cfg.Services.Project,
		Token: func(_ context.Context, tenantID string) (string, error) {
			return issuer.MintService(cfg.Name, tenantID)
		},
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("source resolver: %w", err)
	}

	worker, err := work.New(work.Options{
		Bus:      b,
		Runner:   runner,
		Store:    store,
		Resolver: resolver,
		Secrets:  vaultClient,
		Log:      slog.Default(),
		Version:  version,
		// Identical to the path the compose bind mount uses on both sides, so
		// the clone is visible to the daemon when the archive step reads it.
		WorkspaceRoot: workspaceRoot(),
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, err
	}

	return &deps{
		cfg: cfg, bus: b, runner: runner, store: store,
		vault: vaultClient, resolver: resolver, worker: worker,
	}, nil
}

// workspaceRoot is where clones land before archiving.
//
// Shared with the scan workers so a single bind mount serves both, and read
// from the environment because the host and container paths MUST be identical:
// engines and clones run as sibling containers, and the daemon resolves every
// mount path against the host filesystem, not against this container.
func workspaceRoot() string {
	if v := os.Getenv("ENCOREBOM_WORKSPACE_ROOT"); v != "" {
		return v
	}
	return "/var/lib/encorebom/workspaces"
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
	if d.runner != nil {
		_ = d.runner.Close()
	}
	if d.bus != nil {
		_ = d.bus.Close()
	}
}

// serviceMiddleware returns this service's chain additions.
func serviceMiddleware(_ *deps) []httpx.Middleware { return nil }

// startBackground launches the fetch consumer.
//
// Returns immediately, as the contract requires — the HTTP server must start so
// readiness can be probed. A consumer failure is logged rather than fatal: an
// instance that can still answer /readyz is worth more than one that exits
// because NATS blinked, and the bus reconnects forever by design.
func startBackground(ctx context.Context, d *deps) {
	go func() {
		if err := d.worker.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Error("fetch consumer stopped", "cause", err.Error())
		}
	}()
}
