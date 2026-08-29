package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
	"github.com/axebom/axebom/services/webrecon/internal/fingerprint"
	"github.com/axebom/axebom/services/webrecon/internal/work"
)

// deps holds this service's constructed dependencies.
//
// ⚠ NO VAULT, AND THAT IS THE POINT (unlike services/fetcher/deps.go, its
// closest sibling). A url source is never authenticated — see
// project.web_sources' own migration comment — so there is no credential
// this process could ever need to hold. It has a Docker runner for exactly
// one reason: subfinder, the one third-party binary this service runs, and
// it needs network egress the way the fetcher's git clone does.
//
// It has no database pool either, for the same reason the fetcher has none:
// a url source's config (root_url, discovery_enabled, max_hosts) belongs to
// the project service's schema and is read over its service-only source
// endpoint, so this process cannot read — or corrupt — another service's
// tables.
type deps struct {
	cfg      *config.Service
	bus      *bus.Bus
	runner   *sandbox.DockerRunner
	store    *blob.Store
	resolver *projectsource.Client
	worker   *work.Worker
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	// NATS is REQUIRED. Every url-sourced scan begins with a webrecon job.
	b, err := bus.Connect(ctx, bus.Config{URL: cfg.NATS.URL, Name: cfg.Name})
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}

	// subfinder runs in a container — the same reasoning as the fetcher's
	// clone: it needs network egress, so it is sandboxed rather than trusted.
	runner, err := sandbox.NewDockerRunner(slog.Default())
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	if err := runner.Ping(ctx); err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("docker is unreachable, so subfinder cannot run: %w", err)
	}

	store, err := blob.Open(ctx, cfg.S3)
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("open object storage: %w", err)
	}

	// The credential this service presents to the project service — the
	// same machine-identity mechanism the fetcher uses, minus a Vault client:
	// this token only ever reads a url source's public config, never a
	// credential_ref.
	tokens, err := oidcauth.NewServiceTokenSource(oidcauth.ServiceTokenConfig{
		KeyPath:   cfg.OIDC.ServiceKeyPath,
		BaseURL:   cfg.OIDC.InternalURL,
		Issuer:    cfg.OIDC.Issuer,
		ProjectID: cfg.OIDC.ProjectID,
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("service credential: %w", err)
	}

	resolver, err := projectsource.New(projectsource.Options{
		BaseURL: cfg.Services.Project,
		Token:   tokens.Token,
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, fmt.Errorf("source resolver: %w", err)
	}

	worker, err := work.New(work.Options{
		Bus: b, Runner: runner, Store: store, Resolver: resolver,
		Signatures: fingerprint.EmbeddedSignatures,
		Log:        slog.Default(), Version: version,
	})
	if err != nil {
		_ = runner.Close()
		_ = b.Close()
		return nil, err
	}

	return &deps{
		cfg: cfg, bus: b, runner: runner, store: store,
		resolver: resolver, worker: worker,
	}, nil
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

// startBackground launches the webrecon consumer.
//
// Returns immediately, as the contract requires — the HTTP server must start
// so readiness can be probed. A consumer failure is logged rather than
// fatal: an instance that can still answer /readyz is worth more than one
// that exits because NATS blinked, and the bus reconnects forever by design.
func startBackground(ctx context.Context, d *deps) {
	go func() {
		if err := d.worker.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Error("webrecon consumer stopped", "cause", err.Error())
		}
	}()
}
