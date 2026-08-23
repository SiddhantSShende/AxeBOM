package main

import (
	"context"

	"github.com/encorebom/encorebom/libs/go-shared/platform/health"
)

// registerHealthChecks wires this service's dependency probes.
//
//	Register()         critical   — failure removes the instance from the LB
//	RegisterOptional() non-critical — failure degrades, still serves traffic
//
// NATS and Docker are CRITICAL: without either, this service cannot fetch
// anything, and every scan in the system begins with a fetch. Reporting ready
// while unable to do its only job would let a deployment roll forward over a
// fleet that silently stalls every scan.
//
// Vault is OPTIONAL. A public repository needs no credential, so a Vault outage
// degrades the service to public-only rather than stopping it — and the jobs
// that do need a token fail individually, with a stated reason, instead of the
// whole fleet dropping out.
func registerHealthChecks(c *health.Checker, d *deps) {
	c.Register("nats", d.bus.Ping)
	c.Register("docker", func(ctx context.Context) error {
		return d.runner.Ping(ctx)
	})
	c.RegisterOptional("vault", d.vault.Ping)
	c.RegisterOptional("objectstore", func(ctx context.Context) error {
		return d.store.Ping(ctx)
	})
}
