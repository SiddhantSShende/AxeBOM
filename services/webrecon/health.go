package main

import (
	"context"

	"github.com/axebom/axebom/libs/go-shared/platform/health"
)

// registerHealthChecks wires this service's dependency probes.
//
//	Register()         critical   — failure removes the instance from the LB
//	RegisterOptional() non-critical — failure degrades, still serves traffic
//
// NATS and Docker are CRITICAL: without either, this service cannot
// discover or fingerprint anything, and every url-sourced scan begins with
// a webrecon job. Object storage is OPTIONAL by the same reasoning the
// fetcher's own comment gives for its store check — degrading is more
// useful than refusing to serve at all.
func registerHealthChecks(c *health.Checker, d *deps) {
	c.Register("nats", d.bus.Ping)
	c.Register("docker", func(ctx context.Context) error {
		return d.runner.Ping(ctx)
	})
	c.RegisterOptional("objectstore", func(ctx context.Context) error {
		return d.store.Ping(ctx)
	})
}
