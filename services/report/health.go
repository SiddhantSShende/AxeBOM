package main

import (
	"context"

	"github.com/axebom/axebom/libs/go-shared/platform/health"
)

// registerHealthChecks wires this service's dependency probes.
//
// GENERATED SCAFFOLD, then hand-edited. Written only if absent.
//
// Read health's package doc before adding anything here. The short version:
//
//	Register()         critical   — failure removes the instance from the LB
//	RegisterOptional() non-critical — failure degrades, still serves traffic
//
// Nothing here affects /healthz. Liveness performs no I/O by design: a database
// blip that fails liveness gets the entire fleet killed and turns a short
// outage into a long one.
func registerHealthChecks(c *health.Checker, d *deps) {
	// ⚠ CRITICAL. Every route in this service reads a report row, and without
	// Postgres there is no tenant scope either — RLS fails closed, so the
	// service would answer every request with an error that reads like a bug.
	c.Register("postgres", func(ctx context.Context) error {
		return d.pool.Ping(ctx)
	})

	// ⚠ ALSO CRITICAL, unlike in most services. Object storage is where every
	// rendered artifact lives: without it downloads fail and renders cannot
	// complete, which is the whole of what this service does. Marking it
	// optional would keep an instance in the load balancer that can serve only
	// metadata.
	c.Register("object-storage", func(ctx context.Context) error {
		return d.blob.Ping(ctx)
	})
}
