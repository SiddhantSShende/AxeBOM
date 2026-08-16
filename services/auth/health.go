package main

import (
	"github.com/encorebom/encorebom/libs/go-shared/platform/health"
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
	// Critical: auth cannot verify a password or mint a session without
	// Postgres, so an instance that has lost it should leave the load balancer
	// rather than answer every login with a 500.
	c.Register("postgres", d.pool.Ping)
}
