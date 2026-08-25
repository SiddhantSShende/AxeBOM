package main

import (
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
	c.Register("postgres", d.pool.Ping)

	// ⚠ VAULT IS CRITICAL HERE, UNLIKE IN MOST SERVICES. Every webhook signing
	// secret lives there, resolved per delivery. An instance that cannot reach
	// Vault will accept subscriptions and fail every webhook — after telling the
	// customer their endpoint was configured. Better to leave the load balancer.
	c.Register("vault", d.vault.Ping)
}
