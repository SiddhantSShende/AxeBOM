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
	// Critical: the database is the SOURCE OF TRUTH for scan state. An
	// instance that lost it can neither create a scan nor report on one.
	c.Register("postgres", d.pool.Ping)

	// Critical: without NATS this service accepts scans it can never dispatch,
	// which is worse than refusing them.
	c.Register("nats", d.bus.Ping)
}
