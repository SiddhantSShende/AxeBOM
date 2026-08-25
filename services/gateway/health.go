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
//
// # Every upstream is OPTIONAL, and that is the whole decision
//
// The gateway holds no database and owns no data; its only dependencies are the
// services it forwards to. Registering those as CRITICAL would mean one
// restarting service takes the gateway out of the load balancer — and with the
// gateway gone, every other service becomes unreachable too. A partial outage
// would escalate itself into a total one.
//
// Degraded is the honest signal: /readyz answers 200 with the failing upstream
// named, the routes that do work keep working, and the routes that do not
// return INTERNAL_DEPENDENCY_UNAVAILABLE naming the service — which is far more
// actionable than a gateway that has vanished.
func registerHealthChecks(c *health.Checker, d *deps) {
	for _, up := range d.router.Upstreams() {
		c.RegisterOptional(up.Name, up.Probe)
	}
}
