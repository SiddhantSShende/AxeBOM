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
	// Critical: the database is where campaigns, runs and the leader lock live.
	// An instance that cannot reach it can neither serve CRUD nor schedule.
	c.Register("postgres", d.pool.Ping)

	// ⚠ LEADERSHIP IS NOT A HEALTH CHECK, AND MUST NEVER BECOME ONE. Exactly
	// one instance holds the advisory lock; if "am I the leader?" fed readiness,
	// every follower would be pulled out of the load balancer and the service
	// would serve CRUD from a single pod. A follower is healthy — it is simply
	// not the one polling.
}
