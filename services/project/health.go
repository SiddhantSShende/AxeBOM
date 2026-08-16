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
	// Critical: every endpoint reads or writes a project row.
	c.Register("postgres", d.pool.Ping)

	// Critical: uploads are one of the two registration paths, so an instance
	// that cannot reach object storage should leave the load balancer rather
	// than accept files it will drop.
	c.Register("objectstore", d.blob.Ping)

	// OPTIONAL, deliberately. Vault being down blocks connecting a PRIVATE
	// repository; it does not block public repositories, uploads, manual
	// registration, or any read. Marking it critical would convert a
	// credential-store outage into a total outage of the projects module.
	c.RegisterOptional("vault", d.vault.Ping)
}
