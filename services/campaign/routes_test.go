package main

import (
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/routeguard"
)

// TestEveryRouteIsGuardedOrDeliberatelyPublic parses routes.go and fails on any
// route that carries no middleware and is not a listed public exemption.
//
// The logic lives in libs/go-shared/routeguard so all eight services share one
// implementation; the publicRoutes map stays HERE, next to the routes it
// describes, because the exemptions are a per-service security decision.
func TestEveryRouteIsGuardedOrDeliberatelyPublic(t *testing.T) {
	findings, err := routeguard.Check("routes.go", publicRoutes)
	if err != nil {
		t.Fatalf("route guard: %v", err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestThisServiceHasNoPublicRoutes.
//
// ⚠ A CAMPAIGN IS A STANDING INSTRUCTION TO FETCH SOMEBODY'S SOURCE. An
// unauthenticated caller who could create or trigger one would have a way to
// make the platform clone a repository of their choosing, on a schedule, from
// our egress — an SSRF amplifier with a cron field. There is no version of this
// service that needs an anonymous route.
func TestThisServiceHasNoPublicRoutes(t *testing.T) {
	if len(publicRoutes) != 0 {
		t.Fatalf("publicRoutes has %d entries: %v\n\n"+
			"Every entry is a route reachable with no identity. On this service "+
			"that means anonymous control over what the platform fetches and how "+
			"often. If one is genuinely required, state what makes it safe beside "+
			"it and change this test deliberately.", len(publicRoutes), publicRoutes)
	}
}

// TestTriggeringIsADistinctPermissionFromEditing.
//
// Turning a campaign on schedules work indefinitely; running it once spends
// scan capacity immediately. Collapsing them into one matrix cell would let any
// role that may rename a campaign also drain the scan queue.
func TestTriggeringIsADistinctPermissionFromEditing(t *testing.T) {
	perms, err := routeguard.Permissions("routes.go")
	if err != nil {
		t.Fatalf("reading permissions: %v", err)
	}

	run, ok := perms["POST /v1/campaigns/{id}/run"]
	if !ok {
		t.Fatal("the run-now route is not mounted")
	}
	enable, ok := perms["POST /v1/campaigns/{id}/enabled"]
	if !ok {
		t.Fatal("the enable route is not mounted")
	}

	if run.Action() == enable.Action() {
		t.Errorf("run-now and enable both use %q; spending compute now and "+
			"scheduling it later are different authorizations", run.Action())
	}
}
