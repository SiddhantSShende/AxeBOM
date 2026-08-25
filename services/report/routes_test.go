package main

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/routeguard"
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

// TestTheOnlyPublicRouteIsTheShareLink.
//
// ⚠ THIS SERVICE HOLDS THE PRODUCT'S ONLY UNAUTHENTICATED DATA ROUTE, so the
// exemption list is the thing most worth watching. A second entry appearing
// here is a security decision that deserves a review, and this test is where
// that review gets forced — routeguard would happily accept any number of them.
func TestTheOnlyPublicRouteIsTheShareLink(t *testing.T) {
	if len(publicRoutes) != 1 {
		t.Fatalf("publicRoutes has %d entries: %v\n\n"+
			"Every entry is a route that serves data with no identity attached. "+
			"Adding one is a deliberate security decision — state the reason "+
			"beside it and update this test.", len(publicRoutes), keys(publicRoutes))
	}

	reason, ok := publicRoutes["GET /shared/{token}"]
	if !ok {
		t.Fatalf("the share-link route is no longer the public one: %v", keys(publicRoutes))
	}

	// The reason is the review surface. An entry saying "public" tells the next
	// reader nothing about what makes it safe.
	for _, want := range []string{"audited", "entropy", "Analyst"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the exemption reason does not mention %q; it should say what "+
				"makes an unauthenticated route acceptable, not merely that it is one",
				want)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
