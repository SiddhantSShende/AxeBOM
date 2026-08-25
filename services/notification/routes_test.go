package main

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/routeguard"
)

// TestEveryRouteIsGuardedOrDeliberatelyPublic parses routes.go and fails on any
// route that carries no middleware and is not a listed public exemption.
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
// ⚠ THIS SERVICE SENDS WEBHOOKS; IT DOES NOT RECEIVE THEM. An inbound callback
// route is the shape that usually ends up unauthenticated — "the signature is
// the auth" — and there is nothing here for one to do. If an entry ever appears
// in this map, the question to ask is whether the route should exist at all.
func TestThisServiceHasNoPublicRoutes(t *testing.T) {
	if len(publicRoutes) != 0 {
		t.Fatalf("publicRoutes has %d entries: %v", len(publicRoutes), publicRoutes)
	}
}

// TestNoRouteReadsASecretBack.
//
// ⚠ THERE IS NO "SHOW SECRET" ENDPOINT, BY DESIGN. A webhook signing secret is
// returned exactly once, at creation. An endpoint that reads one back is one
// XSS, one stolen session or one over-broad role away from disclosure, and it
// buys nothing: a customer who lost their copy rotates it.
func TestNoRouteReadsASecretBack(t *testing.T) {
	perms, err := routeguard.Permissions("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	for pattern := range perms {
		for _, forbidden := range []string{"secret", "reveal", "credential"} {
			if contains(pattern, forbidden) {
				t.Errorf("route %q looks like it reads a secret back", pattern)
			}
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
