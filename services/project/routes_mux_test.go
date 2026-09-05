package main

import (
	"net/http"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/services/project/internal/handler"
)

// TestEveryRoutePatternRegistersWithoutConflict.
//
// ⚠ NOTHING BUILT THE MUX UNTIL THIS TEST, SO A PATTERN CONFLICT WAS A STARTUP
// CRASH RATHER THAN A FAILING BUILD.
//
// Go 1.22's ServeMux PANICS when two patterns overlap and neither is more
// specific. The obvious device routing — `/v1/hbom/{projectId}/devices` for the
// list and `/v1/hbom/devices/{deviceId}` for one device — is exactly that case:
// both match "/v1/hbom/devices/devices". `TestEveryRouteIsGuardedOrDeliberatelyPublic`
// parses this file as TEXT, so it would have passed happily while the service
// refused to start in the container.
//
// The routes are declared against a real mux here, with dependencies that are
// never called: registerRoutes only closes over the handler and the guard, so a
// zero-value handler and a zero-value Guard are enough to exercise every
// `mux.Handle` call — which is the only thing under test.
func TestEveryRoutePatternRegistersWithoutConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registering this service's routes panics, so the service "+
				"would not start:\n%v", r)
		}
	}()

	registerRoutes(http.NewServeMux(), &deps{
		handler:  &handler.Handler{},
		identity: &oidcauth.Guard{},
	})
}
