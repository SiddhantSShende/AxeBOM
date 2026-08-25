package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The service boundary is enforced by depguard, and depguard needs ONE RULE PER
// SERVICE because it matches import paths by prefix and has no notion of "the
// package I am in" (see the comment block in .golangci.yml).
//
// That creates a gap this test closes: adding a service to the registry without
// adding its rule would silently leave that service unguarded — free to import
// any other service, with nothing failing. The guard would look present because
// seven other rules are there.
//
// So: the registry is the source of truth, and the lint config must cover it.
func TestEveryServiceHasABoundaryRule(t *testing.T) {
	path := filepath.Join("..", "..", ".golangci.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	cfg := string(raw)

	for _, s := range services {
		rule := "service-boundaries-" + s.Name + ":"
		if !strings.Contains(cfg, rule) {
			t.Errorf("service %q has no depguard rule.\n"+
				"    Add to .golangci.yml under depguard.rules:\n"+
				"        %s\n"+
				"          list-mode: lax\n"+
				"          files: [\"**/services/%s/**\"]\n"+
				"          allow: [github.com/axebom/axebom/services/%s]\n"+
				"          deny: *cross-service-deny\n"+
				"    Without it, %s can import any other service and nothing fails.",
				s.Name, rule, s.Name, s.Name, s.Name)
			continue
		}

		// The rule must be scoped to that service's files, or it applies
		// everywhere and its `allow` silently punches a hole in every other
		// service's boundary.
		wantFiles := `files: ["**/services/` + s.Name + `/**"]`
		if !strings.Contains(cfg, wantFiles) {
			t.Errorf("service %q's depguard rule is missing its file scope %s", s.Name, wantFiles)
		}

		wantAllow := "allow: [github.com/axebom/axebom/services/" + s.Name + "]"
		if !strings.Contains(cfg, wantAllow) {
			t.Errorf("service %q's depguard rule does not allow its own packages (%s), "+
				"so the service cannot import its own internal/ tree", s.Name, wantAllow)
		}
	}
}
