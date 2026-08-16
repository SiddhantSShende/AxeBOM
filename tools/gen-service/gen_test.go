package main

import (
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
)

// The generator's registry and the runtime config's service list must agree.
//
// If they drift, a service generated here gets config.defaultPort's fallback of
// 8080 and collides with the gateway in the local stack — a confusing failure
// that presents as "the gateway is flaky" rather than "these two lists differ".
func TestRegistryMatchesConfig(t *testing.T) {
	gen := serviceNames()
	runtime := config.KnownServices()

	if len(gen) != len(runtime) {
		t.Fatalf("service count differs: generator has %d %v, config has %d %v",
			len(gen), gen, len(runtime), runtime)
	}

	inConfig := make(map[string]bool, len(runtime))
	for _, s := range runtime {
		inConfig[s] = true
	}
	for _, s := range gen {
		if !inConfig[s] {
			t.Errorf("service %q is in the generator registry but not config.KnownServices()", s)
		}
	}
}

// Every generated service must get a distinct port, or `task dev` fails with a
// bind error that does not say which two services collided.
func TestPortsUnique(t *testing.T) {
	seen := map[int]string{}
	for _, s := range services {
		if other, dup := seen[s.Port]; dup {
			t.Errorf("port %d assigned to both %q and %q", s.Port, other, s.Name)
		}
		seen[s.Port] = s.Name
	}
}

// The generator's port table must match the one config resolves at runtime.
func TestPortsMatchConfig(t *testing.T) {
	for _, s := range services {
		cfg, err := config.LoadService(s.Name)
		if err != nil {
			t.Fatalf("LoadService(%q): %v", s.Name, err)
		}
		if cfg.HTTPPort != s.Port {
			t.Errorf("%s: generator port %d, config port %d", s.Name, s.Port, cfg.HTTPPort)
		}
	}
}

func TestAllTemplatesParse(t *testing.T) {
	spec := serviceSpec{Name: "example", Summary: "test", Port: 9999, Phase: 0}
	for _, f := range files {
		t.Run(f.tmpl, func(t *testing.T) {
			// Render into a temp path so nothing in the tree is touched.
			dest := t.TempDir() + "/" + f.tmpl
			if _, err := render(dest, f, spec, false); err != nil {
				t.Fatalf("render %s: %v", f.tmpl, err)
			}
		})
	}
}
