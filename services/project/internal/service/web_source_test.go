package service_test

import (
	"testing"

	"github.com/axebom/axebom/services/project/internal/service"
)

// ValidateWebSourceURL is shape validation only — see its own doc comment.
// This test exists to prove the shape rules, not to double as an SSRF test.
func TestValidateWebSourceURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid https", "https://example.com/", false},
		{"valid https with path", "https://example.com/app", false},
		{"empty", "", true},
		{"http rejected", "http://example.com/", true},
		{"ssh scheme rejected", "ssh://example.com/", true},
		{"ext transport rejected", "ext::sh -c calc", true},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"no host", "https:///path", true},
		{"embedded credentials rejected", "https://user:pass@example.com/", true},
		{"whitespace rejected", "https://example.com/ evil", true},
		{"control character rejected", "https://example.com/\nevil", true},
		{"too long", "https://example.com/" + string(make([]byte, 2048)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ValidateWebSourceURL(tt.raw)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateWebSourceURL(%q): want error, got nil", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateWebSourceURL(%q): unexpected error: %v", tt.raw, err)
			}
		})
	}
}

func TestCreateWebSourceDefaultsMaxHostsAndDiscovery(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	w, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
		RootURL: "https://example.com/",
	})
	if err != nil {
		t.Fatalf("CreateWebSource: %v", err)
	}

	if w.RootURL != "https://example.com/" {
		t.Errorf("root_url = %q, want the validated URL", w.RootURL)
	}
	// Explicit so the row is honest about what was chosen, per the service's
	// own comment — not an implicit NULL/zero that later code has to guess at.
	if w.MaxHosts != 25 {
		t.Errorf("max_hosts = %d, want 25 (the column default, made explicit)", w.MaxHosts)
	}
	if !w.DiscoveryEnabled {
		t.Error("discovery_enabled = false, want true (the common case is a one-field form)")
	}
	if w.ID == "" {
		t.Error("no id assigned")
	}
}

func TestCreateWebSourceHonorsExplicitMaxHostsAndDiscoveryDisabled(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	w, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
		RootURL:           "https://example.com/",
		MaxHosts:          5,
		DiscoveryDisabled: true,
	})
	if err != nil {
		t.Fatalf("CreateWebSource: %v", err)
	}
	if w.MaxHosts != 5 {
		t.Errorf("max_hosts = %d, want 5", w.MaxHosts)
	}
	if w.DiscoveryEnabled {
		t.Error("discovery_enabled = true, want false — DiscoveryDisabled was set")
	}
}

func TestCreateWebSourceRejectsMaxHostsOutOfRange(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	// 0 is excluded: it means "unset" and defaults to 25, covered separately
	// by TestCreateWebSourceDefaultsMaxHostsAndDiscovery.
	for _, n := range []int{-5, 101, 1000} {
		_, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
			RootURL: "https://example.com/", MaxHosts: n,
		})
		if err == nil {
			t.Errorf("max_hosts=%d: want error, got none", n)
		}
	}
}

func TestCreateWebSourceRejectsAnInvalidURL(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	if _, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
		RootURL: "http://example.com/",
	}); err == nil {
		t.Error("a non-https root_url was accepted")
	}
}

func TestListWebSourcesReturnsNewestFirst(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	first, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
		RootURL: "https://first.example.com/",
	})
	if err != nil {
		t.Fatalf("CreateWebSource: %v", err)
	}
	second, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
		RootURL: "https://second.example.com/",
	})
	if err != nil {
		t.Fatalf("CreateWebSource: %v", err)
	}

	got, err := f.svc.ListWebSources(t.Context(), tenantA, p.ID)
	if err != nil {
		t.Fatalf("ListWebSources: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].ID != second.ID || got[1].ID != first.ID {
		t.Error("web sources are not ordered newest first")
	}
}

// A cross-tenant project id must not attach a source: without the ownership
// check, this is a write primitive against a project the caller cannot see.
func TestCreateWebSourceOnAnotherTenantsProjectIsRefused(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)

	_, err := f.svc.CreateWebSource(t.Context(), tenantB, p.ID, service.WebSourceInput{
		RootURL: "https://example.com/",
	})
	if err == nil {
		t.Fatal("tenant B attached a web source to tenant A's project")
	}
	assertNotFound(t, err)
}

func TestListWebSourcesOnAnotherTenantsProjectIsEmpty(t *testing.T) {
	f := newFixture(t)
	p := createProject(t, f, tenantA)
	if _, err := f.svc.CreateWebSource(t.Context(), tenantA, p.ID, service.WebSourceInput{
		RootURL: "https://example.com/",
	}); err != nil {
		t.Fatalf("CreateWebSource: %v", err)
	}

	got, err := f.svc.ListWebSources(t.Context(), tenantB, p.ID)
	if err != nil {
		t.Fatalf("ListWebSources: %v", err)
	}
	// RLS scopes the query to tenant B, which owns nothing under this project
	// id — not a 404 here, since a bare list has no single resource to 404 on,
	// but the rows must never leak across the tenant boundary.
	if len(got) != 0 {
		t.Errorf("tenant B saw %d of tenant A's web sources, want 0", len(got))
	}
}
