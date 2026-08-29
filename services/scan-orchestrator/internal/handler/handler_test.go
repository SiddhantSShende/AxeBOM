package handler

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
)

// TestTriggerFields is a regression guard for a real 500: POST /v1/scans
// authenticated with an API key (the CLI's own "CI, scripting" path, per
// `axebom apikey mint --help`) previously fed oidcauth's "apikey:<id>"
// subject string straight into scan.scans.trigger_ref, a uuid column,
// and Postgres rejected the insert outright.
func TestTriggerFields(t *testing.T) {
	cases := []struct {
		name          string
		subject       string
		wantTriggered string
		wantRequested string
	}{
		{
			name:          "a real user id passes through as the trigger ref",
			subject:       "01a03df3-e253-7425-9b44-d29402317722",
			wantTriggered: "user",
			wantRequested: "01a03df3-e253-7425-9b44-d29402317722",
		},
		{
			name:          "an API key principal has no user/campaign id to store",
			subject:       oidcauth.APIKeySubjectPrefix + "e102b73ab0c4",
			wantTriggered: "api",
			wantRequested: "",
		},
		{
			name:          "a service principal is likewise not a storable ref",
			subject:       oidcauth.ServiceSubjectPrefix + "svc-fetcher",
			wantTriggered: "api",
			wantRequested: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTriggered, gotRequested := triggerFields(tc.subject)
			if gotTriggered != tc.wantTriggered {
				t.Errorf("triggeredBy = %q, want %q", gotTriggered, tc.wantTriggered)
			}
			if gotRequested != tc.wantRequested {
				t.Errorf("requestedBy = %q, want %q", gotRequested, tc.wantRequested)
			}
		})
	}
}
