package handler

import (
	"encoding/json"
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

// TestACampaignsProvenanceSurvivesTheRequest.
//
// ⚠ THE CAMPAIGN SERVICE SENT IT AND THIS HANDLER DROPPED IT. createScanRequest
// had no field for triggered_by or trigger_ref, so every scheduled scan would
// have been recorded as a plain `api` call with no campaign attached — losing
// exactly the provenance the campaign's own comment promises ("a scan's
// provenance answers 'why does this exist?' without a join").
func TestACampaignsProvenanceSurvivesTheRequest(t *testing.T) {
	var req createScanRequest
	body := `{"project_id":"p1","source_kind":"git","families":["sbom"],` +
		`"triggered_by":"campaign","trigger_ref":"01900000-0000-7000-8000-0000000000c1"}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.TriggeredBy != "campaign" {
		t.Errorf("triggered_by did not survive the decode: %q", req.TriggeredBy)
	}
	if req.TriggerRef == "" {
		t.Error("trigger_ref did not survive the decode")
	}
}

// TestOnlyAServicePrincipalMayNameItsOwnTrigger.
//
// ⚠ A SIGNED-IN PERSON MUST NOT BE ABLE TO CLAIM `campaign`. Attribution is
// what makes a scan's provenance worth anything; if a browser could assert it,
// anybody could attribute their own scan to an automation that never ran. This
// is the same reason triggerFields derives the value from the verified subject
// rather than reading it from the body.
func TestOnlyAServicePrincipalMayNameItsOwnTrigger(t *testing.T) {
	if isServicePrincipal("01900000-0000-7000-8000-0000000000a1") {
		t.Error("a human subject was treated as a service principal")
	}
	if isServicePrincipal(oidcauth.APIKeySubjectPrefix + "some-key") {
		t.Error("an API key was treated as a service principal; a key holder " +
			"could then attribute scans to a campaign that never ran")
	}
	if !isServicePrincipal(oidcauth.ServiceSubjectPrefix + "campaign") {
		t.Error("the campaign service is not recognised as a service principal, " +
			"so its provenance would be discarded")
	}
}
