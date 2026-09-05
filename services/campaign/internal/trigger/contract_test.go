package trigger

import (
	"encoding/json"
	"testing"
	"time"
)

// scanRequestAsSent mirrors the ORCHESTRATOR's createScanRequest exactly.
//
// ⚠ COPIED, NOT IMPORTED, BECAUSE depguard FORBIDS THE IMPORT — a service may
// not reach into another service's internal packages (invariant 11). That is
// precisely why this contract went untested and then broke: both sides had
// tests, the boundary between them had none, and the campaign's own tests use
// an httptest server that accepts any JSON at all.
//
// Keep the tags in step with
// services/scan-orchestrator/internal/handler.createScanRequest.
type scanRequestAsSent struct {
	ProjectID  string   `json:"project_id"`
	SourceKind string   `json:"source_kind"`
	Families   []string `json:"families"`
	Engines    []string `json:"engines,omitempty"`
}

// TestTheCampaignRequestDecodesAsTheOrchestratorReadsIt.
//
// ⚠ CAMPAIGNS HAVE NEVER STARTED A SCAN, AND THIS IS WHY. The campaign sent
// `bom_types` where the orchestrator reads `families`, and sent no
// `source_kind` at all. CreateScan rejects both:
//
//	len(in.Families) == 0            -> "select at least one BOM family"
//	in.SourceKind not one of four    -> "source_kind must be git, upload, image or url"
//
// A database with 58 scans contains zero whose triggered_by is `campaign`.
//
// Decoding the real body with the real struct is the whole point: a field
// rename on either side fails here instead of silently producing a scheduled
// scan that never runs.
func TestTheCampaignRequestDecodesAsTheOrchestratorReadsIt(t *testing.T) {
	body := captureScanRequest(t)

	var got scanRequestAsSent
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("the orchestrator cannot decode what the campaign sends: %v", err)
	}

	if got.ProjectID == "" {
		t.Error("project_id did not survive the decode")
	}
	if len(got.Families) == 0 {
		t.Error("families is empty after decoding the campaign's body; CreateScan " +
			"refuses this with \"select at least one BOM family\", so the scan is " +
			"never created and the campaign silently does nothing")
	}
	switch got.SourceKind {
	case "git", "upload", "image", "url":
	default:
		t.Errorf("source_kind = %q; CreateScan accepts only git, upload, image or url, "+
			"so a scheduled scan is rejected before it exists", got.SourceKind)
	}
}

// captureScanRequest drives a real Trigger against a recording server and
// returns the exact body it sent.
func captureScanRequest(t *testing.T) []byte {
	t.Helper()
	rec := &recorder{}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	if _, err := tr.Trigger(t.Context(), campaign("p1"), "run-1", time.Now()); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if len(rec.requests) != 1 {
		t.Fatalf("%d requests recorded, want 1", len(rec.requests))
	}
	return []byte(rec.requests[0]["body"])
}
