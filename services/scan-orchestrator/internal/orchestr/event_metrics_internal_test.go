package orchestr

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
)

// TestTheLiveFeedCarriesWhatEachEngineActuallyFound.
//
// ⚠ `ScanEventV1.Metrics` EXISTED SINCE PHASE 6 AND NO PUBLISHER FILLED IT.
// The field was defined, carried through the WebSocket and rendered by nothing,
// so a customer watching a scan saw a percentage and an engine name and no idea
// what was being found. These pin the two shapes that now reach the feed.
func TestTheLiveFeedCarriesWhatEachEngineActuallyFound(t *testing.T) {
	t.Run("an engine that breaks its results down reports the breakdown", func(t *testing.T) {
		// This is what somebody watching a scan wants: "2 vector stores" rather
		// than "11 components", which is what the four summary dimensions would
		// have given them.
		got := eventMetrics(events.ScanResultV1{
			Engine:      "airom",
			Summary:     events.Summary{Components: events.Count(11)},
			Discoveries: map[string]int64{"ai_models": 3, "ai_asset.vector_store": 1},
		})
		if got["ai_models"] != 3 || got["ai_asset.vector_store"] != 1 {
			t.Errorf("the engine's own breakdown did not reach the feed: %v", got)
		}
		if _, present := got["components"]; present {
			t.Error("the summary was mixed into the breakdown; a reader cannot " +
				"tell which number counts what")
		}
	})

	t.Run("an engine that does not falls back to the summary", func(t *testing.T) {
		got := eventMetrics(events.ScanResultV1{
			Engine:  "syft",
			Summary: events.Summary{Components: events.Count(21)},
		})
		if got["components"] != 21 {
			t.Errorf("components = %v, want 21", got["components"])
		}
	})

	t.Run("a dimension that was never measured is omitted, never zeroed", func(t *testing.T) {
		// ⚠ `nil` MEANS "NOT MEASURED" AND `0` MEANS "MEASURED, NONE". Publishing
		// 0 for grype's licences would tell a live feed that grype found no
		// licences — which grype never looked for.
		got := eventMetrics(events.ScanResultV1{
			Engine: "grype",
			Summary: events.Summary{
				Vulnerabilities: events.Count(0),
			},
		})
		if v, present := got["vulnerabilities"]; !present || v != 0 {
			t.Errorf("a measured zero was lost: %v", got)
		}
		for _, absent := range []string{"components", "licenses", "crypto_assets"} {
			if _, present := got[absent]; present {
				t.Errorf("%q was published for an engine that never measured it", absent)
			}
		}
	})

	t.Run("an engine that measured nothing publishes no metrics", func(t *testing.T) {
		if got := eventMetrics(events.ScanResultV1{Engine: "x"}); got != nil {
			t.Errorf("got %v, want nil — an empty map renders as a row of nothing", got)
		}
	})
}
