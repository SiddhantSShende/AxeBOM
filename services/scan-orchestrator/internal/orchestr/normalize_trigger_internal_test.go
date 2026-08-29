package orchestr

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/policy"
)

// familyTerminal must not report readiness for a family with no matching
// engine run at all — "nothing to wait on" is not the same as "ready to
// normalize", and conflating them would let a CBOM result (say) trigger an
// SBOM normalization for a scan that never ran any SBOM engine.
func TestFamilyTerminalIsFalseWhenNoEngineMatchesTheFamily(t *testing.T) {
	registry := policy.DefaultRegistry()
	latest := map[string]EngineRun{
		"cbomkit-theia": {EngineID: "cbomkit-theia", Status: events.StatusSucceeded},
	}
	if familyTerminal(latest, registry, events.FamilySBOM) {
		t.Error("familyTerminal reported ready for sbom with only a cbom engine run present")
	}
}

// The core readiness rule: not ready while anything is still queued or
// running, ready once every matching engine has reached a terminal status —
// whatever that status is (succeeded, partial, failed, skipped, unavailable,
// timeout are all terminal; only queued/running are not).
func TestFamilyTerminal(t *testing.T) {
	registry := policy.DefaultRegistry()

	tests := []struct {
		name string
		runs map[string]EngineRun
		want bool
	}{
		{
			name: "one queued engine blocks readiness",
			runs: map[string]EngineRun{
				"syft":  {EngineID: "syft", Status: events.StatusSucceeded},
				"grype": {EngineID: "grype", Status: "queued"},
			},
			want: false,
		},
		{
			name: "one running engine blocks readiness",
			runs: map[string]EngineRun{
				"syft":  {EngineID: "syft", Status: "running"},
				"grype": {EngineID: "grype", Status: events.StatusSucceeded},
			},
			want: false,
		},
		{
			name: "every engine terminal, mixed outcomes",
			runs: map[string]EngineRun{
				"syft":  {EngineID: "syft", Status: events.StatusSucceeded},
				"grype": {EngineID: "grype", Status: events.StatusFailed},
			},
			want: true,
		},
		{
			name: "a cbom run alongside sbom runs does not block sbom readiness",
			runs: map[string]EngineRun{
				"syft":          {EngineID: "syft", Status: events.StatusSucceeded},
				"cbomkit-theia": {EngineID: "cbomkit-theia", Status: "running"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := familyTerminal(tt.runs, registry, events.FamilySBOM); got != tt.want {
				t.Errorf("familyTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// latestRunsByEngine must reduce multiple retry attempts down to the
// attempt TerminalStatuses' own SQL would pick: prefer a non-failed
// attempt over a failed one, then the highest attempt number — "a retry
// that succeeds must not be outvoted by the attempt that failed before it"
// (docs/02-CONTRACTS.md §4).
func TestLatestRunsByEngine(t *testing.T) {
	runs := []EngineRun{
		{EngineID: "syft", Attempt: 1, Status: events.StatusFailed},
		{EngineID: "syft", Attempt: 2, Status: events.StatusSucceeded},
		{EngineID: "grype", Attempt: 1, Status: events.StatusSucceeded},
		{EngineID: "grype", Attempt: 2, Status: events.StatusFailed},
	}

	latest := latestRunsByEngine(runs)

	if got := latest["syft"]; got.Status != events.StatusSucceeded || got.Attempt != 2 {
		t.Errorf("syft = %+v, want the succeeded attempt 2, not the failed attempt 1", got)
	}
	if got := latest["grype"]; got.Status != events.StatusSucceeded || got.Attempt != 1 {
		t.Errorf("grype = %+v, want the succeeded attempt 1, not outvoted by the later failed attempt", got)
	}
}
