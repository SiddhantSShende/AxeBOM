package service

import (
	"strings"
	"testing"

	"github.com/axebom/axebom/services/project/internal/hbom"
)

// TestValidateHardwareComponent — the LIVE validator, tested for the first time.
//
// ⚠ THESE RULES WERE TESTED ONLY ON THE COPY PRODUCTION NEVER RUNS.
//
// `workers/hbom/form.py` carries thirteen assertions about exactly this
// behaviour, and this function's own comment says it "matches the assertions
// workers/hbom/form.py's from_payload() makes". But `form.py` is imported by
// nothing except its own test — the live path is this Go re-implementation, and
// it had no test at all.
//
// Two implementations of one rule, with the tests attached to the wrong one, is
// how they drift: the Python side could be tightened, both suites stay green,
// and the API keeps accepting what the specification now rejects.
//
// ⚠ AN INTERNAL TEST (`package service`), UNLIKE ITS NEIGHBOURS, because the
// function is unexported and it is the unit under test — exporting it purely to
// test it would widen the service's surface to satisfy a test runner.
func TestValidateHardwareComponent(t *testing.T) {
	tests := []struct {
		name      string
		component *hbom.Component
		wantErr   string
	}{
		{
			name:      "a product name is required",
			component: &hbom.Component{ModelNumber: "ENC-1"},
			wantErr:   "product name",
		},
		{
			name:      "a nil payload is rejected rather than panicking",
			component: nil,
			wantErr:   "empty",
		},
		{
			name:      "a name of only whitespace is not a name",
			component: &hbom.Component{ProductName: "   "},
			wantErr:   "product name",
		},
		{
			name: "an unknown criticality is refused, not silently dropped",
			component: &hbom.Component{
				ProductName: "Edge Gateway", Criticality: "urgent",
			},
			wantErr: "criticality",
		},
		{
			name: "criticality is case-insensitive",
			component: &hbom.Component{
				ProductName: "Edge Gateway", Criticality: "CRITICAL",
			},
		},
		{
			name:      "an absent criticality is legal — it is reported as a gap, not an error",
			component: &hbom.Component{ProductName: "Edge Gateway"},
		},
		{
			// ⚠ EVERYTHING ELSE MAY BE ABSENT. Invariant 3: an unknown is
			// recorded as not-provided and scores zero. Rejecting the save
			// would mean a customer cannot record what they DO know until they
			// know everything.
			name:      "a component with nothing but a name is accepted",
			component: &hbom.Component{ProductName: "Unidentified part"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHardwareComponent(tt.component, "the component")

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error; want one mentioning %q", tt.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidationRecursesIntoChildren.
//
// A fetched tree round-tripped through the edit form carries its children along,
// so a bad value three levels down must be caught — otherwise it is written and
// only surfaces as a CHECK-constraint violation from Postgres, whose message
// names a column rather than the part the customer was editing.
func TestValidationRecursesIntoChildren(t *testing.T) {
	root := &hbom.Component{
		ProductName: "Edge Gateway",
		Children: []*hbom.Component{
			{ProductName: "Board"},
			{ProductName: "Resistor", Criticality: "extremely"},
		},
	}

	err := validateHardwareComponent(root, "the component")
	if err == nil {
		t.Fatal("a bad criticality on a child was accepted")
	}
	if !strings.Contains(err.Error(), "criticality") {
		t.Errorf("error does not name the failing field: %v", err)
	}
}
