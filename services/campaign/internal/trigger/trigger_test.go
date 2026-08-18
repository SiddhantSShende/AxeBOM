package trigger

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/encorebom/encorebom/services/campaign/internal/scheduler"
)

func token(context.Context, string) (string, error) { return "service-token", nil }

func campaign(projects ...string) scheduler.Campaign {
	return scheduler.Campaign{
		ID: "campaign-1", TenantID: "tenant-a",
		ProjectIDs: projects, BOMTypes: []string{"sbom", "cbom"},
	}
}

// recorder captures what the scan service was asked to do.
type recorder struct {
	mu       sync.Mutex
	requests []map[string]string
	// fail names projects the scan service rejects.
	fail map[string]bool
}

func (rec *recorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)

		projectID := extract(string(body), "project_id")

		rec.mu.Lock()
		rec.requests = append(rec.requests, map[string]string{
			"project_id":      projectID,
			"idempotency_key": r.Header.Get("Idempotency-Key"),
			"authorization":   r.Header.Get("Authorization"),
			"body":            string(body),
		})
		n := len(rec.requests)
		rec.mu.Unlock()

		if rec.fail[projectID] {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"SCAN_UNAVAILABLE"}}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"id":"scan-%d"}`, n)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// extract pulls a JSON string field out of a body without a full decode.
func extract(body, field string) string {
	marker := `"` + field + `":"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func mustTrigger(t *testing.T, url string) *Trigger {
	t.Helper()
	tr, err := New(Options{BaseURL: url, Token: token, Client: &http.Client{Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestOneScanPerProject(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	scans, err := tr.Trigger(context.Background(),
		campaign("p1", "p2", "p3"), "run-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 {
		t.Fatalf("started %d scans for 3 projects: %v", len(scans), scans)
	}
	if len(rec.requests) != 3 {
		t.Fatalf("%d requests, want 3", len(rec.requests))
	}
}

func TestAPartialFailureStillReportsTheStartedScans(t *testing.T) {
	// ⚠ THE CASE THIS PACKAGE EXISTS TO GET RIGHT. Two scans are already
	// running when the third is refused; discarding them would leave the
	// product asserting nothing happened while two reports appear from nowhere.
	rec := &recorder{fail: map[string]bool{"p3": true}}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	scans, err := tr.Trigger(context.Background(),
		campaign("p1", "p2", "p3", "p4"), "run-1", time.Now())

	if err == nil {
		t.Fatal("a refused project produced no error")
	}
	if len(scans) != 3 {
		t.Fatalf("started %d scans alongside the error, want 3 (p1, p2, p4)", len(scans))
	}
	if !strings.Contains(err.Error(), "p3") {
		t.Errorf("the error does not name the project that failed: %v", err)
	}
	if !strings.Contains(err.Error(), "1 of 4") {
		t.Errorf("the error does not say how much of the campaign ran: %v", err)
	}
}

func TestTheIdempotencyKeyIsStableAcrossRetries(t *testing.T) {
	// ⚠ A FRESH RANDOM KEY PER ATTEMPT WOULD CREATE A SECOND SCAN ON EVERY
	// RETRY. Keying on (run, project) is the same argument as
	// UNIQUE (campaign_id, scheduled_for), one layer down.
	rec := &recorder{}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	for range 3 {
		if _, err := tr.Trigger(context.Background(),
			campaign("p1"), "run-1", time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	first := rec.requests[0]["idempotency_key"]
	if first == "" {
		t.Fatal("no idempotency key was sent")
	}
	for i, req := range rec.requests {
		if req["idempotency_key"] != first {
			t.Fatalf("attempt %d used key %q, want the stable %q",
				i, req["idempotency_key"], first)
		}
	}
}

func TestTheIdempotencyKeyDistinguishesProjects(t *testing.T) {
	// One key for the whole run would make the second project's scan look like
	// a retry of the first, and the campaign would scan one project.
	rec := &recorder{}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	if _, err := tr.Trigger(context.Background(),
		campaign("p1", "p2"), "run-1", time.Now()); err != nil {
		t.Fatal(err)
	}

	if rec.requests[0]["idempotency_key"] == rec.requests[1]["idempotency_key"] {
		t.Fatalf("both projects used the key %q, so one scan would be dropped as a retry",
			rec.requests[0]["idempotency_key"])
	}
}

func TestTheScanRecordsItsCampaignProvenance(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	if _, err := tr.Trigger(context.Background(),
		campaign("p1"), "run-1", time.Now()); err != nil {
		t.Fatal(err)
	}

	body := rec.requests[0]["body"]
	if !strings.Contains(body, `"triggered_by":"campaign"`) {
		t.Errorf("the scan does not record that a campaign started it: %s", body)
	}
	if !strings.Contains(body, `"trigger_ref":"campaign-1"`) {
		t.Errorf("the scan does not record WHICH campaign started it: %s", body)
	}
}

func TestTheRequestCarriesAServiceToken(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	tr := mustTrigger(t, srv.URL)

	if _, err := tr.Trigger(context.Background(),
		campaign("p1"), "run-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := rec.requests[0]["authorization"]; got != "Bearer service-token" {
		t.Errorf("authorization = %q, want a bearer token", got)
	}
}

func TestAnEmptyScanIDIsRejected(t *testing.T) {
	// A 202 with no id would otherwise be recorded as a successful run with no
	// scan attached — a run history entry that points at nothing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	tr := mustTrigger(t, srv.URL)
	scans, err := tr.Trigger(context.Background(), campaign("p1"), "run-1", time.Now())
	if err == nil {
		t.Fatal("a response with no scan id was accepted")
	}
	if len(scans) != 0 {
		t.Errorf("recorded %d scans from a response with no id", len(scans))
	}
}

func TestNewRefusesAnUnconfiguredTrigger(t *testing.T) {
	if _, err := New(Options{Token: token}); err == nil {
		t.Error("a trigger with no base URL was built")
	}
	if _, err := New(Options{BaseURL: "http://scan"}); err == nil {
		t.Error("a trigger with no token source was built")
	}
}
