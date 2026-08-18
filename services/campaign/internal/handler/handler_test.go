package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/services/campaign/internal/store"
)

var clock = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

func now() time.Time { return clock }

// ---------------------------------------------------------------------------
// A fake store that enforces tenancy the way RLS does: a row belonging to
// another tenant is INVISIBLE, not forbidden. Anything else in this fake would
// let a cross-tenant test pass while the real thing leaked.
// ---------------------------------------------------------------------------

type fakeStore struct {
	campaigns map[string]store.Campaign // id -> campaign
	runs      map[string][]store.Run
	seq       int
}

func newFakeStore() *fakeStore {
	return &fakeStore{campaigns: map[string]store.Campaign{}, runs: map[string][]store.Run{}}
}

func (f *fakeStore) visible(tenantID, id string) (store.Campaign, bool) {
	c, ok := f.campaigns[id]
	if !ok || c.TenantID != tenantID {
		return store.Campaign{}, false
	}
	return c, true
}

func (f *fakeStore) Create(_ context.Context, tenantID string, c store.Campaign) (store.Campaign, error) {
	f.seq++
	c.ID = fmt.Sprintf("campaign-%d", f.seq)
	c.TenantID = tenantID
	c.CreatedAt, c.UpdatedAt = clock, clock
	f.campaigns[c.ID] = c
	return c, nil
}

func (f *fakeStore) Get(_ context.Context, tenantID, id string) (store.Campaign, error) {
	c, ok := f.visible(tenantID, id)
	if !ok {
		return store.Campaign{}, store.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) List(_ context.Context, tenantID string, _ int) ([]store.Campaign, error) {
	var out []store.Campaign
	for _, c := range f.campaigns {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) Update(
	_ context.Context, tenantID, id string, c store.Campaign, _ time.Time,
) (store.Campaign, error) {
	existing, ok := f.visible(tenantID, id)
	if !ok {
		return store.Campaign{}, store.ErrNotFound
	}
	c.ID, c.TenantID, c.CreatedAt = existing.ID, existing.TenantID, existing.CreatedAt
	c.UpdatedAt = clock
	f.campaigns[id] = c
	return c, nil
}

func (f *fakeStore) SetEnabled(
	_ context.Context, tenantID, id string, enabled bool, at time.Time,
) (store.Campaign, error) {
	c, ok := f.visible(tenantID, id)
	if !ok {
		return store.Campaign{}, store.ErrNotFound
	}
	c.Enabled = enabled
	if enabled {
		next, err := store.FirstOccurrence(c.CronExpr, c.Timezone, at)
		if err != nil {
			return store.Campaign{}, err
		}
		c.NextRunAt = &next
	} else {
		c.NextRunAt = nil
	}
	f.campaigns[id] = c
	return c, nil
}

func (f *fakeStore) Delete(_ context.Context, tenantID, id string) error {
	if _, ok := f.visible(tenantID, id); !ok {
		return store.ErrNotFound
	}
	delete(f.campaigns, id)
	return nil
}

func (f *fakeStore) ListRuns(_ context.Context, tenantID, campaignID string, _ int) ([]store.Run, error) {
	if _, ok := f.visible(tenantID, campaignID); !ok {
		return nil, store.ErrNotFound
	}
	return f.runs[campaignID], nil
}

type fakeRunNow struct {
	calls int
	err   error
}

func (f *fakeRunNow) RunNow(context.Context, string, string, time.Time) (string, []string, error) {
	f.calls++
	if f.err != nil {
		return "", nil, f.err
	}
	return "run-1", []string{"scan-1"}, nil
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

func request(method, target, tenantID, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := ctxkey.WithTenantID(r.Context(), tenantID)
	ctx = ctxkey.WithUserID(ctx, "user-1")
	return r.WithContext(ctx)
}

func validBody(name string) string {
	return fmt.Sprintf(`{
		"name": %q,
		"project_ids": ["project-1"],
		"cron_expr": "30 2 * * *",
		"timezone": "UTC",
		"bom_types": ["sbom"],
		"report_levels": ["top_level"],
		"standards": ["spdx"],
		"formats": ["pdf"],
		"enabled": true
	}`, name)
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	return out
}

func newHandler() (*Handler, *fakeStore, *fakeRunNow) {
	s := newFakeStore()
	rn := &fakeRunNow{}
	return New(s, rn, now), s, rn
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func TestCreateComputesTheFirstOccurrence(t *testing.T) {
	h, _, _ := newHandler()
	w := httptest.NewRecorder()

	h.Create(w, request(http.MethodPost, "/v1/campaigns", "tenant-a", validBody("nightly")))

	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	// 09:00 on the 17th, daily at 02:30 → the 18th.
	if body["next_run_at"] != "2026-08-18T02:30:00Z" {
		t.Errorf("next_run_at = %v, want 2026-08-18T02:30:00Z", body["next_run_at"])
	}
}

func TestADisabledCampaignIsCreatedWithNoNextRun(t *testing.T) {
	h, _, _ := newHandler()
	w := httptest.NewRecorder()

	body := strings.Replace(validBody("paused"), `"enabled": true`, `"enabled": false`, 1)
	h.Create(w, request(http.MethodPost, "/v1/campaigns", "tenant-a", body))

	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := decodeBody(t, w)["next_run_at"]; got != nil {
		t.Errorf("a disabled campaign has next_run_at = %v, want none", got)
	}
}

func TestAnUnparseableCronIsRejectedAtWriteTime(t *testing.T) {
	// ⚠ THE WHOLE POINT OF VALIDATING HERE. Accepted, it becomes a campaign
	// that never fires — discovered at audit, not in the product.
	h, _, _ := newHandler()
	w := httptest.NewRecorder()

	body := strings.Replace(validBody("broken"), `"30 2 * * *"`, `"every tuesday"`, 1)
	h.Create(w, request(http.MethodPost, "/v1/campaigns", "tenant-a", body))

	// 422, not 400: VALIDATION_* maps to Unprocessable Entity across the
	// product (docs/02-CONTRACTS.md §9). The body parsed fine; its CONTENT is
	// what this build refuses.
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cron") {
		t.Errorf("the error does not name the field: %s", w.Body.String())
	}
}

func TestAnUnknownTimezoneIsRejectedAtWriteTime(t *testing.T) {
	// Silently falling back to UTC is off by up to fourteen hours, and nothing
	// in the product would say so.
	h, _, _ := newHandler()
	w := httptest.NewRecorder()

	body := strings.Replace(validBody("wrong-zone"), `"UTC"`, `"Mars/Olympus_Mons"`, 1)
	h.Create(w, request(http.MethodPost, "/v1/campaigns", "tenant-a", body))

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body.String())
	}
}

func TestACampaignNeedsAProjectABOMTypeAndAFormat(t *testing.T) {
	h, _, _ := newHandler()

	for field, body := range map[string]string{
		"project": strings.Replace(validBody("x"), `["project-1"]`, `[]`, 1),
		"bomtype": strings.Replace(validBody("x"), `"bom_types": ["sbom"]`, `"bom_types": []`, 1),
		"format":  strings.Replace(validBody("x"), `"formats": ["pdf"]`, `"formats": []`, 1),
		"name":    strings.Replace(validBody("x"), `"name": "x"`, `"name": ""`, 1),
	} {
		w := httptest.NewRecorder()
		h.Create(w, request(http.MethodPost, "/v1/campaigns", "tenant-a", body))
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("missing %s produced status %d, want 422", field, w.Code)
		}
	}
}

func TestAnUnknownFieldIsRejected(t *testing.T) {
	h, _, _ := newHandler()
	w := httptest.NewRecorder()

	body := strings.Replace(validBody("typo"), `"enabled": true`, `"enabld": true`, 1)
	h.Create(w, request(http.MethodPost, "/v1/campaigns", "tenant-a", body))

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a typo'd field was accepted silently (status %d)", w.Code)
	}
}

func TestEmptyListsSerializeAsArraysNotNull(t *testing.T) {
	// A JSON `null` where the client expects a list crashes only in the empty
	// case — which is every newly created campaign's run history.
	h, s, _ := newHandler()
	s.campaigns["c1"] = store.Campaign{ID: "c1", TenantID: "tenant-a"}

	w := httptest.NewRecorder()
	r := request(http.MethodGet, "/v1/campaigns/c1/runs", "tenant-a", "")
	r.SetPathValue("id", "c1")
	h.Runs(w, r)
	if !strings.Contains(w.Body.String(), `"runs":[]`) {
		t.Errorf("empty run history serialized as %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	h.List(w, request(http.MethodGet, "/v1/campaigns", "tenant-b", ""))
	if !strings.Contains(w.Body.String(), `"campaigns":[]`) {
		t.Errorf("empty campaign list serialized as %s", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Enable / disable
// ---------------------------------------------------------------------------

func TestDisablingClearsTheCursorAndReEnablingLooksForward(t *testing.T) {
	// ⚠ THE NO-BACKFILL RULE, END TO END. Re-enabling a campaign that was off
	// for a month must not fire a month of missed scans.
	h, s, _ := newHandler()
	s.campaigns["c1"] = store.Campaign{
		ID: "c1", TenantID: "tenant-a",
		CronExpr: "30 2 * * *", Timezone: "UTC", Enabled: true,
	}

	w := httptest.NewRecorder()
	r := request(http.MethodPost, "/v1/campaigns/c1/enabled", "tenant-a", `{"enabled":false}`)
	r.SetPathValue("id", "c1")
	h.SetEnabled(w, r)

	if got := decodeBody(t, w)["next_run_at"]; got != nil {
		t.Fatalf("a disabled campaign still has next_run_at = %v", got)
	}

	// A month later, re-enabled.
	clock = time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	defer func() { clock = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC) }()

	w = httptest.NewRecorder()
	r = request(http.MethodPost, "/v1/campaigns/c1/enabled", "tenant-a", `{"enabled":true}`)
	r.SetPathValue("id", "c1")
	h.SetEnabled(w, r)

	got := decodeBody(t, w)["next_run_at"]
	if got != "2026-09-18T02:30:00Z" {
		t.Fatalf("re-enabling set next_run_at = %v, want the next FUTURE occurrence "+
			"2026-09-18T02:30:00Z; anything in the past would backfill a month of scans", got)
	}
}

// ---------------------------------------------------------------------------
// Tenancy — the phase names this explicitly
// ---------------------------------------------------------------------------

// TestCampaignsOfAnotherTenantAreInvisibleAndUntriggerable.
//
// ⚠ 404, NEVER 403. A 403 confirms the id exists, which turns any endpoint into
// an existence oracle: an attacker with one valid session enumerates ids and
// learns which belong to somebody. RLS makes absent and belonging-to-somebody-
// else indistinguishable at the database, and every layer above must preserve
// that rather than helpfully explaining the difference.
func TestCampaignsOfAnotherTenantAreInvisibleAndUntriggerable(t *testing.T) {
	h, s, runNow := newHandler()
	s.campaigns["c1"] = store.Campaign{
		ID: "c1", TenantID: "tenant-b", Name: "someone else's nightly",
		CronExpr: "30 2 * * *", Timezone: "UTC", Enabled: true,
	}
	s.runs["c1"] = []store.Run{{ID: "run-1", CampaignID: "c1", TenantID: "tenant-b"}}

	routes := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
		verb string
		body string
	}{
		{"get", h.Get, http.MethodGet, ""},
		{"runs", h.Runs, http.MethodGet, ""},
		{"delete", h.Delete, http.MethodDelete, ""},
		{"update", h.Update, http.MethodPut, validBody("hijacked")},
		{"enable", h.SetEnabled, http.MethodPost, `{"enabled":false}`},
		{"run-now", h.RunNow, http.MethodPost, ""},
	}

	for _, route := range routes {
		w := httptest.NewRecorder()
		r := request(route.verb, "/v1/campaigns/c1", "tenant-a", route.body)
		r.SetPathValue("id", "c1")
		route.fn(w, r)

		if w.Code != http.StatusNotFound {
			t.Errorf("%s returned %d for another tenant's campaign, want 404: %s",
				route.name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "someone else's nightly") {
			t.Errorf("%s leaked the campaign name", route.name)
		}
	}

	// The campaign is untouched, and nothing was triggered.
	if c := s.campaigns["c1"]; c.Name != "someone else's nightly" || !c.Enabled {
		t.Error("another tenant's campaign was modified")
	}
	if runNow.calls != 0 {
		t.Errorf("run-now fired %d times for another tenant's campaign", runNow.calls)
	}

	// And listing shows nothing.
	w := httptest.NewRecorder()
	h.List(w, request(http.MethodGet, "/v1/campaigns", "tenant-a", ""))
	if strings.Contains(w.Body.String(), "c1") {
		t.Errorf("the list leaked another tenant's campaign: %s", w.Body.String())
	}
}

func TestAMissingTenantIsRejected(t *testing.T) {
	// No verified token means no tenant, and no tenant means no data — never a
	// default, never the first tenant found.
	h, _, _ := newHandler()
	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest(http.MethodGet, "/v1/campaigns", nil))

	if w.Code == http.StatusOK {
		t.Fatal("an unauthenticated request listed campaigns")
	}
}

// ---------------------------------------------------------------------------
// Run history and manual triggering
// ---------------------------------------------------------------------------

func TestASkippedRunCarriesItsReasonToTheClient(t *testing.T) {
	// A run-history gap with no explanation is barely better than no row.
	h, s, _ := newHandler()
	s.campaigns["c1"] = store.Campaign{ID: "c1", TenantID: "tenant-a"}
	s.runs["c1"] = []store.Run{{
		ID: "run-1", CampaignID: "c1", TenantID: "tenant-a",
		Status: "skipped", SkipReason: "missed while the scheduler was unavailable",
		ScheduledFor: clock,
	}}

	w := httptest.NewRecorder()
	r := request(http.MethodGet, "/v1/campaigns/c1/runs", "tenant-a", "")
	r.SetPathValue("id", "c1")
	h.Runs(w, r)

	if !strings.Contains(w.Body.String(), "scheduler was unavailable") {
		t.Errorf("the skip reason did not reach the client: %s", w.Body.String())
	}
}

func TestRunNowReturns202WithTheRunAndScans(t *testing.T) {
	h, s, _ := newHandler()
	s.campaigns["c1"] = store.Campaign{ID: "c1", TenantID: "tenant-a"}

	w := httptest.NewRecorder()
	r := request(http.MethodPost, "/v1/campaigns/c1/run", "tenant-a", "")
	r.SetPathValue("id", "c1")
	h.RunNow(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["run_id"] != "run-1" {
		t.Errorf("run_id = %v", body["run_id"])
	}
}
