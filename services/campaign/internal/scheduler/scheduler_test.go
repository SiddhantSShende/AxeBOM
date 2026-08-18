package scheduler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fakes
//
// ⚠ THE FAKE STORE MODELS `UNIQUE (campaign_id, scheduled_for)` EXACTLY, because
// that constraint — not the advisory lock — is what makes dispatch idempotent.
// A fake that let two claims through for the same occurrence would let every
// test in this file pass while the real system double-fired.
// ---------------------------------------------------------------------------

type run struct {
	ID           string
	CampaignID   string
	TenantID     string
	ScheduledFor time.Time
	Status       string
	SkipReason   string
	ScanIDs      []string
	Error        string
}

type fakeStore struct {
	mu sync.Mutex

	campaigns []Campaign
	// runs is keyed by the UNIQUE constraint: campaign_id + scheduled_for.
	runs map[string]*run
	seq  int

	// dueErr, claimErr let a test inject a database failure.
	dueErr   error
	claimErr error

	dueCalls int
}

func newStore(campaigns ...Campaign) *fakeStore {
	return &fakeStore{campaigns: campaigns, runs: map[string]*run{}}
}

func key(campaignID string, at time.Time) string {
	// UTC, so two representations of the same instant collide exactly as
	// Postgres timestamptz would.
	return campaignID + "@" + at.UTC().Format(time.RFC3339Nano)
}

func (s *fakeStore) DueCampaigns(_ context.Context, now time.Time, limit int) ([]Campaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dueCalls++
	if s.dueErr != nil {
		return nil, s.dueErr
	}

	var out []Campaign
	for _, c := range s.campaigns {
		if !c.Cursor.After(now) && len(out) < limit {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *fakeStore) ClaimRun(_ context.Context, c Campaign, at time.Time) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimErr != nil {
		return "", false, s.claimErr
	}

	k := key(c.ID, at)
	if _, exists := s.runs[k]; exists {
		// This is `INSERT ... ON CONFLICT DO NOTHING` returning zero rows.
		return "", false, nil
	}
	s.seq++
	id := fmt.Sprintf("run-%d", s.seq)
	s.runs[k] = &run{
		ID: id, CampaignID: c.ID, TenantID: c.TenantID,
		ScheduledFor: at, Status: "pending",
	}
	return id, true, nil
}

func (s *fakeStore) RecordSkipped(_ context.Context, c Campaign, at time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(c.ID, at)
	if _, exists := s.runs[k]; exists {
		return nil // the same UNIQUE constraint applies to skipped rows
	}
	s.seq++
	s.runs[k] = &run{
		ID: fmt.Sprintf("run-%d", s.seq), CampaignID: c.ID, TenantID: c.TenantID,
		ScheduledFor: at, Status: "skipped", SkipReason: reason,
	}
	return nil
}

func (s *fakeStore) StartRun(_ context.Context, _ Campaign, runID string, scanIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.runs {
		if r.ID == runID {
			r.Status = "running"
			r.ScanIDs = scanIDs
			return nil
		}
	}
	return fmt.Errorf("no run %s", runID)
}

func (s *fakeStore) FailRun(_ context.Context, _ Campaign, runID string, cause string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.runs {
		if r.ID == runID {
			r.Status = "failed"
			r.Error = cause
			return nil
		}
	}
	return fmt.Errorf("no run %s", runID)
}

func (s *fakeStore) AdvanceCursor(_ context.Context, c Campaign, next, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.campaigns {
		if s.campaigns[i].ID == c.ID {
			s.campaigns[i].Cursor = next
			return nil
		}
	}
	return fmt.Errorf("no campaign %s", c.ID)
}

func (s *fakeStore) fired() []*run {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*run
	for _, r := range s.runs {
		if r.Status != "skipped" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScheduledFor.Before(out[j].ScheduledFor) })
	return out
}

func (s *fakeStore) skipped() []*run {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*run
	for _, r := range s.runs {
		if r.Status == "skipped" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScheduledFor.Before(out[j].ScheduledFor) })
	return out
}

// fakeTrigger records what it was asked to scan.
type fakeTrigger struct {
	mu    sync.Mutex
	calls []string
	err   error
	// hold blocks inside Trigger so a test can interleave two instances.
	//
	// ⚠ ONLY THE FIRST CALLER BLOCKS, AND THAT MATTERS FOR THE MUTATION.
	// Blocking every caller was the first version, and when the UNIQUE
	// constraint was deliberately broken to check these tests catch it, the
	// second instance reached Trigger and blocked forever — so the test
	// DEADLOCKED instead of failing. A ten-minute hang says far less than an
	// assertion, and under `go test ./...` it stalls every other package.
	hold   chan struct{}
	holdMu sync.Mutex
	held   bool
}

func (t *fakeTrigger) Trigger(_ context.Context, c Campaign, runID string, at time.Time) ([]string, error) {
	if t.hold != nil {
		t.holdMu.Lock()
		first := !t.held
		t.held = true
		t.holdMu.Unlock()
		if first {
			<-t.hold
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err != nil {
		return nil, t.err
	}
	t.calls = append(t.calls, fmt.Sprintf("%s@%s", c.ID, at.UTC().Format(time.RFC3339)))
	return []string{"scan-" + runID}, nil
}

func (t *fakeTrigger) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.calls)
}

// fakeLock models Postgres advisory-lock semantics: ONE holder at a time,
// process-wide, released when the holder's session ends.
type fakeLock struct {
	shared *lockState
	id     string
}

type lockState struct {
	mu     sync.Mutex
	holder string
}

func newLockPair(names ...string) []*fakeLock {
	shared := &lockState{}
	out := make([]*fakeLock, len(names))
	for i, n := range names {
		out[i] = &fakeLock{shared: shared, id: n}
	}
	return out
}

func (l *fakeLock) Acquire(context.Context) (bool, error) {
	l.shared.mu.Lock()
	defer l.shared.mu.Unlock()
	if l.shared.holder == "" || l.shared.holder == l.id {
		l.shared.holder = l.id
		return true, nil
	}
	return false, nil
}

func (l *fakeLock) Release(context.Context) error {
	l.shared.mu.Lock()
	defer l.shared.mu.Unlock()
	if l.shared.holder == l.id {
		l.shared.holder = ""
	}
	return nil
}

// die simulates the holder's process vanishing: Postgres notices the session is
// gone and drops the lock, WITHOUT the holder ever calling Release.
func (l *fakeLock) die() {
	l.shared.mu.Lock()
	defer l.shared.mu.Unlock()
	if l.shared.holder == l.id {
		l.shared.holder = ""
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustNew(t *testing.T, store Store, trigger Trigger, lock Lock) *Scheduler {
	t.Helper()
	s, err := New(Options{Store: store, Trigger: trigger, Lock: lock, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------------------
// Firing
// ---------------------------------------------------------------------------

func daily(id string, at time.Time) Campaign {
	return Campaign{
		ID: id, TenantID: "tenant-a", Name: id,
		CronExpr: "30 2 * * *", Timezone: "UTC",
		ProjectIDs: []string{"project-1"},
		BOMTypes:   []string{"sbom"},
		Cursor:     at,
	}
}

func TestADueCampaignFiresOnce(t *testing.T) {
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)
	res, err := s.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dispatched != 1 {
		t.Fatalf("dispatched %d, want 1", res.Dispatched)
	}
	if trigger.count() != 1 {
		t.Fatalf("triggered %d scans, want 1", trigger.count())
	}

	fired := store.fired()
	if len(fired) != 1 {
		t.Fatalf("%d run rows, want 1", len(fired))
	}
	if fired[0].Status != "running" {
		t.Errorf("run status %q, want running", fired[0].Status)
	}
	if len(fired[0].ScanIDs) == 0 {
		t.Error("the run records no scan ids, so run history cannot reach the scan")
	}

	// ⚠ AND IT DOES NOT FIRE AGAIN. The cursor advanced past the occurrence, so
	// a second tick at the same instant has nothing to do.
	res, err = s.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dispatched != 0 {
		t.Fatalf("a second tick dispatched %d, want 0", res.Dispatched)
	}
}

func TestScheduledForRecordsTheSlotNotTheFiringInstant(t *testing.T) {
	// ⚠ OTHERWISE RUN HISTORY IS NOT COMPARABLE. A tick lands somewhere in a
	// 30-second window; if `scheduled_for` recorded when the tick happened,
	// every restart would shift it, and the UNIQUE constraint that makes
	// dispatch idempotent would stop matching.
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	s := mustNew(t, store, &fakeTrigger{}, nil)

	// A tick 27 seconds late.
	now := time.Date(2026, 8, 18, 2, 30, 27, 0, time.UTC)
	if _, err := s.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}

	fired := store.fired()
	want := time.Date(2026, 8, 18, 2, 30, 0, 0, time.UTC)
	if !fired[0].ScheduledFor.Equal(want) {
		t.Fatalf("scheduled_for = %s, want the slot %s", fired[0].ScheduledFor, want)
	}
}

func TestADisabledCampaignDoesNotFire(t *testing.T) {
	// A disabled campaign is not returned by DueCampaigns at all — the filter
	// is `WHERE enabled` in the query, which is why the fake's campaign list is
	// the set of enabled ones.
	store := newStore() // nothing enabled
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)
	res, err := s.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dispatched != 0 || trigger.count() != 0 {
		t.Fatal("a disabled campaign fired")
	}
}

func TestReEnablingDoesNotBackfill(t *testing.T) {
	// ⚠ THE RULE FALLS OUT OF THE CURSOR, WHICH IS WHY THERE IS NO
	// `enabled_at` COLUMN. Enabling sets the cursor to the next FUTURE
	// occurrence; there is nothing behind it to catch up on. A design that
	// caught up from `last_run_at` would fire a month of scans the moment
	// somebody re-enabled a campaign they had paused.
	now := time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)

	// Enabled now, after a month off: the handler sets the cursor forward.
	cursor := time.Date(2026, 8, 19, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	res, err := s.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dispatched != 0 {
		t.Fatalf("re-enabling backfilled %d runs", res.Dispatched)
	}
	if len(store.skipped()) != 0 {
		t.Fatalf("re-enabling recorded %d skipped runs it should never have seen",
			len(store.skipped()))
	}
}

// ---------------------------------------------------------------------------
// Missed runs
// ---------------------------------------------------------------------------

func TestMissedRunsFireOnceAndRecordTheRest(t *testing.T) {
	// Hourly campaign, scheduler down for six hours.
	c := Campaign{
		ID: "c1", TenantID: "tenant-a", CronExpr: "0 * * * *", Timezone: "UTC",
		Cursor: time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC),
	}
	store := newStore(c)
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	now := time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC)
	res, err := s.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}

	// ⚠ ONE SCAN, NOT SIX. Six concurrent scans of the same projects would
	// starve every other tenant's queue and produce six near-identical reports.
	if res.Dispatched != 1 {
		t.Fatalf("dispatched %d runs after downtime, want exactly 1", res.Dispatched)
	}
	if trigger.count() != 1 {
		t.Fatalf("triggered %d scans, want 1", trigger.count())
	}

	skipped := store.skipped()
	if len(skipped) != 5 {
		t.Fatalf("recorded %d skipped occurrences, want 5", len(skipped))
	}

	// ⚠ THE GAP IS VISIBLE, WITH A REASON. A compliance customer discovering at
	// audit that six hours have no scan — and nothing saying why — is the
	// failure these rows exist to prevent.
	for _, r := range skipped {
		if r.SkipReason == "" {
			t.Errorf("skipped run at %s carries no reason", r.ScheduledFor)
		}
	}

	// The one that ran is the MOST RECENT, not the oldest.
	fired := store.fired()
	want := time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)
	if !fired[0].ScheduledFor.Equal(want) {
		t.Errorf("caught up with the slot at %s, want the most recent %s",
			fired[0].ScheduledFor, want)
	}
}

// ---------------------------------------------------------------------------
// Idempotency — the part that is actually load-bearing
// ---------------------------------------------------------------------------

func TestRestartDuringATickDoesNotDoubleFire(t *testing.T) {
	// The crash window: the run row is inserted and the scan is triggered, then
	// the process dies before the cursor advances. On restart the campaign is
	// still due for the same occurrence.
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{}
	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)

	first := mustNew(t, store, trigger, nil)
	if _, err := first.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}

	// Simulate the crash: put the cursor back to where it was before the tick,
	// leaving the claimed run row in place — exactly what the database would
	// look like if the process died between the two writes.
	store.mu.Lock()
	store.campaigns[0].Cursor = cursor
	store.mu.Unlock()

	second := mustNew(t, store, trigger, nil)
	res, err := second.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}

	if res.Dispatched != 0 {
		t.Fatalf("the restarted scheduler dispatched %d, want 0", res.Dispatched)
	}
	if res.Claimed != 1 {
		t.Errorf("claimed-elsewhere = %d, want 1 (the occurrence was already taken)", res.Claimed)
	}
	if trigger.count() != 1 {
		t.Fatalf("%d scans were triggered across a restart, want 1", trigger.count())
	}
}

func TestTwoInstancesProduceExactlyOneDispatch(t *testing.T) {
	// TestLeaderElection's sibling: the same property WITHOUT any lock at all.
	//
	// ⚠ THIS IS THE TEST THAT MATTERS. The package claims the scheduler is
	// correct with leader election removed entirely — that the lock is a
	// polling optimisation and the UNIQUE constraint is the safety mechanism.
	// If a future change makes correctness depend on leadership, this test
	// fails and that one still passes.
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{}
	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)

	a := mustNew(t, store, trigger, nil) // no lock
	b := mustNew(t, store, trigger, nil) // no lock

	var wg sync.WaitGroup
	results := make([]Result, 2)
	for i, s := range []*Scheduler{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.Tick(context.Background(), now)
			if err != nil {
				t.Error(err)
			}
			results[i] = res
		}()
	}
	wg.Wait()

	total := results[0].Dispatched + results[1].Dispatched
	if total != 1 {
		t.Fatalf("two lock-free instances dispatched %d times, want exactly 1", total)
	}
	if trigger.count() != 1 {
		t.Fatalf("%d scans triggered, want 1", trigger.count())
	}
}

func TestLeaderElection(t *testing.T) {
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{}
	locks := newLockPair("a", "b")

	a := mustNew(t, store, trigger, locks[0])
	b := mustNew(t, store, trigger, locks[1])

	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)

	resA, err := a.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	resB, err := b.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}

	if !resA.Leader {
		t.Fatal("the first instance did not become leader")
	}
	if resB.Leader {
		t.Fatal("both instances led at once")
	}

	// ⚠ THE FOLLOWER DID NOT EVEN LOOK. That is the whole point of the lock:
	// N replicas do not each run the due-campaign query every thirty seconds.
	if store.dueCalls != 1 {
		t.Errorf("the due-campaign query ran %d times, want 1", store.dueCalls)
	}

	if resA.Dispatched+resB.Dispatched != 1 {
		t.Fatalf("dispatched %d, want 1", resA.Dispatched+resB.Dispatched)
	}
}

func TestKillingTheLeaderMidTickLosesNothingAndDuplicatesNothing(t *testing.T) {
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{hold: make(chan struct{})}
	locks := newLockPair("a", "b")

	a := mustNew(t, store, trigger, locks[0])
	b := mustNew(t, store, trigger, locks[1])
	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)

	// A starts a tick and blocks inside Trigger, holding the lock.
	done := make(chan Result, 1)
	go func() {
		res, err := a.Tick(context.Background(), now)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()

	// Wait until A has claimed the run — it is now mid-dispatch.
	deadline := time.Now().Add(2 * time.Second)
	for {
		store.mu.Lock()
		claimed := len(store.runs)
		store.mu.Unlock()
		if claimed > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the leader never claimed the run")
		}
		time.Sleep(time.Millisecond)
	}

	// ⚠ THE LEADER'S PROCESS VANISHES. It never calls Release; Postgres notices
	// the session is gone and drops the lock. This is the case a lease cannot
	// protect against, and the case the UNIQUE constraint must.
	locks[0].die()

	// B becomes leader and ticks while A is still notionally in flight.
	resB, err := b.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !resB.Leader {
		t.Fatal("the survivor did not take over")
	}

	// Let A finish. Both instances have now processed the same occurrence.
	close(trigger.hold)
	resA := <-done

	if resA.Dispatched+resB.Dispatched != 1 {
		t.Fatalf("takeover produced %d dispatches, want exactly 1",
			resA.Dispatched+resB.Dispatched)
	}
	if trigger.count() != 1 {
		t.Fatalf("%d scans triggered across a leader change, want 1", trigger.count())
	}
	if len(store.fired()) != 1 {
		t.Fatalf("%d run rows for one occurrence", len(store.fired()))
	}

	// And no gap: the occurrence did happen.
	if store.fired()[0].Status == "skipped" {
		t.Fatal("the occurrence was lost in the takeover")
	}
}

// ---------------------------------------------------------------------------
// DST — real transition dates
// ---------------------------------------------------------------------------

func TestDSTSpringForwardDoesNotLoseTheRun(t *testing.T) {
	// America/New_York, 2026-03-08: 02:00 becomes 03:00. A 02:30 daily campaign
	// has no 02:30 that day.
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("zone database unavailable: %v", err)
	}

	c := Campaign{
		ID: "c1", TenantID: "tenant-a", CronExpr: "30 2 * * *",
		Timezone: "America/New_York",
		Cursor:   time.Date(2026, 3, 7, 2, 30, 0, 0, loc),
	}
	store := newStore(c)
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	now := time.Date(2026, 3, 8, 12, 0, 0, 0, loc)
	res, err := s.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}

	// ⚠ IT MUST NOT VANISH. A daily compliance scan silently skipping one day a
	// year is a gap nobody notices until an audit asks for that day.
	if res.Dispatched != 1 {
		t.Fatalf("spring-forward dispatched %d, want 1", res.Dispatched)
	}

	fired := store.fired()[0].ScheduledFor.In(loc)
	if fired.Day() != 8 {
		t.Fatalf("the run landed on the %d, want the 8th: %s", fired.Day(), fired)
	}
	if fired.Hour() != 3 {
		t.Errorf("spring-forward run at %s, want 03:30 (the slot did not exist)", fired)
	}
	t.Logf("spring forward: 02:30 resolved to %s", fired.Format(time.RFC3339))
}

func TestDSTFallBackDoesNotFireTwice(t *testing.T) {
	// America/New_York, 2026-11-01: 02:00 happens twice, so 01:30 EDT and
	// 01:30 EST are two distinct instants an hour apart.
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("zone database unavailable: %v", err)
	}

	c := Campaign{
		ID: "c1", TenantID: "tenant-a", CronExpr: "30 1 * * *",
		Timezone: "America/New_York",
		Cursor:   time.Date(2026, 10, 31, 1, 30, 0, 0, loc),
	}
	store := newStore(c)
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	// Tick after both 01:30s have passed.
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, loc)
	if _, err := s.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}

	// ⚠ ONE RUN FOR THE DAY, NOT TWO. Two scans, two reports and two
	// notifications for a single scheduled occurrence is the autumn half of the
	// bug, and it is the half that is visible to the customer.
	var onTheFirst int
	for _, r := range store.fired() {
		if r.ScheduledFor.In(loc).Day() == 1 && r.ScheduledFor.In(loc).Month() == time.November {
			onTheFirst++
		}
	}
	if onTheFirst != 1 {
		t.Fatalf("fall-back produced %d runs on 2026-11-01, want 1", onTheFirst)
	}
	if trigger.count() != 1 {
		t.Fatalf("%d scans triggered, want 1", trigger.count())
	}

	// And the NEXT day's run is still correct — the cursor did not get stuck in
	// the repeated hour.
	store.mu.Lock()
	next := store.campaigns[0].Cursor.In(loc)
	store.mu.Unlock()
	if next.Day() != 2 || next.Hour() != 1 || next.Minute() != 30 {
		t.Errorf("next run = %s, want 2026-11-02 01:30 local", next.Format(time.RFC3339))
	}
	t.Logf("fall back: ran at %s, next at %s",
		store.fired()[0].ScheduledFor.In(loc).Format(time.RFC3339),
		next.Format(time.RFC3339))
}

func TestAnUnknownTimezoneIsAnErrorNotUTC(t *testing.T) {
	// ⚠ SILENTLY FALLING BACK TO UTC IS OFF BY UP TO FOURTEEN HOURS, and
	// nothing in the product would say so. A campaign a customer set for 02:00
	// Asia/Kolkata running at 02:00 UTC is 07:30 local — during the working day
	// the scan was scheduled to avoid.
	c := Campaign{
		ID: "c1", TenantID: "tenant-a", CronExpr: "30 2 * * *",
		Timezone: "Mars/Olympus_Mons",
		Cursor:   time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC),
	}
	store := newStore(c)
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	res, err := s.Tick(context.Background(), time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("one bad campaign returned a tick error: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("failed = %d, want 1", res.Failed)
	}
	if trigger.count() != 0 {
		t.Fatal("a campaign with an unknown timezone fired anyway")
	}
}

// ---------------------------------------------------------------------------
// Failure isolation
// ---------------------------------------------------------------------------

func TestOneBadCampaignDoesNotStopTheRest(t *testing.T) {
	// ⚠ A SINGLE TENANT'S DATA ERROR MUST NOT BECOME A PLATFORM OUTAGE. An
	// unparseable cron in one campaign stopping every other tenant's schedule
	// is the kind of blast radius that turns a support ticket into an incident.
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)

	bad := daily("bad", cursor)
	bad.CronExpr = "not a cron expression"
	bad.TenantID = "tenant-a"

	good := daily("good", cursor)
	good.TenantID = "tenant-b"

	store := newStore(bad, good)
	trigger := &fakeTrigger{}
	s := mustNew(t, store, trigger, nil)

	res, err := s.Tick(context.Background(), time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("tick returned an error for one bad campaign: %v", err)
	}
	if res.Failed != 1 {
		t.Errorf("failed = %d, want 1", res.Failed)
	}
	if res.Dispatched != 1 {
		t.Fatalf("the healthy campaign dispatched %d, want 1", res.Dispatched)
	}
	if trigger.count() != 1 {
		t.Fatalf("triggered %d, want 1 (the good campaign)", trigger.count())
	}
}

func TestAFailedTriggerLeavesTheRunVisibleAndDoesNotRetry(t *testing.T) {
	// ⚠ THE RUN ROW STAYS, MARKED FAILED. Deleting it would make the occurrence
	// claimable again, and the retry would re-trigger a campaign that may
	// already have started scans before erroring — the duplicate the UNIQUE
	// constraint exists to prevent.
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	store := newStore(daily("c1", cursor))
	trigger := &fakeTrigger{err: errors.New("scan orchestrator unreachable")}
	s := mustNew(t, store, trigger, nil)

	now := time.Date(2026, 8, 18, 2, 30, 5, 0, time.UTC)
	res, err := s.Tick(context.Background(), now)
	if err != nil {
		t.Fatalf("tick returned an error rather than isolating the campaign: %v", err)
	}
	if res.Failed != 1 {
		t.Errorf("failed = %d, want 1", res.Failed)
	}

	fired := store.fired()
	if len(fired) != 1 {
		t.Fatalf("%d run rows, want 1 (failed, retained)", len(fired))
	}
	if fired[0].Status != "failed" {
		t.Errorf("run status %q, want failed", fired[0].Status)
	}
	if !strings.Contains(fired[0].Error, "unreachable") {
		t.Errorf("the failed run does not say why: %q", fired[0].Error)
	}

	// A later tick does not re-trigger it: the occurrence is claimed.
	if _, err := s.Tick(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := len(store.fired()); n != 1 {
		t.Fatalf("a retry created %d run rows for one occurrence", n)
	}
}

func TestADatabaseFailureIsReturnedNotSwallowed(t *testing.T) {
	store := newStore(daily("c1", time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)))
	store.dueErr = errors.New("connection refused")
	s := mustNew(t, store, &fakeTrigger{}, nil)

	if _, err := s.Tick(context.Background(), time.Now()); err == nil {
		t.Fatal("a database failure was swallowed")
	}
}

func TestTheBatchBoundsOneTick(t *testing.T) {
	// A tick that tries to dispatch every campaign in a large deployment holds
	// the leader lock for minutes; the remainder is picked up thirty seconds
	// later because their cursors were not advanced.
	cursor := time.Date(2026, 8, 17, 2, 30, 0, 0, time.UTC)
	var campaigns []Campaign
	for i := range 10 {
		campaigns = append(campaigns, daily(fmt.Sprintf("c%d", i), cursor))
	}
	store := newStore(campaigns...)
	trigger := &fakeTrigger{}

	s, err := New(Options{Store: store, Trigger: trigger, Logger: quietLogger(), Batch: 3})
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.Tick(context.Background(), time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if res.Dispatched != 3 {
		t.Fatalf("dispatched %d in one tick with batch 3, want 3", res.Dispatched)
	}
}

func TestNewRefusesAnIncompleteScheduler(t *testing.T) {
	if _, err := New(Options{Trigger: &fakeTrigger{}}); err == nil {
		t.Error("a scheduler with no store was constructed")
	}
	if _, err := New(Options{Store: newStore()}); err == nil {
		t.Error("a scheduler with no trigger was constructed")
	}
}
