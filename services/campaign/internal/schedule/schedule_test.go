package schedule

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, expr string) Spec {
	t.Helper()
	spec, err := Parse(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	return spec
}

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		// ⚠ SKIP RATHER THAN FAIL. Windows has no system tzdata unless the Go
		// binary imports time/tzdata; a missing database is an environment
		// fact, not a defect in the scheduler. See TestTimezoneDataIsAvailable,
		// which fails loudly if that is why these skipped.
		t.Skipf("timezone %s unavailable: %v", name, err)
	}
	return loc
}

// TestTimezoneDataIsAvailable makes a skipped DST suite impossible to miss.
//
// ⚠ THE DST TESTS ARE THE POINT OF THIS PACKAGE. If they silently skip because
// the platform has no tzdata, the suite is green and the correctness this phase
// exists for is unverified. This one fails instead.
func TestTimezoneDataIsAvailable(t *testing.T) {
	if _, err := time.LoadLocation("America/New_York"); err != nil {
		t.Fatalf(
			"no timezone database, so every DST test in this package SKIPPED "+
				"rather than ran: %v\n"+
				"    Import _ \"time/tzdata\" in the campaign service to embed it.", err)
	}
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

func TestParseAcceptsTheStandardForms(t *testing.T) {
	for _, expr := range []string{
		"0 2 * * *",
		"*/15 * * * *",
		"0 0 1 * *",
		"30 2 * * MON",
		"0 9-17 * * 1-5",
		"0 0 1 JAN *",
		"0,30 * * * *",
	} {
		if _, err := Parse(expr); err != nil {
			t.Errorf("Parse(%q): %v", expr, err)
		}
	}
}

func TestParseRejectsNonsense(t *testing.T) {
	for _, expr := range []string{
		"", "0 2 * *", "0 2 * * * *", "60 2 * * *", "0 24 * * *",
		"0 2 32 * *", "0 2 * 13 *", "x 2 * * *", "*/0 * * * *",
	} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) was accepted", expr)
		}
	}
}

func TestSundayIsBothZeroAndSeven(t *testing.T) {
	// ⚠ ACCEPTING ONE AND NOT THE OTHER silently never fires an "every Sunday"
	// campaign written the other way.
	loc := time.UTC
	base := time.Date(2026, 3, 2, 0, 0, 0, 0, loc) // a Monday

	zero, _ := Next(mustParse(t, "0 3 * * 0"), base, loc)
	seven, _ := Next(mustParse(t, "0 3 * * 7"), base, loc)

	if !zero.Equal(seven) {
		t.Fatalf("Sunday as 0 gave %s, as 7 gave %s", zero, seven)
	}
	if zero.Weekday() != time.Sunday {
		t.Errorf("fired on %s, want Sunday", zero.Weekday())
	}
}

// ---------------------------------------------------------------------------
// DST — the phase's named exit criterion
// ---------------------------------------------------------------------------

// TestDSTSpringForwardDoesNotVanish uses a real transition date.
//
// ⚠ ON 2026-03-08 IN NEW YORK, 02:30 DOES NOT EXIST. The clock jumps 02:00 →
// 03:00. A daily 02:30 campaign must still run that day — a scheduler that
// skips it produces a silent gap in a compliance record, discovered at audit.
func TestDSTSpringForwardDoesNotVanish(t *testing.T) {
	loc := mustLoad(t, "America/New_York")
	spec := mustParse(t, "30 2 * * *")

	// The evening before the transition.
	before := time.Date(2026, 3, 7, 20, 0, 0, 0, loc)

	next, err := Next(spec, before, loc)
	if err != nil {
		t.Fatalf("next: %v", err)
	}

	// It must land ON the transition day, not skip to the 9th.
	if next.Day() != 8 || next.Month() != time.March {
		t.Fatalf("the 02:30 run on the spring-forward day VANISHED: next run is %s", next)
	}
	// ⚠ 03:30 EDT, NOT 01:30 EST. Go's own normalization moves a non-existent
	// wall clock BACKWARDS, which would fire the run an hour EARLY and collide
	// it with the 01:30 slot. The scheduler corrects that forward — see
	// resolveSlot.
	if next.Hour() != 3 || next.Minute() != 30 {
		t.Errorf("run at %s; want 03:30, the instant 02:30 EST would have been",
			next.Format(time.RFC3339))
	}
	t.Logf("spring forward: 02:30 resolved to %s", next.Format(time.RFC3339))
}

// TestDSTFallBackDoesNotFireTwice uses a real transition date.
//
// ⚠ ON 2026-11-01 IN NEW YORK, 01:30 HAPPENS TWICE. The clock goes 02:00 →
// 01:00. A daily 01:30 campaign must run ONCE — firing twice costs a duplicate
// scan and produces two reports for one schedule.
func TestDSTFallBackDoesNotFireTwice(t *testing.T) {
	loc := mustLoad(t, "America/New_York")
	spec := mustParse(t, "30 1 * * *")

	before := time.Date(2026, 10, 31, 20, 0, 0, 0, loc)

	first, err := Next(spec, before, loc)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if first.Day() != 1 || first.Month() != time.November {
		t.Fatalf("the fall-back day's run is on %s", first)
	}

	// Asking again from just after the first run must move to the NEXT DAY,
	// not to the second 01:30 of the same day.
	second, err := Next(spec, first, loc)
	if err != nil {
		t.Fatalf("next: %v", err)
	}

	if second.Day() == first.Day() && second.Month() == first.Month() {
		t.Fatalf(
			"THE CAMPAIGN FIRED TWICE ON THE FALL-BACK DAY: %s then %s",
			first.Format(time.RFC3339), second.Format(time.RFC3339))
	}
	if second.Day() != 2 {
		t.Errorf("second run is %s, want November 2nd", second.Format(time.RFC3339))
	}
	t.Logf("fall back: one run at %s, next at %s",
		first.Format(time.RFC3339), second.Format(time.RFC3339))
}

func TestAdjacentSlotsAcrossTheSpringGapStayDistinct(t *testing.T) {
	// ⚠ THE SECOND HALF OF THE SPRING-FORWARD BUG. Go's backwards
	// normalization collapses the 02:30 slot onto 01:30, so `30 1,2 * * *`
	// would fire ONCE on the transition day instead of twice — a silently
	// halved schedule.
	loc := mustLoad(t, "America/New_York")
	spec := mustParse(t, "30 1,2 * * *")

	first, err := Next(spec, time.Date(2026, 3, 8, 0, 0, 0, 0, loc), loc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Next(spec, first, loc)
	if err != nil {
		t.Fatal(err)
	}

	if first.Equal(second) {
		t.Fatalf("both slots collapsed onto %s", first.Format(time.RFC3339))
	}
	if second.Day() != 8 {
		t.Fatalf("the second slot fell off the transition day: %s", second.Format(time.RFC3339))
	}
	t.Logf("distinct: %s then %s", first.Format(time.RFC3339), second.Format(time.RFC3339))
}

func TestDSTIsHandledInASouthernHemisphereZoneToo(t *testing.T) {
	// The transitions run the other way round in the calendar. A rule written
	// against northern dates alone can pass while being wrong here.
	loc := mustLoad(t, "Australia/Sydney")
	spec := mustParse(t, "30 2 * * *")

	// Sydney springs forward on 2026-10-04: 02:00 -> 03:00.
	before := time.Date(2026, 10, 3, 20, 0, 0, 0, loc)
	next, err := Next(spec, before, loc)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if next.Day() != 4 {
		t.Fatalf("the Sydney spring-forward run vanished: %s", next.Format(time.RFC3339))
	}
}

func TestADailyRunAcrossATransitionKeepsItsWallClock(t *testing.T) {
	// ⚠ THE DATE IS ADVANCED IN CALENDAR DAYS, NOT BY 24 HOURS. Adding 24h
	// drifts the wall clock by an hour across a transition, so a 09:00 daily
	// campaign starts running at 08:00 or 10:00 for half the year.
	loc := mustLoad(t, "America/New_York")
	spec := mustParse(t, "0 9 * * *")

	cursor := time.Date(2026, 3, 6, 0, 0, 0, 0, loc)
	for i := range 5 {
		next, err := Next(spec, cursor, loc)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if next.Hour() != 9 || next.Minute() != 0 {
			t.Fatalf("run %d drifted to %s", i, next.Format(time.RFC3339))
		}
		cursor = next
	}
}

// ---------------------------------------------------------------------------
// The day-of-month / day-of-week rule
// ---------------------------------------------------------------------------

func TestDayOfMonthAndDayOfWeekAreOredWhenBothRestricted(t *testing.T) {
	// ⚠ CRON'S DOCUMENTED BEHAVIOUR, AND SURPRISING ENOUGH THAT
	// IMPLEMENTATIONS GET IT WRONG IN BOTH DIRECTIONS. `0 0 1 * MON` means
	// "the 1st, AND every Monday" — not "the 1st when it is a Monday".
	loc := time.UTC
	spec := mustParse(t, "0 0 1 * MON")

	// 2026-06-01 is a Monday; 2026-06-08 is the next Monday; 2026-07-01 is a
	// Wednesday and must still match, because the day-of-month matches.
	cursor := time.Date(2026, 6, 30, 0, 0, 0, 0, loc)
	next, err := Next(spec, cursor, loc)
	if err != nil {
		t.Fatal(err)
	}
	if next.Day() != 1 || next.Month() != time.July {
		t.Fatalf("next = %s; July 1st is a Wednesday and must match on day-of-month",
			next.Format(time.RFC3339))
	}
}

func TestOnlyDayOfWeekRestrictedMatchesThatWeekday(t *testing.T) {
	loc := time.UTC
	spec := mustParse(t, "0 0 * * FRI")
	next, err := Next(spec, time.Date(2026, 6, 1, 0, 0, 0, 0, loc), loc)
	if err != nil {
		t.Fatal(err)
	}
	if next.Weekday() != time.Friday {
		t.Errorf("fired on %s", next.Weekday())
	}
}

func TestAnImpossibleDateIsAnErrorRatherThanAnInfiniteLoop(t *testing.T) {
	// February 30th. Looping forever inside a scheduler tick would take the
	// whole service down.
	spec := mustParse(t, "0 0 30 2 *")
	if _, err := Next(spec, time.Now(), time.UTC); err == nil {
		t.Fatal("an impossible date returned a run")
	}
}

// ---------------------------------------------------------------------------
// Basics
// ---------------------------------------------------------------------------

func TestNextIsStrictlyAfter(t *testing.T) {
	// ⚠ A RUN EXACTLY AT `after` MUST NOT BE RETURNED AGAIN — that is what
	// double-fires on a restart, when the scheduler asks "what is next" with
	// the last run's timestamp.
	loc := time.UTC
	spec := mustParse(t, "0 * * * *")
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, loc)

	next, err := Next(spec, at, loc)
	if err != nil {
		t.Fatal(err)
	}
	if !next.After(at) {
		t.Fatalf("next = %s, which is not after %s", next, at)
	}
	if next.Hour() != 11 {
		t.Errorf("next = %s, want 11:00", next.Format(time.RFC3339))
	}
}

func TestStepsAreHonoured(t *testing.T) {
	loc := time.UTC
	spec := mustParse(t, "*/15 * * * *")
	cursor := time.Date(2026, 6, 1, 10, 0, 0, 0, loc)

	want := []int{15, 30, 45, 0}
	for i, minute := range want {
		next, err := Next(spec, cursor, loc)
		if err != nil {
			t.Fatal(err)
		}
		if next.Minute() != minute {
			t.Fatalf("run %d at minute %d, want %d", i, next.Minute(), minute)
		}
		cursor = next
	}
}

// ---------------------------------------------------------------------------
// Missed runs
// ---------------------------------------------------------------------------

func TestCatchUpFiresOnceAndRecordsTheRest(t *testing.T) {
	// ⚠ AN HOURLY CAMPAIGN DOWN FOR TWO DAYS HAS 48 MISSED OCCURRENCES.
	//
	// Firing all of them is a thundering herd: 48 concurrent scans of the same
	// projects, starving every other tenant and producing 48 near-identical
	// reports. Firing none leaves an invisible gap a compliance customer
	// discovers at audit.
	loc := time.UTC
	spec := mustParse(t, "0 * * * *")

	lastRun := time.Date(2026, 6, 1, 0, 0, 0, 0, loc)
	now := time.Date(2026, 6, 1, 6, 30, 0, 0, loc)

	occurrences, err := CatchUp(spec, lastRun, now, loc)
	if err != nil {
		t.Fatal(err)
	}

	if len(occurrences) != 6 {
		t.Fatalf("got %d occurrences, want 6 missed hours", len(occurrences))
	}

	var fired, skipped int
	for _, o := range occurrences {
		if o.Skipped {
			skipped++
			if o.Reason == "" {
				t.Error("a skipped occurrence carries no reason; the gap would be invisible")
			}
		} else {
			fired++
		}
	}

	if fired != 1 {
		t.Errorf("%d occurrences would fire, want exactly 1", fired)
	}
	if skipped != 5 {
		t.Errorf("%d occurrences recorded as skipped, want 5", skipped)
	}

	// The one that fires is the MOST RECENT — an old one would scan a state
	// the project is no longer in.
	last := occurrences[len(occurrences)-1]
	if last.Skipped {
		t.Error("the most recent missed occurrence was skipped rather than fired")
	}
	if last.ScheduledFor.Hour() != 6 {
		t.Errorf("the fired occurrence is %s, want 06:00", last.ScheduledFor.Format(time.RFC3339))
	}
}

func TestCatchUpReturnsNothingWhenNothingWasMissed(t *testing.T) {
	loc := time.UTC
	spec := mustParse(t, "0 3 * * *")

	lastRun := time.Date(2026, 6, 1, 3, 0, 0, 0, loc)
	now := time.Date(2026, 6, 1, 4, 0, 0, 0, loc)

	occurrences, err := CatchUp(spec, lastRun, now, loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(occurrences) != 0 {
		t.Fatalf("got %d occurrences from an up-to-date campaign", len(occurrences))
	}
}

func TestSkipReasonNamesTheSupersedingRun(t *testing.T) {
	loc := time.UTC
	spec := mustParse(t, "0 * * * *")

	occurrences, err := CatchUp(spec,
		time.Date(2026, 6, 1, 0, 0, 0, 0, loc),
		time.Date(2026, 6, 1, 3, 30, 0, 0, loc), loc)
	if err != nil {
		t.Fatal(err)
	}

	// A reader of the run history needs to know WHICH run covered the gap, not
	// merely that one did.
	if !contains(occurrences[0].Reason, "03:00") {
		t.Errorf("the skip reason does not name the superseding run: %q", occurrences[0].Reason)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
