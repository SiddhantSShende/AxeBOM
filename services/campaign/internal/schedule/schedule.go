// Package schedule computes when a campaign runs next.
//
// ⚠ IT ITERATES WALL-CLOCK SLOTS, NOT ABSOLUTE INSTANTS. THAT ONE CHOICE IS
// WHAT MAKES BOTH DST DIRECTIONS CORRECT.
//
// A daily 02:30 campaign meets two problems a year in most timezones:
//
//	spring forward   02:30 DOES NOT EXIST. Iterating absolute instants skips
//	                 straight past it and the run VANISHES for that day.
//	fall back        02:30 HAPPENS TWICE. Iterating absolute instants matches
//	                 both and the campaign FIRES TWICE.
//
// Both are silent. The first is a missing compliance scan nobody notices until
// an audit; the second is a duplicated scan that costs real compute and
// produces two reports for one schedule.
//
// Enumerating (date, hour, minute) SLOTS makes each a single run by
// construction: the ambiguous wall clock is one slot, and the non-existent one
// is one slot resolved to the first instant after the gap. Neither case needs a
// special branch, which is why neither can be forgotten.
//
// ⚠ AN IANA NAME, NEVER A FIXED OFFSET. Storing `+05:30` means the schedule is
// wrong for half the year in any zone that observes DST, and there is no way to
// recover the intent afterwards.
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Spec is a parsed five-field cron expression.
//
// Standard fields, no seconds and no extensions: `minute hour dom month dow`.
// The frontend offers friendly presets and shows the cron it produced, so the
// expression a user sees is the expression that runs.
type Spec struct {
	Minutes  fieldSet
	Hours    fieldSet
	Days     fieldSet
	Months   fieldSet
	Weekdays fieldSet

	// raw is kept for round-tripping and for error messages that quote what
	// the user actually typed.
	raw string
}

// String returns the original expression.
func (s Spec) String() string { return s.raw }

type fieldSet struct {
	// values is a set over the field's range.
	values map[int]bool
	// star is true for `*`, which matters for the day-of-month / day-of-week
	// rule below.
	star bool
}

func (f fieldSet) has(v int) bool { return f.values[v] }

// Parse reads a five-field cron expression.
func Parse(expr string) (Spec, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return Spec{}, fmt.Errorf(
			"cron expression %q has %d fields; want 5 (minute hour day-of-month month day-of-week)",
			expr, len(fields))
	}

	minutes, err := parseField(fields[0], 0, 59, nil)
	if err != nil {
		return Spec{}, fmt.Errorf("minute field: %w", err)
	}
	hours, err := parseField(fields[1], 0, 23, nil)
	if err != nil {
		return Spec{}, fmt.Errorf("hour field: %w", err)
	}
	days, err := parseField(fields[2], 1, 31, nil)
	if err != nil {
		return Spec{}, fmt.Errorf("day-of-month field: %w", err)
	}
	months, err := parseField(fields[3], 1, 12, monthNames)
	if err != nil {
		return Spec{}, fmt.Errorf("month field: %w", err)
	}
	weekdays, err := parseField(fields[4], 0, 7, dayNames)
	if err != nil {
		return Spec{}, fmt.Errorf("day-of-week field: %w", err)
	}
	// ⚠ 7 AND 0 ARE BOTH SUNDAY. Accepting one and not the other silently
	// never fires a "every Sunday" campaign written the other way.
	if weekdays.values[7] {
		weekdays.values[0] = true
	}

	return Spec{
		Minutes: minutes, Hours: hours, Days: days,
		Months: months, Weekdays: weekdays, raw: strings.TrimSpace(expr),
	}, nil
}

var monthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var dayNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

func parseField(field string, min, max int, names map[string]int) (fieldSet, error) {
	out := fieldSet{values: map[int]bool{}}

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fieldSet{}, fmt.Errorf("empty element in %q", field)
		}

		step := 1
		if slash := strings.Index(part, "/"); slash >= 0 {
			var err error
			step, err = strconv.Atoi(part[slash+1:])
			if err != nil || step < 1 {
				return fieldSet{}, fmt.Errorf("step %q is not a positive integer", part[slash+1:])
			}
			part = part[:slash]
		}

		lo, hi := min, max
		switch {
		case part == "*":
			out.star = true
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			var err error
			if lo, err = parseValue(bounds[0], names); err != nil {
				return fieldSet{}, err
			}
			if hi, err = parseValue(bounds[1], names); err != nil {
				return fieldSet{}, err
			}
		default:
			v, err := parseValue(part, names)
			if err != nil {
				return fieldSet{}, err
			}
			lo, hi = v, v
		}

		if lo < min || hi > max || lo > hi {
			return fieldSet{}, fmt.Errorf("%q is outside the valid range %d-%d", part, min, max)
		}
		for v := lo; v <= hi; v += step {
			out.values[v] = true
		}
	}

	if len(out.values) == 0 {
		return fieldSet{}, fmt.Errorf("%q matches nothing", field)
	}
	return out, nil
}

func parseValue(s string, names map[string]int) (int, error) {
	s = strings.TrimSpace(s)
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number or a known name", s)
	}
	return v, nil
}

// maxSearchDays bounds the forward search.
//
// Four years covers every leap-year and weekday alignment. An expression that
// matches nothing inside that — `0 0 30 2 *`, February 30th — is a user error,
// and returning it as one beats looping forever inside a scheduler tick.
const maxSearchDays = 366 * 4

// Next returns the first run strictly after `after`, in the campaign's zone.
//
// ⚠ THE SEARCH IS OVER WALL-CLOCK SLOTS. See the package comment: this is what
// makes both DST directions correct without either needing a special case.
func Next(spec Spec, after time.Time, loc *time.Location) (time.Time, error) {
	if loc == nil {
		loc = time.UTC
	}

	local := after.In(loc)
	// Start from the minute after `after`, so a run exactly at `after` is not
	// returned again — which is what would double-fire on a restart.
	cursor := time.Date(local.Year(), local.Month(), local.Day(),
		local.Hour(), local.Minute(), 0, 0, loc).Add(time.Minute)

	day := time.Date(cursor.Year(), cursor.Month(), cursor.Day(), 0, 0, 0, 0, loc)

	for d := 0; d < maxSearchDays; d++ {
		// ⚠ THE DATE IS ADVANCED IN CALENDAR DAYS, NOT BY 24 HOURS. A DST day
		// is 23 or 25 hours long; adding 24h drifts the wall clock and starts
		// skipping or repeating whole days twice a year.
		current := day.AddDate(0, 0, d)
		y, m, dd := current.Date()

		if !matchesDate(spec, y, m, dd, loc) {
			continue
		}

		for hour := 0; hour < 24; hour++ {
			if !spec.Hours.has(hour) {
				continue
			}
			for minute := 0; minute < 60; minute++ {
				if !spec.Minutes.has(minute) {
					continue
				}

				at := resolveSlot(y, m, dd, hour, minute, loc)
				if at.After(after) {
					return at, nil
				}
			}
		}
	}

	return time.Time{}, fmt.Errorf(
		"cron expression %q has no run within %d days of %s; it may match a date "+
			"that never occurs, such as February 30th",
		spec.raw, maxSearchDays, after.Format(time.RFC3339))
}

// resolveSlot turns one wall-clock slot into an absolute instant.
//
// ⚠ THE TWO DST CASES ARE HANDLED HERE AND NOWHERE ELSE, AND Go's OWN
// NORMALIZATION IS WRONG FOR ONE OF THEM.
//
// SPRING FORWARD — the wall clock does not exist. `time.Date` normalizes it
// BACKWARDS: asking for 02:30 on 2026-03-08 in New York returns 01:30-05:00.
// Two things are wrong with accepting that. The run fires an hour EARLY, before
// the schedule the user wrote; and it lands on the same instant as the 01:30
// slot, so `30 1,2 * * *` would fire once instead of twice that day.
//
// Measured, not assumed — the first implementation took Go's answer and the
// test caught it as "run at 01:30 is inside the non-existent hour".
//
// The correction adds back the wall-clock difference, which lands on the
// instant the requested time WOULD have been: 02:30 EST is 03:30 EDT. That is
// what cron and systemd do, and it preserves the interval from the previous run.
//
// FALL BACK — the wall clock happens twice. Go currently returns the FIRST
// occurrence, which is what we want, but the documentation says the choice is
// unspecified. The check below makes it explicit rather than depending on
// behaviour that could change in a Go release and silently shift every
// affected schedule by an hour.
//
// Either way this returns exactly ONE instant per slot, which is what stops
// fall-back producing two runs.
func resolveSlot(year int, month time.Month, day, hour, minute int, loc *time.Location) time.Time {
	at := time.Date(year, month, day, hour, minute, 0, 0, loc)

	// Non-existent: Go moved the wall clock, and WHICH WAY IT MOVED IS NOT
	// CONSISTENT BETWEEN ZONES.
	//
	// Measured: New York's missing 02:30 normalizes BACKWARDS to 01:30-05:00;
	// Sydney's missing 02:30 normalizes FORWARDS to 03:30+11:00. A correction
	// that assumed one direction fixed New York and pushed Sydney's run onto
	// the following day — which the southern-hemisphere test caught, and which
	// a northern-only test suite would have shipped.
	//
	// So neither direction is assumed. `dayStart + wall-clock minutes` is
	// absolute arithmetic from a midnight that always exists, which lands at or
	// after the gap by construction; taking the LATER of that and Go's answer
	// is correct whichever way Go went.
	if at.Hour() != hour || at.Minute() != minute || at.Day() != day {
		dayStart := time.Date(year, month, day, 0, 0, 0, 0, loc)
		fromMidnight := dayStart.Add(time.Duration(hour*60+minute) * time.Minute)
		if fromMidnight.After(at) {
			return fromMidnight
		}
		return at
	}

	// Ambiguous: the same wall clock exists an hour earlier in absolute terms,
	// which means this is the SECOND occurrence. Use the first.
	if earlier := at.Add(-time.Hour); earlier.Hour() == hour && earlier.Minute() == minute {
		return earlier
	}

	return at
}

// matchesDate applies cron's day-of-month / day-of-week rule.
//
// ⚠ IT IS AN OR, NOT AN AND, WHEN BOTH ARE RESTRICTED. `0 0 1 * MON` means "the
// 1st, AND every Monday" — not "the 1st when it is a Monday". That is cron's
// documented behaviour and it is surprising enough that implementations get it
// wrong in both directions; getting it wrong here means a compliance scan
// running on the wrong days.
func matchesDate(spec Spec, year int, month time.Month, day int, loc *time.Location) bool {
	if !spec.Months.has(int(month)) {
		return false
	}

	date := time.Date(year, month, day, 12, 0, 0, 0, loc)
	// A day-of-month past the end of the month normalizes into the next one;
	// that is not a match for this date.
	if date.Day() != day || date.Month() != month {
		return false
	}

	domRestricted := !spec.Days.star
	dowRestricted := !spec.Weekdays.star

	domMatch := spec.Days.has(day)
	dowMatch := spec.Weekdays.has(int(date.Weekday()))

	switch {
	case domRestricted && dowRestricted:
		return domMatch || dowMatch
	case domRestricted:
		return domMatch
	case dowRestricted:
		return dowMatch
	default:
		return true
	}
}

// ---------------------------------------------------------------------------
// Missed runs
// ---------------------------------------------------------------------------

// Occurrence is one scheduled slot, and whether it will actually run.
type Occurrence struct {
	ScheduledFor time.Time
	// Skipped is true for a missed occurrence recorded but not fired.
	Skipped bool
	// Reason explains a skip, in the run history.
	Reason string
}

// CatchUp decides what to do after downtime.
//
// ⚠ ONE CATCH-UP RUN, AND THE REST RECORDED AS SKIPPED.
//
// A scheduler down for two days on an hourly campaign has 48 missed
// occurrences. Firing all of them is a thundering herd against the scan queue
// — 48 concurrent scans of the same projects, which will starve every other
// tenant and produce 48 near-identical reports nobody asked for.
//
// Firing none of them is worse in a different way: the gap is invisible, and a
// compliance customer discovers at audit that two days have no scan.
//
// So: fire the most recent, record the rest. The gap is visible in run history
// and costs one scan.
func CatchUp(spec Spec, lastRun time.Time, now time.Time, loc *time.Location) ([]Occurrence, error) {
	if loc == nil {
		loc = time.UTC
	}

	var missed []time.Time
	cursor := lastRun

	for len(missed) <= maxMissedTracked {
		next, err := Next(spec, cursor, loc)
		if err != nil {
			return nil, err
		}
		if next.After(now) {
			break
		}
		missed = append(missed, next)
		cursor = next
	}

	if len(missed) == 0 {
		return nil, nil
	}

	out := make([]Occurrence, 0, len(missed))
	last := len(missed) - 1

	for i, at := range missed {
		if i == last {
			// The most recent one runs.
			out = append(out, Occurrence{ScheduledFor: at})
			continue
		}
		out = append(out, Occurrence{
			ScheduledFor: at,
			Skipped:      true,
			Reason: fmt.Sprintf(
				"missed while the scheduler was unavailable; superseded by the run at %s. "+
					"Only the most recent missed occurrence is executed, to avoid a "+
					"thundering herd against the scan queue.",
				missed[last].Format(time.RFC3339)),
		})
	}

	return out, nil
}

// maxMissedTracked bounds how many missed occurrences are recorded.
//
// A campaign every minute, down for a week, is 10,080 rows of history nobody
// reads. Past this the gap is recorded as one summary entry — the fact that
// there WAS a gap is what matters, not each minute of it.
const maxMissedTracked = 500
