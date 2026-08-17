package level

import (
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/model"
)

func depth(n int) *int { return &n }

func corpus() []Component {
	return []Component{
		{Key: "root", Depth: depth(0), IsDirect: false},
		{Key: "direct-a", Depth: depth(1), IsDirect: true},
		{Key: "direct-b", Depth: depth(1), IsDirect: true},
		{Key: "transitive-a", Depth: depth(2)},
		{Key: "transitive-b", Depth: depth(3)},
		{Key: "orphan", Depth: nil, IsOrphan: true},
		{Key: "out-of-scope", Depth: depth(1), Scope: "excluded"},
	}
}

func TestTopLevelKeepsOnlyDepthZeroAndOne(t *testing.T) {
	p, err := Project(corpus(), TopLevel)
	if err != nil {
		t.Fatal(err)
	}

	keys := strings.Join(keysOf(p), ",")
	if keys != "direct-a,direct-b,root" {
		t.Fatalf("unexpected Top-Level set: %s", keys)
	}
	if p.ExcludedTransitive != 2 {
		t.Errorf("expected 2 transitive exclusions, got %d", p.ExcludedTransitive)
	}
}

// TestAnOrphanNeverAppearsInTopLevel is the honest-answer test.
//
// ⚠ We do not know where an orphan sits. Including it would assert a tree
// position that was never established; the alternative failure — forcing it to
// depth 1 — inflates the direct-dependency count, which is a headline number.
func TestAnOrphanNeverAppearsInTopLevel(t *testing.T) {
	p, _ := Project(corpus(), TopLevel)

	for _, c := range p.Components {
		if c.Key == "orphan" {
			t.Fatal("an orphan was included in a Top-Level BOM")
		}
	}
	if p.ExcludedOrphans != 1 {
		t.Errorf("the orphan was not counted as excluded: %d", p.ExcludedOrphans)
	}
}

func TestAnOrphanIsIncludedAndFlaggedInComplete(t *testing.T) {
	p, _ := Project(corpus(), Complete)

	found := false
	for _, c := range p.Components {
		if c.Key == "orphan" {
			found = true
			if c.Depth != nil {
				t.Error("the orphan acquired a depth")
			}
		}
	}
	if !found {
		t.Fatal("the orphan is missing from the Complete BOM")
	}

	if note := OrphanNote(p.Components); note == "" {
		t.Error("a Complete BOM containing orphans must flag them")
	}
}

// TestNothingIsSilentlyDropped is the property that makes a narrowed report
// honest rather than merely shorter.
func TestNothingIsSilentlyDropped(t *testing.T) {
	all := corpus()
	for _, l := range []Level{TopLevel, Complete} {
		p, _ := Project(all, l)
		if got := p.Total() + p.ExcludedTotal(); got != len(all) {
			t.Errorf("%s: %d listed + %d excluded = %d, but there are %d components",
				l, p.Total(), p.ExcludedTotal(), got, len(all))
		}
	}
}

// TestANarrowedReportSaysSo — a Top-Level report claiming "42 components"
// without saying it omitted 900 is indistinguishable from a project that
// genuinely has 42.
func TestANarrowedReportSaysSo(t *testing.T) {
	p, _ := Project(corpus(), TopLevel)

	if p.Note == "" {
		t.Fatal("a narrowed report carries no note explaining the narrowing")
	}
	for _, want := range []string{"Top-Level", "transitive", "omits"} {
		if !strings.Contains(p.Note, want) {
			t.Errorf("the note does not mention %q: %s", want, p.Note)
		}
	}
	if !strings.Contains(p.Note, "Complete BOM") {
		t.Error("the note should point at where the omitted components can be found")
	}
}

func TestAnUnnarrowedReportHasNoNote(t *testing.T) {
	clean := []Component{{Key: "a", Depth: depth(1)}}
	p, _ := Project(clean, TopLevel)
	if p.Note != "" {
		t.Errorf("nothing was excluded but a note was rendered: %s", p.Note)
	}
}

func TestExcludedScopeIsDroppedFromBothLevelsButCounted(t *testing.T) {
	for _, l := range []Level{TopLevel, Complete} {
		p, _ := Project(corpus(), l)
		for _, c := range p.Components {
			if c.Key == "out-of-scope" {
				t.Errorf("%s: an out-of-scope component was listed", l)
			}
		}
		if p.ExcludedByScope != 1 {
			t.Errorf("%s: out-of-scope component was not counted", l)
		}
	}
}

// TestAnUnimplementedLevelIsRefused — rendering a Complete BOM under a label
// the customer chose for something narrower would mislabel the report.
func TestAnUnimplementedLevelIsRefused(t *testing.T) {
	for _, l := range []Level{"n-level", "delivery", "transitive", ""} {
		if _, err := Project(corpus(), l); err == nil {
			t.Errorf("level %q was accepted but is not implemented", l)
		}
	}
}

func TestProjectionIsDeterministic(t *testing.T) {
	a, _ := Project(corpus(), Complete)
	reversed := corpus()
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	b, _ := Project(reversed, Complete)

	if strings.Join(keysOf(a), ",") != strings.Join(keysOf(b), ",") {
		t.Error("projection output depends on input order")
	}
}

func keysOf(p Projection) []string {
	out := make([]string, 0, len(p.Components))
	for _, c := range p.Components {
		out = append(out, c.Key)
	}
	return out
}

// TestLevelsMatchTheProfile is the guard for a bug that only a real database
// would otherwise have found.
//
// ⚠ THE LEVEL STRING CROSSES THREE BOUNDARIES. This package uses it, the
// database CHECK on report.reports.level accepts it, and both derive from
// certin-v2.0.yaml via model.BOMLevels. These constants were spelled
// `top-level` with a hyphen at first — which reads fine in Go, renders fine in
// a report, and fails the CHECK constraint on the first INSERT with an error
// pointing at the database rather than at the two spellings.
//
// Nothing in the Go build catches that, so this does.
func TestLevelsMatchTheProfile(t *testing.T) {
	for _, l := range []Level{TopLevel, Complete} {
		if !Known(l) {
			t.Errorf("level %q is not in model.BOMLevels (%v), so an INSERT using "+
				"it will fail the CHECK constraint on report.reports.level",
				l, model.BOMLevels)
		}
	}
}

// TestKnownAndValidAreDifferentQuestions.
//
// "we do not build that yet" and "that is not a BOM level" call for different
// answers. A caller asking for `delivery` deserves the first; collapsing them
// would have somebody spend an afternoon checking the spelling of a level that
// this build genuinely does not produce.
func TestKnownAndValidAreDifferentQuestions(t *testing.T) {
	for _, l := range []Level{"n_level", "delivery", "transitive"} {
		if !Known(l) {
			t.Errorf("%q is defined by CERT-In §3.1 but Known() says otherwise", l)
		}
		if Valid(l) {
			t.Errorf("%q is not produced by this build but Valid() accepts it; a "+
				"report would be labelled with a level narrower than its contents", l)
		}
	}

	for _, l := range []Level{"top-level", "", "nonsense"} {
		if Known(l) {
			t.Errorf("%q is not a CERT-In level but Known() accepts it", l)
		}
	}
}
