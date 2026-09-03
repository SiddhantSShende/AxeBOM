package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/services/report/internal/render"
	"github.com/axebom/axebom/services/report/internal/store"
)

// fakeLoader is a Source whose Load returns a scripted sequence of results,
// one per call — enough to drive loadNormalizedBOM through "not found a few
// times, then found" and "never found" without a real database.
type fakeLoader struct {
	results []loadResult
	calls   int
}

type loadResult struct {
	bom render.BOM
	err error
}

func (f *fakeLoader) Load(_ context.Context, _ store.Report) (render.BOM, error) {
	i := f.calls
	f.calls++
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	return f.results[i].bom, f.results[i].err
}

func testWorker(src Source) *Worker {
	return &Worker{source: src, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestLoadNormalizedBOM(t *testing.T) {
	t.Run("succeeds immediately, no waiting", func(t *testing.T) {
		want := render.BOM{ReportID: "r1"}
		src := &fakeLoader{results: []loadResult{{bom: want, err: nil}}}
		w := testWorker(src)

		got, err := w.loadNormalizedBOM(context.Background(), store.Report{ID: "r1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ReportID != want.ReportID {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if src.calls != 1 {
			t.Errorf("calls = %d, want 1 (no retry needed)", src.calls)
		}
	})

	// ⚠ THE REGRESSION THIS GUARDS. A report queued the instant its scan is
	// created can race normalization by a second or two — confirmed live
	// against a real webrecon-sourced scan (see loadNormalizedBOM's doc
	// comment). This is that race, reproduced deterministically: not found
	// twice, then found — same as the real timeline where the third check
	// would have landed after normalize.bom_documents was written.
	t.Run("retries through store.ErrNotFound and succeeds once the document appears", func(t *testing.T) {
		restoreDelay := normalizedBOMRetryDelay
		normalizedBOMRetryDelay = time.Millisecond
		defer func() { normalizedBOMRetryDelay = restoreDelay }()

		want := render.BOM{ReportID: "r1"}
		src := &fakeLoader{results: []loadResult{
			{err: store.ErrNotFound},
			{err: store.ErrNotFound},
			{bom: want, err: nil},
		}}
		w := testWorker(src)

		got, err := w.loadNormalizedBOM(context.Background(), store.Report{ID: "r1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ReportID != want.ReportID {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if src.calls != 3 {
			t.Errorf("calls = %d, want 3 (two misses, one hit)", src.calls)
		}
	})

	t.Run("gives up after normalizedBOMRetryAttempts and returns ErrNotFound", func(t *testing.T) {
		restoreDelay := normalizedBOMRetryDelay
		normalizedBOMRetryDelay = time.Millisecond
		defer func() { normalizedBOMRetryDelay = restoreDelay }()

		src := &fakeLoader{results: []loadResult{{err: store.ErrNotFound}}}
		w := testWorker(src)

		_, err := w.loadNormalizedBOM(context.Background(), store.Report{ID: "r1"})
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("err = %v, want store.ErrNotFound", err)
		}
		if src.calls != normalizedBOMRetryAttempts {
			t.Errorf("calls = %d, want %d (every attempt spent)", src.calls, normalizedBOMRetryAttempts)
		}
	})

	// ⚠ ANY OTHER ERROR IS TERMINAL, IMMEDIATELY. Only "the document does not
	// exist yet" is a race worth waiting out; a real query failure retrying
	// silently for normalizedBOMRetryAttempts * normalizedBOMRetryDelay would
	// turn a fast, diagnosable failure into a slow one for no benefit.
	t.Run("does not retry a non-ErrNotFound failure", func(t *testing.T) {
		boom := errors.New("boom")
		src := &fakeLoader{results: []loadResult{{err: boom}}}
		w := testWorker(src)

		_, err := w.loadNormalizedBOM(context.Background(), store.Report{ID: "r1"})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
		if src.calls != 1 {
			t.Errorf("calls = %d, want 1 (no retry on a non-ErrNotFound error)", src.calls)
		}
	})

	t.Run("returns promptly when the context is cancelled mid-wait", func(t *testing.T) {
		restoreDelay := normalizedBOMRetryDelay
		normalizedBOMRetryDelay = time.Hour
		defer func() { normalizedBOMRetryDelay = restoreDelay }()

		src := &fakeLoader{results: []loadResult{{err: store.ErrNotFound}}}
		w := testWorker(src)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan struct{})
		var err error
		go func() {
			_, err = w.loadNormalizedBOM(ctx, store.Report{ID: "r1"})
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("loadNormalizedBOM did not return promptly on context cancellation")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

func TestTheVulnMatchStatusIsExportedEvenWhenNothingWasSearched(t *testing.T) {
	// ⚠ THE ONE PROPERTY THAT MUST NOT BE OMITTED WHEN EMPTY.
	//
	// Every other absent value is omitted, because the coverage numbers report
	// the gap. If the status were omitted too, a hardware component would reach
	// SPDX and CycloneDX with no vulnerability properties at all — which every
	// downstream consumer reads as "no known vulnerabilities". That is the most
	// dangerous wrong inference this export can invite, and it is invited by
	// silence rather than by a wrong value.
	props := hardwareProperties(render.HardwareComponent{Name: "Resistor"})

	var status string
	for _, p := range props {
		if p.Name == "axebom:hbom:vuln_match_status" {
			status = p.Value
		}
	}
	if status != "not-attempted" {
		t.Fatalf("an unsearched component exports status %q, want %q", status, "not-attempted")
	}
}

func TestAnExportedHardwareCVENeverAppearsWithoutItsQualifier(t *testing.T) {
	// A bare CVE id in a standards document asserts the part is affected. It is
	// a string match against NVD's vocabulary, and the qualifier has to be
	// inseparable from the claim.
	props := hardwareProperties(render.HardwareComponent{
		Name:            "MCU",
		VulnMatchStatus: "matched",
		Vulnerabilities: []render.HardwareFinding{{
			CVEID:           "CVE-2021-1472",
			MatchBasis:      "vendor+product",
			MatchConfidence: "low",
		}},
	})

	var found bool
	for _, p := range props {
		if p.Name != "certin:hbom:vulnerability" {
			continue
		}
		found = true
		if p.Value == "CVE-2021-1472" {
			t.Errorf("the CVE is exported bare, with no advisory qualifier: %q", p.Value)
		}
		for _, want := range []string{"CVE-2021-1472", "vendor+product", "low", "advisory"} {
			if !strings.Contains(p.Value, want) {
				t.Errorf("the exported value %q omits %q", p.Value, want)
			}
		}
	}
	if !found {
		t.Error("no vulnerability property was exported for a matched component")
	}
}
