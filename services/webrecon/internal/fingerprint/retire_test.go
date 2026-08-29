package fingerprint_test

import (
	"testing"

	"github.com/axebom/axebom/services/webrecon/internal/fingerprint"
)

// ⚠ THE RE2/PCRE COMPATIBILITY SPIKE, AS A PERMANENT REGRESSION GUARD.
//
// These exact counts were measured by compiling every uri+filecontent
// pattern in the real, vendored retire.js database against Go's regexp —
// see signatures/PROVENANCE.md for the full spike. This test pins them so a
// re-vendored (newer) database that silently changes the compatibility
// picture — more backreferences added, say — is caught here, not discovered
// as a quiet drop in detection coverage months later.
func TestLoadSignaturesMatchesTheSpikeFindings(t *testing.T) {
	m, stats, err := fingerprint.LoadSignatures(fingerprint.EmbeddedSignatures)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if m == nil {
		t.Fatal("LoadSignatures returned a nil Matcher with no error")
	}

	if stats.Libraries != 76 {
		t.Errorf("Libraries = %d, want 76 (the vendored database's own library count)", stats.Libraries)
	}
	// 76 uri + 208 filecontent = 284 total. filecontentreplace (8 patterns)
	// and hashes (18 entries) are deliberately not loaded by this package —
	// see its own doc comment.
	if stats.PatternsTotal != 284 {
		t.Errorf("PatternsTotal = %d, want 284 (76 uri + 208 filecontent)", stats.PatternsTotal)
	}
	if stats.SkippedIncompatible != 2 {
		t.Errorf("SkippedIncompatible = %d, want 2 (jQuery's backreference filecontent variant "+
			"and lodash's lookbehind variant — see the PROVENANCE doc)", stats.SkippedIncompatible)
	}
	if stats.CappedRepeat != 7 {
		t.Errorf("CappedRepeat = %d, want 7 (tinyMCE, underscore.js, Vue x2, Next.js x2, select2 "+
			"— see the PROVENANCE doc)", stats.CappedRepeat)
	}
	wantCompiled := stats.PatternsTotal - stats.SkippedIncompatible
	if stats.PatternsCompiled != wantCompiled {
		t.Errorf("PatternsCompiled = %d, want %d (total minus skipped)", stats.PatternsCompiled, wantCompiled)
	}
}

// A real, well-known signature — jQuery's own minified banner — must still
// match AND extract the correct version, proving the capture-group
// substitution and the matcher's happy path both work against real data, not
// just a synthetic fixture.
func TestMatchContentDetectsAKnownLibrary(t *testing.T) {
	m, _, err := fingerprint.LoadSignatures(fingerprint.EmbeddedSignatures)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}

	const banner = `/*! jQuery v3.5.1 | (c) JS Foundation and other contributors | jquery.org/license */`
	match, ok := m.MatchContent(banner)
	if !ok {
		t.Fatal("jQuery's own real banner comment did not match any filecontent signature")
	}
	if match.Library != "jquery" {
		t.Errorf("library = %q, want jquery", match.Library)
	}
	if match.Version != "3.5.1" {
		t.Errorf("version = %q, want 3.5.1", match.Version)
	}
}

// jQuery 1.6.2 falls inside CVE-2011-4969's `below: 1.6.3` range — a real,
// still-listed advisory in the vendored database — proving version-range
// evaluation actually attaches vulnerabilities, not just detects the
// library.
func TestMatchContentAttachesAKnownVulnerability(t *testing.T) {
	m, _, err := fingerprint.LoadSignatures(fingerprint.EmbeddedSignatures)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}

	const banner = `/*! jQuery v1.6.2 | (c) JS Foundation and other contributors | jquery.org/license */`
	match, ok := m.MatchContent(banner)
	if !ok {
		t.Fatal("jQuery 1.6.2's banner did not match")
	}
	found := false
	for _, v := range match.Vulnerabilities {
		for _, cve := range v.CVE {
			if cve == "CVE-2011-4969" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("jQuery 1.6.2 should be flagged for CVE-2011-4969 (below 1.6.3); got %+v", match.Vulnerabilities)
	}
}

// A version at or past every known vulnerability's ceiling must carry none —
// the matcher must not over-flag, which would be as dishonest as
// under-flagging.
func TestMatchContentReportsNoVulnerabilitiesForAPatchedVersion(t *testing.T) {
	m, _, err := fingerprint.LoadSignatures(fingerprint.EmbeddedSignatures)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}

	const banner = `/*! jQuery v3.7.1 | (c) JS Foundation and other contributors | jquery.org/license */`
	match, ok := m.MatchContent(banner)
	if !ok {
		t.Fatal("jQuery 3.7.1's banner did not match")
	}
	if len(match.Vulnerabilities) != 0 {
		t.Errorf("jQuery 3.7.1 should carry no vulnerabilities from this database; got %+v", match.Vulnerabilities)
	}
}

func TestMatchContentReturnsFalseForOrdinaryCode(t *testing.T) {
	m, _, err := fingerprint.LoadSignatures(fingerprint.EmbeddedSignatures)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}

	if _, ok := m.MatchContent(`function add(a, b) { return a + b; }`); ok {
		t.Error("ordinary application code matched a library signature")
	}
}

func TestLoadSignaturesRejectsMalformedJSON(t *testing.T) {
	_, _, err := fingerprint.LoadSignatures([]byte(`not json`))
	if err == nil {
		t.Fatal("malformed JSON was accepted")
	}
}
