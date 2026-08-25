package csaf

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 8, 17, 9, 14, 3, 0, time.UTC)

func input() VEXInput {
	return VEXInput{
		ClusterID:     "cluster-1",
		DisplayID:     "CVE-2021-23337",
		Aliases:       []string{"GHSA-35jh-r3h4-6jhm"},
		Status:        "not_affected",
		Justification: "vulnerable_code_not_in_execute_path",
		Products: []Product{
			{ID: "lodash-4.17.20", Name: "lodash 4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
		},
		Version:   1,
		CreatedAt: fixedTime,
	}
}

func options() Options {
	return Options{
		TrackingID:    "AXEBOM-2026-0001",
		Title:         "lodash prototype pollution assessment",
		PublisherName: "Acme Ltd",
		PublisherNS:   "https://acme.example",
		Now:           fixedTime,
	}
}

// ---------------------------------------------------------------------------
// Round trip — the exit criterion
// ---------------------------------------------------------------------------

// TestRoundTrip is the phase's named exit criterion.
//
// ⚠ THE UNMODELLED FIELDS ARE THE POINT. CSAF 2.0 defines far more than this
// product models, and `csaf_advisories.document` claims to store the full
// document "for round-trip fidelity". A parser that silently drops what it does
// not understand makes that claim false — and the loss surfaces at whoever
// consumes the document next, not here.
func TestRoundTrip(t *testing.T) {
	original := []byte(`{
	  "document": {
	    "category": "csaf_vex",
	    "csaf_version": "2.0",
	    "title": "Assessment",
	    "publisher": {"category": "vendor", "name": "Acme Ltd", "namespace": "https://acme.example"},
	    "tracking": {
	      "id": "ACME-2026-0001",
	      "status": "final",
	      "version": "2",
	      "initial_release_date": "2026-08-01T00:00:00Z",
	      "current_release_date": "2026-08-17T09:14:03Z",
	      "revision_history": [{"number": "1", "date": "2026-08-01T00:00:00Z", "summary": "Initial"}]
	    },
	    "lang": "en",
	    "distribution": {"tlp": {"label": "WHITE"}},
	    "aggregate_severity": {"text": "Moderate"}
	  },
	  "product_tree": {
	    "full_product_names": [
	      {"product_id": "p1", "name": "lodash", "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.20"}}
	    ]
	  },
	  "vulnerabilities": [
	    {
	      "cve": "CVE-2021-23337",
	      "product_status": {"known_not_affected": ["p1"]},
	      "threats": [{"category": "impact", "details": "not in execute path", "product_ids": ["p1"]}],
	      "discovery_date": "2021-02-15T00:00:00Z",
	      "involvements": [{"party": "vendor", "status": "completed"}]
	    }
	  ]
	}`)

	doc, err := Parse(original)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The fields we DO model came through.
	if doc.DocumentMeta.Tracking.ID != "ACME-2026-0001" {
		t.Errorf("tracking id = %q", doc.DocumentMeta.Tracking.ID)
	}
	if doc.Vulns[0].CVE != "CVE-2021-23337" {
		t.Errorf("cve = %q", doc.Vulns[0].CVE)
	}

	// ⚠ AND THE ONES WE DO NOT. `lang`, `distribution`, `aggregate_severity`,
	// `discovery_date` and `involvements` are all real CSAF fields this build
	// does not model — and all of them must survive.
	out, err := doc.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var before, after map[string]any
	if err := json.Unmarshal(original, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &after); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(before, after) {
		t.Fatalf("the document did not round-trip.\n before: %s\n after:  %s",
			mustIndent(before), mustIndent(after))
	}
}

func TestUnmodelledFieldsAreNamedInTheFailure(t *testing.T) {
	// A narrower check than the round trip, so a regression says WHICH field
	// was lost rather than dumping two documents.
	doc, err := Parse([]byte(`{
	  "document": {"category":"csaf_vex","csaf_version":"2.0","title":"t",
	    "publisher":{"category":"vendor","name":"n","namespace":"ns"},
	    "tracking":{"id":"i","status":"final","version":"1",
	      "initial_release_date":"2026-01-01T00:00:00Z",
	      "current_release_date":"2026-01-01T00:00:00Z",
	      "revision_history":[{"number":"1","date":"2026-01-01T00:00:00Z","summary":"s"}]},
	    "lang": "en"},
	  "custom_top_level": {"kept": true}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if doc.DocumentMeta.Extra["lang"] != "en" {
		t.Errorf("document.lang was dropped: %v", doc.DocumentMeta.Extra)
	}
	if doc.Extra["custom_top_level"] == nil {
		t.Errorf("a top-level unmodelled key was dropped: %v", doc.Extra)
	}
}

func TestExtraNeverOverwritesAModelledField(t *testing.T) {
	// ⚠ Extra IS A RECORD OF WHAT WE DID NOT UNDERSTAND, NOT A SHADOW COPY
	// THAT CAN WIN. A stale value there silently reverting an edit would be the
	// worst kind of bug: correct-looking output that ignores the change.
	doc, _ := Parse([]byte(`{"document":{"category":"csaf_vex","csaf_version":"2.0","title":"original",
	  "publisher":{"category":"vendor","name":"n","namespace":"ns"},
	  "tracking":{"id":"i","status":"final","version":"1",
	    "initial_release_date":"2026-01-01T00:00:00Z",
	    "current_release_date":"2026-01-01T00:00:00Z",
	    "revision_history":[{"number":"1","date":"2026-01-01T00:00:00Z","summary":"s"}]}}}`))

	doc.DocumentMeta.Extra = map[string]any{"title": "stale"}
	doc.DocumentMeta.Title = "edited"

	out, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"title":"edited"`) {
		t.Fatalf("Extra overwrote a modelled field: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

func TestGenerateProducesAValidDocument(t *testing.T) {
	doc, err := Generate([]VEXInput{input()}, options())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if problems := doc.Validate(); len(problems) > 0 {
		t.Fatalf("generated an invalid document: %v", problems)
	}
	if doc.DocumentMeta.Category != "csaf_vex" {
		t.Errorf("category = %q; this document asserts exploitability, it does not "+
			"announce a vulnerability", doc.DocumentMeta.Category)
	}
}

func TestTheStatusSpellingIsCSAFsNotCERTIns(t *testing.T) {
	// ⚠ NOT COSMETIC. Emitting `not_affected` into a CSAF document produces
	// something a consumer's validator rejects.
	doc, err := Generate([]VEXInput{input()}, options())
	if err != nil {
		t.Fatal(err)
	}

	status := doc.Vulns[0].ProductStatus
	if len(status.KnownNotAffected) != 1 {
		t.Fatalf("known_not_affected = %v, want the product", status.KnownNotAffected)
	}

	out, _ := doc.Marshal()
	if strings.Contains(string(out), `"not_affected"`) {
		t.Errorf("CERT-In's spelling leaked into the CSAF document: %s", out)
	}
}

func TestEveryCERTInStatusMapsToACSAFKey(t *testing.T) {
	for _, status := range []string{"not_affected", "affected", "fixed", "under_investigation"} {
		in := input()
		in.Status = status

		doc, err := Generate([]VEXInput{in}, options())
		if err != nil {
			t.Fatalf("status %q: %v", status, err)
		}

		s := doc.Vulns[0].ProductStatus
		total := len(s.Fixed) + len(s.KnownAffected) + len(s.KnownNotAffected) + len(s.UnderInvestigation)
		if total != 1 {
			t.Errorf("status %q produced %d product entries, want 1", status, total)
		}
	}
}

func TestAnUnknownStatusIsRefused(t *testing.T) {
	in := input()
	in.Status = "mitigated"
	if _, err := Generate([]VEXInput{in}, options()); err == nil {
		t.Fatal("a status outside CERT-In's four was published")
	}
}

func TestTheCVEGoesInCVEAndEverythingElseInIDs(t *testing.T) {
	// ⚠ CSAF's `cve` FIELD IS DEFINED AS A CVE. Putting a GHSA there produces a
	// document that validates structurally and lies about what the identifier is.
	doc, err := Generate([]VEXInput{input()}, options())
	if err != nil {
		t.Fatal(err)
	}

	v := doc.Vulns[0]
	if v.CVE != "CVE-2021-23337" {
		t.Errorf("cve = %q", v.CVE)
	}
	if len(v.IDs) != 1 || v.IDs[0].Text != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("ids = %+v, want the GHSA", v.IDs)
	}
	if v.IDs[0].SystemName != "GitHub Security Advisory" {
		t.Errorf("system name = %q; a consumer needs to know what scheme it is reading",
			v.IDs[0].SystemName)
	}
}

func TestACVEFoundOnlyInTheAliasesIsPromoted(t *testing.T) {
	// The display id is a GHSA but a CVE exists. CSAF's `cve` field should
	// carry it — that is the identifier a consumer's tooling keys on.
	in := input()
	in.DisplayID = "GHSA-35jh-r3h4-6jhm"
	in.Aliases = []string{"CVE-2021-23337"}

	doc, err := Generate([]VEXInput{in}, options())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Vulns[0].CVE != "CVE-2021-23337" {
		t.Errorf("cve = %q, want the alias promoted", doc.Vulns[0].CVE)
	}
}

func TestAJustificationBecomesTheImpactStatementCSAFRequires(t *testing.T) {
	doc, err := Generate([]VEXInput{input()}, options())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, threat := range doc.Vulns[0].Threats {
		if threat.Category == "impact" && threat.Details == "vulnerable_code_not_in_execute_path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the justification did not become an impact statement: %+v", doc.Vulns[0].Threats)
	}
}

func TestAnUnjustifiedSuppressionFailsGenerationRatherThanPublishing(t *testing.T) {
	// ⚠ THE ONE OUTPUT THIS PACKAGE MUST NEVER PRODUCE. Publishing an
	// unjustified suppression under a customer's name is worse than refusing.
	in := input()
	in.Justification = ""

	_, err := Generate([]VEXInput{in}, options())
	if err == nil {
		t.Fatal("an unjustified known_not_affected was published")
	}
	if !strings.Contains(err.Error(), "impact statement") {
		t.Errorf("the refusal does not name the missing piece: %v", err)
	}
}

func TestDowntimeIsPublishedRatherThanDropped(t *testing.T) {
	// Named in the guideline on p.35 and the field an operator planning a
	// remediation window actually needs. CSAF has no dedicated place for it, so
	// it becomes a note rather than being lost.
	in := input()
	in.Status = "fixed"
	in.Downtime = "30 minutes, rolling restart"

	doc, err := Generate([]VEXInput{in}, options())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, n := range doc.Vulns[0].Notes {
		if strings.Contains(n.Text, "rolling restart") {
			found = true
		}
	}
	if !found {
		t.Fatalf("downtime was dropped: %+v", doc.Vulns[0].Notes)
	}
}

func TestTheRevisionHistoryMirrorsTheSupersessionChain(t *testing.T) {
	// ⚠ PUBLISHING ONLY THE CURRENT VERSION THROWS AWAY THE EVIDENCE on the way
	// out — the same evidence the append-only VEX design exists to produce.
	in := input()
	in.Version = 3
	in.Revisions = []RevisionInput{
		{Version: 1, CreatedAt: fixedTime.AddDate(0, 0, -10), Summary: "Under investigation"},
		{Version: 2, CreatedAt: fixedTime.AddDate(0, 0, -5), Summary: "Confirmed affected"},
		{Version: 3, CreatedAt: fixedTime, Summary: "Not affected: code not reachable"},
	}

	doc, err := Generate([]VEXInput{in}, options())
	if err != nil {
		t.Fatal(err)
	}

	history := doc.DocumentMeta.Tracking.RevisionHistory
	if len(history) != 3 {
		t.Fatalf("revision history has %d entries, want the whole chain", len(history))
	}
	if history[0].Summary != "Under investigation" {
		t.Errorf("history is not oldest-first: %q", history[0].Summary)
	}
	if doc.DocumentMeta.Tracking.Version != "3" {
		t.Errorf("tracking version = %q, want the highest", doc.DocumentMeta.Tracking.Version)
	}
	// The initial release date is the FIRST decision, not this render.
	if !strings.HasPrefix(doc.DocumentMeta.Tracking.InitialReleaseDate, "2026-08-07") {
		t.Errorf("initial release date = %q, want the first revision's",
			doc.DocumentMeta.Tracking.InitialReleaseDate)
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	// A CSAF advisory is dated by the decision it publishes, not by the moment
	// somebody regenerated it — and a re-render must produce the same bytes.
	first, err := Generate([]VEXInput{input()}, options())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := first.Marshal()

	for i := range 20 {
		again, err := Generate([]VEXInput{input()}, options())
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		againBytes, _ := again.Marshal()
		if string(firstBytes) != string(againBytes) {
			t.Fatalf("the document changed between generations on iteration %d", i)
		}
	}
}

func TestATrackingIDAndPublisherAreRequired(t *testing.T) {
	opts := options()
	opts.TrackingID = ""
	if _, err := Generate([]VEXInput{input()}, opts); err == nil {
		t.Error("an advisory with no stable identity was generated")
	}

	opts = options()
	opts.PublisherName = ""
	if _, err := Generate([]VEXInput{input()}, opts); err == nil {
		t.Error("an advisory with no publisher was generated")
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestADanglingProductIDIsCaught(t *testing.T) {
	// ⚠ THE MOST COMMON WAY A HAND-BUILT CSAF DOCUMENT FAILS A CONSUMER'S
	// VALIDATOR, and it is silent in ours until somebody else parses it.
	doc := &Document{
		DocumentMeta: DocumentMeta{
			Category: "csaf_vex", CSAFVersion: "2.0", Title: "t",
			Publisher: Publisher{Name: "n"},
			Tracking: Tracking{
				ID:              "i",
				RevisionHistory: []Revision{{Number: "1"}},
			},
		},
		ProductTree: &ProductTree{FullProductNames: []FullProductName{{ProductID: "p1"}}},
		Vulns: []Vulnerability{{
			CVE:           "CVE-1",
			ProductStatus: &ProductStatus{KnownAffected: []string{"p1", "p-missing"}},
		}},
	}

	problems := doc.Validate()
	var found bool
	for _, p := range problems {
		if strings.Contains(p, "p-missing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a dangling product id was not caught: %v", problems)
	}
}

func TestTheWrongCSAFVersionIsRejected(t *testing.T) {
	doc := &Document{DocumentMeta: DocumentMeta{CSAFVersion: "1.2"}}
	if len(doc.Validate()) == 0 {
		t.Fatal("a CSAF 1.2 document was accepted")
	}
}

func mustIndent(v any) string {
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}
