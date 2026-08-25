package email

import (
	"reflect"
	"strings"
	"testing"
)

func data() Data {
	return Data{
		ProjectName: "payments-api",
		Status:      "completed_with_errors",
		Components:  412, Findings: 37, Critical: 3, High: 9,
		EnginesUnavailable: 1,
		UnavailableEngines: []string{"dependency-check"},
		URL:                "https://app.axebom.example/scans/0199",
		OccurredAt:         "2026-08-17T09:14:03Z",
	}
}

// TestNoMessageCarriesComponentOrVulnerabilityDetail.
//
// ⚠ AN EMAIL IS FORWARDED, SYNCED TO A PHONE, AND CROSSES AT LEAST ONE RELAY IN
// PLAINTEXT AT THE EDGES. BOM content is confidential under CERT-In §5.3, so
// the message says what happened and links to the detail.
func TestNoMessageCarriesComponentOrVulnerabilityDetail(t *testing.T) {
	// The forbidden strings are placed where a careless template would pick
	// them up — but Data has nowhere to put them, which is the actual control.
	d := data()
	d.ProjectName = "payments-api"

	for _, kind := range Kinds() {
		msg, err := Render(kind, d)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range []string{msg.Subject, msg.Text, msg.HTML} {
			for _, forbidden := range []string{"CVE-", "GHSA-", "pkg:", "lodash", "@4.17"} {
				if strings.Contains(part, forbidden) {
					t.Errorf("%s contains %q", kind, forbidden)
				}
			}
		}
	}
}

// TestEmailDataHasNoPlaceToPutComponentDetail is the structural half.
//
// The string test above only proves that TODAY's templates do not leak. This
// asserts the SHAPE: there is no field a future template could read a component
// name out of, so adding one is a deliberate, visible decision.
func TestEmailDataHasNoPlaceToPutComponentDetail(t *testing.T) {
	allowed := map[string]bool{
		"ProjectName": true, "CampaignName": true, "Status": true,
		"Components": true, "Findings": true, "Critical": true, "High": true,
		"EnginesUnavailable": true, "UnavailableEngines": true,
		"URL": true, "OccurredAt": true, "Cause": true,
	}

	typ := reflect.TypeOf(Data{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("email.Data has a field %q that is not on the allow-list.\n"+
				"    An email leaves our control the moment it is sent. If this field\n"+
				"    is genuinely a count, a status, a name the recipient owns, or a\n"+
				"    URL, add it here deliberately — do not widen the test to pass.",
				name)
		}
	}
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

func TestAHostileProjectNameCannotInjectHeaders(t *testing.T) {
	// ⚠ A SUBJECT LINE IS A HEADER. "x\r\nBcc: everyone@example.com" turns a
	// notification into a mail relay — the same defect class as the report
	// service's Content-Disposition filename.
	hostile := []string{
		"x\r\nBcc: everyone@example.com",
		"x\nSubject: something else",
		"x\r\n\r\nA whole new body",
		"x\x00y",
	}

	for _, name := range hostile {
		d := data()
		d.ProjectName = name
		msg, err := Render(KindScanCompleted, d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(msg.Subject, "\r\n\x00") {
			t.Errorf("subject from %q = %q, which can inject a header", name, msg.Subject)
		}
	}
}

func TestAHostileProjectNameIsEscapedInTheHTMLPart(t *testing.T) {
	// ⚠ html/template, NOT text/template. A project name is user-controlled and
	// an HTML mail client renders what it is given: text/template here would be
	// stored XSS delivered by email.
	d := data()
	d.ProjectName = `<img src=x onerror="alert(1)">`

	msg, err := Render(KindScanCompleted, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.HTML, "<img") {
		t.Fatalf("the HTML part contains a live tag from a project name:\n%s", msg.HTML)
	}
	if !strings.Contains(msg.HTML, "&lt;img") {
		t.Errorf("the project name was not escaped: %s", msg.HTML)
	}
}

func TestALongSubjectIsTruncated(t *testing.T) {
	d := data()
	d.ProjectName = strings.Repeat("a", 5000)

	msg, err := Render(KindScanCompleted, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Subject) > 200 {
		t.Errorf("subject is %d bytes; RFC 5322 wants lines under 998 and a "+
			"5000-character subject is a sign of misuse", len(msg.Subject))
	}
}

// ---------------------------------------------------------------------------
// Honesty
// ---------------------------------------------------------------------------

func TestUnavailableEnginesAreStatedInBothParts(t *testing.T) {
	// ⚠ ZERO FINDINGS FROM ZERO ENGINES IS NOT GOOD NEWS. The same rule as a
	// report's Engine Coverage section: an email that says "0 findings" while
	// an engine could not run has converted an unknown into a false negative
	// the recipient trusts.
	d := data()
	d.Findings, d.Critical, d.High = 0, 0, 0
	d.EnginesUnavailable = 2
	d.UnavailableEngines = []string{"dependency-check", "osv-scanner"}

	msg, err := Render(KindScanCompleted, d)
	if err != nil {
		t.Fatal(err)
	}

	for name, part := range map[string]string{"text": msg.Text, "html": msg.HTML} {
		if !strings.Contains(part, "could not run") {
			t.Errorf("the %s part does not mention that engines could not run:\n%s", name, part)
		}
		if !strings.Contains(part, "dependency-check") {
			t.Errorf("the %s part does not name the unavailable engines", name)
		}
		if !strings.Contains(part, "not") || !strings.Contains(part, "included") {
			t.Errorf("the %s part does not say the numbers are incomplete", name)
		}
	}
}

func TestBothPartsAreAlwaysRendered(t *testing.T) {
	// A mail client with HTML disabled — the default in a security-conscious
	// enterprise — would otherwise show an empty message, and the sender would
	// believe it arrived.
	for _, kind := range Kinds() {
		d := data()
		d.CampaignName = "nightly"
		d.Cause = "the scan service was unreachable"

		msg, err := Render(kind, d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(msg.Text) == "" {
			t.Errorf("%s has an empty text part", kind)
		}
		if strings.TrimSpace(msg.HTML) == "" {
			t.Errorf("%s has an empty HTML part", kind)
		}
		if strings.TrimSpace(msg.Subject) == "" {
			t.Errorf("%s has an empty subject", kind)
		}
		if !strings.Contains(msg.Text, d.URL) {
			t.Errorf("%s does not link anywhere; the recipient cannot act on it", kind)
		}
	}
}

func TestAFailureMessageShowsNoCounts(t *testing.T) {
	// "The scan failed" beside "0 findings" reads as a clean result.
	d := data()
	d.Cause = "the scan service was unreachable"
	d.CampaignName = "nightly"

	msg, err := Render(KindCampaignFailed, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.Text, "Findings:") {
		t.Errorf("a failure message shows a findings count:\n%s", msg.Text)
	}
	if !strings.Contains(msg.Text, "unreachable") {
		t.Errorf("a failure message does not say why:\n%s", msg.Text)
	}
}

func TestAMessageWithoutAURLIsRefused(t *testing.T) {
	d := data()
	d.URL = ""
	if _, err := Render(KindScanCompleted, d); err == nil {
		t.Fatal("a message with no link was rendered; the recipient could not act on it")
	}
}

func TestAnUnknownKindIsRefused(t *testing.T) {
	if _, err := Render("scan_probably_fine", data()); err == nil {
		t.Fatal("an unknown message kind rendered")
	}
}

func TestTheCriticalCountReachesTheSubject(t *testing.T) {
	// A notification that cannot convey urgency is one people turn off. A
	// number is not an inventory.
	d := data()
	d.Critical = 3
	msg, err := Render(KindNewCriticalFindings, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Subject, "3") {
		t.Errorf("subject %q does not carry the count", msg.Subject)
	}
	if !strings.Contains(msg.Subject, "payments-api") {
		t.Errorf("subject %q does not say which project", msg.Subject)
	}
}

func TestTruncationDoesNotSplitARune(t *testing.T) {
	// ⚠ A BYTE CUT MID-RUNE PUTS U+FFFD IN SOMEBODY'S SUBJECT LINE. Multi-byte
	// project names are ordinary, not exotic — and the ellipsis is itself three
	// bytes, which is how the first version of this overshot its own limit.
	for _, name := range []string{
		strings.Repeat("日", 500),
		strings.Repeat("é", 500),
		strings.Repeat("🔐", 300),
	} {
		d := data()
		d.ProjectName = name

		msg, err := Render(KindScanCompleted, d)
		if err != nil {
			t.Fatal(err)
		}
		if len(msg.Subject) > 200 {
			t.Errorf("subject is %d bytes for a %d-byte name", len(msg.Subject), len(name))
		}
		if strings.ContainsRune(msg.Subject, '\uFFFD') {
			t.Errorf("truncation split a rune: %q", msg.Subject)
		}
		if !strings.HasSuffix(msg.Subject, "…") {
			t.Errorf("a truncated subject does not say it was truncated: %q", msg.Subject)
		}
	}
}
