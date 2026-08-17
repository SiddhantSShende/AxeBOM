package handler

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/report/internal/share"
	"github.com/encorebom/encorebom/services/report/internal/store"
)

// TestTheDownloadFilenameCannotBreakOutOfTheHeader.
//
// ⚠ THE FILENAME IS BUILT FROM THE REPORT ID, NEVER FROM THE PROJECT NAME.
//
// A project name is user-controlled. One containing a quote closes the
// Content-Disposition parameter; one containing CR or LF splits the response
// and lets the caller inject headers or a whole second response; one containing
// a path separator aims the browser's save dialog somewhere else. That is
// response splitting and path traversal in a single field.
//
// This asserts the property directly: whatever the report says, the filename is
// built from a uuid and a known extension.
func TestTheDownloadFilenameCannotBreakOutOfTheHeader(t *testing.T) {
	hostile := []string{
		`x"; filename="evil.exe`,
		"x\r\nX-Injected: yes",
		"../../etc/passwd",
		"x\nSet-Cookie: session=stolen",
	}

	for _, name := range hostile {
		// The hostile value is placed where a careless implementation would
		// have reached for it — the report's own fields.
		r := store.Report{ID: name, Format: "pdf"}
		got := filename(r)

		if strings.ContainsAny(got, "\r\n\"") {
			t.Errorf("filename(%q) = %q, which can break out of the header", name, got)
		}
		if strings.Contains(got, "..") || strings.ContainsAny(got, `/\`) {
			t.Errorf("filename(%q) = %q, which contains a path", name, got)
		}
	}
}

// TestTheFilenameCarriesTheRightExtension — a downloaded SPDX document that
// saves as `.spdx` opens in nothing; `.spdx.json` opens in an editor.
func TestTheFilenameCarriesTheRightExtension(t *testing.T) {
	for format, want := range map[string]string{
		"pdf":       ".pdf",
		"xlsx":      ".xlsx",
		"json":      ".json",
		"spdx":      ".spdx.json",
		"cyclonedx": ".cdx.json",
	} {
		got := filename(store.Report{ID: "0199-report", Format: format})
		if !strings.HasSuffix(got, want) {
			t.Errorf("format %q produced %q, want suffix %q", format, got, want)
		}
	}
}

// TestEveryDownloadResponseIsAnAttachmentAndUncacheable.
//
// ⚠ A REPORT IS ATTACKER-INFLUENCED CONTENT SERVED FROM OUR ORIGIN.
//
// Without `attachment` a browser renders it inline, and an HTML payload
// smuggled into a component description becomes stored XSS against the
// customer's own session. `nosniff` closes the other half, where a browser
// ignores our content type and sniffs the bytes.
//
// `no-store` matters for a different reason: a shared report that is later
// revoked must not survive in a proxy or a browser cache. Revocation that only
// applies to the next cold request is not revocation.
func TestEveryDownloadResponseIsAnAttachmentAndUncacheable(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDownloadHeaders(rec, store.Report{
		ID: "0199-report", Format: "pdf", SizeBytes: 4096,
		SHA256: "abc123", SigningKeyID: "encorebom-report-signing:v2",
	})

	h := rec.Header()

	if cd := h.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}

	cc := h.Get("Cache-Control")
	for _, want := range []string{"no-store", "private"} {
		if !strings.Contains(cc, want) {
			t.Errorf("Cache-Control = %q, missing %q", cc, want)
		}
	}

	if got := h.Get("Content-Type"); got != "application/pdf" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Get("Content-Length"); got != "4096" {
		t.Errorf("Content-Length = %q", got)
	}
	// The digest is what the detached signature also covers, so a client can
	// check integrity without fetching the signature.
	if got := h.Get("X-EncoreBOM-SHA256"); got != "abc123" {
		t.Errorf("X-EncoreBOM-SHA256 = %q", got)
	}
	if got := h.Get("X-EncoreBOM-Signing-Key"); got == "" {
		t.Error("the signing key id is not advertised, so a consumer cannot tell " +
			"which published key to verify against")
	}
}

// TestAnUnsignedReportAdvertisesNoKey — the absence has to be visible, or a
// consumer assumes a signature exists and cannot find it.
func TestAnUnsignedReportAdvertisesNoKey(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDownloadHeaders(rec, store.Report{ID: "r", Format: "json"})

	if got := rec.Header().Get("X-EncoreBOM-Signing-Key"); got != "" {
		t.Errorf("an unsigned report advertised key %q", got)
	}
	if got := rec.Header().Get("X-EncoreBOM-Truncated"); got != "" {
		t.Errorf("an untruncated report advertised truncation %q", got)
	}
}

// TestATruncatedReportSaysSoInAHeader — the customer downloading a truncated
// PDF should not have to open it to find out.
func TestATruncatedReportSaysSoInAHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDownloadHeaders(rec, store.Report{ID: "r", Format: "pdf", Truncated: true})

	if got := rec.Header().Get("X-EncoreBOM-Truncated"); got != "true" {
		t.Errorf("X-EncoreBOM-Truncated = %q, want true", got)
	}
}

// TestARefusedShareLinkGetsItsOwnCode.
//
// The holder already had a valid token, so telling them WHY costs nothing a
// guesser could use — a 256-bit value is not enumerable — and saves them
// guessing whether to ask for a new link or wait.
func TestARefusedShareLinkGetsItsOwnCode(t *testing.T) {
	tests := map[share.Outcome]errs.Code{
		share.OutcomeExpired:   errs.ReportShareExpired,
		share.OutcomeRevoked:   errs.ReportShareRevoked,
		share.OutcomeExhausted: errs.ReportShareExpired,
	}

	for outcome, want := range tests {
		err := refusal(outcome)
		if !errs.Is(err, want) {
			t.Errorf("outcome %q produced %v, want %v", outcome, errs.From(err).Code, want)
		}
	}

	// A revoked link must NOT report as expired: revocation is a deliberate act
	// by an operator, and reporting it as an expiry hides that somebody
	// withdrew access on purpose.
	if errs.Is(refusal(share.OutcomeRevoked), errs.ReportShareExpired) {
		t.Error("a revoked link reported as expired")
	}

	// Anything unrecognized falls back to a bare not-found rather than leaking
	// a state we do not have words for.
	if !errs.Is(refusal("something-new"), errs.NotFoundReport) {
		t.Error("an unknown outcome did not fall back to not-found")
	}
}

// TestCrossTenantBecomesNotFound.
//
// ⚠ 404, NEVER 403. RLS filters the row out, so the store genuinely saw
// nothing — "no such report" is the honest answer, and a 403 would confirm the
// id exists to somebody enumerating uuids.
func TestCrossTenantBecomesNotFound(t *testing.T) {
	err := mapNotFound(store.ErrNotFound)
	if !errs.Is(err, errs.NotFoundReport) {
		t.Fatalf("a store miss produced %v, want %v", errs.From(err).Code, errs.NotFoundReport)
	}
	if errs.From(err).HTTPStatus() != 404 {
		t.Errorf("status = %d, want 404", errs.From(err).HTTPStatus())
	}

	// An unrelated error must pass through unchanged rather than being
	// laundered into a 404, which would hide a real failure as a missing row.
	other := errors.New("connection reset")
	if mapNotFound(other) != other { //nolint:errorlint // identity is the assertion
		t.Error("an unrelated error was rewritten as not-found")
	}
}

// TestAViewerCannotDownloadAPrivateReport is the phase requirement, checked at
// the exact call the handler makes.
//
// CERT-In §5.3.2 requires maintaining both a public report and a private one
// containing vulnerability detail. The route's matrix cell lets every role
// through; this is the decision that depends on the ROW.
func TestAViewerCannotDownloadAPrivateReport(t *testing.T) {
	if d := authz.CanDownloadReport(authz.RoleViewer, authz.VisibilityPrivate); d.Allowed {
		t.Fatal("a Viewer was allowed to download a private report")
	}
	if d := authz.CanDownloadReport(authz.RoleViewer, authz.VisibilityPublic); !d.Allowed {
		t.Error("a Viewer was refused the PUBLIC report, which they are entitled to")
	}
	if d := authz.CanDownloadReport(authz.RoleAnalyst, authz.VisibilityPrivate); !d.Allowed {
		t.Error("an Analyst was refused a private report")
	}

	// The refusal must carry the reason, because the handler renders it and the
	// caller can act on it by asking for a role.
	d := authz.CanDownloadReport(authz.RoleViewer, authz.VisibilityPrivate)
	if !strings.Contains(d.Reason, "5.3.2") {
		t.Errorf("the refusal does not cite the rule: %q", d.Reason)
	}
}

// TestMediaTypesMatchTheFormats — a CycloneDX document served as `text/plain`
// is one a customer's validator will refuse to look at.
func TestMediaTypesMatchTheFormats(t *testing.T) {
	for format, want := range map[string]string{
		"pdf":       "application/pdf",
		"xlsx":      "spreadsheetml",
		"spdx":      "application/spdx+json",
		"cyclonedx": "vnd.cyclonedx+json",
		"json":      "application/json",
	} {
		if got := mediaType(format); !strings.Contains(got, want) {
			t.Errorf("format %q -> %q, want it to contain %q", format, got, want)
		}
	}
}

// TestAMalformedTokenAndAnUnknownOneLookIdentical.
//
// ⚠ THE ENDPOINT MUST NOT CONFIRM THAT A SHAPE IS THE RIGHT SHAPE. If a
// malformed token answered differently from a well-formed unknown one, a
// guesser who had no idea of the format would learn it from the difference.
func TestAMalformedTokenAndAnUnknownOneLookIdentical(t *testing.T) {
	malformed := httptest.NewRecorder()
	notFoundShare(malformed, httptest.NewRequest("GET", "/shared/nope", nil))

	unknown := httptest.NewRecorder()
	notFoundShare(unknown, httptest.NewRequest("GET", "/shared/"+strings.Repeat("A", 43), nil))

	if malformed.Code != unknown.Code {
		t.Errorf("status differs: malformed %d, unknown %d", malformed.Code, unknown.Code)
	}
	if malformed.Body.String() != unknown.Body.String() {
		t.Errorf("body differs:\n  malformed: %s\n  unknown:   %s",
			malformed.Body.String(), unknown.Body.String())
	}
	if cc := malformed.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; a share-link 404 must not be cached", cc)
	}
}
