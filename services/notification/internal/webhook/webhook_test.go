package webhook

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/events"
)

// TestEventStringsMatchTheSharedEnvelope guards the one place these four
// values are declared twice. libs/go-shared/events.NotifyEventV1 (published
// by scan-orchestrator, campaign and report; consumed by this service) has
// its own copy of these strings, because a shared library cannot import a
// service's internal package. This is what catches the day the two drift.
func TestEventStringsMatchTheSharedEnvelope(t *testing.T) {
	pairs := []struct {
		event Event
		want  string
	}{
		{EventScanCompleted, events.NotifyEventScanCompleted},
		{EventNewCriticalFindings, events.NotifyEventFindingsNewCritical},
		{EventCampaignFailed, events.NotifyEventCampaignFailed},
		{EventReportReady, events.NotifyEventReportReady},
	}
	for _, p := range pairs {
		if string(p.event) != p.want {
			t.Errorf("webhook.Event %q does not match events.NotifyEvent* %q", p.event, p.want)
		}
	}
	if len(pairs) != len(Events()) {
		t.Errorf("this test checks %d events but Events() returns %d; a new event "+
			"was added to one side without the other", len(pairs), len(Events()))
	}
}

var now = time.Date(2026, 8, 17, 9, 14, 3, 0, time.UTC)

var secret = []byte("a-shared-secret-of-reasonable-length")

func payload() Payload {
	return Payload{
		Event:      EventNewCriticalFindings,
		Timestamp:  now.Format(time.RFC3339),
		DeliveryID: "0199-delivery",
		TenantID:   "0199-tenant",
		ProjectID:  "0199-project",
		ScanID:     "0199-scan",
		Status:     "completed_with_errors",
		Counts:     Counts{Components: 412, Findings: 37, Critical: 3, High: 9, EnginesUnavailable: 1},
		URL:        "https://app.axebom.example/scans/0199-scan",
	}
}

// ---------------------------------------------------------------------------
// The payload rule — the phase names this explicitly
// ---------------------------------------------------------------------------

// TestPayloadCarriesNoComponentOrFindingDetail is the phase's named assertion.
//
// ⚠ A RECEIVER LOGS THE BODY. That is normal behaviour for a webhook endpoint —
// and BOM content is confidential under CERT-In §5.3. A payload containing
// "lodash 4.17.20, CVE-2021-23337, critical" puts a customer's vulnerability
// inventory into a third party's log aggregator, indexed and searchable, from a
// feature they enabled to get a Slack ping.
//
// It inspects the SERIALIZED BYTES rather than the struct, so a field added to
// a nested type cannot slip past.
func TestPayloadCarriesNoComponentOrFindingDetail(t *testing.T) {
	body, err := Encode(payload())
	if err != nil {
		t.Fatal(err)
	}

	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatal(err)
	}

	// ⚠ AN ALLOW-LIST, NOT A DENY-LIST. A deny-list of forbidden key names
	// passes the moment somebody adds `pkg_name`, and the whole point is that a
	// NEW field must be a deliberate decision rather than an accident.
	allowed := map[string]bool{
		"event": true, "timestamp": true, "delivery_id": true,
		"tenant_id": true, "project_id": true, "scan_id": true,
		"report_id": true, "campaign_id": true,
		"status": true, "counts": true, "url": true,
	}

	for key := range generic {
		if !allowed[key] {
			t.Errorf(
				"webhook payload carries an unexpected field %q.\n"+
					"    A receiver LOGS this body, and BOM content is confidential\n"+
					"    (CERT-In §5.3). If this field is genuinely an id, a count, a\n"+
					"    status or a URL, add it to the allow-list in this test\n"+
					"    deliberately — do not widen the test to make it pass.", key)
		}
	}

	allowedCounts := map[string]bool{
		"components": true, "findings": true, "critical": true,
		"high": true, "engines_unavailable": true,
	}
	if counts, ok := generic["counts"].(map[string]any); ok {
		for key := range counts {
			if !allowedCounts[key] {
				t.Errorf("counts carries an unexpected field %q", key)
			}
		}
	}

	// And the concrete case: no component name, no advisory id, anywhere.
	text := string(body)
	for _, forbidden := range []string{"lodash", "CVE-", "GHSA-", "pkg:"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("payload contains %q: %s", forbidden, text)
		}
	}
}

func TestTheEnginesUnavailableCountIsIncluded(t *testing.T) {
	// ⚠ DELIBERATE. A receiver seeing zero findings must be able to tell
	// "clean" from "nothing ran" — the same honesty rule as Engine Coverage in
	// a report, applied to a one-line notification.
	body, _ := Encode(payload())
	if !strings.Contains(string(body), "engines_unavailable") {
		t.Fatal("a receiver cannot distinguish a clean scan from one where no engine ran")
	}
}

func TestAnUnknownEventIsRefused(t *testing.T) {
	p := payload()
	p.Event = "scan.probably_fine"
	if _, err := Encode(p); err == nil {
		t.Fatal("an event outside the published set was encoded")
	}
}

func TestAPayloadWithoutATimestampIsRefused(t *testing.T) {
	// The signature covers it; encoding one without would produce a delivery
	// that cannot be replay-checked.
	p := payload()
	p.Timestamp = ""
	if _, err := Encode(p); err == nil {
		t.Fatal("a payload with no timestamp was encoded")
	}
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

func TestAGoodSignatureVerifies(t *testing.T) {
	body, _ := Encode(payload())
	header := Sign(body, now, secret)

	if err := Verify(body, header, secret, now.Add(30*time.Second)); err != nil {
		t.Fatalf("a fresh delivery did not verify: %v", err)
	}
}

func TestATamperedBodyDoesNotVerify(t *testing.T) {
	body, _ := Encode(payload())
	header := Sign(body, now, secret)

	tampered := []byte(strings.Replace(string(body), `"critical":3`, `"critical":0`, 1))
	if string(tampered) == string(body) {
		t.Fatal("the tamper did not change the body")
	}

	if err := Verify(tampered, header, secret, now); err == nil {
		t.Fatal("a tampered body verified")
	}
}

func TestAnotherSecretDoesNotVerify(t *testing.T) {
	body, _ := Encode(payload())
	header := Sign(body, now, secret)

	if err := Verify(body, header, []byte("a-different-secret-entirely"), now); err == nil {
		t.Fatal("a foreign secret verified the signature")
	}
}

func TestAReplayedDeliveryIsRejected(t *testing.T) {
	// ⚠ THE TIMESTAMP IS INSIDE THE SIGNED PAYLOAD. A signature over the body
	// alone is replayable forever: capture one delivery, resend it in a year,
	// and it verifies.
	body, _ := Encode(payload())
	header := Sign(body, now, secret)

	err := Verify(body, header, secret, now.Add(MaxAge+time.Minute))
	if err == nil {
		t.Fatal("a delivery older than the replay window was accepted")
	}

	var replay ErrReplay
	if !errors.As(err, &replay) {
		t.Fatalf("the rejection is not typed as a replay: %v", err)
	}
	if !strings.Contains(err.Error(), "replay window") {
		t.Errorf("the error does not say why: %v", err)
	}
}

func TestARewrittenTimestampDoesNotVerify(t *testing.T) {
	// ⚠ THE ATTACK THE IN-PAYLOAD TIMESTAMP PREVENTS. If the timestamp lived in
	// a header the signature did not cover, an attacker replaying an old
	// delivery would simply rewrite it to now.
	body, _ := Encode(payload())
	header := Sign(body, now, secret)

	// Move the timestamp forward, leaving the signature untouched.
	fresh := now.Add(MaxAge + time.Minute)
	rewritten := strings.Replace(header,
		"t="+timestampIn(header),
		"t="+isoUnix(fresh), 1)

	if err := Verify(body, rewritten, secret, fresh); err == nil {
		t.Fatal("rewriting the timestamp defeated the replay window")
	}
}

func TestAFutureDeliveryIsAlsoRejected(t *testing.T) {
	// Clock skew cuts both ways; a delivery from an hour in the future is as
	// suspect as one from an hour ago.
	body, _ := Encode(payload())
	header := Sign(body, now.Add(time.Hour), secret)

	if err := Verify(body, header, secret, now); err == nil {
		t.Fatal("a delivery from the future was accepted")
	}
}

func TestAMalformedHeaderIsRejectedClearly(t *testing.T) {
	body, _ := Encode(payload())
	for _, header := range []string{
		"", "garbage", "v1=abc", "t=123", "v2=abc,t=123", "v1=abc,t=notanumber",
	} {
		if err := Verify(body, header, secret, now); err == nil {
			t.Errorf("header %q was accepted", header)
		}
	}
}

func TestTheSignatureCarriesAVersionPrefix(t *testing.T) {
	// ⚠ IT IS WHAT LETS THE SCHEME CHANGE without every receiver silently
	// accepting both the old and the new form during a transition — which is
	// how a signature downgrade happens.
	body, _ := Encode(payload())
	header := Sign(body, now, secret)

	if !strings.HasPrefix(header, "v1=") {
		t.Fatalf("signature header = %q, want a v1 prefix", header)
	}
	if !strings.Contains(header, ",t=") {
		t.Errorf("signature header carries no timestamp: %q", header)
	}
}

func TestSigningIsDeterministic(t *testing.T) {
	// The same payload must produce the same signature, or a retry would look
	// like a different delivery to a receiver deduplicating on it.
	body, _ := Encode(payload())
	first := Sign(body, now, secret)
	for range 10 {
		if Sign(body, now, secret) != first {
			t.Fatal("the signature changed between calls")
		}
	}
}

// ---------------------------------------------------------------------------
// Delivery policy
// ---------------------------------------------------------------------------

func TestA4xxIsNotRetried(t *testing.T) {
	// ⚠ A RECEIVER ANSWERING 401 OR 404 WILL ANSWER THE SAME WAY IN AN HOUR.
	// Retrying is a small denial of service against somebody who already told
	// us to stop.
	for _, status := range []int{400, 401, 403, 404, 422} {
		out := Classify(status, 1)
		if out.Retryable {
			t.Errorf("status %d was marked retryable", status)
		}
		if !ShouldDeadLetter(out) {
			t.Errorf("status %d did not dead-letter", status)
		}
		if out.Reason == "" {
			t.Errorf("status %d gives no reason for the operator reading the DLQ", status)
		}
	}
}

func TestTimeoutAndRateLimitAreRetried(t *testing.T) {
	// The two 4xx codes that genuinely mean "try later".
	for _, status := range []int{408, 429} {
		if !Classify(status, 1).Retryable {
			t.Errorf("status %d was not retried", status)
		}
	}
}

func TestA5xxRetriesThenDeadLetters(t *testing.T) {
	for attempt := 1; attempt < MaxAttempts; attempt++ {
		out := Classify(503, attempt)
		if ShouldDeadLetter(out) {
			t.Fatalf("attempt %d dead-lettered early", attempt)
		}
	}

	// ⚠ IT STOPS. Retrying forever against a receiver that is gone is a queue
	// that never drains.
	final := Classify(503, MaxAttempts)
	if !ShouldDeadLetter(final) {
		t.Fatal("delivery retried past the attempt limit")
	}
}

func TestASuccessNeverDeadLetters(t *testing.T) {
	for _, status := range []int{200, 201, 202, 204} {
		out := Classify(status, 1)
		if !out.Delivered {
			t.Errorf("status %d was not treated as delivered", status)
		}
		if ShouldDeadLetter(out) {
			t.Errorf("a delivered %d was dead-lettered", status)
		}
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	previous := time.Duration(0)
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		wait := Backoff(attempt)
		if wait < previous {
			t.Fatalf("backoff shrank at attempt %d: %s after %s", attempt, wait, previous)
		}
		if wait > time.Hour {
			t.Fatalf("backoff exceeded an hour at attempt %d: %s", attempt, wait)
		}
		previous = wait
	}
	if Backoff(1) != 30*time.Second {
		t.Errorf("first retry waits %s, want 30s", Backoff(1))
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func timestampIn(header string) string {
	for _, part := range strings.Split(header, ",") {
		if key, value, ok := strings.Cut(part, "="); ok && key == "t" {
			return value
		}
	}
	return ""
}

func isoUnix(t time.Time) string { return itoa(t.UTC().Unix()) }

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}
