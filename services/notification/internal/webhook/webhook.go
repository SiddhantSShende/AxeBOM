// Package webhook signs and delivers notification callbacks.
//
// ⚠ THE PAYLOAD CARRIES IDS AND COUNTS, NEVER COMPONENT OR FINDING DETAIL.
//
// A receiver logs the body. That is normal, expected behaviour for a webhook
// endpoint — and BOM content is confidential under CERT-In §5.3. A payload
// containing "lodash 4.17.20, CVE-2021-23337, critical" puts a customer's
// vulnerability inventory into a third party's log aggregator, indexed and
// searchable, from a feature they enabled to get a Slack ping.
//
// So the payload says WHAT HAPPENED and WHERE TO LOOK. The receiver follows the
// link and authenticates like anybody else.
//
// ⚠ THE TIMESTAMP IS INSIDE THE SIGNED PAYLOAD, NOT BESIDE IT.
//
// A signature over the body alone is replayable forever: capture one delivery,
// resend it in a year, and it verifies. Signing `timestamp.body` and rejecting
// anything older than five minutes bounds that window — and putting the
// timestamp in a header the signature does not cover would let an attacker
// simply rewrite it.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Event is a notification kind.
type Event string

const (
	// EventScanCompleted fires once per scan, whatever its terminal status.
	EventScanCompleted Event = "scan.completed"
	// EventNewCriticalFindings fires when a scan introduces criticals that were
	// not in the previous scan of the same project.
	EventNewCriticalFindings Event = "findings.new_critical"
	// EventCampaignFailed fires when a scheduled run could not complete.
	EventCampaignFailed Event = "campaign.failed"
	// EventReportReady fires when an artifact finishes rendering.
	EventReportReady Event = "report.ready"
)

// Events returns every event a subscription may filter on.
func Events() []Event {
	return []Event{
		EventScanCompleted,
		EventNewCriticalFindings,
		EventCampaignFailed,
		EventReportReady,
	}
}

// Valid reports whether e is a known event.
func (e Event) Valid() bool {
	for _, known := range Events() {
		if e == known {
			return true
		}
	}
	return false
}

// Payload is what a receiver gets.
//
// ⚠ EVERY FIELD HERE IS AN ID, A COUNT, A STATUS OR A URL. Adding a component
// name, a package version, a CVE id or a finding description would put
// confidential BOM content into somebody else's logs —
// TestPayloadCarriesNoComponentOrFindingDetail asserts that, and it inspects the
// serialized bytes rather than the struct so a field added to a nested type
// cannot slip past.
type Payload struct {
	Event Event `json:"event"`
	// Timestamp is RFC3339 UTC with a literal Z. It is SIGNED — see Sign.
	Timestamp string `json:"timestamp"`
	// DeliveryID lets a receiver deduplicate a retry.
	DeliveryID string `json:"delivery_id"`

	TenantID   string `json:"tenant_id"`
	ProjectID  string `json:"project_id,omitempty"`
	ScanID     string `json:"scan_id,omitempty"`
	ReportID   string `json:"report_id,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`

	// Status is the scan or run status, from the same vocabulary the API uses.
	Status string `json:"status,omitempty"`

	// Counts are aggregates only.
	Counts Counts `json:"counts,omitempty"`

	// URL is where the detail lives. Following it requires authentication, which
	// is the whole point: the webhook says something happened, the API says what.
	URL string `json:"url,omitempty"`
}

// Counts are the aggregate numbers a notification may carry.
type Counts struct {
	Components int `json:"components,omitempty"`
	Findings   int `json:"findings,omitempty"`
	Critical   int `json:"critical,omitempty"`
	High       int `json:"high,omitempty"`
	// EnginesUnavailable is included deliberately: a receiver seeing zero
	// findings should be able to tell "clean" from "nothing ran".
	EnginesUnavailable int `json:"engines_unavailable,omitempty"`
}

// SignatureHeader is where the signature travels.
const SignatureHeader = "X-EncoreBOM-Signature"

// TimestampHeader carries the same timestamp as the payload, for a receiver
// that wants to check freshness before parsing the body.
//
// ⚠ IT IS A CONVENIENCE, NOT THE SOURCE OF TRUTH. Verify reads the timestamp
// from the SIGNED payload; a receiver that trusted this header instead would be
// trusting a value the signature does not cover.
const TimestampHeader = "X-EncoreBOM-Timestamp"

// MaxAge is how old a delivery may be and still be accepted.
//
// Five minutes covers clock skew and a slow network without leaving a useful
// replay window. Longer is a bigger window; shorter starts rejecting honest
// deliveries from a receiver whose clock drifted.
const MaxAge = 5 * time.Minute

// Sign produces the signature header value for a payload.
//
// ⚠ THE SIGNED STRING IS `v1=<timestamp>.<body>`, AND THE VERSION PREFIX
// MATTERS. It is what lets the scheme change later without every existing
// receiver silently accepting both the old and the new form during the
// transition — which is how a signature downgrade happens.
func Sign(body []byte, timestamp time.Time, secret []byte) string {
	unix := strconv.FormatInt(timestamp.UTC().Unix(), 10)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unix))
	mac.Write([]byte("."))
	mac.Write(body)

	return fmt.Sprintf("v1=%s,t=%s", hex.EncodeToString(mac.Sum(nil)), unix)
}

// ErrReplay means the delivery is older than MaxAge.
type ErrReplay struct{ Age time.Duration }

func (e ErrReplay) Error() string {
	return fmt.Sprintf(
		"delivery is %s old, older than the %s replay window", e.Age.Round(time.Second), MaxAge)
}

// Verify checks a received delivery.
//
// ⚠ THE SIGNATURE IS CHECKED BEFORE THE AGE, AND BOTH BEFORE THE BODY IS
// PARSED. Reading a timestamp out of an unverified body to decide whether to
// verify it would let an attacker choose their own freshness — and parsing
// attacker-controlled JSON before authenticating it is work an unauthenticated
// caller can make us do.
func Verify(body []byte, header string, secret []byte, now time.Time) error {
	signature, unix, err := parseHeader(header)
	if err != nil {
		return err
	}

	expected := Sign(body, time.Unix(unix, 0), secret)
	expectedMAC, _, err := parseHeader(expected)
	if err != nil {
		return err
	}

	// ⚠ CONSTANT TIME. A byte-by-byte compare leaks how much of a forged
	// signature is correct, which turns forgery into a few thousand requests.
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedMAC)) != 1 {
		return fmt.Errorf("webhook signature does not verify")
	}

	age := now.Sub(time.Unix(unix, 0))
	if age < 0 {
		age = -age
	}
	if age > MaxAge {
		return ErrReplay{Age: age}
	}

	return nil
}

func parseHeader(header string) (signature string, unix int64, err error) {
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "v1":
			signature = value
		case "t":
			unix, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return "", 0, fmt.Errorf("webhook signature has an unreadable timestamp")
			}
		}
	}
	if signature == "" {
		return "", 0, fmt.Errorf(
			"webhook signature header has no v1 component; this build only issues v1")
	}
	if unix == 0 {
		return "", 0, fmt.Errorf("webhook signature header has no timestamp")
	}
	return signature, unix, nil
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

// MaxAttempts is how many times a delivery is tried before dead-lettering.
const MaxAttempts = 5

// Backoff is the retry schedule.
//
// ⚠ IT ENDS AT AN HOUR AND THEN STOPS. Retrying forever against a receiver that
// is gone is a queue that never drains; the dead letter is RETAINED so an
// operator can see what was not delivered, which is the part that matters.
func Backoff(attempt int) time.Duration {
	// ⚠ INDEXED FROM THE FRONT AFTER AN EXPLICIT CLAMP, not with arithmetic the
	// reader has to verify. `schedule[attempt-1]` is correct here and gosec
	// still flags it, because proving it needs both bounds checks above held —
	// and a reader has the same problem the analyser does. Walking a clamped
	// index is provably in range on its face.
	schedule := []time.Duration{
		30 * time.Second,
		2 * time.Minute,
		10 * time.Minute,
		1 * time.Hour,
	}

	i := attempt - 1
	if i < 0 {
		i = 0
	}
	if i >= len(schedule) {
		i = len(schedule) - 1
	}
	return schedule[i]
}

// Outcome is what happened to one delivery attempt.
type Outcome struct {
	Delivered bool
	// Retryable distinguishes a receiver that is down from one that refuses.
	//
	// ⚠ A 4xx IS NOT RETRIED. A receiver answering 401 or 404 will answer the
	// same way in an hour, and retrying is a small denial of service against
	// somebody who already told us to stop.
	Retryable bool
	Status    int
	Attempt   int
	Reason    string
}

// Classify reads an HTTP status into an outcome.
func Classify(status int, attempt int) Outcome {
	switch {
	case status >= 200 && status < 300:
		return Outcome{Delivered: true, Status: status, Attempt: attempt}

	case status == 408 || status == 429:
		// Timeout and rate-limit are the two 4xx codes that mean "try later".
		return Outcome{
			Retryable: true, Status: status, Attempt: attempt,
			Reason: "the receiver asked us to slow down or timed out",
		}

	case status >= 400 && status < 500:
		return Outcome{
			Status: status, Attempt: attempt,
			Reason: "the receiver rejected the delivery; retrying would send the " +
				"same thing to somebody who already refused it",
		}

	default:
		return Outcome{
			Retryable: true, Status: status, Attempt: attempt,
			Reason: "the receiver is unavailable",
		}
	}
}

// ShouldDeadLetter reports whether an attempt exhausts the schedule.
func ShouldDeadLetter(o Outcome) bool {
	if o.Delivered {
		return false
	}
	return !o.Retryable || o.Attempt >= MaxAttempts
}

// ---------------------------------------------------------------------------
// Payload construction
// ---------------------------------------------------------------------------

// Encode serializes a payload for signing and sending.
//
// Deterministic: Go's encoder emits struct fields in declaration order, so the
// same payload produces the same bytes and therefore the same signature. A map
// anywhere in this type would break that.
func Encode(p Payload) ([]byte, error) {
	if !p.Event.Valid() {
		return nil, fmt.Errorf("webhook event %q is not one this build emits", p.Event)
	}
	if p.Timestamp == "" {
		return nil, fmt.Errorf("webhook payload has no timestamp; the signature covers it")
	}
	if p.TenantID == "" {
		return nil, fmt.Errorf("webhook payload has no tenant id")
	}
	return json.Marshal(p)
}
