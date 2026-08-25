package events

import "fmt"

// NotifyEventSchema versions the notification envelope.
const NotifyEventSchema = "axebom.notify.event/v1"

// The four events this build emits.
//
// ⚠ THESE STRINGS ARE THE SSOT. services/notification/internal/webhook.Event
// cannot be referenced from here (this package must not import a service's
// internal package, and the dependency would in any case run the wrong way —
// publishers outside services/notification need these constants too), so
// that package's four constants are declared independently — but the STRING
// VALUES must stay identical. services/notification/internal/webhook's own
// test file asserts that equality (it CAN import this public package), which
// is what catches the day they drift.
const (
	NotifyEventScanCompleted       = "scan.completed"
	NotifyEventFindingsNewCritical = "findings.new_critical"
	NotifyEventCampaignFailed      = "campaign.failed"
	NotifyEventReportReady         = "report.ready"
)

// NotifyEventV1 is published to `notify.<event>` and consumed only by
// services/notification.
//
// ⚠ DELIBERATELY RICHER THAN services/notification/internal/webhook.Payload.
// That type is a CUSTOMER-FACING artifact — a receiver logs it, so it is
// ids/counts/status/url only (CLAUDE.md, docs/05-SECURITY-MODEL.md §5). This
// type is an INTERNAL message between our own services and never leaves the
// process boundary it crosses, so it may carry what the EMAIL channel needs
// to render a human-readable message (a project name, a campaign name, a
// failure cause) that the webhook channel deliberately does not. notification
// derives BOTH the narrower webhook.Payload and the richer email.Data from
// this one envelope — see services/notification/internal/worker.
type NotifyEventV1 struct {
	Schema string `json:"schema"`
	// Event is one of the NotifyEvent* constants above. A string, not a typed
	// enum: the enum's canonical home is services/notification's webhook
	// package, which this shared package cannot import.
	Event string `json:"event"`

	TenantID string `json:"tenant_id"`

	ProjectID   string `json:"project_id,omitempty"`
	ProjectName string `json:"project_name,omitempty"`
	ScanID      string `json:"scan_id,omitempty"`
	ReportID    string `json:"report_id,omitempty"`
	CampaignID  string `json:"campaign_id,omitempty"`
	// CampaignName is set for campaign messages.
	CampaignName string `json:"campaign_name,omitempty"`

	// Status is the scan or run status, from the API's own vocabulary.
	Status string `json:"status,omitempty"`

	Components int `json:"components,omitempty"`
	Findings   int `json:"findings,omitempty"`
	Critical   int `json:"critical,omitempty"`
	High       int `json:"high,omitempty"`
	// EnginesUnavailable lets a recipient tell "clean" from "nothing ran" —
	// the same honesty rule a report's own Engine Coverage section applies.
	EnginesUnavailable int `json:"engines_unavailable,omitempty"`
	// UnavailableEngines names them. Engine names are OUR identifiers, not
	// customer data, so — unlike a component or a CVE — they are safe in a
	// webhook payload too; carried here regardless of channel for uniformity.
	UnavailableEngines []string `json:"unavailable_engines,omitempty"`

	// Cause is set for a failure message: an operator-facing string from our
	// own error taxonomy, never a scanner's raw output.
	Cause string `json:"cause,omitempty"`

	// URL is where the detail lives, behind authentication.
	URL string `json:"url,omitempty"`
	// OccurredAt is RFC3339 UTC with a literal Z — when the underlying thing
	// happened, not when this event was published.
	OccurredAt string `json:"occurred_at"`
}

// Subject is the NATS subject this event publishes to — `notify.<event>`,
// matching docs/02-CONTRACTS.md §2's `notify.<event_type>` pattern.
func (e NotifyEventV1) Subject() string { return "notify." + e.Event }

// Validate refuses an event too incomplete to route or display.
func (e NotifyEventV1) Validate() error {
	if e.Event == "" {
		return fmt.Errorf("notify event has no event type")
	}
	if e.TenantID == "" {
		return fmt.Errorf("notify event has no tenant id")
	}
	if e.OccurredAt == "" {
		return fmt.Errorf("notify event has no occurred_at")
	}
	return nil
}
