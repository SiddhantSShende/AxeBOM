package worker

import (
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

func TestToWebhookPayloadNarrowsToTheWireSafeShape(t *testing.T) {
	evt := events.NotifyEventV1{
		Schema: events.NotifyEventSchema, Event: events.NotifyEventReportReady,
		TenantID: "t1", ProjectID: "p1", ProjectName: "payments-api",
		ReportID: "r1", Status: "ready",
		Components: 42, Findings: 7, Critical: 2, High: 1, EnginesUnavailable: 1,
		Cause: "should never reach the payload", URL: "https://x/reports/r1",
		OccurredAt: "2026-08-25T10:00:00Z",
	}

	p := toWebhookPayload(evt)

	if p.Event != webhook.EventReportReady || p.TenantID != "t1" || p.ProjectID != "p1" ||
		p.ReportID != "r1" || p.Status != "ready" || p.URL != "https://x/reports/r1" {
		t.Fatalf("payload = %+v, missing an id/status/url field", p)
	}
	if p.Counts.Components != 42 || p.Counts.Findings != 7 || p.Counts.Critical != 2 ||
		p.Counts.High != 1 || p.Counts.EnginesUnavailable != 1 {
		t.Errorf("counts = %+v, want the envelope's counts carried through", p.Counts)
	}
	if p.Timestamp != evt.OccurredAt {
		t.Errorf("timestamp = %q, want %q", p.Timestamp, evt.OccurredAt)
	}
	// ⚠ evt.ProjectName AND evt.Cause HAVE NO WHERE TO GO HERE, AND THAT IS
	// THE POINT. webhook.Payload's own struct definition has no field for
	// either — TestPayloadCarriesNoComponentOrFindingDetail in the webhook
	// package is what asserts that at the wire level; this test only needs
	// to show toWebhookPayload does not need one either.
}

func TestEmailKindForOnlyCoversEventsWithAnEmailTemplate(t *testing.T) {
	cases := []struct {
		event webhook.Event
		want  bool
	}{
		{webhook.EventScanCompleted, true},
		{webhook.EventNewCriticalFindings, true},
		{webhook.EventCampaignFailed, true},
		// report.ready is webhook-only by design — see attempt.go's comment.
		{webhook.EventReportReady, false},
	}
	for _, c := range cases {
		_, ok := emailKindFor(c.event)
		if ok != c.want {
			t.Errorf("emailKindFor(%s) ok = %v, want %v", c.event, ok, c.want)
		}
	}
}

func TestToEmailDataCarriesCountsAndURL(t *testing.T) {
	p := webhook.Payload{
		Event: webhook.EventScanCompleted, Status: "completed",
		ProjectID: "p1", URL: "https://x/scans/s1", Timestamp: "2026-08-25T10:00:00Z",
		Counts: webhook.Counts{Components: 10, Findings: 3, Critical: 1, High: 0, EnginesUnavailable: 2},
	}

	d := toEmailData(p)

	if d.Status != "completed" || d.URL != "https://x/scans/s1" || d.OccurredAt != p.Timestamp {
		t.Errorf("data = %+v", d)
	}
	if d.Components != 10 || d.Findings != 3 || d.Critical != 1 || d.EnginesUnavailable != 2 {
		t.Errorf("counts not carried through: %+v", d)
	}
}
