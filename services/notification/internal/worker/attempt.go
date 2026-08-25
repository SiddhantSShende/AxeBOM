// Package worker drives notify.> events to delivery.
//
// ⚠ TWO DRIVERS, ONE ATTEMPT PATH. Consumer fires the FIRST attempt the
// moment a notify.> event fans out to a subscription; Poller fires every
// RETRY, on its own clock, by claiming rows whose next_retry_at has passed
// (migrations/notify/0002). They cannot share one mechanism — a webhook
// target being down must not hold up the other four subscriptions the same
// event fanned out to, and NATS message redelivery would do exactly that if
// a single delivery's retry schedule were tied to the event message instead
// of its own row. Attempter is the one piece of logic both drivers call.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/axebom/axebom/services/notification/internal/delivery"
	"github.com/axebom/axebom/services/notification/internal/email"
	"github.com/axebom/axebom/services/notification/internal/mail"
	"github.com/axebom/axebom/services/notification/internal/store"
	"github.com/axebom/axebom/services/notification/internal/subscription"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

// Attempter makes one delivery attempt and records what happened.
type Attempter struct {
	store    *store.Store
	delivery *delivery.Client
	mail     *mail.Sender
	now      func() time.Time
	log      *slog.Logger
}

// NewAttempter builds an Attempter. A nil clock uses time.Now.
func NewAttempter(st *store.Store, dc *delivery.Client, ms *mail.Sender, now func() time.Time, log *slog.Logger) *Attempter {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Attempter{store: st, delivery: dc, mail: ms, now: now, log: log}
}

// Attempt tries one delivery and persists the outcome. Never returns an
// error: a failed webhook or a bounced email is a fact recorded on the row,
// not a fault the caller must handle — see delivery.Client's own design.
func (a *Attempter) Attempt(
	ctx context.Context, tenantID string, sub subscription.Subscription,
	deliveryID string, payload webhook.Payload, attempt int,
) {
	// ⚠ SET HERE, NOT TRUSTED FROM THE STORED ROW. The delivery id is what
	// lets a receiver deduplicate a retry (webhook.Payload's own doc
	// comment); it must be the row's real id on every attempt, first or
	// hundredth.
	payload.DeliveryID = deliveryID

	switch sub.Kind {
	case subscription.KindWebhook:
		a.attemptWebhook(ctx, tenantID, deliveryID, sub, payload, attempt)
	case subscription.KindEmail:
		a.attemptEmail(ctx, tenantID, deliveryID, sub, payload, attempt)
	default:
		a.deadLetter(ctx, tenantID, deliveryID, attempt,
			fmt.Sprintf("subscription %s has an unknown kind %q", sub.ID, sub.Kind))
	}
}

func (a *Attempter) attemptWebhook(
	ctx context.Context, tenantID, deliveryID string, sub subscription.Subscription,
	payload webhook.Payload, attempt int,
) {
	result, err := a.delivery.Deliver(ctx, sub, payload, attempt)
	if err != nil {
		// ⚠ NOT A DELIVERY FAILURE — OUR OWN MISCONFIGURATION (delivery.Deliver's
		// own doc comment: an unresolvable Vault secret). Retrying five times
		// against our own broken config wastes the schedule on something a
		// receiver's outage did not cause.
		a.log.Error("a webhook delivery could not even be attempted",
			"delivery_id", deliveryID, "subscription_id", sub.ID, "error", err)
		a.deadLetter(ctx, tenantID, deliveryID, attempt, err.Error())
		return
	}

	status := "pending"
	switch {
	case result.Delivered:
		status = "delivered"
	case result.DeadLettered:
		status = "dead_lettered"
	}
	a.record(ctx, tenantID, deliveryID, status, result.Attempt, result.Status, result.Reason, result.NextRetryAt)
}

func (a *Attempter) attemptEmail(
	ctx context.Context, tenantID, deliveryID string, sub subscription.Subscription,
	payload webhook.Payload, attempt int,
) {
	kind, ok := emailKindFor(payload.Event)
	if !ok {
		// ⚠ SHOULD NOT HAPPEN — the consumer's fan-out already skips an email
		// subscription for an event with no email form (see emailKindFor) — but
		// a retry attempted long after that check ran must still fail closed
		// rather than panic on a Render call it knows will refuse.
		a.deadLetter(ctx, tenantID, deliveryID, attempt,
			fmt.Sprintf("event %q has no email form", payload.Event))
		return
	}

	msg, err := email.Render(kind, toEmailData(payload))
	if err != nil {
		// Terminal: the same payload renders the same way next time.
		a.deadLetter(ctx, tenantID, deliveryID, attempt, err.Error())
		return
	}

	if err := a.mail.Send(ctx, sub.Target, msg); err != nil {
		a.log.Warn("email delivery failed", "delivery_id", deliveryID, "attempt", attempt, "error", err)
		if attempt >= webhook.MaxAttempts {
			a.deadLetter(ctx, tenantID, deliveryID, attempt, err.Error())
			return
		}
		next := a.now().Add(webhook.Backoff(attempt))
		a.record(ctx, tenantID, deliveryID, "pending", attempt, 0, err.Error(), &next)
		return
	}

	a.record(ctx, tenantID, deliveryID, "delivered", attempt, 0, "", nil)
}

func (a *Attempter) deadLetter(ctx context.Context, tenantID, deliveryID string, attempt int, cause string) {
	a.record(ctx, tenantID, deliveryID, "dead_lettered", attempt, 0, cause, nil)
}

func (a *Attempter) record(
	ctx context.Context, tenantID, deliveryID, status string,
	attempt, responseCode int, cause string, nextRetryAt *time.Time,
) {
	if err := a.store.RecordAttempt(ctx, tenantID, deliveryID, status, attempt, responseCode, cause, nextRetryAt); err != nil {
		a.log.Error("could not record a delivery attempt; the row's status may now be stale",
			"delivery_id", deliveryID, "status", status, "error", err)
	}
}

// emailKindFor maps a webhook event to its email form.
//
// ⚠ report.ready HAS NONE, DELIBERATELY (email.Kinds()'s own shape) — a
// rendered artifact finishing is a webhook-only integration event, not
// something a person needs an inbox notification for. The consumer's
// fan-out skips an email subscription here rather than enqueueing a
// delivery this function will always refuse.
func emailKindFor(e webhook.Event) (email.Kind, bool) {
	switch e {
	case webhook.EventScanCompleted:
		return email.KindScanCompleted, true
	case webhook.EventNewCriticalFindings:
		return email.KindNewCriticalFindings, true
	case webhook.EventCampaignFailed:
		return email.KindCampaignFailed, true
	default:
		return "", false
	}
}

// toEmailData derives email.Data from the stored webhook.Payload.
//
// ⚠ ProjectName/CampaignName ARE IDS, NOT NAMES, AND Cause IS ALWAYS EMPTY —
// A KNOWN, FLAGGED GAP, NOT A DESIGN CHOICE. `EnqueueDelivery` stores
// `webhook.Payload` (ids/counts/status/url only), not the richer
// `events.NotifyEventV1` a publisher actually sends — so by the time an
// email is rendered, ProjectName/CampaignName/Cause have already been
// narrowed away at fan-out time, before the row was ever written. Both
// `scan.completed`'s and `campaign.failed`'s publishers (scan-orchestrator,
// campaign) DO populate the richer fields on the envelope they publish; none
// of it survives to here. The template degrades honestly rather than
// crashing — a raw id where a name would go, and the Cause line simply
// omitted (`{{if .Data.Cause}}` in email.go's own template) — but a real fix
// means widening what `EnqueueDelivery`/`notify.deliveries.payload` stores
// to the richer envelope type, not something to do as a side effect of
// wiring a publisher.
func toEmailData(p webhook.Payload) email.Data {
	return email.Data{
		ProjectName:        p.ProjectID,
		CampaignName:       p.CampaignID,
		Status:             p.Status,
		Components:         p.Counts.Components,
		Findings:           p.Counts.Findings,
		Critical:           p.Counts.Critical,
		High:               p.Counts.High,
		EnginesUnavailable: p.Counts.EnginesUnavailable,
		URL:                p.URL,
		OccurredAt:         p.Timestamp,
	}
}
