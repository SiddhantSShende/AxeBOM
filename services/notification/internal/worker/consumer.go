package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/services/notification/internal/store"
	"github.com/axebom/axebom/services/notification/internal/subscription"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

// ConsumerDurableName is the shared consumer name.
//
// ⚠ ONE DURABLE FOR EVERY REPLICA, NOT ONE PER INSTANCE — bus.StreamNotify is
// a WorkQueue stream, which permits exactly one consumer per filter subject;
// NATS distributes between the members. Same constraint report's render
// consumer already documents.
const ConsumerDurableName = "notification-delivery"

// Consumer fans a notify.> event out to every matching subscription and
// fires the FIRST delivery attempt for each. Retries are the Poller's job —
// see attempt.go's package doc for why the two cannot share one mechanism.
type Consumer struct {
	bus       *bus.Bus
	store     *store.Store
	attempter *Attempter
	log       *slog.Logger
}

// NewConsumer builds a Consumer.
func NewConsumer(b *bus.Bus, st *store.Store, a *Attempter, log *slog.Logger) *Consumer {
	if log == nil {
		log = slog.Default()
	}
	return &Consumer{bus: b, store: st, attempter: a, log: log}
}

// Run consumes until the context is cancelled.
func (c *Consumer) Run(ctx context.Context) error {
	consumer, err := c.bus.EnsureConsumer(ctx, bus.ConsumerConfig{
		Stream:        bus.StreamNotify,
		Durable:       ConsumerDurableName,
		FilterSubject: "notify.>",
		// Fan-out plus a first attempt per subscription is in-process work of
		// low seconds, not a sandboxed scan — much closer to a render than a
		// scan job.
		AckWait: 2 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("ensure the notification consumer: %w", err)
	}

	c.log.Info("consuming notify events",
		"stream", bus.StreamNotify, "durable", ConsumerDurableName, "subject", "notify.>")

	return c.bus.Consume(ctx, consumer, "notify.dlq", c.handle)
}

// handle fans one event out to its subscriptions.
//
// ⚠ ACKS UNCONDITIONALLY ONCE FAN-OUT ITSELF SUCCEEDS, EVEN IF EVERY
// DELIVERY FAILS. A delivery failure is not a reason to redeliver the EVENT
// — that would re-run fan-out for subscriptions that already got an enqueued
// row, creating duplicates, for a problem the Poller's retry schedule
// already owns. Only a failure BEFORE any row was written (the
// MatchingSubscriptions lookup itself) is safe to retry at the message
// level, because nothing has been enqueued yet to duplicate.
func (c *Consumer) handle(ctx context.Context, msg jetstream.Msg) error {
	var evt events.NotifyEventV1
	if err := json.Unmarshal(msg.Data(), &evt); err != nil {
		c.log.Error("a notify event could not be decoded", "error", err)
		return err // terminal: the same bytes will not parse next time
	}
	if err := evt.Validate(); err != nil {
		c.log.Error("a notify event is not usable", "error", err)
		return err // terminal
	}

	event := webhook.Event(evt.Event)
	if !event.Valid() {
		c.log.Error("a notify event names an event type this build does not emit",
			"event", evt.Event)
		return fmt.Errorf("unknown notify event %q", evt.Event) // terminal
	}

	subs, err := c.store.MatchingSubscriptions(ctx, evt.TenantID, event)
	if err != nil {
		c.log.Warn("subscriptions could not be looked up; the event will be retried",
			"tenant_id", evt.TenantID, "event", evt.Event, "error", err)
		return fmt.Errorf("%w: %w", bus.ErrRetry, err)
	}

	payload := toWebhookPayload(evt)
	for _, sub := range subs {
		if sub.Kind == subscription.KindEmail {
			if _, ok := emailKindFor(event); !ok {
				c.log.Warn("an email subscription matched an event with no email form; skipping",
					"subscription_id", sub.ID, "event", evt.Event)
				continue
			}
		}

		id, err := c.store.EnqueueDelivery(ctx, evt.TenantID, sub.ID, payload)
		if err != nil {
			// ⚠ ONE SUBSCRIPTION'S FAILURE MUST NOT BLOCK THE OTHERS, and must
			// not retry the whole message either — see the function doc.
			c.log.Error("could not enqueue a delivery",
				"subscription_id", sub.ID, "event", evt.Event, "error", err)
			continue
		}
		c.attempter.Attempt(ctx, evt.TenantID, sub, id, payload, 1)
	}
	return nil
}

// toWebhookPayload narrows the internal envelope to the wire-safe shape —
// see events.NotifyEventV1's own doc comment on why the two are different
// types.
func toWebhookPayload(e events.NotifyEventV1) webhook.Payload {
	return webhook.Payload{
		Event:      webhook.Event(e.Event),
		Timestamp:  e.OccurredAt,
		TenantID:   e.TenantID,
		ProjectID:  e.ProjectID,
		ScanID:     e.ScanID,
		ReportID:   e.ReportID,
		CampaignID: e.CampaignID,
		Status:     e.Status,
		Counts: webhook.Counts{
			Components:         e.Components,
			Findings:           e.Findings,
			Critical:           e.Critical,
			High:               e.High,
			EnginesUnavailable: e.EnginesUnavailable,
		},
		URL: e.URL,
	}
}
