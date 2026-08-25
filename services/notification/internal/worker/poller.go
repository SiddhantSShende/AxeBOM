package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/axebom/axebom/services/notification/internal/store"
)

// PollInterval is how often the poller looks for due retries.
//
// ⚠ SHORTER THAN webhook.Backoff's FIRST STEP (30s), NOT LONGER. A retry due
// at t+30s that is only noticed at the next tick some minutes later turns a
// documented backoff schedule into an approximate one; polling faster than
// the shortest step keeps the schedule meaning what it says.
const PollInterval = 15 * time.Second

// ClaimBatchSize bounds one tick's work, matching campaign.DueCampaigns'
// batch-limit reasoning: after an outage, a huge batch should not make the
// process that drains it unresponsive to shutdown for minutes.
const ClaimBatchSize = 100

// Poller retries deliveries whose next_retry_at has passed. See attempt.go's
// package doc for why this cannot be NATS message redelivery instead.
type Poller struct {
	store     *store.Store
	attempter *Attempter
	now       func() time.Time
	log       *slog.Logger
}

// NewPoller builds a Poller. A nil clock uses time.Now.
func NewPoller(st *store.Store, a *Attempter, now func() time.Time, log *slog.Logger) *Poller {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Poller{store: st, attempter: a, now: now, log: log}
}

// Run ticks until the context is cancelled. Never returns an error — a
// poller that cannot reach the database logs and waits for the next tick,
// the same "log, do not exit" contract every background worker in this
// product follows.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()

	p.log.Info("polling for due deliveries", "interval", PollInterval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.tick(ctx)
		}
	}
}

func (p *Poller) tick(ctx context.Context) {
	due, err := p.store.ClaimDueDeliveries(ctx, p.now(), ClaimBatchSize)
	if err != nil {
		p.log.Error("could not claim due deliveries", "error", err)
		return
	}

	for _, d := range due {
		sub, err := p.store.GetSubscription(ctx, d.TenantID, d.SubscriptionID)
		if err != nil {
			// ⚠ THE SUBSCRIPTION IS GONE, NOT UNREACHABLE. DeleteSubscription
			// cascades its deliveries (store.go's own doc comment), so a claimed
			// row whose subscription cannot be found means it was deleted in
			// the gap between claim and lookup — dead-letter rather than spin
			// on a row that can never resolve.
			p.log.Warn("a due delivery's subscription is gone; dead-lettering",
				"delivery_id", d.ID, "subscription_id", d.SubscriptionID, "error", err)
			p.attempter.deadLetter(ctx, d.TenantID, d.ID, d.Attempt, err.Error())
			continue
		}

		// The attempt number is the one about to happen, not the one already
		// recorded — matches Consumer's first call passing 1, not 0.
		p.attempter.Attempt(ctx, d.TenantID, sub, d.ID, d.Payload, d.Attempt+1)
	}
}
