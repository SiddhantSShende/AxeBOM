package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/notification/internal/subscription"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

// GetSubscription reads one subscription. The delivery worker calls this
// after MatchingSubscriptions/ClaimDueDeliveries has already told it which
// subscription_id a delivery belongs to — this is the tenant-scoped follow-up
// read, not a second way to enumerate subscriptions.
func (s *Store) GetSubscription(ctx context.Context, tenantID, id string) (subscription.Subscription, error) {
	var out subscription.Subscription
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var err error
		out, err = scanSubscription(tx.QueryRow(ctx, subscriptionColumns+` WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return subscription.Subscription{}, ErrNotFound
	}
	if err != nil {
		return subscription.Subscription{}, fmt.Errorf("get subscription: %w", err)
	}
	return out, nil
}

// DueDelivery is a claimed row, ready for the worker to attempt.
type DueDelivery struct {
	ID             string
	TenantID       string
	SubscriptionID string
	EventType      string
	Payload        webhook.Payload
	Attempt        int
}

// ClaimDueDeliveries is the poller's cross-tenant read.
//
// ⚠ THE ONE CROSS-TENANT READ IN THIS SERVICE — this file's package doc
// comment ("nothing in this service needs to read across tenants... unlike
// the campaign scheduler") predates the retry poller and is now the ONE
// documented exception, the same shape campaign.DueCampaigns already is: a
// narrow SECURITY DEFINER function (migrations/notify/0002), never
// BYPASSRLS, never a superuser connection. Everything the poller does AFTER
// this call runs inside WithTenant using the tenant_id this function
// returned.
func (s *Store) ClaimDueDeliveries(ctx context.Context, now time.Time, limit int) ([]DueDelivery, error) {
	rows, err := s.pool.Raw().Query(ctx,
		`SELECT id, tenant_id, subscription_id, event_type, payload, attempt
		   FROM notify.claim_due_deliveries($1, $2)`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("claim due deliveries: %w", err)
	}
	defer rows.Close()

	var out []DueDelivery
	for rows.Next() {
		var (
			d    DueDelivery
			body []byte
		)
		if err := rows.Scan(&d.ID, &d.TenantID, &d.SubscriptionID, &d.EventType,
			&body, &d.Attempt); err != nil {
			return nil, fmt.Errorf("scan due delivery: %w", err)
		}
		if err := json.Unmarshal(body, &d.Payload); err != nil {
			return nil, fmt.Errorf("decode stored payload for delivery %s: %w", d.ID, err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
