// Package store is the notification service's persistence layer.
//
// Every query goes through db.WithTenant, with exactly ONE exception:
// ClaimDueDeliveries (worker.go), which the retry poller calls with no tenant
// to scope by — the same shape campaign's DueCampaigns already is, and the
// same answer: a narrow SECURITY DEFINER function, never BYPASSRLS, never a
// superuser connection.
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

// ErrNotFound is returned when a row does not exist FOR THIS TENANT.
var ErrNotFound = errors.New("not found")

// Store is the notification service's database access.
type Store struct{ pool *db.Pool }

// New builds a store over a pool.
func New(pool *db.Pool) *Store { return &Store{pool: pool} }

const subscriptionColumns = `
	SELECT id, tenant_id, kind, target, events, COALESCE(secret_ref, ''), enabled,
	       COALESCE(created_by::text, '')
	FROM notify.subscriptions`

func scanSubscription(row pgx.Row) (subscription.Subscription, error) {
	var s subscription.Subscription
	var kind string
	err := row.Scan(&s.ID, &s.TenantID, &kind, &s.Target, &s.Events,
		&s.SecretRef, &s.Enabled, &s.CreatedBy)
	s.Kind = subscription.Kind(kind)
	return s, err
}

// CreateSubscription registers a delivery target.
func (s *Store) CreateSubscription(
	ctx context.Context, tenantID string, sub subscription.Subscription,
) (subscription.Subscription, error) {
	var out subscription.Subscription
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var err error
		out, err = scanSubscription(tx.QueryRow(ctx, `
			INSERT INTO notify.subscriptions
			    (tenant_id, kind, target, events, secret_ref, enabled, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid)
			RETURNING id, tenant_id, kind, target, events, COALESCE(secret_ref, ''),
			          enabled, COALESCE(created_by::text, '')`,
			tenantID, string(sub.Kind), sub.Target, sub.Events,
			nullIfEmpty(sub.SecretRef), sub.Enabled, sub.CreatedBy))
		return err
	})
	if err != nil {
		return subscription.Subscription{}, fmt.Errorf("create subscription: %w", err)
	}
	return out, nil
}

// ListSubscriptions returns a tenant's delivery targets.
func (s *Store) ListSubscriptions(
	ctx context.Context, tenantID string,
) ([]subscription.Subscription, error) {
	var out []subscription.Subscription
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, subscriptionColumns+` ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			sub, err := scanSubscription(rows)
			if err != nil {
				return err
			}
			out = append(out, sub)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	return out, nil
}

// MatchingSubscriptions returns the enabled targets that want an event.
//
// ⚠ THE EVENT FILTER IS APPLIED IN GO, NOT IN SQL, and deliberately: an empty
// `events` array means "everything" (see subscription.Matches), which is
// awkward to express as a WHERE clause and easy to get backwards there. One
// implementation of the rule, in the place that documents it.
func (s *Store) MatchingSubscriptions(
	ctx context.Context, tenantID string, event webhook.Event,
) ([]subscription.Subscription, error) {
	all, err := s.ListSubscriptions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []subscription.Subscription
	for _, sub := range all {
		if sub.Matches(event) {
			out = append(out, sub)
		}
	}
	return out, nil
}

// SetSubscriptionEnabled turns a subscription on or off.
func (s *Store) SetSubscriptionEnabled(
	ctx context.Context, tenantID, id string, enabled bool,
) (subscription.Subscription, error) {
	var out subscription.Subscription
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var err error
		out, err = scanSubscription(tx.QueryRow(ctx, `
			UPDATE notify.subscriptions SET enabled = $2 WHERE id = $1
			RETURNING id, tenant_id, kind, target, events, COALESCE(secret_ref, ''),
			          enabled, COALESCE(created_by::text, '')`, id, enabled))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return subscription.Subscription{}, ErrNotFound
	}
	if err != nil {
		return subscription.Subscription{}, fmt.Errorf("set subscription enabled: %w", err)
	}
	return out, nil
}

// DeleteSubscription removes a delivery target. Deliveries cascade.
func (s *Store) DeleteSubscription(ctx context.Context, tenantID, id string) error {
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM notify.subscriptions WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return fmt.Errorf("delete subscription: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Deliveries
// ---------------------------------------------------------------------------

// Delivery mirrors notify.deliveries.
type Delivery struct {
	ID             string
	TenantID       string
	SubscriptionID string
	EventType      string
	Payload        webhook.Payload
	Attempt        int
	Status         string
	ResponseCode   int
	Error          string
	NextRetryAt    *time.Time
	CreatedAt      time.Time
	DeliveredAt    *time.Time
}

// EnqueueDelivery records a delivery about to be attempted.
func (s *Store) EnqueueDelivery(
	ctx context.Context, tenantID, subscriptionID string, payload webhook.Payload,
) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	var id string
	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO notify.deliveries
			    (tenant_id, subscription_id, event_type, payload, attempt, status)
			VALUES ($1, $2, $3, $4, 1, 'pending')
			RETURNING id`, tenantID, subscriptionID, string(payload.Event), body).Scan(&id)
	})
	if err != nil {
		return "", fmt.Errorf("enqueue delivery: %w", err)
	}
	return id, nil
}

// RecordAttempt updates a delivery after one attempt.
//
// ⚠ A DEAD-LETTERED ROW IS RETAINED, NOT DELETED. It is the only record that a
// notification was owed and never arrived; deleting it makes the queue look
// clean and leaves the customer wondering why they were not told.
func (s *Store) RecordAttempt(
	ctx context.Context, tenantID, deliveryID, status string,
	attempt, responseCode int, cause string, nextRetryAt *time.Time,
) error {
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE notify.deliveries
			SET status = $2,
			    attempt = $3,
			    response_code = NULLIF($4, 0),
			    error = NULLIF($5, ''),
			    next_retry_at = $6,
			    delivered_at = CASE WHEN $2 = 'delivered' THEN now() ELSE delivered_at END
			WHERE id = $1`,
			deliveryID, status, attempt, responseCode, cause, nextRetryAt)
		return err
	})
	if err != nil {
		return fmt.Errorf("record delivery attempt: %w", err)
	}
	return nil
}

// ListDeliveries returns a subscription's delivery history, newest first.
func (s *Store) ListDeliveries(
	ctx context.Context, tenantID, subscriptionID string, limit int,
) ([]Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var out []Delivery
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, subscription_id, event_type, payload, attempt, status,
			       COALESCE(response_code, 0), COALESCE(error, ''), next_retry_at,
			       created_at, delivered_at
			FROM notify.deliveries
			WHERE subscription_id = $1
			ORDER BY created_at DESC
			LIMIT $2`, subscriptionID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var d Delivery
			var body []byte
			if err := rows.Scan(&d.ID, &d.TenantID, &d.SubscriptionID, &d.EventType,
				&body, &d.Attempt, &d.Status, &d.ResponseCode, &d.Error,
				&d.NextRetryAt, &d.CreatedAt, &d.DeliveredAt); err != nil {
				return err
			}
			if err := json.Unmarshal(body, &d.Payload); err != nil {
				return fmt.Errorf("decode stored payload for delivery %s: %w", d.ID, err)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	return out, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// SetSubscriptionSecretRef records where a webhook's signing secret lives.
//
// ⚠ IT STORES A PATH, AND THE COLUMN IS NAMED secret_ref FOR THAT REASON. If a
// secret itself ever reaches this function, every database backup and every
// read replica becomes a disclosure of every customer's signing key.
func (s *Store) SetSubscriptionSecretRef(
	ctx context.Context, tenantID, id, ref string,
) (subscription.Subscription, error) {
	var out subscription.Subscription
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var err error
		out, err = scanSubscription(tx.QueryRow(ctx, `
			UPDATE notify.subscriptions SET secret_ref = $2 WHERE id = $1
			RETURNING id, tenant_id, kind, target, events, COALESCE(secret_ref, ''),
			          enabled, COALESCE(created_by::text, '')`, id, ref))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return subscription.Subscription{}, ErrNotFound
	}
	if err != nil {
		return subscription.Subscription{}, fmt.Errorf("set subscription secret ref: %w", err)
	}
	return out, nil
}
