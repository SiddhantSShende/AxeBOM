// Package handler is the notification service's HTTP surface.
//
// ⚠ THE SECRET IS WRITE-ONLY OVER THIS API.
//
// Creating a webhook subscription accepts a secret, which is stored in Vault
// and referenced by path. Nothing ever reads it back — not to the owner, not to
// an admin. A "show secret" endpoint means the secret is one XSS, one stolen
// session or one over-broad role away from disclosure, and it buys nothing: a
// customer who has lost their copy rotates it, which is a safe operation, while
// revealing it is not.
package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/notification/internal/store"
	"github.com/axebom/axebom/services/notification/internal/subscription"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

const maxRequestBody = 64 << 10

// Store is the persistence this handler needs.
type Store interface {
	CreateSubscription(ctx context.Context, tenantID string, s subscription.Subscription) (subscription.Subscription, error)
	ListSubscriptions(ctx context.Context, tenantID string) ([]subscription.Subscription, error)
	SetSubscriptionEnabled(ctx context.Context, tenantID, id string, enabled bool) (subscription.Subscription, error)
	DeleteSubscription(ctx context.Context, tenantID, id string) error
	SetSubscriptionSecretRef(ctx context.Context, tenantID, id, ref string) (subscription.Subscription, error)
	ListDeliveries(ctx context.Context, tenantID, subscriptionID string, limit int) ([]store.Delivery, error)
}

// Vault stores webhook signing secrets.
//
// ⚠ THE REF IS BUILT FROM FACTS THE SERVER KNOWS — tenant, kind, row id — never
// from a path a client supplied. vault.Ref.Path() derives a tenant-prefixed
// path deterministically, which is what makes the ownership check on read
// possible and what stops one tenant naming another's secret.
type Vault interface {
	Put(ctx context.Context, ref vault.Ref, data map[string]string) (string, error)
	Delete(ctx context.Context, ref vault.Ref, stored string) error
}

// Handler serves the notification endpoints.
type Handler struct {
	store Store
	vault Vault
	now   func() time.Time
}

// New builds a handler.
func New(s Store, v Vault, now func() time.Time) *Handler {
	if now == nil {
		now = time.Now
	}
	return &Handler{store: s, vault: v, now: now}
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type subscriptionResponse struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Target string   `json:"target"`
	Events []string `json:"events"`

	// ⚠ HasSecret, NOT THE SECRET. The UI needs to show that a webhook is
	// signed and offer to rotate; it never needs the value, and an endpoint
	// that returns one is a disclosure waiting for a stolen session.
	HasSecret bool `json:"has_secret"`

	Enabled bool `json:"enabled"`
}

func toResponse(s subscription.Subscription) subscriptionResponse {
	events := s.Events
	if events == nil {
		events = []string{}
	}
	return subscriptionResponse{
		ID: s.ID, Kind: string(s.Kind), Target: s.Target,
		Events: events, HasSecret: s.SecretRef != "", Enabled: s.Enabled,
	}
}

type deliveryResponse struct {
	ID           string `json:"id"`
	EventType    string `json:"event_type"`
	Attempt      int    `json:"attempt"`
	Status       string `json:"status"`
	ResponseCode int    `json:"response_code,omitempty"`
	Error        string `json:"error,omitempty"`
	NextRetryAt  string `json:"next_retry_at,omitempty"`
	CreatedAt    string `json:"created_at"`
	DeliveredAt  string `json:"delivered_at,omitempty"`
}

func toDeliveryResponse(d store.Delivery) deliveryResponse {
	out := deliveryResponse{
		ID: d.ID, EventType: d.EventType, Attempt: d.Attempt, Status: d.Status,
		ResponseCode: d.ResponseCode, Error: d.Error,
		CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339),
	}
	if d.NextRetryAt != nil {
		out.NextRetryAt = d.NextRetryAt.UTC().Format(time.RFC3339)
	}
	if d.DeliveredAt != nil {
		out.DeliveredAt = d.DeliveredAt.UTC().Format(time.RFC3339)
	}
	return out
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

// Create registers a delivery target.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		Kind   string   `json:"kind"`
		Target string   `json:"target"`
		Events []string `json:"events"`
		// Secret is optional for a webhook: absent, one is generated and
		// returned ONCE. This is the only moment it is ever visible.
		Secret string `json:"secret"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	sub := subscription.Subscription{
		TenantID: tenantID,
		Kind:     subscription.Kind(req.Kind),
		Target:   req.Target,
		Events:   req.Events,
		Enabled:  true,
		// A placeholder so Validate() sees a webhook as signed. The real path
		// is written below, once the row has an id to name it with.
		SecretRef: pendingRef,
	}
	if sub.Kind != subscription.KindWebhook {
		sub.SecretRef = ""
	}

	if err := sub.Validate(); err != nil {
		errs.Write(w, r, err)
		return
	}

	var secret string
	if sub.Kind == subscription.KindWebhook {
		secret = req.Secret
		if secret == "" {
			secret, err = generateSecret()
			if err != nil {
				errs.Write(w, r, err)
				return
			}
		}
		if len(secret) < minSecretLen {
			errs.Write(w, r, errs.Newf(errs.ValidationFieldInvalid,
				"a webhook signing secret must be at least %d characters; a short "+
					"secret is brute-forceable against a captured delivery", minSecretLen))
			return
		}
	}

	created, err := h.store.CreateSubscription(r.Context(), tenantID, sub)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	if sub.Kind == subscription.KindWebhook {
		// ⚠ THE SECRET GOES TO VAULT, NEVER TO POSTGRES. The row holds the
		// path. A secret in the database is a secret in every backup, every
		// read replica, and every ad-hoc query by an on-call engineer.
		ref := vault.Ref{
			TenantID: tenantID, Kind: vault.KindWebhookSecret, ID: created.ID,
		}
		stored, err := h.vault.Put(r.Context(), ref, map[string]string{"secret": secret})
		if err != nil {
			// The row exists but has no usable secret, so remove it rather than
			// leaving a subscription that will fail every delivery with a
			// confusing error.
			_ = h.store.DeleteSubscription(r.Context(), tenantID, created.ID)
			errs.Write(w, r, err)
			return
		}

		// The row records WHERE the secret lives. It never holds the secret.
		updated, err := h.store.SetSubscriptionSecretRef(r.Context(), tenantID, created.ID, stored)
		if err != nil {
			errs.Write(w, r, err)
			return
		}
		created = updated
	}

	out := map[string]any{"subscription": toResponse(created)}
	if secret != "" {
		// ⚠ RETURNED EXACTLY ONCE, ON CREATION. There is no endpoint that
		// reads it back; a customer who loses it rotates the subscription.
		out["secret"] = secret
		out["secret_notice"] = "This is the only time this secret is shown. " +
			"Store it now; it cannot be retrieved, only rotated."
	}
	errs.WriteJSON(w, http.StatusCreated, out)
}

// List returns a tenant's delivery targets.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	subs, err := h.store.ListSubscriptions(r.Context(), tenantID)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]subscriptionResponse, 0, len(subs))
	for _, s := range subs {
		out = append(out, toResponse(s))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

// SetEnabled turns a subscription on or off.
func (h *Handler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	updated, err := h.store.SetSubscriptionEnabled(
		r.Context(), tenantID, r.PathValue("id"), req.Enabled)
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, toResponse(updated))
}

// Delete removes a subscription and its secret.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	id := r.PathValue("id")
	if err := h.store.DeleteSubscription(r.Context(), tenantID, id); err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	// ⚠ THE SECRET IS REMOVED TOO, AND ITS FAILURE DOES NOT FAIL THE REQUEST.
	// The subscription is gone, so nothing can use the secret; an orphaned
	// Vault entry is untidy rather than dangerous, and returning 500 here would
	// tell the caller the delete failed when it did not.
	ref := vault.Ref{TenantID: tenantID, Kind: vault.KindWebhookSecret, ID: id}
	if path, perr := ref.Path(); perr == nil {
		if err := h.vault.Delete(r.Context(), ref, path); err != nil {
			_ = err // reported by the vault client's own metrics
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// Deliveries returns a subscription's delivery history.
func (h *Handler) Deliveries(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	deliveries, err := h.store.ListDeliveries(r.Context(), tenantID, r.PathValue("id"), limit)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]deliveryResponse, 0, len(deliveries))
	for _, d := range deliveries {
		out = append(out, toDeliveryResponse(d))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"deliveries": out})
}

// Events lists the events a subscription may filter on.
//
// The UI renders checkboxes from this rather than a hardcoded list, so adding
// an event to the product adds it to the settings screen.
func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	out := make([]string, 0, len(webhook.Events()))
	for _, e := range webhook.Events() {
		out = append(out, string(e))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"events": out})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// pendingRef stands in for a Vault path before the row has an id.
const pendingRef = "pending"

// minSecretLen is the shortest signing secret accepted.
//
// 32 characters of the generated form is 128 bits. A short secret is
// brute-forceable offline against a single captured delivery, which turns the
// signature from a proof into a formality.
const minSecretLen = 32

func generateSecret() (string, error) {
	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return "", errs.Wrap(err, errs.InternalUnexpected, "could not generate a signing secret")
	}
	return hex.EncodeToString(buf), nil
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errs.Newf(errs.ValidationFieldInvalid, "malformed request body: %v", err)
	}
	return nil
}

func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errs.New(errs.NotFoundResource, "no such subscription")
	}
	return err
}
