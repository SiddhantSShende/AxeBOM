// Package delivery posts signed webhooks and records what happened.
//
// ⚠ THE DELIVERY CLIENT IS THE SECOND HALF OF THE SSRF DEFENCE.
//
// subscription.ValidateWebhookURL rejects the obvious targets when a customer
// types them, which gives a clear error at the right moment. It cannot be the
// whole control: DNS rebinding means a hostname that resolves to a public
// address at validation time can resolve to 127.0.0.1 when the socket is
// dialled, and the attacker sets the TTL.
//
// So every request goes through safedial, which resolves once, refuses if ANY
// candidate address is private, and connects to the IP literal it validated.
// Same rule as the fetcher, same implementation.
package delivery

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/platform/safedial"
	"github.com/axebom/axebom/services/notification/internal/subscription"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

// Timeout bounds one delivery attempt.
//
// ⚠ SHORT ON PURPOSE. A receiver that holds the connection open is doing to us
// what a slowloris does to a web server: with no timeout, a handful of slow
// endpoints occupy every delivery worker and nobody else's notifications go
// out. Ten seconds is generous for accepting a small JSON body.
const Timeout = 10 * time.Second

// MaxResponseBytes bounds what we read back.
//
// The response is only used for the audit record. A receiver answering with a
// gigabyte would otherwise be an out-of-memory vector against the sender.
const MaxResponseBytes = 8 << 10

// Secrets resolves a subscription's signing key.
//
// ⚠ RESOLVED PER DELIVERY, NEVER CACHED IN THE SUBSCRIPTION. A secret held in a
// long-lived struct is a secret in every heap dump and every crash report.
type Secrets interface {
	// ⚠ IT TAKES THE IDENTITY, NOT JUST THE STORED PATH. The Vault client
	// re-derives the correct path from (tenant, kind, id) and compares it with
	// what the database held, so a secret_ref tampered with in Postgres points
	// at nothing rather than at another tenant's key. Passing only the string
	// would throw that check away.
	Resolve(ctx context.Context, tenantID, subscriptionID, storedRef string) ([]byte, error)
}

// Client posts webhook deliveries.
type Client struct {
	http    *http.Client
	secrets Secrets
	now     func() time.Time
}

// Options configure a Client.
type Options struct {
	Secrets Secrets
	// Transport is overridable for tests. nil builds the SSRF-safe one.
	Transport http.RoundTripper
	Now       func() time.Time
}

// New builds a Client.
func New(opts Options) (*Client, error) {
	if opts.Secrets == nil {
		return nil, fmt.Errorf("delivery: a secret resolver is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	transport := opts.Transport
	if transport == nil {
		transport = safedial.Transport(&safedial.Dialer{Timeout: Timeout})
	}

	return &Client{
		http: &http.Client{
			Timeout:   Timeout,
			Transport: transport,
			// ⚠ REDIRECTS ARE REFUSED OUTRIGHT, NOT FOLLOWED SAFELY.
			//
			// A webhook has no reason to redirect: the customer gave us the
			// endpoint. Following one lets a receiver that we validated hand us
			// off to an address we did not — and the signed payload, which
			// proves the delivery came from us, goes with it.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return fmt.Errorf(
					"webhook endpoint redirected to %s; deliveries are not redirected, "+
						"because the signed payload would follow to an address that was "+
						"never validated", req.URL.Redacted())
			},
		},
		secrets: opts.Secrets,
		now:     opts.Now,
	}, nil
}

// Result is what one attempt produced.
type Result struct {
	webhook.Outcome
	// Response is the first few kilobytes the receiver returned, for the audit
	// record. Truncated, and never interpreted.
	Response string
	// NextRetryAt is set when the delivery will be tried again.
	NextRetryAt *time.Time
	// DeadLettered is true when this was the last attempt.
	DeadLettered bool
}

// Deliver posts one payload to one subscription.
func (c *Client) Deliver(
	ctx context.Context, sub subscription.Subscription, payload webhook.Payload, attempt int,
) (Result, error) {
	if sub.Kind != subscription.KindWebhook {
		return Result{}, fmt.Errorf("delivery: %s is not a webhook subscription", sub.ID)
	}

	body, err := webhook.Encode(payload)
	if err != nil {
		return Result{}, err
	}

	secret, err := c.secrets.Resolve(ctx, sub.TenantID, sub.ID, sub.SecretRef)
	if err != nil {
		// ⚠ NOT RETRYABLE AS A DELIVERY. An unresolvable secret is our
		// misconfiguration, not the receiver's outage, and retrying it five
		// times with backoff buries the real cause under transport noise.
		return Result{}, fmt.Errorf("resolve webhook secret for %s: %w", sub.ID, err)
	}
	if len(secret) == 0 {
		return Result{}, fmt.Errorf("webhook secret for %s is empty", sub.ID)
	}

	sentAt := c.now().UTC()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Target, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AxeBOM-Webhook/1")
	req.Header.Set(webhook.SignatureHeader, webhook.Sign(body, sentAt, secret))
	req.Header.Set(webhook.TimestampHeader, sentAt.Format(time.RFC3339))
	// The delivery id lets a receiver deduplicate a retry without parsing.
	req.Header.Set("X-AxeBOM-Delivery", payload.DeliveryID)
	req.Header.Set("X-AxeBOM-Event", string(payload.Event))

	resp, err := c.http.Do(req)
	if err != nil {
		// A transport failure — DNS, TLS, timeout, or a blocked address. The
		// first three are retryable; a blocked address is not, and saying so
		// keeps a misconfigured endpoint from consuming five attempts.
		return c.transportFailure(err, attempt, sentAt), nil
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))

	out := webhook.Classify(resp.StatusCode, attempt)
	result := Result{Outcome: out, Response: string(raw)}
	c.schedule(&result, attempt, sentAt)
	return result, nil
}

func (c *Client) transportFailure(err error, attempt int, sentAt time.Time) Result {
	retryable := true
	reason := fmt.Sprintf("the endpoint could not be reached: %v", err)

	if isBlockedAddress(err) {
		// ⚠ RETRYING WOULD BE POINTLESS AND SLIGHTLY DANGEROUS. The address is
		// refused by policy, so four more attempts change nothing — and each
		// one is another DNS lookup driven by an attacker-controlled name.
		retryable = false
		reason = fmt.Sprintf(
			"the endpoint resolves to an address this platform will not connect to: %v", err)
	}

	result := Result{Outcome: webhook.Outcome{
		Retryable: retryable, Attempt: attempt, Reason: reason,
	}}
	c.schedule(&result, attempt, sentAt)
	return result
}

// schedule fills in the retry time or marks the delivery dead.
func (c *Client) schedule(r *Result, attempt int, sentAt time.Time) {
	if webhook.ShouldDeadLetter(r.Outcome) {
		// ⚠ DEAD-LETTERED, NOT DELETED. The row is RETAINED so an operator can
		// see what was not delivered and why. A queue that silently drops what
		// it could not send is a queue that lies about its own state.
		r.DeadLettered = true
		return
	}
	if r.Delivered {
		return
	}
	next := sentAt.Add(webhook.Backoff(attempt))
	r.NextRetryAt = &next
}

// isBlockedAddress reports whether the failure was our SSRF policy.
//
// ⚠ IT UNWRAPS. http.Client wraps a dialer error in *url.Error, so a direct
// type assertion on the returned error finds nothing and every blocked address
// would be retried five times.
func isBlockedAddress(err error) bool {
	return errs.Is(err, errs.FetchPrivateAddressBlocked)
}
