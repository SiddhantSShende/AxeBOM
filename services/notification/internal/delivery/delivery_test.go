package delivery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/services/notification/internal/subscription"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

var sentAt = time.Date(2026, 8, 17, 9, 14, 3, 0, time.UTC)

type fakeSecrets struct {
	secret []byte
	err    error
	calls  int
}

func (f *fakeSecrets) Resolve(context.Context, string, string, string) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.secret, nil
}

func payload() webhook.Payload {
	return webhook.Payload{
		Event:      webhook.EventScanCompleted,
		Timestamp:  sentAt.Format(time.RFC3339),
		DeliveryID: "0199-delivery",
		TenantID:   "0199-tenant",
		ScanID:     "0199-scan",
		Status:     "completed",
		URL:        "https://app.axebom.example/scans/0199-scan",
	}
}

func sub(target string) subscription.Subscription {
	return subscription.Subscription{
		ID: "sub-1", TenantID: "tenant-a",
		Kind: subscription.KindWebhook, Target: target,
		SecretRef: "secret/data/tenants/tenant-a/webhooks/sub-1",
		Enabled:   true,
	}
}

// client builds a Client whose transport is the test server's, bypassing
// safedial so an httptest server on 127.0.0.1 is reachable.
//
// ⚠ THE SSRF DEFENCE IS TESTED SEPARATELY, BELOW, WITH THE REAL TRANSPORT.
// Overriding it here is what makes the rest of these tests possible at all —
// every httptest server listens on loopback, which the real client refuses.
func client(t *testing.T, secrets *fakeSecrets) *Client {
	t.Helper()
	c, err := New(Options{
		Secrets:   secrets,
		Transport: http.DefaultTransport,
		Now:       func() time.Time { return sentAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---------------------------------------------------------------------------
// Signing on the wire
// ---------------------------------------------------------------------------

func TestTheDeliveredRequestVerifiesAtTheReceiver(t *testing.T) {
	secret := []byte("a-shared-secret-of-reasonable-length")
	var verified bool
	var verifyErr error

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)

		// Exactly what a customer's receiver would do.
		verifyErr = webhook.Verify(body, r.Header.Get(webhook.SignatureHeader), secret, sentAt)
		verified = verifyErr == nil
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{secret: secret})
	res, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Delivered {
		t.Fatalf("delivery was not recorded as delivered: %+v", res.Outcome)
	}
	if !verified {
		t.Fatalf("the receiver could not verify the signature: %v", verifyErr)
	}
}

func TestTheDeliveryCarriesIdentifyingHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")})
	if _, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1); err != nil {
		t.Fatal(err)
	}

	// The delivery id lets a receiver deduplicate a retry without parsing.
	if got.Get("X-AxeBOM-Delivery") != "0199-delivery" {
		t.Errorf("no delivery id header: %v", got)
	}
	if got.Get("X-AxeBOM-Event") != string(webhook.EventScanCompleted) {
		t.Errorf("no event header: %v", got)
	}
	if got.Get(webhook.SignatureHeader) == "" {
		t.Error("no signature header")
	}
}

func TestTheSecretIsResolvedPerDeliveryAndNeverHeld(t *testing.T) {
	// ⚠ A SECRET IN A LONG-LIVED STRUCT IS A SECRET IN EVERY HEAP DUMP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secrets := &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")}
	c := client(t, secrets)

	for range 3 {
		if _, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1); err != nil {
			t.Fatal(err)
		}
	}
	if secrets.calls != 3 {
		t.Fatalf("the secret was resolved %d times for 3 deliveries; it is being cached", secrets.calls)
	}
}

func TestAnUnresolvableSecretIsAConfigurationErrorNotARetry(t *testing.T) {
	// Retrying it five times with backoff buries our misconfiguration under
	// transport noise.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{err: errors.New("vault sealed")})
	if _, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1); err == nil {
		t.Fatal("an unresolvable secret produced no error")
	}

	c = client(t, &fakeSecrets{secret: nil})
	if _, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1); err == nil {
		t.Fatal("an empty secret was used to sign a delivery")
	}
}

// ---------------------------------------------------------------------------
// Retry and dead-letter
// ---------------------------------------------------------------------------

func TestA5xxSchedulesARetryAndTheFifthDeadLetters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")})

	for attempt := 1; attempt < webhook.MaxAttempts; attempt++ {
		res, err := c.Deliver(context.Background(), sub(srv.URL), payload(), attempt)
		if err != nil {
			t.Fatal(err)
		}
		if res.DeadLettered {
			t.Fatalf("attempt %d dead-lettered early", attempt)
		}
		if res.NextRetryAt == nil {
			t.Fatalf("attempt %d scheduled no retry", attempt)
		}
		if !res.NextRetryAt.After(sentAt) {
			t.Errorf("attempt %d scheduled a retry in the past", attempt)
		}
	}

	final, err := c.Deliver(context.Background(), sub(srv.URL), payload(), webhook.MaxAttempts)
	if err != nil {
		t.Fatal(err)
	}
	if !final.DeadLettered {
		t.Fatal("delivery kept retrying past the attempt limit")
	}
	if final.NextRetryAt != nil {
		t.Error("a dead-lettered delivery still has a retry time")
	}
	// ⚠ RETAINED, NOT DROPPED. The reason is what an operator reads.
	if final.Reason == "" {
		t.Error("the dead-lettered delivery carries no reason")
	}
}

func TestA4xxDeadLettersOnTheFirstAttempt(t *testing.T) {
	// A receiver answering 401 will answer the same way in an hour; retrying is
	// a small denial of service against somebody who already told us to stop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")})
	res, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DeadLettered {
		t.Fatal("a 401 was retried")
	}
}

func TestTheResponseIsRecordedButBounded(t *testing.T) {
	// A receiver answering with a gigabyte would otherwise be an out-of-memory
	// vector against the sender.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20)))
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")})
	res, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Response) > MaxResponseBytes {
		t.Fatalf("recorded %d bytes of response, cap is %d", len(res.Response), MaxResponseBytes)
	}
	if len(res.Response) == 0 {
		t.Error("no response was recorded for the audit trail")
	}
}

// ---------------------------------------------------------------------------
// SSRF — with the REAL transport
// ---------------------------------------------------------------------------

// TestTheRealClientWillNotConnectToLoopback.
//
// ⚠ THE OTHER TESTS OVERRIDE THE TRANSPORT, so this is the only one that
// exercises what actually ships. It uses an httptest server precisely because
// it listens on 127.0.0.1 — the delivery must fail, and it must fail as a
// POLICY refusal rather than a retryable network error.
func TestTheRealClientWillNotConnectToLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Options{
		Secrets: &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")},
		Now:     func() time.Time { return sentAt },
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Delivered {
		t.Fatal("the shipping client connected to loopback")
	}

	// ⚠ NOT RETRYABLE. Four more attempts change nothing, and each one is
	// another DNS lookup driven by an attacker-controlled name.
	if res.Retryable {
		t.Errorf("a blocked address was marked retryable: %s", res.Reason)
	}
	if !res.DeadLettered {
		t.Error("a blocked address was not dead-lettered on the first attempt")
	}
	if !strings.Contains(res.Reason, "will not connect") {
		t.Errorf("the reason does not explain the refusal: %s", res.Reason)
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	// ⚠ A REDIRECT WOULD CARRY THE SIGNED PAYLOAD TO AN ADDRESS WE NEVER
	// VALIDATED, and the signature is what proves the delivery came from us.
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		if r.URL.Path == "/final" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	c := client(t, &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")})
	res, err := c.Deliver(context.Background(), sub(srv.URL), payload(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Delivered {
		t.Fatal("a redirected delivery was recorded as delivered")
	}
	if hops != 1 {
		t.Errorf("the client made %d requests; it followed the redirect", hops)
	}
}

func TestANonWebhookSubscriptionIsRefused(t *testing.T) {
	c := client(t, &fakeSecrets{secret: []byte("s3cret-of-reasonable-length")})
	s := sub("https://hooks.example.com/x")
	s.Kind = subscription.KindEmail

	if _, err := c.Deliver(context.Background(), s, payload(), 1); err == nil {
		t.Fatal("an email subscription was posted as a webhook")
	}
}

func TestNewRefusesAClientWithNoSecretResolver(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a delivery client with no secret resolver was built")
	}
}
