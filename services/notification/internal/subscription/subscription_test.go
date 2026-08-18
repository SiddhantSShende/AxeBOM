package subscription

import (
	"strings"
	"testing"

	"github.com/encorebom/encorebom/services/notification/internal/webhook"
)

func webhookSub() Subscription {
	return Subscription{
		ID: "sub-1", TenantID: "tenant-a",
		Kind: KindWebhook, Target: "https://hooks.example.com/encorebom",
		SecretRef: "secret/data/tenants/tenant-a/webhooks/sub-1",
		Enabled:   true,
	}
}

// ---------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------

// TestAWebhookURLCannotPointInsideThePlatform.
//
// ⚠ THE PLATFORM MAKES AN AUTHENTICATED POST TO WHATEVER A CUSTOMER TYPES, from
// inside our network, on a schedule they control. The cloud metadata endpoint
// is the canonical target — it needs no credentials and returns instance
// credentials.
func TestAWebhookURLCannotPointInsideThePlatform(t *testing.T) {
	blocked := []string{
		"https://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://localhost/hook",
		"https://127.0.0.1:8080/hook",
		"https://[::1]/hook",
		"https://postgres.internal/hook",
		"https://vault.local/hook",
	}

	for _, raw := range blocked {
		if err := ValidateWebhookURL(raw); err == nil {
			t.Errorf("%s was accepted as a webhook target", raw)
		}
	}
}

func TestAWebhookURLMustBeHTTPS(t *testing.T) {
	// A signed payload over http is signed AND readable, and the signature
	// proves authenticity to an eavesdropper as much as to the receiver.
	for _, raw := range []string{
		"http://hooks.example.com/x",
		"ftp://hooks.example.com/x",
		"file:///etc/passwd",
		"gopher://hooks.example.com/x",
	} {
		if err := ValidateWebhookURL(raw); err == nil {
			t.Errorf("%s was accepted", raw)
		}
	}
}

func TestAWebhookURLMustNotEmbedCredentials(t *testing.T) {
	// Credentials in a URL end up in logs and in the subscription row.
	if err := ValidateWebhookURL("https://user:password@hooks.example.com/x"); err == nil {
		t.Fatal("a URL with embedded credentials was accepted")
	}
}

func TestAnOrdinaryWebhookURLIsAccepted(t *testing.T) {
	// The check must not be so strict it rejects the normal case — a validator
	// nobody can satisfy gets removed, not fixed.
	for _, raw := range []string{
		"https://hooks.slack.com/services/T000/B000/XXXX",
		"https://example.com:8443/encorebom?source=prod",
		"https://sub.domain.example.co.in/hook",
	} {
		if err := ValidateWebhookURL(raw); err != nil {
			t.Errorf("%s was rejected: %v", raw, err)
		}
	}
}

func TestTheParseTimeCheckIsDocumentedAsIncomplete(t *testing.T) {
	// ⚠ DNS REBINDING DEFEATS ANY PARSE-TIME CHECK. A hostname resolving to a
	// public address now can resolve to 127.0.0.1 when the socket is dialled.
	// This test exists to keep that fact attached to the function: a name we do
	// not recognise passes here, and MUST still be blocked at connection time.
	if err := ValidateWebhookURL("https://rebind.example.com/hook"); err != nil {
		t.Fatalf("a public-looking name was rejected at parse time: %v", err)
	}
	// The connection-time control lives in the delivery client. If that ever
	// stops existing, this comment is the trail back to why it must.
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

func TestAWebhookSubscriptionNeedsASigningSecret(t *testing.T) {
	// An unsigned delivery cannot be distinguished from a forged one by the
	// receiver, which makes the whole channel untrustworthy.
	s := webhookSub()
	s.SecretRef = ""
	if err := s.Validate(); err == nil {
		t.Fatal("a webhook subscription with no signing secret was accepted")
	}
}

func TestTheSubscriptionCarriesAPathNotASecret(t *testing.T) {
	// ⚠ A SECRET IN POSTGRES IS A SECRET IN EVERY BACKUP, EVERY READ REPLICA,
	// AND EVERY AD-HOC QUERY. The row says where the secret lives.
	s := webhookSub()
	if !strings.HasPrefix(s.SecretRef, "secret/") {
		t.Errorf("secret_ref = %q, which does not look like a Vault path", s.SecretRef)
	}
	if strings.Contains(s.Redacted(), s.Target) {
		t.Error("the log form contains the callback URL")
	}
}

func TestTheLogFormRevealsNoTarget(t *testing.T) {
	// An email target is personal data; a callback URL is an attack surface.
	s := Subscription{
		ID: "sub-1", Kind: KindEmail, Target: "security@customer.example",
		Enabled: true,
	}
	if strings.Contains(s.Redacted(), "security@customer.example") {
		t.Errorf("the log form leaks the address: %s", s.Redacted())
	}
	if !strings.Contains(s.Redacted(), "sub-1") {
		t.Errorf("the log form does not identify the subscription: %s", s.Redacted())
	}
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

func TestAnEmptyFilterMeansEverything(t *testing.T) {
	// ⚠ THE OPPOSITE OF A PERMISSION DEFAULT, DELIBERATELY. A subscription
	// exists because somebody asked to be told; reading an empty list as
	// "nothing" produces a subscription that silently receives no messages, and
	// silence is indistinguishable from "no events happened".
	s := webhookSub()
	s.Events = nil

	for _, e := range webhook.Events() {
		if !s.Matches(e) {
			t.Errorf("an unfiltered subscription did not match %s", e)
		}
	}
}

func TestAFilterExcludesEverythingElse(t *testing.T) {
	s := webhookSub()
	s.Events = []string{string(webhook.EventNewCriticalFindings)}

	if !s.Matches(webhook.EventNewCriticalFindings) {
		t.Error("the subscribed event did not match")
	}
	if s.Matches(webhook.EventScanCompleted) {
		t.Error("an unsubscribed event matched")
	}
}

func TestADisabledSubscriptionMatchesNothing(t *testing.T) {
	s := webhookSub()
	s.Enabled = false
	for _, e := range webhook.Events() {
		if s.Matches(e) {
			t.Errorf("a disabled subscription matched %s", e)
		}
	}
}

func TestAnUnknownEventIsRefusedAtWriteTime(t *testing.T) {
	// Otherwise the subscription looks configured and receives nothing.
	s := webhookSub()
	s.Events = []string{"scan.probably_fine"}
	if err := s.Validate(); err == nil {
		t.Fatal("a subscription to an event this build never emits was accepted")
	}
}

// ---------------------------------------------------------------------------
// Email targets
// ---------------------------------------------------------------------------

func TestAnEmailTargetCannotInjectHeaders(t *testing.T) {
	for _, target := range []string{
		"a@b.com\r\nBcc: everyone@example.com",
		"a@b.com\nX-Injected: yes",
		"a@b.com, evil@example.com",
		"a@b.com; evil@example.com",
		"a@b.com\x00",
	} {
		s := Subscription{Kind: KindEmail, Target: target, Enabled: true}
		if err := s.Validate(); err == nil {
			t.Errorf("%q was accepted as an email target", target)
		}
	}
}

func TestAnOrdinaryAddressIsAccepted(t *testing.T) {
	for _, target := range []string{
		"security@customer.example",
		"first.last+encorebom@customer.co.in",
	} {
		s := Subscription{Kind: KindEmail, Target: target, Enabled: true}
		if err := s.Validate(); err != nil {
			t.Errorf("%q was rejected: %v", target, err)
		}
	}
}

func TestAnUnknownKindIsRefused(t *testing.T) {
	s := Subscription{Kind: "carrier_pigeon", Target: "x", Enabled: true}
	if err := s.Validate(); err == nil {
		t.Fatal("an unsupported channel was accepted")
	}
}
