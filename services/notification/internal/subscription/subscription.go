// Package subscription decides who is notified of what.
//
// ⚠ THE SECRET IS NEVER IN THE DATABASE. A subscription row holds `secret_ref`
// — a Vault path — and nothing else. A webhook HMAC secret in Postgres means
// every database backup, every read replica, every ad-hoc query by an on-call
// engineer, and every SQL injection is a disclosure of every customer's
// signing key. The row says where the secret lives; only the delivery path
// resolves it, moments before use.
package subscription

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/notification/internal/webhook"
)

// Kind is a delivery channel.
type Kind string

const (
	// KindEmail delivers to an address.
	KindEmail Kind = "email"
	// KindWebhook posts to a URL.
	KindWebhook Kind = "webhook"
)

// Subscription mirrors notify.subscriptions.
type Subscription struct {
	ID       string
	TenantID string

	Kind Kind
	// Target is an email address or a URL, depending on Kind.
	Target string
	// Events filters what this subscription receives. EMPTY MEANS ALL — see
	// Matches for why that is the safe default here and not everywhere.
	Events []string

	// SecretRef is a Vault path. It is NEVER the secret.
	SecretRef string

	Enabled   bool
	CreatedBy string
}

// Matches reports whether this subscription wants an event.
//
// ⚠ AN EMPTY FILTER MEANS EVERYTHING, WHICH IS THE OPPOSITE OF THE DEFAULT FOR
// A PERMISSION CHECK — and deliberately so. A subscription exists because
// somebody asked to be told; an empty list is "tell me about everything", not
// "tell me about nothing". Getting this backwards produces a subscription that
// silently receives nothing, and silence is indistinguishable from "no events
// happened", which is exactly the failure a notification is meant to prevent.
func (s Subscription) Matches(event webhook.Event) bool {
	if !s.Enabled {
		return false
	}
	if len(s.Events) == 0 {
		return true
	}
	for _, e := range s.Events {
		if e == string(event) {
			return true
		}
	}
	return false
}

// Validate checks a subscription before it is stored.
func (s Subscription) Validate() error {
	switch s.Kind {
	case KindEmail:
		if err := validateEmail(s.Target); err != nil {
			return err
		}
	case KindWebhook:
		if err := ValidateWebhookURL(s.Target); err != nil {
			return err
		}
		if s.SecretRef == "" {
			return errs.New(errs.ValidationFieldRequired,
				"a webhook subscription needs a signing secret; an unsigned delivery "+
					"cannot be distinguished from a forged one by the receiver")
		}
	default:
		return errs.Newf(errs.ValidationFieldInvalid,
			"%q is not a delivery channel this build supports", s.Kind)
	}

	for _, e := range s.Events {
		if !webhook.Event(e).Valid() {
			return errs.Newf(errs.ValidationFieldInvalid,
				"%q is not an event this build emits", e)
		}
	}
	return nil
}

// ValidateWebhookURL checks a callback target.
//
// ⚠ A WEBHOOK URL IS AN SSRF PRIMITIVE. The platform will make an authenticated
// POST to whatever address a customer types, from inside our network, on a
// schedule they control. `http://169.254.169.254/latest/meta-data/` is the
// canonical target; so is anything on 10./172.16./192.168.
//
// This is the PARSE-TIME half, and it is deliberately not the whole control.
// DNS rebinding defeats any parse-time check — a hostname that resolves to a
// public address now can resolve to 127.0.0.1 at connection time — so the
// delivery client ALSO blocks private ranges when the socket is dialled, the
// same rule the fetcher follows (docs/05-SECURITY-MODEL.md §4). Rejecting the
// obvious cases here gives the customer a clear error at the moment they type
// it, instead of a delivery that mysteriously never arrives.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errs.Newf(errs.ValidationFieldInvalid, "webhook URL is unparseable: %v", err)
	}

	// https only. A signed payload over http is signed and readable.
	if u.Scheme != "https" {
		return errs.Newf(errs.ValidationFieldInvalid,
			"webhook URL must be https; %q would send a signed payload in the clear", u.Scheme)
	}
	if u.Host == "" {
		return errs.New(errs.ValidationFieldInvalid, "webhook URL has no host")
	}
	if u.User != nil {
		// Credentials in a URL end up in logs and in the subscription row.
		return errs.New(errs.ValidationFieldInvalid,
			"webhook URL must not embed credentials; use the signing secret instead")
	}

	host := strings.ToLower(u.Hostname())
	for _, blocked := range []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
		"169.254.169.254", "metadata.google.internal",
	} {
		if host == blocked {
			return errs.Newf(errs.FetchPrivateAddressBlocked,
				"webhook URL points at %s, which is not reachable from outside this "+
					"platform and is a common target for exfiltration", host)
		}
	}
	if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return errs.Newf(errs.FetchPrivateAddressBlocked,
			"webhook URL points at the internal name %s", host)
	}

	return nil
}

func validateEmail(target string) error {
	// Deliberately shallow. Full RFC 5322 validation rejects addresses that
	// work and accepts ones that do not; what matters here is that the value
	// cannot inject a header and is plausibly an address.
	if strings.ContainsAny(target, "\r\n\x00,;") {
		return errs.New(errs.ValidationFieldInvalid,
			"email target contains a control or separator character")
	}
	at := strings.LastIndex(target, "@")
	if at <= 0 || at == len(target)-1 {
		return errs.Newf(errs.ValidationFieldInvalid, "%q is not an email address", target)
	}
	if len(target) > 320 {
		return errs.New(errs.ValidationFieldInvalid, "email target is too long")
	}
	return nil
}

// Redacted is the safe form for logs.
//
// The target is a customer's address or callback URL — personal data in one
// case and an attack surface in the other. Neither belongs in a log line.
func (s Subscription) Redacted() string {
	return fmt.Sprintf("subscription{id:%s kind:%s events:%v enabled:%t}",
		s.ID, s.Kind, s.Events, s.Enabled)
}
