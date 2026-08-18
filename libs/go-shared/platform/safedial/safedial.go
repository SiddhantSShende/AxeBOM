// Package safedial connects only to addresses it has validated.
//
// ⚠ THIS DEFEATS DNS REBINDING, WHICH IS WHY IT CANNOT BE A PARSE-TIME CHECK.
//
// A parse-time check asks "does this hostname resolve to something public?" and
// the attacker answers truthfully — then changes the answer before the connect.
// The gap between the two lookups is the vulnerability, and it is not a race
// that can be narrowed away: the attacker controls the DNS TTL.
//
// The only reliable defence is to connect to the ADDRESS YOU VALIDATED. So this
// dialer resolves once, filters every candidate, and dials the resulting IP
// literal — the second lookup the attack depends on never happens.
//
// ⚠ IT LIVES IN go-shared BECAUSE TWO SUBSYSTEMS TAKE A URL FROM A CUSTOMER.
// The fetcher clones a repository they name; the notification service POSTs a
// signed payload to a webhook they name. Both make an outbound request from
// inside our network to an address somebody else chose, and a second
// implementation of this logic is how one of them ends up missing a CIDR — most
// likely the newer one, written by somebody who did not know the older existed.
//
// docs/05-SECURITY-MODEL.md §4
package safedial

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// blockedNets are the ranges no customer-supplied host may resolve into.
//
// Beyond the obvious RFC1918 set:
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
			panic("safedial: bad blocked CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

// blockedErr reports a refused address.
//
// ⚠ IT CARRIES errs.FetchPrivateAddressBlocked EVEN FOR A WEBHOOK. The code
// reads "Fetch", but it means "a private address was blocked", and both callers
// are doing the same thing: making an outbound request to a host a customer
// named. A second code for the identical condition would split the alerting and
// the runbook in two for no gain.
//
// Naming the resolved IP is deliberate: the customer needs to know their
// hostname pointed somewhere internal, and it is their own DNS.
func blockedErr(host, ip string) error {
	return errs.Newf(errs.FetchPrivateAddressBlocked,
		"%s resolved to %s, which is in a blocked range", host, ip)
}

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

// Attempt records one connection decision.
type Attempt struct {
	Host    string
	IP      string
	Blocked bool
}

const maxRecordedAttempts = 64

// Dialer resolves a host, validates every candidate address, and connects to an
// address it validated.
type Dialer struct {
	// Resolver is overridable for tests. nil means net.DefaultResolver.
	Resolver *net.Resolver
	// Timeout bounds one connection attempt.
	Timeout time.Duration

	mu       sync.Mutex
	attempts []Attempt
}

// DialContext is the net.Dialer-compatible hook.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safedial: malformed address %q: %w", addr, err)
	}

	// A literal IP skips resolution — and must still be validated, or
	// https://169.254.169.254/ walks straight past the whole mechanism.
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			d.record(host, ip.String(), true)
			return nil, blockedErr(host, ip.String())
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
		return nil, fmt.Errorf("safedial: resolving %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("safedial: %q resolved to no addresses", host)
	}

	// ⚠ EVERY CANDIDATE MUST BE PERMITTED, AND ONE BLOCKED ADDRESS FAILS THE
	// WHOLE DIAL. Trying the next address instead would let an attacker publish
	// [169.254.169.254, 93.184.216.34] and rely on us skipping to the good one
	// on some runs and not others — non-deterministic security is no security.
	for _, ipAddr := range ips {
		if IsBlockedIP(ipAddr.IP) {
			d.record(host, ipAddr.IP.String(), true)
			return nil, blockedErr(host, ipAddr.IP.String())
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

func (d *Dialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}

func (d *Dialer) record(host, ip string, blocked bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.attempts) >= maxRecordedAttempts {
		return
	}
	d.attempts = append(d.attempts, Attempt{Host: host, IP: ip, Blocked: blocked})
}

// Attempts returns the recorded dial decisions, for audit and tests.
func (d *Dialer) Attempts() []Attempt {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Attempt(nil), d.attempts...)
}

// Transport builds an http.Transport that cannot reach a private address.
//
// ⚠ Proxy IS NIL, DELIBERATELY. A proxy connects on our behalf, so every
// address check here would be bypassed by an HTTPS_PROXY environment variable
// somebody set for an unrelated reason.
func Transport(d *Dialer) *http.Transport {
	if d == nil {
		d = &Dialer{}
	}
	return &http.Transport{
		DialContext:           d.DialContext,
		Proxy:                 nil,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          4,
	}
}
