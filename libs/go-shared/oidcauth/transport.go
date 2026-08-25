package oidcauth

import (
	"fmt"
	"net/http"
	"net/url"
)

// publicHost forces the PUBLIC Host header onto every request to ZITADEL.
//
// ---------------------------------------------------------------------------
// ⚠ THIS IS THE ONE RULE THAT MAKES THE SPLIT-ADDRESS SETUP WORK, AND IT
// APPLIES TO EVERY IN-NETWORK CALL, NOT JUST THE TOKEN ENDPOINT.
//
// ZITADEL is multi-tenant at the instance level and selects the instance from
// the Host header of the request. A service inside the compose network reaches
// it as `zitadel-api:8080`, which matches no instance, and the answer is a 404
// reading:
//
//	unable to set instance using origin &{zitadel-api:8080  http}
//	(ExternalDomain is localhost): Instance not found.
//
// On the token endpoint that surfaces immediately. On the KEY SET it surfaces
// as `AUTH_TOKEN_INVALID` on every request in the product — because the
// verifier cannot fetch keys, so no signature can be checked, and the honest
// "could not be verified" message is indistinguishable from a forged token.
// That is a whole fleet answering 401 with a message pointing at the client.
//
// Overriding the Host makes ZITADEL answer as though the call arrived through
// the public origin, which is also what keeps the issuer consistent: `iss` is
// derived from this same header.
//
// Trusted domains are NOT an alternative. ZITADEL_FIRSTINSTANCE_TRUSTEDDOMAINS
// is applied once at instance creation and lives in the eventstore, so it is
// lost on `task iam:reset` and absent for anyone pointing at an instance they
// did not create. The Host override is a property of our client and travels
// with the code.
type publicHost struct {
	host string
	base http.RoundTripper
}

func (t *publicHost) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone: a RoundTripper must not mutate the request it is handed, and the
	// caller may retry with the same one.
	//
	// ⚠ req.Host, NOT req.Header.Set("Host", ...). Go's transport takes the
	// Host from the field and ignores the header map, so setting the header is
	// a change that appears to work and does nothing.
	r := req.Clone(req.Context())
	r.Host = t.host
	return t.base.RoundTrip(r)
}

// withPublicHost wraps c so requests to a private address still present the
// public host. Returns c unchanged when the two are already the same, so the
// override is visible in a stack trace only where it is actually doing work.
func withPublicHost(c *http.Client, publicURL, targetURL string) (*http.Client, error) {
	pub, err := hostFromURL(publicURL)
	if err != nil {
		return nil, err
	}
	target, err := hostFromURL(targetURL)
	if err != nil {
		return nil, err
	}
	if pub == target {
		return c, nil
	}

	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped := *c
	wrapped.Transport = &publicHost{host: pub, base: base}
	return &wrapped, nil
}

// hostFromURL returns host[:port].
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("oidcauth: %q is not a usable URL", raw)
	}
	return u.Host, nil
}
