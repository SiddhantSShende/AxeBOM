package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The bug this guards produced a fleet-wide "the access token could not be
// verified" — every service, every request — because the key set could not be
// fetched. Nothing about that message points at a Host header.
func TestTheKeySetFetchPresentsThePublicHost(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Host
	}))
	defer srv.Close()

	c, err := withPublicHost(srv.Client(), "https://id.example.com", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL + "/oauth/v2/keys")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if seen != "id.example.com" {
		t.Errorf("upstream saw Host %q, want the public host id.example.com — "+
			"ZITADEL selects its instance from this header and answers "+
			"\"Instance not found\" for anything else", seen)
	}
}

// Wrapping when nothing needs wrapping would put an indirection in the path of
// every single-origin deployment, where it can only be a source of surprise.
func TestASameHostFetchIsNotWrapped(t *testing.T) {
	in := &http.Client{}
	out, err := withPublicHost(in, "https://id.example.com", "https://id.example.com/oauth/v2/keys")
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Error("the client was wrapped even though the public and target hosts match")
	}
}

// A RoundTripper is handed a request the caller may still own and may retry.
// Mutating it in place is the kind of defect that only shows up under a redirect
// or a retry, which is to say in production and not in a test.
func TestTheTransportDoesNotMutateTheCallersRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/oauth/v2/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	before := req.Host

	rt := &publicHost{host: "id.example.com", base: http.DefaultTransport}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if req.Host != before {
		t.Errorf("the caller's request was mutated: Host %q -> %q", before, req.Host)
	}
}

func TestAnUnusableURLIsRefused(t *testing.T) {
	if _, err := withPublicHost(&http.Client{}, "not-a-url", "http://zitadel-api:8080"); err == nil {
		t.Error("a public URL with no host was accepted")
	}
	if _, err := withPublicHost(&http.Client{}, "https://id.example.com", "://bad"); err == nil {
		t.Error("a target URL with no host was accepted")
	}
}
