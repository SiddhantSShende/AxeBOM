package fingerprint_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/axebom/axebom/services/webrecon/internal/fingerprint"
)

func testMatcher(t *testing.T) *fingerprint.Matcher {
	t.Helper()
	m, _, err := fingerprint.LoadSignatures([]byte(`{
		"jquery": {
			"vulnerabilities": [],
			"extractors": {
				"uri": ["/(§§version§§)/jquery(\\.min)?\\.js"],
				"filecontent": ["/\\*!? jQuery v(§§version§§)"]
			}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	return m
}

func TestFetchAndFingerprintDetectsAnInlineScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><script>/*! jQuery v3.5.1 */</script></body></html>`))
	}))
	defer srv.Close()

	result := fingerprint.FetchAndFingerprint(srv.Client(), testMatcher(t), srv.URL)
	if result.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", result.Status)
	}
	if len(result.Libraries) != 1 || result.Libraries[0].Library != "jquery" || result.Libraries[0].Version != "3.5.1" {
		t.Errorf("libraries = %+v, want exactly [jquery@3.5.1]", result.Libraries)
	}
}

func TestFetchAndFingerprintFetchesASameHostExternalScript(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><script src="/js/jquery.js"></script></head></html>`))
	})
	mux.HandleFunc("/js/jquery.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`/*! jQuery v3.5.1 */`))
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	result := fingerprint.FetchAndFingerprint(srv.Client(), testMatcher(t), srv.URL)
	if len(result.Libraries) != 1 || result.Libraries[0].Library != "jquery" {
		t.Errorf("libraries = %+v, want exactly [jquery@3.5.1]", result.Libraries)
	}
	if len(result.Scripts) != 1 || result.Scripts[0].Skipped {
		t.Errorf("scripts = %+v, want the same-host script fetched, not skipped", result.Scripts)
	}
}

// A script src on a host that is neither the page's own host nor on the CDN
// allowlist must never be fetched — that would make this an open proxy for
// whatever URL an attacker gets written into a page's HTML.
func TestFetchAndFingerprintSkipsAnUnallowlistedExternalHost(t *testing.T) {
	fetched := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetched = true
		_, _ = w.Write([]byte(`/*! jQuery v3.5.1 */`))
	}))
	defer evil.Close()

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w,
			`<html><head><script src="%s/jquery.js"></script></head></html>`, evil.URL)
	}))
	defer page.Close()

	result := fingerprint.FetchAndFingerprint(page.Client(), testMatcher(t), page.URL)
	if fetched {
		t.Error("a script on a non-allowlisted external host was fetched")
	}
	if len(result.Scripts) != 1 || !result.Scripts[0].Skipped {
		t.Errorf("scripts = %+v, want the external script recorded as skipped, not silently dropped", result.Scripts)
	}
	if len(result.Libraries) != 0 {
		t.Errorf("libraries = %+v, want none (nothing here was actually fetched)", result.Libraries)
	}
}

func TestFetchAndFingerprintReportsHTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result := fingerprint.FetchAndFingerprint(srv.Client(), testMatcher(t), srv.URL)
	if result.Status != "http_error" {
		t.Errorf("status = %q, want http_error", result.Status)
	}
}

func TestFetchAndFingerprintReportsUnreachableStatus(t *testing.T) {
	// TEST-NET-3, reserved for documentation, never routed.
	client := &http.Client{Timeout: 1}
	result := fingerprint.FetchAndFingerprint(client, testMatcher(t), "https://203.0.113.1/")
	if result.Status != "unreachable" {
		t.Errorf("status = %q, want unreachable", result.Status)
	}
	if result.Error == "" {
		t.Error("no error recorded for an unreachable host")
	}
}

func TestFetchAndFingerprintReturnsNoLibrariesForOrdinaryContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><script>console.log("hi");</script></body></html>`))
	}))
	defer srv.Close()

	result := fingerprint.FetchAndFingerprint(srv.Client(), testMatcher(t), srv.URL)
	if len(result.Libraries) != 0 {
		t.Errorf("libraries = %+v, want none", result.Libraries)
	}
}
