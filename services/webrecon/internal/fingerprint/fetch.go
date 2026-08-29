package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/axebom/axebom/libs/go-shared/fetcher"
)

// perRequestTimeout bounds EVERY individual page/script fetch.
//
// ⚠ WITHOUT THIS, ONE UNRESPONSIVE HOST HANGS THE WHOLE JOB. Unlike the
// fetcher's git clone — which runs inside a sandboxed container whose own
// wall-clock limit kills it — these are plain Go HTTP calls in this
// process's own goroutine, with nothing else bounding them. A discovered
// host that accepts a connection and never responds would otherwise block
// fingerprinting indefinitely, one host at a time, for as many hosts as
// max_hosts allows.
const perRequestTimeout = 15 * time.Second

// scriptFetchAllowlist is the short, explicit CDN allowlist a script `src`
// may be fetched from besides the page's own host.
//
// ⚠ WHY AN ALLOWLIST AND NOT "ANY HOST THE PAGE POINTS AT". A page under a
// tenant's control naming an arbitrary third-party script src would
// otherwise turn this fetcher into an open proxy for any URL an attacker can
// get written into that page's HTML — the confused-deputy risk
// 05-SECURITY-MODEL.md names for webrecon generally, narrowed to its
// sharpest form. These five cover the overwhelming majority of real-world JS
// CDN usage; anything else is simply not fingerprinted, which is a stated
// coverage gap, not a silent one (HostResult records skipped-CDN scripts).
var scriptFetchAllowlist = map[string]bool{
	"cdnjs.cloudflare.com": true,
	"unpkg.com":            true,
	"cdn.jsdelivr.net":     true,
	"ajax.googleapis.com":  true,
	"code.jquery.com":      true,
}

// maxFetchBytes bounds any single page or script fetch — the same limit
// every other fetcher-family download uses, so one hostile response cannot
// exhaust memory.
var maxFetchBytes = fetcher.DefaultArchiveLimits().MaxBytes

// ScriptResult is one <script> this host's page referenced.
type ScriptResult struct {
	// Src is the script's src attribute, "" for an inline script.
	Src string
	// Skipped is set when an external script's host was neither the page's
	// own host nor on scriptFetchAllowlist — recorded, never silently
	// dropped.
	Skipped bool
	Match   *Match
}

// HostResult is everything discovered by fetching and fingerprinting one
// host's root page.
type HostResult struct {
	Host       string
	FetchedURL string
	// Status is "succeeded", "unreachable", or "http_error" — never "failed":
	// a host that could not be reached is a stated per-host gap, not a
	// reason to fail the whole scan (see services/webrecon/internal/work).
	Status  string
	Error   string
	Scripts []ScriptResult
	// Libraries is the deduplicated set of libraries this host's page and
	// scripts matched — the JSON artifact's actual payload; Scripts is kept
	// for diagnostics (a "0 libraries, 4 scripts skipped for CDN" host reads
	// very differently from "0 libraries, 0 scripts found").
	Libraries []Match
}

// FetchAndFingerprint GETs pageURL, extracts every <script>, fetches
// same-host or allowlisted-CDN external ones, and matches everything against
// m.
//
// ⚠ THE SAME SSRF-HARDENED CLIENT EVERY OTHER FETCHER-FAMILY REQUEST USES.
// client must be built via fetcher.SafeHTTPClient — connection-time private-
// IP blocking, redirect re-validation — exactly the reasoning
// materializeURL's own (now-removed, superseded-by-this) doc comment gave in
// Milestone 4.
func FetchAndFingerprint(client *http.Client, m *Matcher, pageURL string) HostResult {
	host := hostOf(pageURL)
	result := HostResult{Host: host, FetchedURL: pageURL}

	body, err := get(client, pageURL, "text/html,application/xhtml+xml")
	if err != nil {
		result.Status = "unreachable"
		result.Error = err.Error()
		return result
	}
	if body == nil {
		result.Status = "http_error"
		return result
	}

	seen := map[string]bool{}
	addMatch := func(match Match) {
		key := match.Library + "@" + match.Version
		if seen[key] {
			return
		}
		seen[key] = true
		result.Libraries = append(result.Libraries, match)
	}

	for _, script := range extractScripts(string(body)) {
		if script.Src == "" {
			sr := ScriptResult{}
			if match, ok := m.MatchContent(script.Inline); ok {
				sr.Match = &match
				addMatch(match)
			}
			result.Scripts = append(result.Scripts, sr)
			continue
		}

		sr := ScriptResult{Src: script.Src}
		resolved := resolveScriptURL(pageURL, script.Src)
		if resolved == "" || !allowedScriptHost(pageURL, resolved) {
			sr.Skipped = true
			result.Scripts = append(result.Scripts, sr)
			continue
		}

		// The src path itself is a signal (retire.js's own "uri" extractors
		// exist for exactly this — a CDN path like "/3.5.1/jquery.min.js"
		// names the library without needing the body at all).
		if match, ok := m.MatchURI(script.Src); ok {
			sr.Match = &match
			addMatch(match)
		}

		scriptBody, err := get(client, resolved, "*/*")
		if err == nil && scriptBody != nil {
			if match, ok := m.MatchContent(string(scriptBody)); ok {
				sr.Match = &match
				addMatch(match)
			}
		}
		result.Scripts = append(result.Scripts, sr)
	}

	result.Status = "succeeded"
	return result
}

// get performs one bounded, SSRF-hardened GET. Returns (nil, nil) for a
// non-200 response — an HTTP error is not a network error, and the caller
// distinguishes them.
func get(client *http.Client, target, accept string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), perRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "AxeBOM-Webrecon/1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
}

type rawScript struct {
	Src    string
	Inline string
}

// extractScripts walks the HTML token stream for every <script> element.
// Malformed HTML degrades gracefully — html.Tokenizer never errors on bad
// markup, it just stops, and whatever was found before that point is still
// returned.
func extractScripts(body string) []rawScript {
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	var out []rawScript

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			return out
		}
		if tt != html.StartTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "script" {
			continue
		}

		var src string
		for _, attr := range token.Attr {
			if attr.Key == "src" {
				src = attr.Val
			}
		}
		if src != "" {
			out = append(out, rawScript{Src: src})
			continue
		}

		// An inline script's text is the NEXT token, not an attribute.
		if next := tokenizer.Next(); next == html.TextToken {
			out = append(out, rawScript{Inline: tokenizer.Token().Data})
		}
	}
}

// resolveScriptURL turns a possibly-relative src into an absolute URL
// against the page it was found on. Returns "" for anything that cannot be
// resolved to a fetchable http(s) URL — a data: URI, a javascript: pseudo-
// URL, or a malformed reference.
func resolveScriptURL(pageURL, src string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(src)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	return resolved.String()
}

// allowedScriptHost reports whether an external script may be fetched: the
// SAME ORIGIN as the page (host AND port — two different ports on the same
// hostname are two different servers, and a same-host check that ignored
// port would let a script on an unrelated service sharing that hostname
// through), or scriptFetchAllowlist (checked by bare hostname; a CDN's port
// is never part of what makes it trusted). See the allowlist's own doc
// comment for why this is not "any host the page names".
func allowedScriptHost(pageURL, scriptURL string) bool {
	page, err := url.Parse(pageURL)
	if err != nil {
		return false
	}
	script, err := url.Parse(scriptURL)
	if err != nil {
		return false
	}
	if strings.EqualFold(script.Host, page.Host) {
		return true
	}
	return scriptFetchAllowlist[hostOf(scriptURL)]
}

func hostOf(rawURL string) string {
	return HostOf(rawURL)
}

// HostOf returns the bare hostname (no port, no scheme) of a URL, or "" if
// it cannot be parsed. Exported for services/webrecon/internal/work, which
// needs the same extraction to decide whether a discovered host IS the
// url source's own root host.
func HostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
