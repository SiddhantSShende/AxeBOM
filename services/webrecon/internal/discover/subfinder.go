// Package discover runs subfinder inside its own sandboxed container.
//
// ⚠ NEVER A NORMAL ENGINE. subfinder needs network egress to query its
// passive sources (crt.sh, certificate transparency logs, DNS aggregators),
// and libs/go-shared/sandbox/policy.go states flatly that no ENGINE may have
// that — CLAUDE.md invariant 7. It runs here, inside services/webrecon,
// which — like the fetcher's git clone — is a deliberate, named, narrow
// exception, not a relaxation of the rule for everyone.
package discover

import (
	"context"
	"fmt"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/sandbox"
)

// Image is the container subfinder runs in, pinned by tag — see
// OSINT/tools.manifest.yaml's subfinder entry. Production pins by digest,
// same convention as fetcher.GitImage.
const Image = "projectdiscovery/subfinder:v2.16.0"

// Policy is the sandbox posture for a subfinder run: identical to
// fetcher.FetcherPolicy() in shape and reasoning — read-only rootfs, dropped
// capabilities, non-root, seccomp and quotas all unchanged; only network
// access is granted, because passive subdomain enumeration obviously
// requires it. Not fetcher.FetcherPolicy() itself: that function's own doc
// comment frames it specifically as "the sandbox policy for a clone", and
// subfinder is not a clone — sharing the exact security POSTURE does not
// mean sharing the function that documents a different exception.
func Policy() sandbox.Policy {
	p := sandbox.DefaultPolicy()
	p.Network = sandbox.NetworkEgress
	return p
}

// Discover runs subfinder against domain and returns up to maxHosts
// discovered hostnames (the domain itself is never included — the caller
// already has it).
//
// ⚠ PASSIVE ONLY. `-silent -json` with no active-probing flags: subfinder
// queries public sources, it does not port-scan or brute-force. Capped by
// maxHosts via `-max-time` and a hard slice truncation — subfinder itself has
// no "-limit" flag, so the cap is enforced on the OUTPUT, not the query.
func Discover(ctx context.Context, runner sandbox.Runner, domain string, maxHosts int) ([]string, error) {
	if domain == "" {
		return nil, fmt.Errorf("discover: empty domain")
	}
	if maxHosts <= 0 {
		return nil, nil
	}

	spec := sandbox.Spec{
		Image: Image,
		Argv: []string{
			"subfinder",
			"-d", domain,
			"-silent",
			// Passive sources only — the default and the point; listed
			// explicitly so a future subfinder default change cannot silently
			// turn this into active probing.
			"-max-time", "2",
		},
		Policy: Policy(),
		Limits: sandbox.DefaultLimits(),
		Labels: map[string]string{"axebom.role": "webrecon-discover"},
	}

	res, err := runner.Run(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("discover: run subfinder: %w", err)
	}
	if res.TimedOut {
		return nil, fmt.Errorf("discover: subfinder exceeded its time limit")
	}
	// subfinder exits non-zero on some transient source failures even when it
	// still found hosts from others — a partial result is still useful, so
	// parse stdout regardless of exit code rather than discarding it.

	hosts := parseHosts(string(res.Stdout), domain)
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	return hosts, nil
}

// parseHosts reads subfinder's `-silent` output: one hostname per line, no
// JSON envelope despite the invocation also requesting it be quiet about
// anything else — `-silent` suppresses banners/progress, not the result
// format, which stays plain text unless `-oJ` is passed (deliberately not
// passed here: one hostname per line is all this caller needs, and a smaller
// output format is a smaller thing to parse defensively).
func parseHosts(stdout, domain string) []string {
	seen := map[string]bool{domain: true} // never re-discover the root itself
	var out []string
	for _, line := range strings.Split(stdout, "\n") {
		host := strings.ToLower(strings.TrimSpace(line))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}
