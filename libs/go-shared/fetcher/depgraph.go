package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// FetchDependencyGraphSBOM calls GitHub's Dependency Graph SBOM export API for
// one repository and returns the inner SPDX 2.3 JSON document — never
// GitHub's own envelope around it.
//
// ⚠ THIS IS A RECONCILIATION SOURCE, NOT A REQUIRED INPUT.
//
// Called only after a clone has already succeeded (services/fetcher/internal/
// work/work.go), using the same repo-scoped credential already in hand. Every
// caller MUST treat a non-nil error as "no native SBOM available" and proceed
// with the scan regardless — a repo with Dependency Graph disabled, a token
// without access to it, or a transient GitHub outage must never fail a scan
// that already has a perfectly good source archive to work from.
//
// ⚠ THE ENVELOPE IS UNWRAPPED HERE, DELIBERATELY.
//
// GitHub's response shape is `{"sbom": {<SPDX document>}}`, not a bare SPDX
// document. Storing the envelope as the "raw artifact" would mean every
// downstream reader — the normalizer's `_ingest_spdx`, a human inspecting
// stored evidence, a future re-export — has to know about a GitHub-specific
// transport detail that has nothing to do with the document's own content.
// Unwrapping once, here, means the stored artifact is a genuine, standalone,
// valid SPDX 2.3 document — reusable by the exact same parser every other
// SPDX-emitting engine (syft-spdx) already has, with no special case.
//
// client is supplied by the caller rather than built internally — production
// passes SafeHTTPClient(nil) (see work.go's fetchDependencyGraphSBOM), and a
// test passes a plain client pointed at a local server. Building the safe
// client internally would make this function untestable against httptest:
// SafeDialer blocks loopback by design, with no bypass, and rightly so — the
// same reason every OTHER SafeHTTPClient test in this package overrides
// Transport after construction rather than asking the dialer to make an
// exception.
//
// apiBase is likewise overridable, mirroring service.GitHubConfig.APIBase —
// pass "" in production for the real https://api.github.com.
func FetchDependencyGraphSBOM(ctx context.Context, client *http.Client, apiBase, repoURL, token string) ([]byte, error) {
	owner, repo, err := ownerRepoFromGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("dependency graph: no credential available for %s/%s", owner, repo)
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}

	// The host is normally a fixed constant, never derived from repoURL beyond
	// the owner/repo path segments — there is no attacker-controlled redirect
	// surface in the URL itself in production, where apiBase is always the
	// literal above.
	url := fmt.Sprintf("%s/repos/%s/%s/dependency-graph/sbom", strings.TrimRight(apiBase, "/"), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("dependency graph: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dependency graph: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Capped: this is a document describing dependencies, not one containing
	// them, but an upstream that streamed forever must not exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("dependency graph: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// 404 covers both "repo not found" and "Dependency Graph disabled" —
		// GitHub does not distinguish them in the response, and neither is
		// worth a different code path here: both mean "nothing to reconcile
		// against." 403 means the token lacks access (a public repo needs no
		// scope for this endpoint, but a private one does).
		return nil, fmt.Errorf("dependency graph: GitHub returned %d for %s/%s: %s",
			resp.StatusCode, owner, repo, truncateForError(string(body)))
	}

	var envelope struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("dependency graph: response is not valid JSON: %w", err)
	}
	if len(envelope.SBOM) == 0 {
		return nil, fmt.Errorf("dependency graph: response carries no 'sbom' field")
	}
	return envelope.SBOM, nil
}

// ownerRepoFromGitHubURL extracts owner/repo from a github.com clone URL.
//
// repoURL has already passed ValidateRepoURL (https-only, no embedded
// credentials) by the time this runs — Connect refuses anything else at
// connection-create time — so this only handles shape, not safety.
func ownerRepoFromGitHubURL(repoURL string) (owner, repo string, err error) {
	u, parseErr := ValidateURL(repoURL)
	if parseErr != nil {
		return "", "", fmt.Errorf("dependency graph: %w", parseErr)
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) < 2 {
		return "", "", fmt.Errorf("dependency graph: %q does not look like a github.com repository URL", repoURL)
	}
	owner = segments[0]
	repo = strings.TrimSuffix(segments[1], ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("dependency graph: could not resolve an owner/repo from %q", repoURL)
	}
	return owner, repo, nil
}
