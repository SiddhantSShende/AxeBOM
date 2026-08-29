package fetcher_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/fetcher"
)

// The GitHub Dependency Graph SBOM client — a reconciliation source, so every
// failure path must return an error the caller can swallow, never a panic and
// never a document that looks real but is not GitHub's.

func TestFetchDependencyGraphSBOMUnwrapsGitHubsEnvelope(t *testing.T) {
	spdxDoc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":      "SPDXRef-DOCUMENT",
		"packages":    []any{map[string]any{"SPDXID": "SPDXRef-lodash", "name": "lodash"}},
	}

	var gotPath, gotAuth, gotAccept, gotAPIVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotAPIVersion = r.Header.Get("X-GitHub-Api-Version")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sbom": spdxDoc})
	}))
	defer srv.Close()

	raw, err := fetcher.FetchDependencyGraphSBOM(t.Context(), srv.Client(), srv.URL,
		"https://github.com/acme/widgets", "gho_faketoken")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if gotPath != "/repos/acme/widgets/dependency-graph/sbom" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer gho_faketoken" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if gotAPIVersion != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q", gotAPIVersion)
	}

	// ⚠ THE POINT OF THE FUNCTION: the envelope is gone. What is returned is
	// the SPDX document itself, byte-for-byte, ready to be stored as a
	// standalone artifact and parsed by _ingest_spdx with no special case.
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("returned bytes are not valid JSON: %v", err)
	}
	if _, hasEnvelope := got["sbom"]; hasEnvelope {
		t.Error("the GitHub envelope ('sbom' key) leaked into the stored artifact")
	}
	if got["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3 — this should be the unwrapped document", got["spdxVersion"])
	}
}

func TestFetchDependencyGraphSBOMHandlesRepoNotFoundOrDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	_, err := fetcher.FetchDependencyGraphSBOM(t.Context(), srv.Client(), srv.URL,
		"https://github.com/acme/private-or-disabled", "gho_faketoken")
	if err == nil {
		t.Fatal("a 404 was treated as success")
	}
}

func TestFetchDependencyGraphSBOMHandlesForbidden(t *testing.T) {
	// A token without access to a private repo's Dependency Graph. Same
	// contract as 404: an error the caller treats as "nothing to reconcile
	// against," not a scan failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetcher.FetchDependencyGraphSBOM(t.Context(), srv.Client(), srv.URL,
		"https://github.com/acme/private-repo", "gho_faketoken")
	if err == nil {
		t.Fatal("a 403 was treated as success")
	}
}

func TestFetchDependencyGraphSBOMRejectsAMalformedEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 200 OK but no "sbom" field at all — a real GitHub shape change, or a
		// misconfigured mock. Either way, nothing to unwrap.
		_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
	}))
	defer srv.Close()

	_, err := fetcher.FetchDependencyGraphSBOM(t.Context(), srv.Client(), srv.URL,
		"https://github.com/acme/widgets", "gho_faketoken")
	if err == nil {
		t.Fatal("a response with no 'sbom' field was accepted")
	}
}

func TestFetchDependencyGraphSBOMRejectsInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	_, err := fetcher.FetchDependencyGraphSBOM(t.Context(), srv.Client(), srv.URL,
		"https://github.com/acme/widgets", "gho_faketoken")
	if err == nil {
		t.Fatal("an unparseable response was accepted")
	}
}

func TestFetchDependencyGraphSBOMRequiresAToken(t *testing.T) {
	// No server needed: this must be refused before any request is made — an
	// upload-sourced or gitlab/bitbucket-connected scan has no GitHub token at
	// all, and the caller (work.go) must not even attempt the call.
	_, err := fetcher.FetchDependencyGraphSBOM(t.Context(), http.DefaultClient, "",
		"https://github.com/acme/widgets", "")
	if err == nil {
		t.Fatal("a request with no token was accepted")
	}
}

func TestFetchDependencyGraphSBOMRejectsAnUnrecognizedRepoURL(t *testing.T) {
	for _, url := range []string{
		"https://github.com/",
		"https://github.com/only-owner",
		"not-a-url",
	} {
		t.Run(url, func(t *testing.T) {
			_, err := fetcher.FetchDependencyGraphSBOM(t.Context(), http.DefaultClient, "",
				url, "gho_faketoken")
			if err == nil {
				t.Fatalf("%q was accepted as a repository URL", url)
			}
		})
	}
}

func TestFetchDependencyGraphSBOMStripsAGitSuffix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sbom": map[string]any{"packages": []any{}}})
	}))
	defer srv.Close()

	if _, err := fetcher.FetchDependencyGraphSBOM(t.Context(), srv.Client(), srv.URL,
		"https://github.com/acme/widgets.git", "gho_faketoken"); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if strings.Contains(gotPath, ".git") {
		t.Errorf("path %q still carries the .git suffix", gotPath)
	}
}
