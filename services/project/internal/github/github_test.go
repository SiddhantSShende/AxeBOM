package github

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GitHub repo listing, against a fake GitHub. No network, and the fake returns
// GitHub's real response shapes — including the ones easy to get wrong.

func fakeGitHub(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(Config{APIBase: srv.URL, HTTPClient: srv.Client()})
}

const twoRepos = `[
  {"id": 1296269, "name": "Hello-World", "full_name": "octocat/Hello-World",
   "private": false, "clone_url": "https://github.com/octocat/Hello-World.git",
   "default_branch": "main", "archived": false},
  {"id": 987654, "name": "private-app", "full_name": "acme/private-app",
   "private": true, "clone_url": "https://github.com/acme/private-app.git",
   "default_branch": "develop", "archived": false}
]`

// The NUMERIC id is the durable identity. Repository names change, and a
// connection keyed on a name silently detaches on rename.
func TestListReposCarriesTheNumericExternalID(t *testing.T) {
	c := fakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(twoRepos))
	})

	page, err := c.ListRepos(t.Context(), "token", ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Repos) != 2 {
		t.Fatalf("got %d repos, want 2", len(page.Repos))
	}
	if page.Repos[0].ExternalID != "1296269" {
		t.Errorf("external_id = %q, want the numeric GitHub id", page.Repos[0].ExternalID)
	}
	if page.Repos[1].DefaultBranch != "develop" {
		t.Errorf("default_branch = %q; assuming 'main' would make every scan of "+
			"this repository read the wrong ref", page.Repos[1].DefaultBranch)
	}
	// The https clone URL, never ssh or git:// — we hold no ssh key, and git://
	// is unauthenticated and unencrypted.
	for _, r := range page.Repos {
		if !strings.HasPrefix(r.CloneURL, "https://") {
			t.Errorf("clone_url %q is not https", r.CloneURL)
		}
	}
}

// Scanning an archived repository produces a compliance report for something
// nobody maintains, so they are excluded unless asked for.
func TestArchivedRepositoriesAreExcludedByDefault(t *testing.T) {
	const withArchived = `[
	  {"id": 1, "name": "live", "full_name": "acme/live", "clone_url": "https://github.com/acme/live.git", "archived": false},
	  {"id": 2, "name": "dead", "full_name": "acme/dead", "clone_url": "https://github.com/acme/dead.git", "archived": true}
	]`

	c := fakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(withArchived))
	})

	page, err := c.ListRepos(t.Context(), "token", ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Repos) != 1 || page.Repos[0].Name != "live" {
		t.Errorf("archived repository was included: %+v", page.Repos)
	}

	page, err = c.ListRepos(t.Context(), "token", ListOptions{IncludeArchived: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Repos) != 2 {
		t.Errorf("IncludeArchived did not include it: %+v", page.Repos)
	}
}

// GitHub's Link header is the authoritative pagination signal. Inferring "a
// full page means there is more" is wrong exactly when the total is a multiple
// of the page size — the user then sees a Next button that loads nothing.
func TestPaginationUsesTheLinkHeader(t *testing.T) {
	tests := []struct {
		name string
		link string
		want int
	}{
		{"has next", `<https://api.github.com/user/repos?page=3&per_page=30>; rel="next", ` +
			`<https://api.github.com/user/repos?page=10>; rel="last"`, 3},
		{"last page", `<https://api.github.com/user/repos?page=1>; rel="first", ` +
			`<https://api.github.com/user/repos?page=9>; rel="prev"`, 0},
		{"no header", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
				if tt.link != "" {
					w.Header().Set("Link", tt.link)
				}
				_, _ = w.Write([]byte(twoRepos))
			})

			page, err := c.ListRepos(t.Context(), "token", ListOptions{})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if page.NextPage != tt.want {
				t.Errorf("next_page = %d, want %d", page.NextPage, tt.want)
			}
		})
	}
}

// A user who only reaches their employer's repositories through a team would
// otherwise get an empty list and conclude the integration is broken.
func TestListRequestsOrganizationAffiliations(t *testing.T) {
	var query string
	c := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	})

	if _, err := c.ListRepos(t.Context(), "token", ListOptions{}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(query, "organization_member") {
		t.Errorf("affiliation does not include org membership: %s", query)
	}
	if !strings.Contains(query, "collaborator") {
		t.Errorf("affiliation does not include collaborations: %s", query)
	}
}

// Search is scoped to the user, so the wizard cannot offer a stranger's public
// repository — a confusing way to scan the wrong code.
func TestSearchIsScopedToTheUser(t *testing.T) {
	var q string
	c := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	if _, err := c.ListRepos(t.Context(), "token", ListOptions{Query: "payments"}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if !strings.Contains(q, "user:@me") {
		t.Errorf("search query %q is not scoped to the signed-in user", q)
	}
	if !strings.Contains(q, "payments") {
		t.Errorf("search query %q lost the search term", q)
	}
}

// 403 means BOTH "rate limited" and "insufficient scope" on this API, and the
// difference decides whether the user should wait or reauthorize.
func TestRateLimitAndScopeErrorsAreDistinguished(t *testing.T) {
	t.Run("rate limited", func(t *testing.T) {
		c := fakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1900000000")
			w.WriteHeader(http.StatusForbidden)
		})
		_, err := c.ListRepos(t.Context(), "token", ListOptions{})
		if err == nil || !strings.Contains(err.Error(), "rate limit") {
			t.Errorf("err = %v, want a rate-limit message with a reset time", err)
		}
	})

	t.Run("insufficient scope", func(t *testing.T) {
		c := fakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "4999")
			w.WriteHeader(http.StatusForbidden)
		})
		_, err := c.ListRepos(t.Context(), "token", ListOptions{})
		if err == nil || !strings.Contains(err.Error(), "scope") {
			t.Errorf("err = %v, want a scope message", err)
		}
	})
}

func TestExpiredTokenSaysToReconnect(t *testing.T) {
	c := fakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.ListRepos(t.Context(), "token", ListOptions{})
	if err == nil || !strings.Contains(err.Error(), "reconnect") {
		t.Errorf("err = %v, want an actionable reconnect message", err)
	}
}

func TestListRequiresAToken(t *testing.T) {
	c := New(Config{})
	if _, err := c.ListRepos(t.Context(), "", ListOptions{}); err == nil {
		t.Error("listing was attempted with no token")
	}
}

// per_page is clamped, so a caller cannot ask GitHub for an unbounded page.
func TestPerPageIsClamped(t *testing.T) {
	var perPage string
	c := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		perPage = r.URL.Query().Get("per_page")
		_, _ = w.Write([]byte(`[]`))
	})

	if _, err := c.ListRepos(t.Context(), "token", ListOptions{PerPage: 10000}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if perPage != "30" {
		t.Errorf("per_page = %q, want the default after clamping", perPage)
	}
}

func TestRepoURLFor(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"octocat/Hello-World", "https://github.com/octocat/Hello-World.git", false},
		{"/octocat/Hello-World/", "https://github.com/octocat/Hello-World.git", false},
		{"octocat", "", true},
		{"a/b/c", "", true},
		{"octocat/../../etc", "", true},
		{"octocat/repo name", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := RepoURLFor(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("accepted %q -> %q", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected %q: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// This package reads METADATA. It must not clone, fetch a tree, or otherwise
// acquire repository CONTENT — that is the Phase 5 fetcher's job, in the
// sandbox, and it is the only component that holds git credentials.
func TestOnlyMetadataEndpointsAreCalled(t *testing.T) {
	var paths []string
	c := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`[]`))
	})

	if _, err := c.ListRepos(t.Context(), "token", ListOptions{}); err != nil {
		t.Fatalf("list: %v", err)
	}

	for _, p := range paths {
		for _, contentPath := range []string{"/tarball", "/zipball", "/contents", "/git/trees", "/git/blobs"} {
			if strings.Contains(p, contentPath) {
				t.Errorf("called %q, which fetches repository CONTENT; "+
					"content acquisition belongs in the Phase 5 sandbox", p)
			}
		}
	}
}
