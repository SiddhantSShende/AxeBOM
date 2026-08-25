// Package github lists repositories the signed-in user can see.
//
// SCOPE BOUNDARY: this package READS METADATA through GitHub's REST API. It
// never clones, never fetches a tree, never touches repository CONTENT. Content
// acquisition is the Phase 5 fetcher's job, in the sandbox, and it is the only
// component that holds git credentials (ADR-0008).
//
// The token used here is the USER'S OAuth token, passed per request and never
// stored by this package. What gets persisted is the token in Vault plus a path
// in Postgres — see service.Connect.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// Client reads repository metadata.
type Client struct {
	apiBase string
	hc      *http.Client
}

// Config configures the client.
type Config struct {
	// APIBase is overridable for tests and GitHub Enterprise.
	APIBase    string
	HTTPClient *http.Client
}

func New(cfg Config) *Client {
	if cfg.APIBase == "" {
		cfg.APIBase = "https://api.github.com"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{apiBase: strings.TrimRight(cfg.APIBase, "/"), hc: hc}
}

// Repo is the subset of a repository we surface in the connect wizard.
type Repo struct {
	// ExternalID is GitHub's NUMERIC id — the durable identity. Repository
	// names change; connections keyed on a name silently detach on rename.
	ExternalID string `json:"external_id"`
	FullName   string `json:"full_name"`
	Name       string `json:"name"`
	Private    bool   `json:"private"`
	// CloneURL is the https URL. Never the ssh or git:// form: we hold no ssh
	// key, and git:// is unauthenticated and unencrypted.
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Description   string `json:"description,omitempty"`
	Archived      bool   `json:"archived"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// Page is one page of results plus the cursor for the next.
type Page struct {
	Repos []Repo `json:"repos"`
	// NextPage is 0 when there are no more results. Derived from the Link
	// header, which is GitHub's own signal — inferring "a full page means
	// there is more" is wrong exactly when the total is a multiple of the
	// page size.
	NextPage int `json:"next_page,omitempty"`
}

// ListOptions configures a listing.
type ListOptions struct {
	// Query filters by name via GitHub's search API. Empty lists the user's
	// own repositories instead, which is the cheaper and more complete path.
	Query   string
	Page    int
	PerPage int
	// IncludeArchived keeps archived repositories in the result. Off by
	// default: scanning an archived repository produces a compliance report
	// for something nobody maintains.
	IncludeArchived bool
}

const maxPerPage = 100

// ListRepos returns repositories the token can see.
func (c *Client) ListRepos(ctx context.Context, token string, opts ListOptions) (Page, error) {
	if token == "" {
		return Page{}, errs.New(errs.AuthTokenInvalid, "no GitHub token available for this user")
	}
	if opts.PerPage <= 0 || opts.PerPage > maxPerPage {
		opts.PerPage = 30
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}

	if strings.TrimSpace(opts.Query) != "" {
		return c.searchRepos(ctx, token, opts)
	}
	return c.listUserRepos(ctx, token, opts)
}

// listUserRepos lists everything the token can see, newest activity first.
func (c *Client) listUserRepos(ctx context.Context, token string, opts ListOptions) (Page, error) {
	q := url.Values{
		"per_page": {strconv.Itoa(opts.PerPage)},
		"page":     {strconv.Itoa(opts.Page)},
		"sort":     {"updated"},
		// `all` includes repositories reached through org membership and
		// collaboration, not only ones the user owns. A user who can only see
		// their employer's repositories through a team would otherwise get an
		// empty list and conclude the integration is broken.
		"affiliation": {"owner,collaborator,organization_member"},
	}

	var raw []githubRepo
	next, err := c.get(ctx, token, "/user/repos?"+q.Encode(), &raw)
	if err != nil {
		return Page{}, err
	}
	return Page{Repos: convert(raw, opts.IncludeArchived), NextPage: next}, nil
}

// searchRepos filters by name.
//
// Scoped with `user:@me` so the search cannot wander into public repositories
// the user has no relationship with — picking a stranger's repository from a
// connect wizard is a confusing way to scan the wrong code.
func (c *Client) searchRepos(ctx context.Context, token string, opts ListOptions) (Page, error) {
	query := strings.TrimSpace(opts.Query)
	q := url.Values{
		"q":        {query + " user:@me fork:true"},
		"per_page": {strconv.Itoa(opts.PerPage)},
		"page":     {strconv.Itoa(opts.Page)},
	}

	var result struct {
		Items []githubRepo `json:"items"`
	}
	next, err := c.get(ctx, token, "/search/repositories?"+q.Encode(), &result)
	if err != nil {
		return Page{}, err
	}
	return Page{Repos: convert(result.Items, opts.IncludeArchived), NextPage: next}, nil
}

// githubRepo is GitHub's payload. Only the fields we use.
type githubRepo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Description   string `json:"description"`
	Archived      bool   `json:"archived"`
	UpdatedAt     string `json:"updated_at"`
}

func convert(in []githubRepo, includeArchived bool) []Repo {
	out := make([]Repo, 0, len(in))
	for _, r := range in {
		if r.Archived && !includeArchived {
			continue
		}
		out = append(out, Repo{
			ExternalID:    strconv.FormatInt(r.ID, 10),
			FullName:      r.FullName,
			Name:          r.Name,
			Private:       r.Private,
			CloneURL:      r.CloneURL,
			DefaultBranch: r.DefaultBranch,
			Description:   r.Description,
			Archived:      r.Archived,
			UpdatedAt:     r.UpdatedAt,
		})
	}
	return out
}

// get performs a request and returns the next page number from the Link header.
func (c *Client) get(ctx context.Context, token, path string, into any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiBase+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, errs.Wrap(err, errs.AuthProviderError, "could not reach GitHub")
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return 0, errs.New(errs.AuthTokenInvalid,
			"GitHub rejected the stored token; reconnect your GitHub account")
	case http.StatusForbidden:
		// 403 is BOTH "rate limited" and "insufficient scope" on this API, and
		// the difference decides whether the user should wait or reauthorize.
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return 0, errs.Newf(errs.RateLimitExceeded,
				"GitHub's rate limit is exhausted; it resets at %s",
				resetTime(resp.Header.Get("X-RateLimit-Reset")))
		}
		return 0, errs.New(errs.AuthProviderError,
			"GitHub refused the request; the token may lack the required scope")
	default:
		return 0, errs.Newf(errs.AuthProviderError, "GitHub returned %d", resp.StatusCode)
	}

	// 8 MiB cap: a page of 100 repositories is well under that, and an
	// unbounded read is a memory exhaustion vector against our own process.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into); err != nil {
		return 0, errs.Wrap(err, errs.AuthProviderError, "GitHub returned an unreadable response")
	}
	return nextPageFromLink(resp.Header.Get("Link")), nil
}

// nextPageFromLink extracts the `rel="next"` page number.
//
// GitHub's Link header is the authoritative pagination signal. Inferring "a
// full page means there is more" is wrong precisely when the total is an exact
// multiple of the page size — the user then sees a Next button that loads
// nothing.
func nextPageFromLink(link string) int {
	for _, part := range strings.Split(link, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end <= start {
			continue
		}
		u, err := url.Parse(part[start+1 : end])
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(u.Query().Get("page")); err == nil {
			return n
		}
	}
	return 0
}

func resetTime(epoch string) string {
	n, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return "an unknown time"
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

// RepoURLFor builds the canonical https clone URL for a full name.
//
// Used when the client supplies `owner/name` rather than a full URL. Kept here
// so the one place that composes a GitHub URL is next to the code that parses
// GitHub's own responses.
func RepoURLFor(fullName string) (string, error) {
	fullName = strings.Trim(strings.TrimSpace(fullName), "/")
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("expected owner/name, got %q", fullName)
	}
	for _, p := range parts {
		if strings.ContainsAny(p, "/\\?#@: \t\n\r\x00") {
			return "", fmt.Errorf("invalid character in %q", fullName)
		}
	}
	return "https://github.com/" + parts[0] + "/" + parts[1] + ".git", nil
}
