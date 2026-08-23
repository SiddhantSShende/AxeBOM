// Package source resolves where a scan's code lives.
//
// # Why this is an HTTP call and not a database query
//
// The repository connection lives in `project.repository_connections`, which
// belongs to the project service. Schema-per-service is enforced by convention
// rather than by the database, so nothing would stop this service opening that
// table directly — and that is exactly why the rule needs holding to. A second
// reader of a table makes the owning service unable to change it, and the
// coupling is invisible until a migration breaks a service that never appeared
// in the review.
//
// # Why the credential is a REF and not a token
//
// The project service returns `credential_ref`, a Vault path. This service then
// exchanges it for the token itself. The token exists in exactly one process —
// this one — for the duration of one clone, and never in Postgres, never in a
// queue message, never in argv.
package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Source is where one scan's code comes from.
type Source struct {
	// ConnectionID is the owning row's id. Required, because the Vault path is
	// RE-DERIVED from (tenant, kind, connection id) rather than trusted from
	// CredentialRef — a stored path is attacker-influenceable, and trusting one
	// turns any mass-assignment bug into a cross-tenant secret read.
	ConnectionID  string `json:"connection_id"`
	Provider      string `json:"provider"`
	RepoURL       string `json:"repo_url"`
	DefaultBranch string `json:"default_branch"`
	// CredentialRef is a VAULT PATH, never a token.
	CredentialRef string `json:"credential_ref"`
}

// ErrNoSource means the project has no repository connection.
//
// A distinct error because it is NOT a fault: a project registered manually or
// scanned from an upload legitimately has nothing to clone. The caller turns it
// into a stated reason on the scan rather than a retry.
var ErrNoSource = errors.New("project has no repository connection")

// TokenFunc mints a service token for one tenant.
type TokenFunc func(ctx context.Context, tenantID string) (string, error)

// Client reads the project service's service-only source endpoint.
type Client struct {
	base  *url.URL
	http  *http.Client
	token TokenFunc
}

// Options configures a Client.
type Options struct {
	// BaseURL is the project service, from configuration.
	//
	// ⚠ CONFIGURED, NEVER TAKEN FROM A REQUEST. A base URL derived from a
	// header or a database row turns this into an SSRF that leaks a service
	// token — and this service's token can read credential refs.
	BaseURL string
	Token   TokenFunc
	Client  *http.Client
}

func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, errors.New("source: no project service URL configured")
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("source: parse %q: %w", opts.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("source: scheme must be http or https, got %q", u.Scheme)
	}
	if opts.Token == nil {
		return nil, errors.New("source: no token function supplied")
	}

	c := opts.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{base: u, http: c, token: opts.Token}, nil
}

// Resolve returns the source for one project.
func (c *Client) Resolve(ctx context.Context, tenantID, projectID string) (Source, error) {
	tok, err := c.token(ctx, tenantID)
	if err != nil {
		return Source{}, fmt.Errorf("source: mint service token: %w", err)
	}

	ref := c.base.JoinPath("v1", "projects", projectID, "source")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.String(), nil)
	if err != nil {
		return Source{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Source{}, fmt.Errorf("source: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// The route answers 404 both for "no connection" and for a caller that
		// is not a service principal — deliberately, so the endpoint does not
		// advertise itself. Either way there is nothing to clone, and a retry
		// would not change it.
		return Source{}, ErrNoSource
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Source{}, fmt.Errorf("source: project service returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out Source
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return Source{}, fmt.Errorf("source: decode: %w", err)
	}
	if out.RepoURL == "" {
		return Source{}, ErrNoSource
	}
	return out, nil
}
