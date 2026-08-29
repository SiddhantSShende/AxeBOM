// Package projectsource resolves where a scan's code lives.
//
// # Why this is an HTTP call and not a database query
//
// A repository connection, an upload or a web source lives in the project
// service's own schema. Schema-per-service is enforced by convention rather
// than by the database, so nothing would stop a caller opening those tables
// directly — and that is exactly why the rule needs holding to. A second
// reader of a table makes the owning service unable to change it, and the
// coupling is invisible until a migration breaks a service that never
// appeared in the review.
//
// # Why this is shared, not owned by one service
//
// The fetcher (git, upload, url — a single root page) and services/webrecon
// (url only, plus discovery config) both call the SAME service-only endpoint
// and decode the SAME response shape. CLAUDE.md invariant 11: "Shared types
// live in libs/go-shared. If two services need a type, it belongs there or in
// proto/." A second, near-identical copy of this client is exactly the drift
// that invariant exists to prevent.
//
// # Why the credential is a REF and not a token
//
// The project service returns `credential_ref`, a Vault path. The caller then
// exchanges it for the token itself. The token exists in exactly one process
// — the fetcher, the only component permitted to hold one — for the duration
// of one clone, and never in Postgres, never in a queue message, never in
// argv. services/webrecon never sees a credential_ref at all: a url source is
// never authenticated, so the project service never sends one for it.
package projectsource

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

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/oidcauth"
)

// Source is where one scan's code comes from.
//
// ⚠ A DISCRIMINATED UNION, NOT ONE SHAPE. The project service's Source()
// endpoint returns a body shaped by the project's source_type — a git
// connection, a stored upload, or a web source — and Kind says which fields
// are populated. Keeping every shape in one struct (rather than an interface
// or a second endpoint) is what lets a caller stay a single `switch
// src.Kind`, matching the "one job, one workspace" contract regardless of
// where the bytes came from.
type Source struct {
	Kind events.SourceKind `json:"kind"`

	// Git-shaped fields. Populated when Kind == events.SourceGit.

	// ConnectionID is the owning row's id. Required, because the Vault path is
	// RE-DERIVED from (tenant, kind, connection id) rather than trusted from
	// CredentialRef — a stored path is attacker-influenceable, and trusting one
	// turns any mass-assignment bug into a cross-tenant secret read.
	ConnectionID  string `json:"connection_id,omitempty"`
	Provider      string `json:"provider,omitempty"`
	RepoURL       string `json:"repo_url,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
	// CredentialRef is a VAULT PATH, never a token.
	CredentialRef string `json:"credential_ref,omitempty"`

	// Upload-shaped fields. Populated when Kind == events.SourceUpload.
	// Never carry a credential: nothing about an upload is ever authenticated.
	UploadID         string `json:"upload_id,omitempty"`
	UploadKind       string `json:"upload_kind,omitempty"`
	StorageRef       string `json:"storage_ref,omitempty"`
	OriginalFilename string `json:"original_filename,omitempty"`

	// URL-shaped fields. Populated when Kind == events.SourceURL. Also never
	// carries a credential — the same reason an upload never does.
	WebSourceID string `json:"web_source_id,omitempty"`
	RootURL     string `json:"root_url,omitempty"`
	// DiscoveryEnabled and MaxHosts are the abuse-guard knobs
	// services/webrecon reads before running subfinder. The fetcher decodes
	// them too (it decodes the whole response) but has never had a reason to
	// read them — its own url handling fetches only the one RootURL.
	DiscoveryEnabled bool `json:"discovery_enabled,omitempty"`
	MaxHosts         int  `json:"max_hosts,omitempty"`
}

// ErrNoSource means the project has no source this caller can read.
//
// A distinct error because it is NOT a fault: a project registered manually,
// scanned from an upload, or not yet given a web source legitimately has
// nothing for this caller to fetch. The caller turns it into a stated reason
// on the scan rather than a retry.
var ErrNoSource = errors.New("project has no source this caller can read")

// TokenFunc mints this component's service credential.
//
// ⚠ IT TAKES NO TENANT, AND THAT IS THE CHANGE ZITADEL FORCED.
//
// The retired issuer minted a token that NAMED the tenant, so the credential
// and the scope arrived together. A ZITADEL machine token is owned by the
// AxeBOM organisation and says nothing about the customer being worked for,
// so the tenant now travels as X-AxeBOM-Tenant on the request — honoured by
// the middleware only for a verified service principal.
//
// The trust boundary is unchanged: our own components could always act for any
// tenant. It is now explicit on the wire instead of buried in a claim.
type TokenFunc func(ctx context.Context) (string, error)

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
	// token — and the fetcher's token can read credential refs.
	BaseURL string
	Token   TokenFunc
	Client  *http.Client
}

func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, errors.New("projectsource: no project service URL configured")
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("projectsource: parse %q: %w", opts.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("projectsource: scheme must be http or https, got %q", u.Scheme)
	}
	if opts.Token == nil {
		return nil, errors.New("projectsource: no token function supplied")
	}

	c := opts.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{base: u, http: c, token: opts.Token}, nil
}

// Resolve returns the source for one project.
func (c *Client) Resolve(ctx context.Context, tenantID, projectID string) (Source, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return Source{}, fmt.Errorf("projectsource: mint service token: %w", err)
	}

	ref := c.base.JoinPath("v1", "projects", projectID, "source")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.String(), nil)
	if err != nil {
		return Source{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	// Which tenant this call is for. See TokenFunc.
	req.Header.Set(oidcauth.HeaderServiceTenant, tenantID)

	resp, err := c.http.Do(req)
	if err != nil {
		return Source{}, fmt.Errorf("projectsource: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// The route answers 404 both for "nothing to read" and for a caller
		// that is not a service principal — deliberately, so the endpoint does
		// not advertise itself. Either way there is nothing to fetch, and a
		// retry would not change it.
		return Source{}, ErrNoSource
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Source{}, fmt.Errorf("projectsource: project service returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out Source
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return Source{}, fmt.Errorf("projectsource: decode: %w", err)
	}

	// Kind-aware validation, and a fallback for an older project-service
	// response that never sent "kind" at all: such a response is necessarily
	// git-shaped, since upload and url support did not exist before this
	// field did.
	switch out.Kind {
	case events.SourceUpload:
		if out.StorageRef == "" {
			return Source{}, ErrNoSource
		}
	case events.SourceURL:
		if out.RootURL == "" {
			return Source{}, ErrNoSource
		}
	default:
		if out.RepoURL == "" {
			return Source{}, ErrNoSource
		}
		out.Kind = events.SourceGit
	}
	return out, nil
}
