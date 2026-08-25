// Package iam provisions and inspects the ZITADEL identity tier.
//
// ⚠ NOTHING HERE LINKS ZITADEL SERVER CODE.
//
// The ZITADEL server is AGPL-3.0-only, and CLAUDE.md invariant 9 keeps
// copyleft in a separate process. It runs as an unmodified published container
// and this package talks to it over gRPC using github.com/zitadel/zitadel-go/v3
// — a separate repository, Apache-2.0, shipping its own generated clients.
// `.golangci.yml` fails the build on any github.com/zitadel/zitadel/ import so
// that boundary cannot erode by accident.
//
// ---------------------------------------------------------------------------
// WHY A GO PROVISIONER AND NOT TERRAFORM
//
// ZITADEL's FirstInstance config can seed an instance, one organisation, one
// human admin and one machine user — and nothing else. Projects, roles,
// applications and per-tenant organisations have to be created through the API,
// and ZITADEL's own documentation points at Terraform for that.
//
// This repository already refuses that trade: `make` and `task` are absent on
// the primary development machine and PowerShell 5.1 has no `&&`, so anything
// a script would do lives in the CLI instead (CLAUDE.md §Conventions). Adding
// Terraform would add a second toolchain, a second state file and a second
// place where the role list is written down. The role keys here are generated
// from authz.AllRoles(), so ZITADEL's roles and the permission matrix cannot
// drift apart.
package iam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config locates the ZITADEL instance and the credential used to provision it.
type Config struct {
	// Domain is the hostname ZITADEL answers for, WITHOUT a port.
	Domain string
	// Port is the port this client connects on. It may differ from the port in
	// the public issuer: the CLI talks to the container directly so it keeps
	// working when the reverse proxy is down.
	Port string
	// Insecure selects plaintext h2c. Development only.
	Insecure bool
	// KeyPath is the machine-user JSON key written by the setup one-shot.
	KeyPath string

	// PublicHost overrides the Host / gRPC :authority ZITADEL sees, when it
	// differs from Domain:Port.
	//
	// ⚠ NEEDED BY ANY IN-NETWORK CALLER. ZITADEL selects its instance from the
	// Host header, and a caller inside the compose network reaches it as
	// zitadel-api:8080 — a Host no instance is registered under, answered with
	// "Instance not found" on every call including the discovery request that
	// has to succeed before any other one can. The CLI (cmd/axebom/iam.go)
	// never hits this: it dials the PUBLISHED port directly as `localhost`,
	// which already matches. Leave empty there.
	//
	// Trusted domains (ZITADEL_FIRSTINSTANCE_TRUSTEDDOMAINS) are NOT an
	// alternative to this, for the same reason they are not one in
	// oidcauth/transport.go: they are eventstore state, lost on
	// `task iam:reset`, and this override is a property of the client that
	// travels with the code instead.
	PublicHost string
}

// Client is an authenticated connection to ZITADEL's management APIs.
type Client struct {
	api *client.Client
	cfg Config
}

// Connect authenticates as the bootstrap machine user.
//
// Authentication is private-key JWT rather than a personal access token: the
// key never leaves the mounted directory, whereas a PAT is a bearer secret that
// is equally useful to anyone who reads it out of a log or a process listing.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Domain == "" {
		return nil, errors.New("iam: no ZITADEL domain configured")
	}
	if _, err := os.Stat(cfg.KeyPath); err != nil {
		return nil, fmt.Errorf(
			"iam: cannot read the ZITADEL machine key at %s "+
				"(it is written by the setup one-shot — run `task iam:up`, or "+
				"`task iam:reset` if the instance and the key have diverged): %w",
			cfg.KeyPath, err)
	}

	opts := []zitadel.Option{}
	if cfg.Insecure {
		opts = append(opts, zitadel.WithInsecure(cfg.Port))
	} else if cfg.Port != "" {
		port, perr := strconv.ParseUint(cfg.Port, 10, 16)
		if perr != nil {
			return nil, fmt.Errorf("iam: port %q is not a number: %w", cfg.Port, perr)
		}
		opts = append(opts, zitadel.WithPort(uint16(port)))
	}

	z := zitadel.New(cfg.Domain, opts...)

	// ⚠ ONLY BUILT WHEN NEEDED — see the field comment on Config.PublicHost.
	var auth publicHostAuth
	if cfg.PublicHost != "" && cfg.PublicHost != z.Host() {
		scheme := "https"
		if cfg.Insecure {
			scheme = "http"
		}
		auth = publicHostAuth{
			httpClient: &http.Client{
				Transport: &publicHostRoundTripper{host: cfg.PublicHost, base: http.DefaultTransport},
			},
			// The assertion's `aud` and the token request's Host both need to
			// be the PUBLIC issuer, mirroring oidcauth.ServiceTokenSource —
			// see serviceUserAuth for why this also means skipping discovery
			// rather than merely Host-overriding it.
			issuer:        scheme + "://" + cfg.PublicHost,
			tokenEndpoint: z.Origin() + "/oauth/v2/token",
		}
	}

	// ScopeZitadelAPI puts urn:zitadel:iam:org:project:id:zitadel:aud in the
	// token. Without it the token is valid but carries no audience for
	// ZITADEL's own management API, and every call answers permission denied
	// — which reads like a missing role rather than a missing scope.
	authInit, err := serviceUserAuth(cfg.KeyPath, auth, client.ScopeZitadelAPI())
	if err != nil {
		return nil, err
	}
	clientOpts := []client.Option{client.WithAuth(authInit)}

	if auth.httpClient != nil {
		// The gRPC side (every management-API call after connect, once a
		// token has been obtained): gRPC's Host equivalent is the :authority
		// pseudo-header, which only grpc.WithAuthority controls — gRPC
		// metadata (what zitadel.WithTransportHeader appends) is a different
		// channel and does not reach it.
		clientOpts = append(clientOpts, client.WithGRPCDialOptions(grpc.WithAuthority(cfg.PublicHost)))
	}

	api, err := client.New(ctx, z, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("iam: connect to ZITADEL at %s: %w", z.Origin(), err)
	}
	return &Client{api: api, cfg: cfg}, nil
}

// publicHostAuth carries the three pieces of the discovery bypass together,
// so a caller cannot set one without the other two — see serviceUserAuth.
// Zero value means "no override", the CLI's normal case.
type publicHostAuth struct {
	httpClient    *http.Client
	issuer        string
	tokenEndpoint string
}

// serviceUserAuth is client.DefaultServiceUserAuthentication, plus the escape
// hatch that helper has no way to offer: a way to reach ZITADEL through an
// address that does not match its own public issuer.
//
// ⚠ A HOST OVERRIDE ALONE IS NOT ENOUGH HERE, UNLIKE EVERYWHERE ELSE IN THIS
// FILE. client.DefaultServiceUserAuthentication calls
// profile.NewJWTProfileTokenSource, which — when no static token endpoint is
// given — runs OIDC discovery and then checks that the discovery document's
// OWN `issuer` field matches the issuer string it was asked for (RFC 8414,
// and the correct behaviour: it is what stops a client from being redirected
// to a different authorization server that happens to answer). ZITADEL
// derives that field from ITS OWN EXTERNALDOMAIN, so a call whose Host is
// overridden to the public value gets back "issuer": "<public>" while the
// code asked discovery for "<internal>" — a mismatch this override exists to
// avoid, one layer up. profile.WithStaticTokenEndpoint skips discovery
// entirely instead of trying to satisfy it.
func serviceUserAuth(keyPath string, auth publicHostAuth, scopes ...string) (client.TokenSourceInitializer, error) {
	keyFile, err := client.ConfigFromKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("iam: read machine key %s: %w", keyPath, err)
	}
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		if auth.httpClient == nil {
			return profile.NewJWTProfileTokenSource(ctx, issuer, keyFile.UserID, keyFile.KeyID, keyFile.Key, scopes)
		}
		return profile.NewJWTProfileTokenSource(ctx, auth.issuer, keyFile.UserID, keyFile.KeyID, keyFile.Key, scopes,
			profile.WithHTTPClient(auth.httpClient),
			profile.WithStaticTokenEndpoint(auth.issuer, auth.tokenEndpoint))
	}, nil
}

// publicHostRoundTripper forces a fixed Host onto every request, the way
// oidcauth/transport.go's publicHost does — see that file for the fuller
// rationale. Duplicated in miniature here rather than imported: the two
// packages authenticate as different kinds of principal (a human/service
// token verifier there, a machine-user management client here) and sharing
// this ~10 lines is not worth a cross-package dependency between them.
type publicHostRoundTripper struct {
	host string
	base http.RoundTripper
}

func (t *publicHostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// ⚠ req.Host, NOT req.Header.Set("Host", ...) — Go's transport takes the
	// Host from the field and ignores the header map.
	r := req.Clone(req.Context())
	r.Host = t.host
	return t.base.RoundTrip(r)
}

// Close releases the gRPC connection.
func (c *Client) Close() error { return c.api.Close() }

// Origin is the address this client is talking to. Reported by `iam verify`,
// because "which ZITADEL did you configure" is the first question when a token
// is rejected.
func (c *Client) Origin() string {
	scheme := "https"
	if c.cfg.Insecure {
		scheme = "http"
	}
	host := c.cfg.Domain
	if c.cfg.Port != "" {
		host += ":" + c.cfg.Port
	}
	return scheme + "://" + host
}

// ⚠ THERE IS NO authCtx HELPER, DELIBERATELY.
//
// client.AuthorizedUserCtx exists to forward an END USER's token out of an
// authenticated HTTP request; called on a bare context it dereferences an
// absent authorization context and panics. The machine user's token is applied
// by the interceptor that client.WithAuth installs, so every call below simply
// passes the plain context and is already authenticated.

// callCtx bounds a single management call.
//
// The default is no deadline at all, and a provisioning run makes dozens of
// calls; one hung call would hang the command with no output and no clue.
func callCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}

// isAlreadyExists reports whether err means "this is already provisioned".
//
// ⚠ BOOTSTRAP MUST BE IDEMPOTENT, and ZITADEL is not uniform about how it says
// so. Some services answer AlreadyExists; others answer FailedPrecondition or
// InvalidArgument with a message naming the conflict. Treating only the tidy
// case as success makes a second `iam bootstrap` fail on a system that is
// already correct, which teaches people to skip the command entirely.
func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.AlreadyExists:
			return true
		case codes.FailedPrecondition, codes.InvalidArgument:
			// fall through to the message check
		default:
			return false
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "alreadyexists") ||
		strings.Contains(msg, "alreadyexisting")
}
