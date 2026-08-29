package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/iam"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
	"github.com/axebom/axebom/services/gateway/internal/middleware"
	"github.com/axebom/axebom/services/gateway/internal/proxy"
)

// deps holds this service's constructed dependencies.
//
// GENERATED SCAFFOLD, then hand-edited. Written only if absent.
//
// One place where every dependency is built and one place where each is torn
// down. main.go calls buildDeps exactly once and hands the result to both
// registerHealthChecks and registerRoutes, so a service can never end up with
// two connection pools or a route holding a handle nothing closes.
//
// Return an error rather than exiting: a service that cannot reach its database
// must fail to START, not start and serve 500s while passing liveness.
//
// The gateway deliberately has NO database pool. It verifies tokens, limits
// rates and proxies; giving it a pool would invite domain logic to accumulate
// in the one component every request passes through. iam is the one
// deliberate exception, and it is a ZITADEL connection, not a database one —
// see internal/signup and config.OIDC.ProvisioningKeyPath.
type deps struct {
	cfg     *config.Service
	issuer  *auth.Issuer
	limiter *middleware.Limiter
	router  *proxy.Router
	// iam is nil when self-service signup is not configured or could not
	// connect at startup. internal/signup.Handler answers a structured
	// INTERNAL_DEPENDENCY_UNAVAILABLE in that case rather than a nil
	// dereference — every other gateway capability works with it absent.
	iam *iam.Client
}

// buildDeps constructs everything this service needs.
func buildDeps(ctx context.Context, cfg *config.Service) (*deps, error) {
	// The gateway VERIFIES tokens; auth mints them. Both need the same key,
	// which is why it is in the shared config section. NewIssuer enforces the
	// minimum key length, so a too-short key stops the process here rather
	// than yielding brute-forceable tokens.
	issuer, err := auth.NewIssuer(auth.TokenConfig{
		SigningKey: []byte(cfg.Auth.JWTSigningKey.Reveal()),
		Issuer:     cfg.Auth.JWTIssuer,
		AccessTTL:  cfg.Auth.AccessTTL,
		RefreshTTL: cfg.Auth.RefreshTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("token issuer: %w", err)
	}

	// TrustedProxyHeader is left EMPTY by default. Honouring X-Forwarded-For
	// on a directly-exposed gateway would let any client pick its own limiter
	// bucket — that is, opt out of rate limiting. Set it only once a proxy
	// that overwrites the header is actually in front.
	limiter := middleware.NewLimiter(middleware.RateLimitConfig{})

	// Upstream URLs are parsed here so a malformed one stops the process at
	// boot. Deferring it to the first request would turn an operator's typo
	// into a user's 500, hours later and on somebody else's shift.
	router, err := proxy.New(cfg.Services, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("proxy router: %w", err)
	}

	// Self-service signup is optional. A gateway that cannot reach the
	// provisioning credential still verifies tokens and proxies every other
	// route fine — logged loudly, not fatal, so a stack that never wires
	// ZITADEL_BOOTSTRAP_KEY (most deployments) starts exactly as before.
	iamClient, err := buildIAMClient(ctx, cfg.OIDC)
	if err != nil {
		slog.Error("self-service signup unavailable", "cause", err)
	}

	return &deps{cfg: cfg, issuer: issuer, limiter: limiter, router: router, iam: iamClient}, nil
}

// buildIAMClient connects the ZITADEL bootstrap credential used by
// internal/signup, or returns (nil, nil) when the feature is not configured
// at all — see config.OIDC.ProvisioningKeyPath.
func buildIAMClient(ctx context.Context, cfg config.OIDC) (*iam.Client, error) {
	if cfg.ProvisioningKeyPath == "" {
		return nil, nil
	}

	internal, err := url.Parse(cfg.InternalURL)
	if err != nil {
		return nil, fmt.Errorf("parse ZITADEL_INTERNAL_URL %q: %w", cfg.InternalURL, err)
	}
	// The public origin, e.g. "localhost:5173" — the same value oidcauth
	// validates every token's `iss` against. ZITADEL selects its instance
	// from the Host header, so a call dialed at cfg.InternalURL's address
	// (zitadel-api:8080 in compose) must still present THIS Host or every
	// call, starting with discovery, 404s as "Instance not found". See
	// iam.Config.PublicHost.
	public, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("parse ZITADEL_ISSUER %q: %w", cfg.Issuer, err)
	}

	return iam.Connect(ctx, iam.Config{
		Domain:       internal.Hostname(),
		Port:         internal.Port(),
		Insecure:     internal.Scheme == "http",
		KeyPath:      cfg.ProvisioningKeyPath,
		PublicHost:   public.Host,
		PublicScheme: public.Scheme,
	})
}

// Close releases the dependencies, in reverse order of construction.
func (d *deps) Close() {
	if d == nil {
		return
	}
	if d.iam != nil {
		_ = d.iam.Close()
	}
}

// serviceMiddleware returns the gateway's chain additions.
//
// RATE LIMITING RUNS BEFORE AUTHENTICATION, deliberately. Login is the
// endpoint most worth brute-forcing and it is unauthenticated by definition —
// a limiter placed after auth would never see the attempts it exists to stop.
func serviceMiddleware(d *deps) []httpx.Middleware {
	return []httpx.Middleware{middleware.RateLimit(d.limiter)}
}

// startBackground launches this service's long-running background workers.
//
// GENERATED SCAFFOLD, then hand-edited. Written only if absent.
//
// Called after buildDeps and before the HTTP server starts. Implementations
// launch their own goroutines and RETURN — this must not block, or the service
// never begins serving. ctx is cancelled on shutdown.
//
// A worker's failure belongs in a log, not in an exit: an instance that can
// still serve HTTP is worth more than one that dies because NATS blinked.
func startBackground(ctx context.Context, d *deps) {
	_, _ = ctx, d
}
