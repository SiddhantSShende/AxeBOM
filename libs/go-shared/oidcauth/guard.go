package oidcauth

import (
	"fmt"
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// Guard is the two halves of authentication, built together.
//
// Verification and resolution are separate types because they are separately
// testable — the middleware tests use a fake resolver and a locally generated
// key — but every service needs both, wired the same way. Building them in one
// place means the issuer/JWKS split (see config.OIDC) is decided once rather
// than copied into five services, where the sixth copy is the one that gets it
// wrong.
type Guard struct {
	Verifier *Verifier
	Resolver Resolver
	// pool backs API-key authentication, a pre-tenant lookup with the same
	// shape as login (migrations/auth/0002) — see Authenticate.
	pool *db.Pool
}

// Open builds the guard for a service.
//
// It fails rather than degrades. A service that starts without a usable
// verifier can still answer /healthz, so it would pass every liveness probe
// while rejecting every real request — an outage that looks like a client bug.
func Open(cfg config.OIDC, pool *db.Pool) (*Guard, error) {
	v, err := NewVerifier(Config{
		Issuer:    cfg.Issuer,
		JWKSURL:   cfg.JWKSURL,
		ProjectID: cfg.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if pool == nil {
		return nil, fmt.Errorf("identity: a database pool is required to resolve accounts")
	}
	return &Guard{Verifier: v, Resolver: NewDBResolver(pool, cfg.IdentityTTL), pool: pool}, nil
}

// Authenticate is the middleware every route mounts.
func (g *Guard) Authenticate() func(http.Handler) http.Handler {
	return Authenticate(g.Verifier, g.Resolver, g.pool)
}
