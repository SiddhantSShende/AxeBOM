package oidcauth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// Principal is a verified caller expressed in AxeBOM's own identifiers.
//
// ⚠ TenantID AND UserID ARE UUIDs, NOT ZITADEL IDs. Every RLS policy casts
// app.current_tenant_id to uuid and six tables hold created_by uuid NOT NULL;
// a ZITADEL snowflake string in either place fails the query rather than
// leaking, but it fails EVERY query. Translating here, once, is the whole
// reason this type exists.
type Principal struct {
	TenantID string
	UserID   string
	Role     authz.Role
}

// Resolver maps a verified ZITADEL identity onto a local principal.
type Resolver interface {
	Resolve(ctx context.Context, in ResolveRequest) (Principal, error)
}

// ResolveRequest is what the token asserted about one caller in one org.
type ResolveRequest struct {
	OrgID         string
	OrgName       string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Role          authz.Role
}

// DBResolver resolves against auth.identity_for, with a short-lived cache.
type DBResolver struct {
	pool *db.Pool
	ttl  time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	principal Principal
	expires   time.Time
}

// NewDBResolver builds a resolver over the application pool.
//
// ttl bounds how long a revoked role can survive in this process. It is a
// SECOND control after the token lifetime, not a substitute for it: shortening
// it does not shorten the token's own 15-minute validity, and lengthening it
// past that would let a role outlive the token that carried it.
func NewDBResolver(pool *db.Pool, ttl time.Duration) *DBResolver {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &DBResolver{pool: pool, ttl: ttl, cache: map[string]cacheEntry{}}
}

// Resolve returns the local principal, provisioning the projection if needed.
func (r *DBResolver) Resolve(ctx context.Context, in ResolveRequest) (Principal, error) {
	// The role is part of the key. A role change in ZITADEL therefore produces
	// a cache MISS rather than a stale hit, so an escalation or a revocation
	// takes effect on the next token rather than after the TTL.
	key := in.OrgID + "|" + in.Subject + "|" + string(in.Role)

	r.mu.Lock()
	if e, ok := r.cache[key]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.principal, nil
	}
	r.mu.Unlock()

	var p Principal
	var role string
	// pool.Raw, not WithTenant: resolving the tenant is what this call is FOR,
	// so there is no tenant to scope it with. auth.identity_for is the narrow
	// SECURITY DEFINER hole that makes exactly this one lookup possible without
	// weakening RLS anywhere else — see migrations/auth/0003.
	err := r.pool.Raw().QueryRow(ctx,
		`SELECT tenant_id::text, user_id::text, role
		   FROM auth.identity_for($1, $2, $3, $4, $5, $6, $7)`,
		in.OrgID, in.OrgName, in.Subject, in.Email, in.EmailVerified, in.Name, string(in.Role),
	).Scan(&p.TenantID, &p.UserID, &role)
	if err != nil {
		return Principal{}, fmt.Errorf("oidcauth: resolve identity: %w", err)
	}
	p.Role = authz.Role(role)

	r.mu.Lock()
	r.cache[key] = cacheEntry{principal: p, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()

	return p, nil
}
