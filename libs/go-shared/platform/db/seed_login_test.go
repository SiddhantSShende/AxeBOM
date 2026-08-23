package db

import (
	"context"
	"testing"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
)

// ⚠ A SEED WHOSE USERS CANNOT LOG IN IS NOT A SEED.
//
// migrations/seed/0001_dev_tenants.sql inserted four users and no
// `password_hash`, so `db:reset` produced a database nobody could authenticate
// against. Nothing failed: the seed reported success, the users were there, and
// the gap only surfaced when a person tried to open the UI. Every automated
// test either used a service token or registered its own account, so the one
// path a developer actually takes was the one path nothing exercised.
//
// These tests are cheap and they close that hole permanently.

// SeedPassword is what the dev seed hashes. Named so it cannot be mistaken for
// a credential; see the seed file's header for why publishing it is safe.
const SeedPassword = "encorebom-dev-only"

// seedLogin is every seeded account and whether it can authenticate locally.
var seedLogin = []struct {
	email    string
	provider string
	// local reports whether this account is expected to have a password.
	local bool
}{
	{"alice@acme.test", "local", true},
	{"aaron@acme.test", "local", true},
	{"bob@beta.test", "local", true},
	// ⚠ SSO-ONLY, AND THAT IS THE POINT. Service.Login has a branch for a user
	// with an empty hash that returns the same generic error as a wrong
	// password, because answering "use GitHub instead" would confirm the
	// address is registered. carol is the only fixture that reaches it.
	{"carol@both.test", "github", false},
}

func TestSeededUsersCanLogIn(t *testing.T) {
	pool := openTestPool(t)

	for _, want := range seedLogin {
		t.Run(want.email, func(t *testing.T) {
			var provider string
			var hash *string

			// auth.users is GLOBAL — no tenant_id, no RLS policy — so this
			// reads through the plain pool rather than WithTenant. A user
			// belongs to tenants through auth.memberships, which is what lets
			// carol be in two of them.
			err := pool.Raw().QueryRow(t.Context(),
				`SELECT auth_provider, password_hash FROM auth.users WHERE email = $1`,
				want.email).Scan(&provider, &hash)
			if err != nil {
				t.Fatalf("seeded user %s is missing: %v (did `task db:seed` run?)", want.email, err)
			}

			if provider != want.provider {
				t.Errorf("auth_provider = %q, want %q", provider, want.provider)
			}

			if !want.local {
				if hash != nil && *hash != "" {
					t.Errorf("%s is an SSO-only fixture and now has a password; "+
						"nothing else reaches Login's empty-hash branch", want.email)
				}
				return
			}

			if hash == nil || *hash == "" {
				t.Fatalf("%s has no password_hash, so nobody can log into a freshly "+
					"seeded database — the exact defect this test exists to prevent",
					want.email)
			}

			// ⚠ VERIFIED, NOT MERELY PRESENT. A hash of the wrong password, or
			// one produced by a different algorithm, is indistinguishable from
			// a correct one until someone tries to log in.
			if err := auth.VerifyPassword(SeedPassword, *hash); err != nil {
				t.Errorf("the seeded hash does not verify against %q: %v", SeedPassword, err)
			}

			if auth.VerifyPassword(SeedPassword+"x", *hash) == nil {
				t.Error("a wrong password verified against the seeded hash")
			}

			// A hash below current policy would be silently rewritten on first
			// login. Harmless, but it means the committed artifact is stale.
			if auth.NeedsRehash(*hash, auth.DefaultArgon2Params()) {
				t.Errorf("the seeded hash is below current argon2 policy and would be " +
					"rehashed on first login; regenerate it (see the seed header)")
			}
		})
	}
}

// Each user gets its own salt. Reusing one across accounts would let a single
// cracked hash unlock every seeded account at once — irrelevant for a published
// dev password, and the wrong pattern to copy out of this file into anything
// that matters.
func TestSeededHashesUseDistinctSalts(t *testing.T) {
	pool := openTestPool(t)

	seen := map[string]string{}
	for _, want := range seedLogin {
		if !want.local {
			continue
		}
		var hash *string
		if err := pool.Raw().QueryRow(t.Context(),
			`SELECT password_hash FROM auth.users WHERE email = $1`, want.email).
			Scan(&hash); err != nil || hash == nil {
			t.Fatalf("seeded user %s has no hash to compare: %v", want.email, err)
		}
		if prior, dup := seen[*hash]; dup {
			t.Errorf("%s and %s share an identical hash, so they share a salt",
				want.email, prior)
		}
		seen[*hash] = want.email
	}
}

// The seeded users must reach the tenants the RLS tests assume, or a login that
// succeeds still lands nowhere: Service.Login rejects an account with no
// membership, and selectMembership is what puts a tenant on the token.
//
// ⚠ COUNTED PER TENANT, THROUGH WithTenant. auth.memberships is tenant-scoped
// and has an RLS policy, so an unscoped count raises `unrecognized
// configuration parameter` — RLS failing closed, correctly. Summing two scoped
// reads is also the more honest shape: it is how the application sees carol,
// as one row in each tenant rather than two rows in one query.
func TestSeededUsersHaveMemberships(t *testing.T) {
	pool := openTestPool(t)
	ctx := t.Context()

	countIn := func(tenant, email string) int {
		var n int
		if err := pool.WithTenant(ctx, tenant, func(ctx context.Context, tx Tx) error {
			return tx.QueryRow(ctx, `
				SELECT count(*) FROM auth.memberships m
				  JOIN auth.users u ON u.id = m.user_id
				 WHERE u.email = $1`, email).Scan(&n)
		}); err != nil {
			t.Fatalf("count memberships for %s in %s: %v", email, tenant, err)
		}
		return n
	}

	for email, wantTenants := range map[string]int{
		"alice@acme.test": 1,
		"aaron@acme.test": 1,
		"bob@beta.test":   1,
		// The case that would break if users were tenant-scoped.
		"carol@both.test": 2,
	} {
		got := countIn(tenantA, email) + countIn(tenantB, email)
		if got != wantTenants {
			t.Errorf("%s is a member of %d tenant(s), want %d — Login rejects an "+
				"account with no membership", email, got, wantTenants)
		}
	}
}
