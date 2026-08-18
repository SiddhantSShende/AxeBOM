package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// ─── API keys ───────────────────────────────────────────────────────────────
//
// ⚠ AN API KEY IS A LONG-LIVED BEARER CREDENTIAL. Everything below exists
// because that sentence is true and cannot be made false.
//
// A user's access token lives fifteen minutes and a service token two. An API
// key lives until somebody revokes it, gets pasted into a CI configuration,
// copied into a wiki, and echoed by a build log. So:
//
//   - it is SHOWN ONCE and stored only as a hash, so a database disclosure is
//     not a disclosure of every customer's key;
//   - it carries SCOPES, not a role, because "this key may start scans" is a
//     smaller blast radius than "this key is an analyst";
//   - it carries a PREFIX in plaintext, so a leaked key can be identified and
//     revoked without asking the customer to prove which one it is;
//   - it EXPIRES by default, because a credential with no expiry is one nobody
//     ever gets round to rotating.

// KeyPrefix marks an EncoreBOM key in logs and in secret scanners.
//
// ⚠ A RECOGNISABLE PREFIX IS A FEATURE, NOT A LEAK. GitHub, GitLab and every
// commercial secret scanner match on known prefixes; a key that looks like
// random base64 is a key that scanners cannot find in a public commit. Making
// ours identifiable is what gets it caught and revoked.
const KeyPrefix = "ebk_"

// keyBytes is the entropy in a key. 32 bytes is 256 bits.
const keyBytes = 32

// idBytes is the plaintext identifying segment.
//
// It is stored alongside the hash so a key can be NAMED without being known —
// which is what makes "revoke the key ending in a1b2c3" possible.
const idBytes = 6

// DefaultTTL is how long a key lives when the caller does not choose.
//
// ⚠ A DEFAULT OF "NEVER EXPIRES" IS HOW A CREDENTIAL OUTLIVES THE PERSON WHO
// CREATED IT. Ninety days is short enough to force a rotation habit and long
// enough not to break a quarterly release train.
const DefaultTTL = 90 * 24 * time.Hour

// MaxTTL bounds what a caller may ask for.
const MaxTTL = 365 * 24 * time.Hour

// Scope is one permission an API key may carry.
//
// ⚠ SCOPES, NOT ROLES. A CI pipeline needs to start a scan and download a
// report. Giving it an analyst role also gives it the ability to triage
// vulnerabilities, mint share links and edit campaigns — none of which it will
// ever do, all of which it could do if the key leaked.
type Scope string

const (
	// ScopeScanRun starts scans. The common CI case.
	ScopeScanRun Scope = "scan:run"
	// ScopeScanRead reads scan status and engine runs.
	ScopeScanRead Scope = "scan:read"
	// ScopeReportRead lists and reads report metadata.
	ScopeReportRead Scope = "report:read"
	// ScopeReportDownload fetches a rendered artifact.
	ScopeReportDownload Scope = "report:download"
	// ScopeProjectRead reads project configuration.
	ScopeProjectRead Scope = "project:read"
	// ScopeFindingRead reads findings.
	ScopeFindingRead Scope = "finding:read"
	// ScopeVEXTriage sets VEX status. Deliberately separate: triage is a
	// judgement about exploitability, and a build pipeline has no business
	// making one.
	ScopeVEXTriage Scope = "vex:triage"
)

// Scopes returns every scope a key may hold.
//
// ⚠ THERE IS NO ADMIN SCOPE, AND THERE MUST NOT BE. Nothing that manages
// tenants, members, roles or subscriptions is reachable with an API key.
// Those actions need a human with a session, because the blast radius of an
// automated credential doing them is the whole tenant.
func Scopes() []Scope {
	return []Scope{
		ScopeScanRun, ScopeScanRead,
		ScopeReportRead, ScopeReportDownload,
		ScopeProjectRead, ScopeFindingRead,
		ScopeVEXTriage,
	}
}

// Valid reports whether s is a known scope.
func (s Scope) Valid() bool {
	for _, known := range Scopes() {
		if s == known {
			return true
		}
	}
	return false
}

// Permission maps a scope onto the authorization matrix.
func (s Scope) Permission() (authz.Resource, authz.Action, bool) {
	switch s {
	case ScopeScanRun:
		return authz.ResourceScan, authz.ActionRun, true
	case ScopeScanRead:
		return authz.ResourceScan, authz.ActionRead, true
	case ScopeReportRead:
		return authz.ResourceReport, authz.ActionRead, true
	case ScopeReportDownload:
		return authz.ResourceReport, authz.ActionDownload, true
	case ScopeProjectRead:
		return authz.ResourceProject, authz.ActionRead, true
	case ScopeFindingRead:
		return authz.ResourceFinding, authz.ActionRead, true
	case ScopeVEXTriage:
		return authz.ResourceVEX, authz.ActionTriage, true
	default:
		return "", "", false
	}
}

// APIKey is the stored record. It never holds the key.
type APIKey struct {
	ID       string
	TenantID string
	Name     string
	// KeyID is the plaintext identifying segment, e.g. `a1b2c3`.
	KeyID string
	// Hash is the SHA-256 of the full key, hex-encoded.
	//
	// ⚠ SHA-256 RATHER THAN ARGON2, AND THAT IS DELIBERATE. A password is
	// low-entropy and needs a slow hash to survive an offline attack. This key
	// carries 256 bits from crypto/rand — brute force is not the threat, and a
	// slow hash on every API request is a denial of service against ourselves.
	Hash      string
	Scopes    []Scope
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  *time.Time
	RevokedAt *time.Time
}

// Active reports whether the key may be used at `now`.
func (k APIKey) Active(now time.Time) bool {
	return k.RevokedAt == nil && now.Before(k.ExpiresAt)
}

// Allows reports whether the key carries a scope.
func (k APIKey) Allows(s Scope) bool {
	for _, held := range k.Scopes {
		if held == s {
			return true
		}
	}
	return false
}

// Minted is a newly created key. The plaintext exists only here.
type Minted struct {
	Record APIKey
	// Key is the full plaintext, returned exactly once.
	//
	// ⚠ NEVER PERSISTED, NEVER LOGGED, NEVER RETURNED AGAIN. A customer who
	// loses it rotates the key, which is safe; revealing it is not.
	Key string
}

// Mint creates an API key.
func Mint(tenantID, name, createdBy string, scopes []Scope, ttl time.Duration, now time.Time) (Minted, error) {
	if tenantID == "" {
		return Minted{}, errs.New(errs.ValidationFieldRequired,
			"an API key must belong to a tenant")
	}
	if strings.TrimSpace(name) == "" {
		// ⚠ A NAME IS REQUIRED SO A KEY CAN BE REVOKED CONFIDENTLY. Faced with
		// six unnamed keys, an operator responding to a leak either revokes all
		// of them and breaks production, or guesses.
		return Minted{}, errs.New(errs.ValidationFieldRequired,
			"an API key needs a name; an unnamed key cannot be revoked with confidence "+
				"when it is the one that leaked")
	}
	if len(scopes) == 0 {
		return Minted{}, errs.New(errs.ValidationFieldRequired,
			"an API key needs at least one scope; a key with none can do nothing, "+
				"and a key with all of them is a role")
	}
	for _, s := range scopes {
		if !s.Valid() {
			return Minted{}, errs.Newf(errs.ValidationFieldInvalid,
				"%q is not a scope this build issues", s)
		}
	}

	switch {
	case ttl <= 0:
		ttl = DefaultTTL
	case ttl > MaxTTL:
		return Minted{}, errs.Newf(errs.ValidationFieldInvalid,
			"an API key may live at most %d days; a credential nobody rotates is one "+
				"that outlives the person who created it", int(MaxTTL.Hours()/24))
	}

	secret := make([]byte, keyBytes)
	if _, err := rand.Read(secret); err != nil {
		return Minted{}, fmt.Errorf("generate API key: %w", err)
	}
	id := make([]byte, idBytes)
	if _, err := rand.Read(id); err != nil {
		return Minted{}, fmt.Errorf("generate API key id: %w", err)
	}

	keyID := hex.EncodeToString(id)
	// base64url without padding: safe in a header, a URL and a shell.
	plaintext := KeyPrefix + keyID + "_" + base64.RawURLEncoding.EncodeToString(secret)

	return Minted{
		Record: APIKey{
			TenantID: tenantID, Name: strings.TrimSpace(name), KeyID: keyID,
			Hash: hashKey(plaintext), Scopes: scopes, CreatedBy: createdBy,
			CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
		},
		Key: plaintext,
	}, nil
}

// hashKey is the storage form.
func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// ParseKeyID extracts the identifying segment from a presented key.
//
// ⚠ THIS IS WHAT MAKES THE LOOKUP A SINGLE INDEXED READ rather than a scan over
// every key in the tenant comparing hashes. Without it, verification is O(keys)
// and a tenant with a thousand keys makes every request slow.
func ParseKeyID(presented string) (string, error) {
	if !strings.HasPrefix(presented, KeyPrefix) {
		return "", errs.New(errs.AuthTokenInvalid, "not an EncoreBOM API key")
	}
	rest := strings.TrimPrefix(presented, KeyPrefix)
	keyID, _, ok := strings.Cut(rest, "_")
	if !ok || len(keyID) != idBytes*2 {
		return "", errs.New(errs.AuthTokenInvalid, "malformed API key")
	}
	return keyID, nil
}

// Verify checks a presented key against a stored record.
//
// ⚠ CONSTANT TIME, AND THE ORDER MATTERS. The hash is compared before the
// expiry and revocation are consulted, so a caller cannot learn whether a key
// EXISTS by timing the difference between "wrong key" and "revoked key".
func Verify(presented string, record APIKey, now time.Time) error {
	expected := hashKey(presented)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(record.Hash)) != 1 {
		return errs.New(errs.AuthTokenInvalid, "API key is not valid")
	}

	if record.RevokedAt != nil {
		return errs.New(errs.AuthTokenInvalid, "API key has been revoked")
	}
	if !now.Before(record.ExpiresAt) {
		return errs.Newf(errs.AuthTokenExpired,
			"API key expired on %s", record.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// AuthorizeKey checks a key's scopes against a required permission.
//
// Named distinctly from `Authorize`, which is the HTTP middleware for a
// session. Two functions called Authorize in one package, one taking a key
// and one returning middleware, is a call site somebody gets wrong.
//
// ⚠ THE SCOPE MUST GRANT IT AND THE MATRIX MUST ALLOW IT. A scope is a
// NARROWING of what a key may do, never a widening — so a scope naming a
// permission the matrix does not grant to an analyst grants nothing.
func AuthorizeKey(key APIKey, resource authz.Resource, action authz.Action) error {
	for _, scope := range key.Scopes {
		res, act, ok := scope.Permission()
		if !ok || res != resource || act != action {
			continue
		}
		if !authz.Allow(authz.RoleAnalyst, resource, action).Allowed {
			// A scope that outruns the role it is capped at is a configuration
			// error in THIS file, not a customer's problem — but it must not
			// silently grant.
			return errs.Newf(errs.PermRoleInsufficient,
				"scope %q names a permission the API-key role does not hold", scope)
		}
		return nil
	}

	return errs.Newf(errs.PermRoleInsufficient,
		"this API key does not carry the %s:%s scope", resource, action)
}

// Redacted is the safe form for logs.
//
// ⚠ THE KEY ID, NEVER THE KEY. The id is what lets an operator match a log line
// to a row and revoke the right credential; the key is what lets them use it.
func (k APIKey) Redacted() string {
	return fmt.Sprintf("apikey{id:%s name:%q scopes:%v expires:%s}",
		k.KeyID, k.Name, k.Scopes, k.ExpiresAt.UTC().Format(time.RFC3339))
}
