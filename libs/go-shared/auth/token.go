// Package auth issues and verifies credentials.
//
// It lives in libs/ because BOTH the gateway (which verifies) and auth-svc
// (which issues) need it, and services may not import each other
// (ADR-0001 mitigation 3).
//
// Two properties this package exists to guarantee:
//
//   - The tenant in a request context comes from a VERIFIED token and nowhere
//     else — never a header, query parameter or body field. That value is what
//     db.WithTenant feeds to Postgres RLS, so trusting a header here would
//     hand the caller every tenant's data.
//
//   - A stolen refresh token is DETECTABLE. Tokens rotate, and presenting an
//     already-rotated one means two parties hold it. The whole family is then
//     revoked, because we cannot tell which party is the legitimate one.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
)

// Claims is the access-token payload.
//
// Deliberately small. A JWT is not a database: every field here is copied into
// every request, cannot be revoked before expiry, and is readable by anyone who
// obtains the token. Anything larger or more sensitive is looked up server-side.
type Claims struct {
	Subject   string     `json:"sub"`  // user id
	TenantID  string     `json:"tid"`  // THE tenancy boundary
	Role      authz.Role `json:"role"` // role WITHIN that tenant
	SessionID string     `json:"sid"`  // session, for revocation
	IssuedAt  int64      `json:"iat"`
	Expires   int64      `json:"exp"`
	JTI       string     `json:"jti"`
	Issuer    string     `json:"iss"`
}

// Valid checks time-based claims. Signature verification happens separately.
func (c Claims) Valid(now time.Time) error {
	if c.Expires <= now.Unix() {
		return errs.New(errs.AuthTokenExpired, "access token has expired")
	}
	// A small tolerance for clock skew between services. Without it, a token
	// issued by a host a second ahead is rejected as not-yet-valid.
	if c.IssuedAt > now.Add(2*time.Minute).Unix() {
		return errs.New(errs.AuthTokenInvalid, "token issued in the future")
	}
	if c.Subject == "" || c.TenantID == "" {
		return errs.New(errs.AuthTokenInvalid, "token is missing subject or tenant")
	}
	if !c.Role.Valid() {
		return errs.New(errs.AuthTokenInvalid, "token carries an unknown role")
	}
	return nil
}

// TokenConfig configures issuance.
type TokenConfig struct {
	SigningKey []byte
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// Issuer mints and verifies tokens.
type Issuer struct{ cfg TokenConfig }

// MinSigningKeyBytes is enforced because a short HMAC key is brute-forceable
// offline by anyone holding one token.
const MinSigningKeyBytes = 32

// NewIssuer validates the configuration up front.
func NewIssuer(cfg TokenConfig) (*Issuer, error) {
	if len(cfg.SigningKey) < MinSigningKeyBytes {
		return nil, fmt.Errorf(
			"JWT signing key is %d bytes; at least %d are required. A short HMAC key "+
				"can be brute-forced offline from a single captured token",
			len(cfg.SigningKey), MinSigningKeyBytes)
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "encorebom"
	}
	return &Issuer{cfg: cfg}, nil
}

// header is the fixed JOSE header.
//
// `alg` is NEVER read from the token. Trusting the token's own algorithm claim
// is the classic JWT vulnerability: a caller sets alg=none, or swaps RS256 for
// HS256 and signs with the public key. We verify with exactly one algorithm.
var header = []byte(`{"alg":"HS256","typ":"JWT"}`)

// IssueAccess mints a signed access token.
func (i *Issuer) IssueAccess(now time.Time, userID, tenantID, sessionID string, role authz.Role) (string, Claims, error) {
	claims := Claims{
		Subject:   userID,
		TenantID:  tenantID,
		Role:      role,
		SessionID: sessionID,
		IssuedAt:  now.Unix(),
		Expires:   now.Add(i.cfg.AccessTTL).Unix(),
		JTI:       uuid.NewString(),
		Issuer:    i.cfg.Issuer,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, err
	}

	signing := b64(header) + "." + b64(payload)
	return signing + "." + b64(i.sign([]byte(signing))), claims, nil
}

// VerifyAccess checks the signature and the time-based claims.
func (i *Issuer) VerifyAccess(token string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errs.New(errs.AuthTokenInvalid, "malformed token")
	}

	signing := parts[0] + "." + parts[1]
	sig, err := unb64(parts[2])
	if err != nil {
		return Claims{}, errs.New(errs.AuthTokenInvalid, "malformed token signature")
	}

	// CONSTANT TIME. A byte-by-byte comparison leaks the correct signature
	// through timing, one byte at a time.
	if !hmac.Equal(sig, i.sign([]byte(signing))) {
		return Claims{}, errs.New(errs.AuthTokenInvalid, "token signature does not verify")
	}

	// Signature first, THEN parse. Parsing attacker-controlled JSON before
	// authenticating it widens the attack surface for no benefit.
	raw, err := unb64(parts[1])
	if err != nil {
		return Claims{}, errs.New(errs.AuthTokenInvalid, "malformed token payload")
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Claims{}, errs.New(errs.AuthTokenInvalid, "unreadable token payload")
	}

	if claims.Issuer != i.cfg.Issuer {
		return Claims{}, errs.New(errs.AuthTokenInvalid, "token was issued by another party")
	}
	if err := claims.Valid(now); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func (i *Issuer) sign(b []byte) []byte {
	m := hmac.New(sha256.New, i.cfg.SigningKey)
	m.Write(b)
	return m.Sum(nil)
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

// RefreshToken is returned to the client ONCE. Only its hash is stored.
type RefreshToken struct {
	// Plaintext is shown to the client and never persisted. A database read
	// must not yield a usable credential.
	Plaintext string
	Hash      string
	// FamilyID links a rotation chain. Reuse revokes the whole family, because
	// we cannot tell the thief from the legitimate holder.
	FamilyID  string
	ExpiresAt time.Time
}

// NewRefreshToken mints a token in a new family.
func (i *Issuer) NewRefreshToken(now time.Time) (RefreshToken, error) {
	return i.rotateRefreshToken(now, uuid.NewString())
}

// RotateRefreshToken mints a successor within the SAME family.
func (i *Issuer) RotateRefreshToken(now time.Time, familyID string) (RefreshToken, error) {
	if familyID == "" {
		return RefreshToken{}, errors.New("rotation requires a family id")
	}
	return i.rotateRefreshToken(now, familyID)
}

func (i *Issuer) rotateRefreshToken(now time.Time, familyID string) (RefreshToken, error) {
	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return RefreshToken{}, fmt.Errorf("generate refresh token: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(buf)
	return RefreshToken{
		Plaintext: plain,
		Hash:      HashRefreshToken(plain),
		FamilyID:  familyID,
		ExpiresAt: now.Add(i.cfg.RefreshTTL),
	}, nil
}

// HashRefreshToken hashes for storage and lookup.
//
// Plain SHA-256, deliberately, NOT argon2id. A refresh token is 256 bits of
// CSPRNG output, so there is nothing to brute-force — and a lookup must be
// fast, whereas argon2 is slow by design. Password hashing is the opposite
// case and uses argon2id; see password.go.
func HashRefreshToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqualHash compares two hex hashes without leaking via timing.
func ConstantTimeEqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// OAuth state
// ---------------------------------------------------------------------------

// NewOAuthState mints an unguessable CSRF state parameter.
//
// Without it, an attacker initiates an OAuth flow, sends the victim the
// callback URL, and the victim's account is linked to the ATTACKER's GitHub
// identity — after which the attacker can sign in as the victim.
func NewOAuthState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// VerifyOAuthState compares in constant time.
func VerifyOAuthState(got, want string) error {
	if want == "" || got == "" {
		return errs.New(errs.AuthStateMismatch, "missing OAuth state parameter")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errs.New(errs.AuthStateMismatch,
			"OAuth state does not match; the request may be forged")
	}
	return nil
}
