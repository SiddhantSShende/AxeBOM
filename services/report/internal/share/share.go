// Package share issues and checks report share links.
//
// A share link is the ONE way report data leaves this product without an
// authenticated identity attached. Everything here follows from that.
//
// See docs/phases/PHASE-09-reports.md step 9 and docs/05-SECURITY-MODEL.md §4.
package share

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenBytes is the token's entropy, in bytes.
//
// ⚠ 256 BITS, AND THE REASON IS THE THREAT MODEL, NOT FASHION.
//
// `/shared/:token` is unauthenticated: the token IS the authorization. There is
// no second factor, no account lockout and no user to notice a compromise, and
// the endpoint is by design reachable by anyone on the internet. A guessable
// token is a full disclosure of a report that may contain every unpatched
// vulnerability in a customer's estate.
const TokenBytes = 32

// Token is a share-link secret.
//
// ⚠ IT IS NEVER PERSISTED, LOGGED, OR PUT IN AN ERROR. Only Hash goes to the
// database — a database read must not yield a working link, the same rule as
// auth.sessions. The type exists so a plaintext token is visible in a signature
// and cannot be confused with the hash.
type Token string

// String deliberately refuses to render the token.
//
// A token reaches a log through fmt.Sprintf("%v", link) far more often than
// through a deliberate log line, and a leaked share token is a working link.
// The value is still available through Reveal, which is greppable.
func (t Token) String() string { return "share-token(redacted)" }

// Reveal returns the plaintext. Call it only when handing the token to the user
// who created the link.
func (t Token) Reveal() string { return string(t) }

// Hash is what the database stores.
func (t Token) Hash() string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// NewToken generates a share-link token.
//
// URL-safe base64 without padding, because the token travels in a path segment
// and `+`, `/` and `=` all require escaping there — a token that must be
// URL-encoded gets mangled by exactly one link in the chain of tools a customer
// pastes it through.
func NewToken() (Token, error) {
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a share token: %w", err)
	}
	return Token(base64.RawURLEncoding.EncodeToString(raw)), nil
}

// ParseToken validates a token from a URL before it reaches the database.
//
// ⚠ IT CHECKS SHAPE ONLY, AND IT NEVER SHORT-CIRCUITS ON CONTENT. Rejecting
// a well-formed but unknown token here would be a free oracle; rejecting a
// malformed one costs an attacker nothing they did not already know, and saves
// a database round trip per garbage request against an unauthenticated
// endpoint.
func ParseToken(s string) (Token, error) {
	// RawURLEncoding of 32 bytes is exactly 43 characters.
	const want = 43
	if len(s) != want {
		return "", ErrMalformedToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != TokenBytes {
		return "", ErrMalformedToken
	}
	return Token(s), nil
}

// ErrMalformedToken means the token is not the right shape. It is NOT
// "not found" — see the handler, which returns the same response for both.
var ErrMalformedToken = errors.New("share token is malformed")

// EqualHash compares two token hashes in constant time.
//
// The hashes are not secret, so this is not strictly required. It is here
// because the habit is what survives: the next comparison somebody adds by
// copying this line may well be against something that is.
func EqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(a)), []byte(strings.ToLower(b))) == 1
}

// Outcome is why an access was granted or refused. The values match the CHECK
// constraint on report.share_access_log.
type Outcome string

const (
	// OutcomeGranted means the download was served and counted.
	OutcomeGranted Outcome = "granted"
	// OutcomeExpired means the link's validity window has passed.
	OutcomeExpired Outcome = "expired"
	// OutcomeRevoked means an operator withdrew the link.
	OutcomeRevoked Outcome = "revoked"
	// OutcomeExhausted means the download cap is used up.
	OutcomeExhausted Outcome = "exhausted"
)

// Valid reports whether an outcome is one the audit log accepts.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeGranted, OutcomeExpired, OutcomeRevoked, OutcomeExhausted:
		return true
	default:
		return false
	}
}

// Link is a share link as the product sees it.
type Link struct {
	ID            string
	TenantID      string
	ReportID      string
	ExpiresAt     *time.Time
	MaxDownloads  *int
	DownloadCount int
	RevokedAt     *time.Time
	CreatedAt     time.Time
	CreatedBy     string
}

// Classify reports what would happen to a download attempt right now.
//
// ⚠ THE DATABASE IS AUTHORITATIVE, NOT THIS.
//
// The real decision is claim_share_download's conditional UPDATE, because a
// download cap has to be checked and consumed in one statement — anything that
// reads state and then acts on it lets two concurrent requests both pass a cap
// of one. This exists for the list view, where an operator wants to see which
// of their links are still live, and for the tests that pin the precedence.
func (l Link) Classify(now time.Time) Outcome {
	// ⚠ Revocation wins over expiry. A revoked link that also expired must
	// report `revoked`: revocation is a deliberate act, and reporting it as an
	// expiry hides that somebody withdrew access on purpose.
	if l.RevokedAt != nil {
		return OutcomeRevoked
	}
	if l.ExpiresAt != nil && !l.ExpiresAt.After(now) {
		return OutcomeExpired
	}
	if l.MaxDownloads != nil && l.DownloadCount >= *l.MaxDownloads {
		return OutcomeExhausted
	}
	return OutcomeGranted
}

// Options are the caller's choices when creating a link.
type Options struct {
	// ExpiresAt is optional. Nil means the link does not expire on its own —
	// permitted, because a link an operator can revoke at any time is a
	// different risk from one that cannot be withdrawn.
	ExpiresAt *time.Time
	// MaxDownloads is optional. Nil means uncapped.
	MaxDownloads *int
}

// MaxLifetime bounds how far ahead an expiry may be set.
//
// A share link is an unauthenticated bearer credential for a document that may
// list every unpatched vulnerability in a customer's estate. One issued with a
// ten-year expiry outlives the person who issued it, the project it describes
// and any memory that it exists.
const MaxLifetime = 90 * 24 * time.Hour

// Validate checks the options against the rules the API enforces.
func (o Options) Validate(now time.Time) error {
	if o.ExpiresAt != nil {
		if !o.ExpiresAt.After(now) {
			return fmt.Errorf("the expiry is in the past")
		}
		if o.ExpiresAt.Sub(now) > MaxLifetime {
			return fmt.Errorf(
				"the expiry is more than %d days out; a share link is an "+
					"unauthenticated credential and must not outlive the reason it "+
					"was issued", int(MaxLifetime.Hours()/24))
		}
	}
	if o.MaxDownloads != nil && *o.MaxDownloads < 1 {
		return fmt.Errorf("the download cap must be at least 1")
	}
	return nil
}
