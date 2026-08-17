package share

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTokensAre256BitsAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := range 2000 {
		tok, err := NewToken()
		if err != nil {
			t.Fatalf("generating (iteration %d): %v", i, err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(tok.Reveal())
		if err != nil {
			t.Fatalf("the token is not URL-safe base64: %v", err)
		}
		if len(raw) != TokenBytes {
			t.Fatalf("token carries %d bytes of entropy, want %d", len(raw), TokenBytes)
		}
		if seen[tok.Reveal()] {
			t.Fatalf("a token repeated after %d draws — the source is not random", i)
		}
		seen[tok.Reveal()] = true
	}
}

// TestTokensAreURLSafe — the token travels in a path segment, and a token that
// needs URL-encoding gets mangled by exactly one tool in the chain a customer
// pastes it through.
func TestTokensAreURLSafe(t *testing.T) {
	for range 200 {
		tok, err := NewToken()
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if strings.ContainsAny(tok.Reveal(), "+/=?&#% ") {
			t.Fatalf("token %q contains a character that must be escaped in a URL",
				tok.Reveal())
		}
	}
}

// TestATokenDoesNotPrintItself.
//
// ⚠ A TOKEN REACHES A LOG THROUGH fmt.Sprintf("%v", link) FAR MORE OFTEN THAN
// THROUGH A DELIBERATE LOG LINE. A leaked share token is a working link to a
// document that may list every unpatched vulnerability a customer has.
func TestATokenDoesNotPrintItself(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	for _, rendered := range []string{
		fmt.Sprintf("%v", tok),
		fmt.Sprintf("%s", tok), //nolint:staticcheck // the point IS what the %s verb produces
		fmt.Sprint(tok),
		fmt.Sprintf("%v", struct{ Token Token }{tok}),
	} {
		if strings.Contains(rendered, tok.Reveal()) {
			t.Fatalf("the plaintext token appears in %q", rendered)
		}
	}

	// It must still be reachable deliberately, or the handler cannot return it.
	if tok.Reveal() == "" {
		t.Fatal("Reveal returned nothing")
	}
}

// TestTheHashIsNotTheToken — a database read must not yield a working link.
func TestTheHashIsNotTheToken(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	hash := tok.Hash()
	if hash == tok.Reveal() {
		t.Fatal("the stored hash IS the token")
	}
	if strings.Contains(hash, tok.Reveal()) {
		t.Fatal("the token is recoverable from the stored hash")
	}
	if len(hash) != 64 {
		t.Fatalf("hash is %d characters, want 64 (hex sha256)", len(hash))
	}
	if hash != tok.Hash() {
		t.Fatal("hashing is not deterministic, so a lookup could never match")
	}
}

// TestParseTokenRejectsShapeButNotContent.
//
// Rejecting a well-formed but unknown token here would be a free oracle for an
// unauthenticated endpoint. Rejecting a malformed one costs an attacker nothing
// they did not already know.
func TestParseTokenRejectsShapeButNotContent(t *testing.T) {
	good, err := NewToken()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	if _, err := ParseToken(good.Reveal()); err != nil {
		t.Fatalf("a freshly generated token was rejected: %v", err)
	}

	// A well-formed token that no database row matches must still PARSE — the
	// "does it exist" answer belongs to the lookup, not to the parser.
	other, err := NewToken()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	if _, err := ParseToken(other.Reveal()); err != nil {
		t.Fatalf("an unknown but well-formed token was rejected at parse time: %v", err)
	}

	for _, bad := range []string{
		"", "short", strings.Repeat("a", 42), strings.Repeat("a", 44),
		"................:...........................",
		"AAAA+AAAA/AAAA=AAAAAAAAAAAAAAAAAAAAAAAAAAAA", // standard base64 alphabet
	} {
		if _, err := ParseToken(bad); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("ParseToken(%q) = %v, want ErrMalformedToken", bad, err)
		}
	}
}

// TestRevocationBeatsExpiry.
//
// ⚠ A REVOKED LINK THAT ALSO EXPIRED MUST REPORT `revoked`. Revocation is a
// deliberate act by an operator; reporting it as an expiry hides that somebody
// withdrew access on purpose, which is exactly the fact an incident review
// needs.
func TestRevocationBeatsExpiry(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	link := Link{RevokedAt: &past, ExpiresAt: &past}
	if got := link.Classify(now); got != OutcomeRevoked {
		t.Fatalf("Classify = %q, want %q", got, OutcomeRevoked)
	}
}

func TestClassifyCoversEveryState(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	cap1, cap5 := 1, 5

	tests := []struct {
		name string
		link Link
		want Outcome
	}{
		{"unlimited and unexpiring", Link{}, OutcomeGranted},
		{"within the window", Link{ExpiresAt: &future}, OutcomeGranted},
		{"past the window", Link{ExpiresAt: &past}, OutcomeExpired},
		{"revoked", Link{RevokedAt: &past}, OutcomeRevoked},
		{"under the cap", Link{MaxDownloads: &cap5, DownloadCount: 4}, OutcomeGranted},
		{"at the cap", Link{MaxDownloads: &cap5, DownloadCount: 5}, OutcomeExhausted},
		{"single-use, unused", Link{MaxDownloads: &cap1}, OutcomeGranted},
		{"single-use, used", Link{MaxDownloads: &cap1, DownloadCount: 1}, OutcomeExhausted},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.link.Classify(now); got != tc.want {
				t.Errorf("Classify = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExpiryIsExclusiveAtTheBoundary — a link whose expiry is exactly now is
// expired. The other choice serves one more download than the operator asked
// for, at the one instant nobody tests by hand.
func TestExpiryIsExclusiveAtTheBoundary(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	link := Link{ExpiresAt: &now}
	if got := link.Classify(now); got != OutcomeExpired {
		t.Fatalf("a link expiring exactly now reported %q", got)
	}
}

// TestAnExpiryCannotOutliveItsPurpose — a share link is an unauthenticated
// bearer credential, and one issued for ten years outlives the person who
// issued it and any memory that it exists.
func TestAnExpiryCannotOutliveItsPurpose(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

	ok := now.Add(MaxLifetime - time.Minute)
	if err := (Options{ExpiresAt: &ok}).Validate(now); err != nil {
		t.Errorf("an expiry inside the limit was rejected: %v", err)
	}

	tooFar := now.Add(MaxLifetime + time.Hour)
	if err := (Options{ExpiresAt: &tooFar}).Validate(now); err == nil {
		t.Error("an expiry beyond the maximum lifetime was accepted")
	}

	past := now.Add(-time.Second)
	if err := (Options{ExpiresAt: &past}).Validate(now); err == nil {
		t.Error("an expiry in the past was accepted")
	}

	zero := 0
	if err := (Options{MaxDownloads: &zero}).Validate(now); err == nil {
		t.Error("a download cap of zero was accepted; it can never serve anything")
	}

	// No expiry and no cap is PERMITTED. A link an operator can revoke at any
	// time is a different risk from one that cannot be withdrawn, and forcing
	// an expiry here would push people to set an absurd one.
	if err := (Options{}).Validate(now); err != nil {
		t.Errorf("an unlimited link was rejected: %v", err)
	}
}

func TestOnlyKnownOutcomesAreValid(t *testing.T) {
	for _, o := range []Outcome{OutcomeGranted, OutcomeExpired, OutcomeRevoked, OutcomeExhausted} {
		if !o.Valid() {
			t.Errorf("%q is not accepted by its own validator", o)
		}
	}
	// The audit table has a CHECK constraint on these values; an outcome that
	// passes here and fails there would lose the audit row for a real download.
	for _, o := range []Outcome{"", "ok", "GRANTED", "denied"} {
		if o.Valid() {
			t.Errorf("%q was accepted", o)
		}
	}
}

func TestEqualHashIsCaseInsensitiveAndExact(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	h := tok.Hash()

	if !EqualHash(h, strings.ToUpper(h)) {
		t.Error("hex case defeated the comparison; a stored uppercase hash would " +
			"never match and the link would silently 404")
	}
	if EqualHash(h, h[:len(h)-1]+"0") {
		t.Error("a different hash compared equal")
	}
}
