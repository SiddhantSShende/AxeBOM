// Package reportsig issues and checks detached Ed25519 signatures over report
// artifacts.
//
// ⚠ IT LIVES IN libs/go-shared BECAUSE THE VERIFICATION PROCEDURE IS PUBLISHED.
//
// A customer must be able to check a report without our software, so the
// envelope, the statement, the domain prefix and the check order are a public
// contract, not a report-service implementation detail. It started inside
// services/report/internal and Go's own internal rule rejected the CLI's
// import — correctly: `axebom verify` is a consumer-facing tool and has no
// business reaching into a service.
//
// ⚠ DETACHED, AND OVER A STATEMENT RATHER THAN OVER THE FILE.
//
// Detached because an embedded signature changes the document: an SPDX file
// with an extra `axebom_signature` key no longer validates against the
// official schema, and a compliance artifact a standard validator rejects is
// worthless however correct its contents are.
//
// Over a statement — a small JSON object naming the artifact and its digest —
// rather than over the bytes directly, because that gives one signature format
// for PDF, XLSX, JSON, SPDX and CycloneDX alike, and because the BINDING is
// then explicit and signed. A signature over raw bytes says "we produced these
// bytes". A signature over the statement says "we produced this artifact, in
// this format, for this report, at this time" — so a valid SPDX document from
// report A cannot be presented as report B's.
//
// See docs/phases/PHASE-09-reports.md step 8.
package reportsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// EnvelopeSchema versions the signature envelope.
const EnvelopeSchema = "axebom.signature/v1"

// domainPrefix separates this signature's payloads from anything else the same
// key might ever sign.
//
// ⚠ CHEAP, AND IT PREVENTS A WHOLE CLASS OF ATTACK. Without domain separation,
// a signature the key issues over some other structure — a share token, an
// attestation, a future envelope version — could be replayed as a report
// signature if the byte patterns ever line up. The prefix makes the two
// message spaces disjoint by construction rather than by convention about how
// the key is used.
//
// It is part of the published verification procedure, not a secret.
var domainPrefix = []byte("axebom.signature/v1\x00")

// Algorithm is the only signature algorithm this package issues or accepts.
//
// One algorithm, not a negotiated field. An envelope carrying `"algorithm":
// "none"` — or any value a verifier switches on — is the classic JWT failure,
// where the artifact chooses how it is checked.
const Algorithm = "ed25519"

// Statement is what actually gets signed.
type Statement struct {
	Schema   string `json:"schema"`
	ReportID string `json:"report_id"`
	TenantID string `json:"tenant_id"`
	// Format is the artifact kind: spdx-2.3-json, cyclonedx-1.6-json, xlsx,
	// json, pdf. Signed, so an XLSX cannot be presented as the SPDX document.
	Format string `json:"format"`
	// SHA256 is the lowercase hex digest of the artifact bytes.
	SHA256 string `json:"sha256"`
	// SizeBytes is belt-and-braces against a truncation that somehow collides;
	// mostly it makes a mismatch legible in the failure message.
	SizeBytes int64 `json:"size_bytes"`
	// GeneratedAt is the SCAN's time, UTC RFC3339 with a literal Z.
	GeneratedAt string `json:"generated_at"`

	ProfileID       string `json:"profile_id"`
	ProfileRevision int    `json:"profile_revision"`
	ToolName        string `json:"tool_name"`
	ToolVersion     string `json:"tool_version"`
}

// Envelope is the detached signature file that ships beside an artifact.
//
// ⚠ IT DOES NOT CARRY THE PUBLIC KEY, DELIBERATELY.
//
// An attacker who can replace the signature can replace an embedded public key
// just as easily, and a verifier that trusts the bundled key then passes every
// forgery. The key comes from the published key material, located by KeyID.
// The temptation is removed by not providing the field.
type Envelope struct {
	Schema string `json:"schema"`

	// Statement is BASE64 of the exact bytes that were signed.
	//
	// ⚠ BASE64, NOT EMBEDDED JSON, AND THIS IS NOT A STYLE CHOICE.
	//
	// It was json.RawMessage first, and every signature broke the moment the
	// envelope was written with json.MarshalIndent: indenting a RawMessage
	// reformats it, so the bytes read back were not the bytes signed. The
	// failure presented as "signature does not verify" on a perfectly good
	// artifact — indistinguishable from a forgery, and pointing at the wrong
	// half of the system.
	//
	// A signature file is meant to be pretty-printed, copied, embedded and
	// round-tripped through whatever JSON tooling a customer has. Base64 makes
	// the signed bytes opaque to all of it. The cost is that the file is no
	// longer human-readable; `axebom verify` prints the statement after
	// checking it, which is the only point at which reading it means anything.
	Statement string `json:"statement"`

	Algorithm string `json:"algorithm"`
	// KeyID names the key and version, e.g. `axebom-report-signing:v2`.
	KeyID string `json:"key_id"`
	// Signature is base64 of the raw Ed25519 signature.
	Signature string `json:"signature"`
}

// DevKeyPrefix marks a key that is not the production signing key.
//
// ⚠ A DEVELOPMENT SIGNATURE MUST NEVER READ AS A PRODUCTION ONE. Verification
// against a locally generated key is a correct cryptographic result and a
// meaningless assurance; the verifier says so out loud rather than printing the
// same "signature valid" as a real check.
const DevKeyPrefix = "insecure-local:"

// Signer produces a raw Ed25519 signature over a payload.
//
// The interface exists so the report service depends on "something that signs"
// rather than on Vault. The production implementation holds no key material at
// all — see VaultSigner.
type Signer interface {
	// SignPayload signs the payload and returns the signature and the key id
	// that produced it.
	SignPayload(payload []byte) (signature []byte, keyID string, err error)
}

// Sign builds a detached signature for an artifact.
func Sign(s Statement, artifact []byte, signer Signer) (Envelope, error) {
	if s.ReportID == "" || s.Format == "" {
		return Envelope{}, errors.New("a statement needs a report id and a format")
	}

	s.Schema = EnvelopeSchema
	s.SHA256 = Digest(artifact)
	s.SizeBytes = int64(len(artifact))

	statement, err := json.Marshal(s)
	if err != nil {
		return Envelope{}, fmt.Errorf("serializing the statement: %w", err)
	}

	signature, keyID, err := signer.SignPayload(payload(statement))
	if err != nil {
		return Envelope{}, fmt.Errorf("signing: %w", err)
	}

	return Envelope{
		Schema:    EnvelopeSchema,
		Statement: base64.StdEncoding.EncodeToString(statement),
		Algorithm: Algorithm,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// payload is the exact byte string the signature covers.
func payload(statement []byte) []byte {
	out := make([]byte, 0, len(domainPrefix)+len(statement))
	out = append(out, domainPrefix...)
	return append(out, statement...)
}

// Digest is the lowercase hex SHA-256 of the artifact.
func Digest(artifact []byte) string {
	sum := sha256.Sum256(artifact)
	return hex.EncodeToString(sum[:])
}

// DigestReader streams the digest, for an artifact too large to hold.
func DigestReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Result describes a successful verification.
type Result struct {
	Statement Statement
	KeyID     string
	// Trusted is false when the signature was issued by a development key.
	// A caller that prints "signature valid" without consulting this is
	// reporting a meaningless assurance as a real one.
	Trusted bool
}

// Verify checks a detached signature against an artifact.
//
// ⚠ THE ORDER OF THESE CHECKS IS THE SECURITY PROPERTY.
//
// The signature is verified FIRST, over the statement bytes as they arrived.
// Only then is the statement parsed and its digest compared to the artifact.
// A verifier that computes the digest, compares it to the statement, and then
// forgets the signature check passes on any tampered artifact whose envelope
// was edited to match — which is exactly what an attacker who can modify the
// file can also do.
//
// publicKey is supplied by the CALLER, from published key material. It is never
// read from the envelope.
func Verify(env Envelope, artifact []byte, publicKey ed25519.PublicKey) (Result, error) {
	digest, err := verifyEnvelope(env, publicKey)
	if err != nil {
		return Result{}, err
	}
	return finish(env, digest, Digest(artifact), int64(len(artifact)))
}

// VerifyReader is Verify for an artifact streamed from disk.
func VerifyReader(env Envelope, artifact io.Reader, publicKey ed25519.PublicKey) (Result, error) {
	statement, err := verifyEnvelope(env, publicKey)
	if err != nil {
		return Result{}, err
	}
	digest, size, err := DigestReader(artifact)
	if err != nil {
		return Result{}, fmt.Errorf("reading the artifact: %w", err)
	}
	return finish(env, statement, digest, size)
}

// verifyEnvelope checks the signature and returns the parsed statement.
func verifyEnvelope(env Envelope, publicKey ed25519.PublicKey) (Statement, error) {
	if env.Schema != EnvelopeSchema {
		return Statement{}, fmt.Errorf(
			"signature schema is %q; this verifier understands %q",
			env.Schema, EnvelopeSchema)
	}
	// ⚠ Compared against the constant, never used to select an implementation.
	if env.Algorithm != Algorithm {
		return Statement{}, fmt.Errorf(
			"signature algorithm is %q; only %q is accepted", env.Algorithm, Algorithm)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Statement{}, fmt.Errorf(
			"public key is %d bytes; an Ed25519 key is %d",
			len(publicKey), ed25519.PublicKeySize)
	}

	signature, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return Statement{}, fmt.Errorf("signature is not base64: %w", err)
	}
	statement, err := base64.StdEncoding.DecodeString(env.Statement)
	if err != nil {
		return Statement{}, fmt.Errorf("the statement is not base64: %w", err)
	}

	if !ed25519.Verify(publicKey, payload(statement), signature) {
		return Statement{}, ErrSignatureInvalid
	}

	// ⚠ PARSED ONLY AFTER THE SIGNATURE CHECKS OUT. Until this line the
	// statement is attacker-controlled bytes; nothing in it may influence a
	// decision, including which key or algorithm to use.
	var s Statement
	if err := json.Unmarshal(statement, &s); err != nil {
		return Statement{}, fmt.Errorf("the signed statement is unreadable: %w", err)
	}
	return s, nil
}

// finish compares the signed statement to the artifact in hand.
func finish(env Envelope, s Statement, digest string, size int64) (Result, error) {
	// Constant time is not strictly required for a public digest, but the
	// comparison costs nothing and the habit is the thing that matters.
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(s.SHA256)), []byte(digest)) != 1 {
		return Result{}, fmt.Errorf(
			"%w: the signature covers a different artifact\n  signed:   %s\n  in hand:  %s",
			ErrArtifactMismatch, s.SHA256, digest)
	}
	if s.SizeBytes != size {
		return Result{}, fmt.Errorf(
			"%w: the signature covers %d bytes, the artifact is %d",
			ErrArtifactMismatch, s.SizeBytes, size)
	}

	return Result{
		Statement: s,
		KeyID:     env.KeyID,
		Trusted:   !strings.HasPrefix(env.KeyID, DevKeyPrefix),
	}, nil
}

// ErrSignatureInvalid means the signature does not verify under the given key.
var ErrSignatureInvalid = errors.New("signature does not verify")

// ErrArtifactMismatch means the signature is valid but describes a different
// artifact — the file was replaced after signing, or the wrong file was paired
// with the envelope.
var ErrArtifactMismatch = errors.New("artifact does not match the signature")
