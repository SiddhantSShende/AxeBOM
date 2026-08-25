package reportsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func statement() Statement {
	return Statement{
		ReportID:        "0199-report",
		TenantID:        "0199-tenant",
		Format:          "spdx-2.3-json",
		GeneratedAt:     "2026-08-17T09:14:03Z",
		ProfileID:       "certin-v2.0",
		ProfileRevision: 1,
		ToolName:        "AxeBOM",
		ToolVersion:     "0.1.0",
	}
}

func signer(t *testing.T) *LocalSigner {
	t.Helper()
	s, err := NewLocalSigner("test")
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return s
}

func TestAGoodSignatureVerifies(t *testing.T) {
	s := signer(t)
	artifact := []byte(`{"spdxVersion":"SPDX-2.3"}`)

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	result, err := Verify(env, artifact, s.PublicKey())
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if result.Statement.ReportID != "0199-report" {
		t.Errorf("report id = %q", result.Statement.ReportID)
	}
	if result.Statement.SHA256 != Digest(artifact) {
		t.Errorf("the statement's digest does not describe the artifact")
	}
}

// TestAMutatedArtifactFails is the phase requirement.
//
// One byte, in the middle of a large document, is the realistic tamper: an
// attacker who removes a vulnerability from a signed report changes very little.
func TestAMutatedArtifactFails(t *testing.T) {
	s := signer(t)
	artifact := []byte(`{"spdxVersion":"SPDX-2.3","name":"acme-web","packages":[]}`)

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	mutated := bytes.Replace(artifact, []byte("acme-web"), []byte("acme-Web"), 1)
	if bytes.Equal(mutated, artifact) {
		t.Fatal("the mutation did not change the artifact")
	}

	if _, err := Verify(env, mutated, s.PublicKey()); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("a mutated artifact verified, or failed for the wrong reason: %v", err)
	}
}

// TestAMutatedStatementFails — editing the envelope to match a tampered
// artifact must not help.
func TestAMutatedStatementFails(t *testing.T) {
	s := signer(t)
	artifact := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	tampered := []byte(`{"spdxVersion":"SPDX-2.2"}`)

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// The attacker recomputes the digest so the statement describes their file.
	var st Statement
	if err := json.Unmarshal(statementBytes(t, env), &st); err != nil {
		t.Fatalf("re-reading the statement: %v", err)
	}
	st.SHA256 = Digest(tampered)
	st.SizeBytes = int64(len(tampered))
	forged, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("re-serializing: %v", err)
	}
	env.Statement = base64.StdEncoding.EncodeToString(forged)

	// ⚠ THIS IS THE CHECK-ORDER TEST. A verifier that hashed the artifact,
	// compared it to the statement, and only then (or never) checked the
	// signature would pass here.
	if _, err := Verify(env, tampered, s.PublicKey()); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a forged statement verified, or failed for the wrong reason: %v", err)
	}
}

// TestAnotherKeyDoesNotVerify — the basic soundness check.
func TestAnotherKeyDoesNotVerify(t *testing.T) {
	s := signer(t)
	other := signer(t)
	artifact := []byte("report")

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if _, err := Verify(env, artifact, other.PublicKey()); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a foreign key verified the signature: %v", err)
	}
}

// TestTheSignatureIsBoundToTheArtifactKind.
//
// A valid SPDX document and a valid XLSX are both genuinely ours. Without the
// format in the signed statement, the SPDX signature would verify against the
// SPDX bytes no matter which download the user believed they were checking.
// This asserts the format is inside the signed payload, so re-labelling it
// breaks the signature.
func TestTheSignatureIsBoundToTheArtifactKind(t *testing.T) {
	s := signer(t)
	artifact := []byte("report")

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Still valid JSON, so the only thing that can reject it is the signature.
	original := statementBytes(t, env)
	relabelled := bytes.Replace(original,
		[]byte(`"format":"spdx-2.3-json"`), []byte(`"format":"xlsx"`), 1)
	if bytes.Equal(relabelled, original) {
		t.Fatalf("the format is not in the signed statement: %s", original)
	}
	if !json.Valid(relabelled) {
		t.Fatalf("the relabelled statement is not valid JSON: %s", relabelled)
	}
	env.Statement = base64.StdEncoding.EncodeToString(relabelled)

	if _, err := Verify(env, artifact, s.PublicKey()); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("the artifact kind is not covered by the signature: %v", err)
	}
}

// TestDomainSeparation — a signature over the bare statement, without the
// prefix, must not verify. Otherwise a signature this key issues over some
// other structure could be replayed as a report signature.
func TestDomainSeparation(t *testing.T) {
	s := signer(t)
	artifact := []byte("report")

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Sign the same statement bytes WITHOUT the domain prefix.
	bare := ed25519.Sign(s.private, statementBytes(t, env))
	env.Signature = base64.StdEncoding.EncodeToString(bare)

	if _, err := Verify(env, artifact, s.PublicKey()); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a payload without the domain prefix verified: %v", err)
	}
}

// TestAlgorithmIsNotNegotiable — the artifact must not choose how it is
// checked. This is the JWT `alg: none` failure, and it has shipped in real
// products more than once.
func TestAlgorithmIsNotNegotiable(t *testing.T) {
	s := signer(t)
	artifact := []byte("report")

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	for _, alg := range []string{"none", "None", "", "hs256"} {
		bad := env
		bad.Algorithm = alg
		if _, err := Verify(bad, artifact, s.PublicKey()); err == nil {
			t.Errorf("algorithm %q was accepted", alg)
		}
	}
}

// TestADevelopmentSignatureIsNotTrusted.
//
// Verification against a locally generated key is a correct cryptographic
// result and a meaningless assurance. If a development signature reported the
// same clean pass as a production one, an unsigned pipeline would look signed.
func TestADevelopmentSignatureIsNotTrusted(t *testing.T) {
	s := signer(t)
	artifact := []byte("report")

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if !strings.HasPrefix(env.KeyID, DevKeyPrefix) {
		t.Fatalf("a local signature is not marked as one: key id %q", env.KeyID)
	}

	result, err := Verify(env, artifact, s.PublicKey())
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if result.Trusted {
		t.Fatal("a development signature reported itself as trusted")
	}
}

// TestAWrongSizedPublicKeyIsRefused — a truncated or PEM-wrapped key must fail
// loudly rather than silently never matching.
func TestAWrongSizedPublicKeyIsRefused(t *testing.T) {
	s := signer(t)
	artifact := []byte("report")
	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	short := s.PublicKey()[:16]
	_, err = Verify(env, artifact, short)
	if err == nil || errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a malformed key was not reported as such: %v", err)
	}
}

// TestSigningIsDeterministic — Ed25519 is deterministic, so the same statement
// over the same artifact yields the same bytes. That is what makes a re-render
// checkable against a previously issued signature.
func TestSigningIsDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, err := NewLocalSignerFromSeed("test", seed)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	artifact := []byte("report")
	first, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	for i := range 10 {
		again, err := Sign(statement(), artifact, s)
		if err != nil {
			t.Fatalf("signing (iteration %d): %v", i, err)
		}
		if again.Signature != first.Signature {
			t.Fatalf("the signature changed between runs on iteration %d", i)
		}
	}
}

// TestVerifyReaderMatchesVerify — the streaming path is what the CLI uses on a
// 200 MB XLSX, and it must not diverge from the in-memory one.
func TestVerifyReaderMatchesVerify(t *testing.T) {
	s := signer(t)
	artifact := bytes.Repeat([]byte("component,"), 5000)

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if _, err := VerifyReader(env, bytes.NewReader(artifact), s.PublicKey()); err != nil {
		t.Fatalf("streaming verification failed: %v", err)
	}
	if _, err := VerifyReader(env, bytes.NewReader(artifact[:len(artifact)-1]), s.PublicKey()); err == nil {
		t.Fatal("a truncated artifact verified through the streaming path")
	}
}

// TestAnUnknownSchemaIsRefused — a future envelope version must be refused
// rather than parsed as though its fields still mean what they did.
func TestAnUnknownSchemaIsRefused(t *testing.T) {
	s := signer(t)
	artifact := []byte("report")
	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	env.Schema = "axebom.signature/v2"
	if _, err := Verify(env, artifact, s.PublicKey()); err == nil {
		t.Fatal("an unknown envelope schema was accepted")
	}
}

// statementBytes decodes the signed payload for a test that needs to tamper
// with it. Deliberately NOT exported: outside a test, reading the statement
// before the signature has been checked is reading attacker-controlled bytes.
func statementBytes(t *testing.T, env Envelope) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(env.Statement)
	if err != nil {
		t.Fatalf("the statement is not base64: %v", err)
	}
	return raw
}

// TestTheEnvelopeSurvivesReformatting is the regression test for the bug that
// broke every signature the first time a real file was written.
//
// ⚠ THE STATEMENT WAS json.RawMessage AND THE ENVELOPE WAS PRETTY-PRINTED.
// json.MarshalIndent reformats an embedded RawMessage, so the bytes read back
// were not the bytes signed. A perfectly good artifact reported "signature does
// not verify" — indistinguishable from a forgery, and pointing at the wrong
// half of the system.
//
// A signature file is meant to be pretty-printed, copied and round-tripped
// through whatever JSON tooling a customer has, so the envelope has to be
// indifferent to all of it.
func TestTheEnvelopeSurvivesReformatting(t *testing.T) {
	s := signer(t)
	artifact := []byte(`{"spdxVersion":"SPDX-2.3","name":"acme-web"}`)

	env, err := Sign(statement(), artifact, s)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	for _, tc := range []struct {
		name    string
		marshal func(any) ([]byte, error)
	}{
		{"compact", json.Marshal},
		{"indented two spaces", func(v any) ([]byte, error) {
			return json.MarshalIndent(v, "", "  ")
		}},
		{"indented with tabs", func(v any) ([]byte, error) {
			return json.MarshalIndent(v, "", "\t")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.marshal(env)
			if err != nil {
				t.Fatalf("serializing the envelope: %v", err)
			}
			var round Envelope
			if err := json.Unmarshal(data, &round); err != nil {
				t.Fatalf("re-reading the envelope: %v", err)
			}
			if _, err := Verify(round, artifact, s.PublicKey()); err != nil {
				t.Fatalf("a %s envelope no longer verifies: %v", tc.name, err)
			}
		})
	}
}
