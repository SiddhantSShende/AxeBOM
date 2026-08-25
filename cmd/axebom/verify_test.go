package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/reportsig"
)

// signedArtifact writes an artifact and its detached signature to a temporary
// directory and returns their paths plus the public key.
func signedArtifact(t *testing.T, body []byte) (artifactPath, sigPath, publicKeyB64 string) {
	t.Helper()

	signer, err := reportsig.NewLocalSigner("cli-test")
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	env, err := reportsig.Sign(reportsig.Statement{
		ReportID:        "0199-report",
		TenantID:        "0199-tenant",
		Format:          "spdx-2.3-json",
		GeneratedAt:     "2026-08-17T09:14:03Z",
		ProfileID:       "certin-v2.0",
		ProfileRevision: 1,
		ToolName:        "AxeBOM",
		ToolVersion:     "0.1.0",
	}, body, signer)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	dir := t.TempDir()
	artifactPath = filepath.Join(dir, "report.spdx.json")
	sigPath = artifactPath + ".sig.json"

	if err := os.WriteFile(artifactPath, body, 0o600); err != nil {
		t.Fatalf("writing the artifact: %v", err)
	}
	envJSON, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("serializing the signature: %v", err)
	}
	if err := os.WriteFile(sigPath, envJSON, 0o600); err != nil {
		t.Fatalf("writing the signature: %v", err)
	}

	return artifactPath, sigPath,
		base64.StdEncoding.EncodeToString(signer.PublicKey())
}

// capture redirects the command's output for the duration of a test.
func capture(t *testing.T) (out, errOut *bytes.Buffer) {
	t.Helper()
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	oldOut, oldErr := stdout, stderr
	stdout, stderr = out, errOut
	t.Cleanup(func() { stdout, stderr = oldOut, oldErr })
	return out, errOut
}

func TestVerifyAcceptsAGoodArtifact(t *testing.T) {
	artifact, _, key := signedArtifact(t, []byte(`{"spdxVersion":"SPDX-2.3"}`))
	out, _ := capture(t)

	// The signature path is left off on purpose: <artifact>.sig.json is the
	// convention a customer receives, and it has to work without a flag.
	if err := runVerify(context.Background(), []string{"-public-key-base64", key, artifact}); err != nil {
		t.Fatalf("a good artifact did not verify: %v", err)
	}

	text := out.String()
	for _, want := range []string{"Signature verified.", "0199-report", "spdx-2.3-json"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output does not mention %q:\n%s", want, text)
		}
	}
}

// TestVerifyRejectsAMutatedArtifact is the phase requirement, exercised the way
// a customer would.
func TestVerifyRejectsAMutatedArtifact(t *testing.T) {
	artifact, _, key := signedArtifact(t, []byte(`{"spdxVersion":"SPDX-2.3","name":"acme"}`))

	// Tamper with the file after it was signed — one byte.
	body, err := os.ReadFile(artifact) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if err := os.WriteFile(artifact, bytes.Replace(body, []byte("acme"), []byte("acmE"), 1), 0o600); err != nil {
		t.Fatalf("tampering: %v", err)
	}

	_, errOut := capture(t)
	err = runVerify(context.Background(), []string{"-public-key-base64", key, artifact})
	if err == nil {
		t.Fatal("a tampered artifact verified")
	}

	var ee exitError
	if !errors.As(err, &ee) || ee.code != 3 {
		t.Fatalf("want exit code 3 for a failed check, got %v", err)
	}

	text := errOut.String()
	if !strings.Contains(text, "VERIFICATION FAILED") {
		t.Errorf("the failure is not stated plainly:\n%s", text)
	}
	// ⚠ The message must tell the reader WHICH failure this is. "Signature
	// invalid" and "this is a different file" call for different responses.
	if !strings.Contains(text, "modified after it was signed") {
		t.Errorf("the failure does not explain what it means:\n%s", text)
	}
}

// TestVerifyRejectsTheWrongKey — and says so differently from a mismatch.
func TestVerifyRejectsTheWrongKey(t *testing.T) {
	artifact, _, _ := signedArtifact(t, []byte("report"))

	other, err := reportsig.NewLocalSigner("attacker")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	wrongKey := base64.StdEncoding.EncodeToString(other.PublicKey())

	_, errOut := capture(t)
	if err := runVerify(context.Background(),
		[]string{"-public-key-base64", wrongKey, artifact}); err == nil {
		t.Fatal("a foreign key verified the signature")
	}
	if !strings.Contains(errOut.String(), "wrong key") {
		t.Errorf("the failure does not suggest checking the key:\n%s", errOut.String())
	}
}

// TestVerifyWarnsOnADevelopmentSignature.
//
// ⚠ THE WHOLE POINT OF THE DevKeyPrefix. A locally signed artifact verifies
// correctly and proves nothing about who produced it. If this printed the same
// clean pass as a production signature, an unsigned pipeline would look signed.
func TestVerifyWarnsOnADevelopmentSignature(t *testing.T) {
	artifact, _, key := signedArtifact(t, []byte("report"))
	out, _ := capture(t)

	if err := runVerify(context.Background(),
		[]string{"-public-key-base64", key, artifact}); err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if !strings.Contains(out.String(), "DEVELOPMENT SIGNATURE") {
		t.Fatalf("a development signature was reported as an ordinary one:\n%s", out.String())
	}
}

// TestVerifyRefusesWithoutAPublicKey.
//
// The key comes from published material, never from the signature file. There
// is no default and no fallback: silently trusting an embedded key would make
// the whole command theatre.
func TestVerifyRefusesWithoutAPublicKey(t *testing.T) {
	artifact, _, _ := signedArtifact(t, []byte("report"))
	capture(t)

	err := runVerify(context.Background(), []string{artifact})
	if err == nil {
		t.Fatal("verification ran with no public key")
	}
	if !strings.Contains(err.Error(), "supplies") && !strings.Contains(err.Error(), "public key") {
		t.Errorf("the error does not explain what is needed: %v", err)
	}

	// It must also not be a "check failed" exit — this is a usage error.
	var ee exitError
	if errors.As(err, &ee) {
		t.Errorf("a missing key reported exit %d; that code means a failed check", ee.code)
	}
}

// TestVerifyDistinguishesAMissingFileFromAFailedCheck.
//
// An operator who learns to ignore exit 1 from a typo learns to ignore a real
// verification failure. The codes have to differ.
func TestVerifyDistinguishesAMissingFileFromAFailedCheck(t *testing.T) {
	_, _, key := signedArtifact(t, []byte("report"))
	capture(t)

	err := runVerify(context.Background(),
		[]string{"-public-key-base64", key, filepath.Join(t.TempDir(), "absent.json")})
	if err == nil {
		t.Fatal("a missing artifact verified")
	}
	var ee exitError
	if errors.As(err, &ee) {
		t.Fatalf("a missing file reported exit %d, the code reserved for a failed check", ee.code)
	}
}

// TestVerifyAcceptsHexOrBase64Keys — a key copied from a web page arrives as
// whichever the reader's tooling produced.
func TestVerifyAcceptsHexOrBase64Keys(t *testing.T) {
	artifact, _, keyB64 := signedArtifact(t, []byte("report"))
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}

	dir := t.TempDir()
	hexPath := filepath.Join(dir, "key.hex")
	if err := os.WriteFile(hexPath, []byte(hexOf(raw)+"\n"), 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}

	capture(t)
	if err := runVerify(context.Background(), []string{"-public-key", hexPath, artifact}); err != nil {
		t.Fatalf("a hex-encoded key was rejected: %v", err)
	}
}

// TestVerifyRefusesAMalformedKey — a truncated or PEM-wrapped key fails loudly
// rather than looking like a forged signature.
func TestVerifyRefusesAMalformedKey(t *testing.T) {
	artifact, _, _ := signedArtifact(t, []byte("report"))
	capture(t)

	err := runVerify(context.Background(),
		[]string{"-public-key-base64", base64.StdEncoding.EncodeToString([]byte("short")), artifact})
	if err == nil {
		t.Fatal("a 5-byte public key was accepted")
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("the error does not name the expected key type: %v", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
