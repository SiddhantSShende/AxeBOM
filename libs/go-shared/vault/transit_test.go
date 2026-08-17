package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTransit is a Vault Transit mount that signs for real.
//
// ⚠ IT USES A REAL Ed25519 KEY, not a canned signature. A fake that returned a
// fixed string would let the client pass while sending Vault the wrong bytes —
// and "what exactly gets signed" is the one thing this client must get right.
type fakeTransit struct {
	t       *testing.T
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	// signed records the bytes Vault was asked to sign.
	signed  []byte
	version int
	keyType string
}

func newFakeTransit(t *testing.T) (*fakeTransit, *httptest.Server) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	f := &fakeTransit{t: t, private: priv, public: pub, version: 3, keyType: "ed25519"}
	return f, httptest.NewServer(f)
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/transit/sign/"):
		var body struct {
			Input string `json:"input"`
			// Recorded so the test can assert we do NOT ask Vault to prehash.
			Prehashed     bool   `json:"prehashed"`
			HashAlgorithm string `json:"hash_algorithm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		input, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.signed = input
		sig := ed25519.Sign(f.private, input)
		writeJSON(w, map[string]any{"data": map[string]any{
			"signature": "vault:v" + itoa(f.version) + ":" +
				base64.StdEncoding.EncodeToString(sig),
		}})

	case strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		writeJSON(w, map[string]any{"data": map[string]any{
			"type":           f.keyType,
			"latest_version": f.version,
			"keys": map[string]any{
				itoa(f.version): map[string]any{
					"public_key": base64.StdEncoding.EncodeToString(f.public),
				},
			},
		}})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func transitClient(t *testing.T, addr string) *Transit {
	t.Helper()
	tr, err := NewTransit(TransitConfig{Address: addr, Token: "test-token"})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}
	return tr
}

// TestSignSendsTheMessageItself, not a digest.
//
// ⚠ THE TRAP THIS GUARDS. Vault's transit sign endpoint takes a hash_algorithm
// for RSA and ECDSA and ignores it for Ed25519, which hashes internally.
// Sending SHA-256 of the message would still produce a VALID signature — over
// the digest — and every verifier following the Ed25519 spec would then reject
// the real document. The failure appears only at a customer's verification
// step, long after ours passed.
func TestSignSendsTheMessageItself(t *testing.T) {
	fake, srv := newFakeTransit(t)
	defer srv.Close()

	message := []byte("encorebom.signature/v1\x00{\"report_id\":\"x\"}")
	sig, err := transitClient(t, srv.URL).Sign(context.Background(), "report-signing", message)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if string(fake.signed) != string(message) {
		t.Fatalf("Vault was asked to sign different bytes:\n  sent: %q\n  want: %q",
			fake.signed, message)
	}
	if !ed25519.Verify(fake.public, message, sig.Signature) {
		t.Fatal("the returned signature does not verify over the message")
	}
	if sig.KeyVersion != 3 {
		t.Errorf("key version = %d, want 3 — a signature issued under one version "+
			"does not verify against another, so the version has to travel with it",
			sig.KeyVersion)
	}
}

// TestPublicKeyReadsTheRequestedVersion.
func TestPublicKeyReadsTheRequestedVersion(t *testing.T) {
	fake, srv := newFakeTransit(t)
	defer srv.Close()
	tr := transitClient(t, srv.URL)

	key, err := tr.PublicKey(context.Background(), "report-signing", 0)
	if err != nil {
		t.Fatalf("reading the latest key: %v", err)
	}
	if string(key) != string(fake.public) {
		t.Fatal("the wrong public key came back")
	}

	if _, err := tr.PublicKey(context.Background(), "report-signing", 99); err == nil {
		t.Fatal("a version that does not exist was accepted")
	}
}

// TestANonEd25519KeyIsRefused.
//
// A transit mount can hold RSA and ECDSA keys, and pointing the report signer
// at one would produce signatures nothing in the published verification
// procedure can check. Better to fail at configuration than at a customer's
// verification step.
func TestANonEd25519KeyIsRefused(t *testing.T) {
	fake, srv := newFakeTransit(t)
	defer srv.Close()
	fake.keyType = "rsa-4096"

	_, err := transitClient(t, srv.URL).PublicKey(context.Background(), "report-signing", 0)
	if err == nil {
		t.Fatal("an RSA key was accepted for report signing")
	}
	if !strings.Contains(err.Error(), "ed25519") {
		t.Errorf("the error does not say what is required: %v", err)
	}
}

// TestAMalformedSignatureEnvelopeIsRefused — Vault's `vault:vN:base64` wrapper
// is parsed, not assumed.
func TestAMalformedSignatureEnvelopeIsRefused(t *testing.T) {
	for _, s := range []string{
		"", "not-a-signature", "vault:v:abc", "vault:vX:abc",
		"vault:v1:!!!notbase64", "other:v1:YWJj",
	} {
		if _, err := parseVaultSignature(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

// TestTransitNeedsAnAddressAndAToken — construction fails closed rather than
// producing a client that 403s on every call.
func TestTransitNeedsAnAddressAndAToken(t *testing.T) {
	if _, err := NewTransit(TransitConfig{Token: "t"}); err == nil {
		t.Error("a client with no address was built")
	}
	if _, err := NewTransit(TransitConfig{Address: "http://x"}); err == nil {
		t.Error("a client with no token was built")
	}
}

// TestTransitDefaultsToTheTransitMount — and NOT to the KV mount, which is
// the confusion a shared Config field would have caused.
func TestTransitDefaultsToTheTransitMount(t *testing.T) {
	tr, err := NewTransit(TransitConfig{Address: "http://x", Token: "t"})
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	if tr.cfg.Mount != "transit" {
		t.Errorf("mount = %q, want \"transit\"", tr.cfg.Mount)
	}
}

// TestVaultErrorsDoNotEchoThePath — the shared request helper drops Vault's
// response text, because it travels into logs and a secret path in a log is a
// map for whoever reads it.
func TestVaultErrorsDoNotEchoThePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["1 error occurred: * encorebom/tenants/acme/repo-token/x"]}`))
	}))
	defer srv.Close()

	_, err := transitClient(t, srv.URL).Sign(context.Background(), "k", []byte("x"))
	if err == nil {
		t.Fatal("a 400 was not reported as an error")
	}
	if strings.Contains(err.Error(), "encorebom/tenants") {
		t.Fatalf("the error echoes a secret path: %v", err)
	}
}
