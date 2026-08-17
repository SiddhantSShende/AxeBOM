package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TransitConfig configures the Transit client.
//
// Separate from Config because the Transit mount is a DIFFERENT mount from the
// KV one. Sharing a single Mount field would have the signing calls hit
// `secret/sign/...`, which 404s in a way that reads like a missing key.
type TransitConfig struct {
	Address string
	Token   string
	// Mount is the transit mount point. Defaults to "transit".
	Mount   string
	Timeout time.Duration

	HTTPClient *http.Client
}

// Transit signs with a key that never leaves Vault.
//
// ⚠ THE POINT IS THAT WE CANNOT EXPORT THE PRIVATE KEY.
//
// Signing a compliance artifact with a key held in the application means every
// process that renders a report can also forge one, and a memory disclosure in
// any of them is a permanent compromise with no revocation story. Transit signs
// on Vault's side: the report service sends bytes and receives a signature, and
// a full compromise of the service buys an attacker signatures only for as long
// as its token is valid.
type Transit struct {
	cfg TransitConfig
	hc  *http.Client
}

// NewTransit builds a client. Like New, it does not contact Vault.
func NewTransit(cfg TransitConfig) (*Transit, error) {
	if cfg.Address == "" {
		return nil, errors.New("vault: no address configured")
	}
	if cfg.Token == "" {
		return nil, errors.New("vault: no token configured")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	cfg.Address = strings.TrimRight(cfg.Address, "/")
	return &Transit{cfg: cfg, hc: hc}, nil
}

// TransitSignature is one signature and the key version that produced it.
type TransitSignature struct {
	// Signature is the raw signature bytes, with Vault's `vault:vN:` prefix
	// already stripped.
	Signature []byte
	// KeyVersion is which version of the key signed. Recorded because keys
	// rotate and a signature issued under version 2 does not verify against
	// version 3 — without the version, an old report becomes unverifiable the
	// first time the key is rotated.
	KeyVersion int
}

// Sign signs data with the named Ed25519 key.
//
// ⚠ ED25519 HASHES INTERNALLY, SO THE INPUT IS NOT PRE-HASHED.
//
// Vault's transit sign endpoint takes a `hash_algorithm` for RSA and ECDSA and
// ignores it for Ed25519, which signs the message itself. Sending a SHA-256
// digest as the "message" would still produce a valid signature — over the
// digest — and a verifier following the Ed25519 spec would then fail on the
// real document. Callers pass the bytes they mean to sign.
func (t *Transit) Sign(ctx context.Context, keyName string, data []byte) (TransitSignature, error) {
	if keyName == "" {
		return TransitSignature{}, errors.New("vault: no signing key named")
	}

	body, err := json.Marshal(map[string]any{
		"input": base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return TransitSignature{}, err
	}

	raw, err := t.do(ctx, http.MethodPost,
		fmt.Sprintf("%s/v1/%s/sign/%s", t.cfg.Address, t.cfg.Mount, keyName), body)
	if err != nil {
		return TransitSignature{}, err
	}

	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return TransitSignature{}, fmt.Errorf("vault: unreadable sign response: %w", err)
	}
	return parseVaultSignature(resp.Data.Signature)
}

// parseVaultSignature splits Vault's `vault:v<N>:<base64>` envelope.
func parseVaultSignature(s string) (TransitSignature, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return TransitSignature{}, fmt.Errorf(
			"vault: signature %q is not in the expected vault:v<N>:<base64> form", s)
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
	if err != nil {
		return TransitSignature{}, fmt.Errorf("vault: unreadable key version in %q", s)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return TransitSignature{}, fmt.Errorf("vault: signature is not base64: %w", err)
	}
	return TransitSignature{Signature: sig, KeyVersion: version}, nil
}

// PublicKey reads the public half of a key version.
//
// ⚠ THIS IS WHAT GETS PUBLISHED, and it is the only thing a consumer needs. A
// verifier must NEVER take the public key from the artifact it is checking —
// an attacker who can replace the signature can replace an embedded key just
// as easily, and the check then passes on a forgery.
func (t *Transit) PublicKey(ctx context.Context, keyName string, version int) ([]byte, error) {
	raw, err := t.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/v1/%s/keys/%s", t.cfg.Address, t.cfg.Mount, keyName), nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("vault: unreadable key response: %w", err)
	}
	if resp.Data.Type != "ed25519" {
		return nil, fmt.Errorf(
			"vault: key %q is type %q; report signing requires ed25519",
			keyName, resp.Data.Type)
	}

	if version <= 0 {
		version = resp.Data.LatestVersion
	}
	entry, ok := resp.Data.Keys[strconv.Itoa(version)]
	if !ok {
		return nil, fmt.Errorf("vault: key %q has no version %d", keyName, version)
	}
	key, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("vault: public key is not base64: %w", err)
	}
	return key, nil
}

// do issues one authenticated request. Mirrors Client.do; kept separate so the
// two mounts cannot be confused by a shared helper reading the wrong config.
func (t *Transit) do(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	return vaultRequest(ctx, t.hc, t.cfg.Token, method, url, body)
}
