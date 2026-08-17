package reportsig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/encorebom/encorebom/libs/go-shared/vault"
)

// VaultSigner signs through Vault Transit.
//
// ⚠ IT HOLDS NO KEY MATERIAL. That is the whole design: the report service can
// request a signature for as long as its Vault token is valid, and it can never
// export the key or forge one after its token is revoked. A memory disclosure
// in the renderer leaks reports, not the ability to sign every future report.
type VaultSigner struct {
	transit *vault.Transit
	keyName string
	ctx     context.Context //nolint:containedctx // see below
}

// NewVaultSigner builds a signer for one Transit key.
//
// ⚠ The context is held on the struct because Signer.SignPayload takes none —
// it is the narrow interface the verification code shares, and widening it to
// carry a context would put Vault's shape into the pure crypto path. The
// context is per-render, and a VaultSigner is constructed per render.
func NewVaultSigner(ctx context.Context, transit *vault.Transit, keyName string) (*VaultSigner, error) {
	if transit == nil {
		return nil, fmt.Errorf("no Vault transit client")
	}
	if keyName == "" {
		return nil, fmt.Errorf("no signing key configured")
	}
	return &VaultSigner{transit: transit, keyName: keyName, ctx: ctx}, nil
}

// SignPayload signs through Transit and reports which key version signed.
func (s *VaultSigner) SignPayload(payload []byte) ([]byte, string, error) {
	sig, err := s.transit.Sign(s.ctx, s.keyName, payload)
	if err != nil {
		return nil, "", err
	}
	// ⚠ The VERSION is part of the key id. Keys rotate, and a signature issued
	// under v2 does not verify against v3 — without the version in the id, every
	// previously issued report becomes unverifiable the first time we rotate.
	return sig.Signature, fmt.Sprintf("%s:v%d", s.keyName, sig.KeyVersion), nil
}

// PublicKey returns the published half of the key that signs today.
func (s *VaultSigner) PublicKey() (ed25519.PublicKey, string, error) {
	key, err := s.transit.PublicKey(s.ctx, s.keyName, 0)
	if err != nil {
		return nil, "", err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf(
			"vault returned a %d-byte public key; an Ed25519 key is %d",
			len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), s.keyName, nil
}

// LocalSigner signs with an in-process key.
//
// ⚠ FOR DEVELOPMENT AND TESTS ONLY, AND IT SAYS SO IN EVERY SIGNATURE IT
// ISSUES. Its key id carries DevKeyPrefix, so Verify reports Trusted=false and
// `encorebom verify` prints a warning instead of a clean pass. A development
// signature that was indistinguishable from a production one would be worse
// than no signature at all — it would let an unsigned pipeline look signed.
type LocalSigner struct {
	private ed25519.PrivateKey
	label   string
}

// NewLocalSigner generates a fresh key.
func NewLocalSigner(label string) (*LocalSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if label == "" {
		label = "dev"
	}
	return &LocalSigner{private: priv, label: label}, nil
}

// NewLocalSignerFromSeed builds a deterministic key, for tests that need the
// same signature twice.
func NewLocalSignerFromSeed(label string, seed []byte) (*LocalSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("an Ed25519 seed is %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	if label == "" {
		label = "dev"
	}
	return &LocalSigner{private: ed25519.NewKeyFromSeed(seed), label: label}, nil
}

// SignPayload signs locally.
func (s *LocalSigner) SignPayload(payload []byte) ([]byte, string, error) {
	return ed25519.Sign(s.private, payload), DevKeyPrefix + s.label, nil
}

// PublicKey returns the verifying key.
func (s *LocalSigner) PublicKey() ed25519.PublicKey {
	pub, ok := s.private.Public().(ed25519.PublicKey)
	if !ok {
		// ed25519.PrivateKey.Public always returns ed25519.PublicKey.
		panic("ed25519 private key did not yield an ed25519 public key")
	}
	return pub
}
