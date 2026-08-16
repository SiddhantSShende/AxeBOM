package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing with argon2id.
//
// argon2id is MEMORY-hard, which is the property that matters: bcrypt and
// PBKDF2 are only CPU-hard, and a GPU or ASIC parallelises them cheaply.
// Forcing an attacker to allocate real memory per guess is what makes an
// offline crack of a leaked hash expensive.
//
// The encoded form carries its own parameters, so raising them later does not
// invalidate existing hashes — old ones verify with their recorded parameters
// and are rehashed on next successful login (see NeedsRehash).

// Argon2Params are the cost parameters.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params follows the OWASP Password Storage Cheat Sheet's
// argon2id recommendation: 19 MiB, 2 iterations, 1 degree of parallelism.
//
// 19 MiB looks small next to "more is better" advice, but it is a deliberate
// trade: at 2 iterations it costs roughly 50 ms per hash, and a login endpoint
// that takes 500 ms is itself a denial-of-service vector.
func DefaultArgon2Params() Argon2Params {
	p := Argon2Params{
		Memory:      19 * 1024,
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	if n := runtime.NumCPU(); n > 1 && n < 255 {
		p.Parallelism = uint8(min(n, 4)) //nolint:gosec // bounded above
	}
	return p
}

// ErrPasswordMismatch is returned when verification fails.
//
// Deliberately indistinguishable from "no such user" at the handler layer:
// distinguishing them turns the login endpoint into an account enumerator.
var ErrPasswordMismatch = errors.New("password does not match")

// HashPassword produces a PHC-format argon2id hash:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func HashPassword(password string, p Argon2Params) (string, error) {
	if len(password) == 0 {
		return "", errors.New("refusing to hash an empty password")
	}

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against an encoded hash.
//
// Comparison is constant time. A byte-by-byte compare leaks the correct hash
// through timing.
func VerifyPassword(password, encoded string) error {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// NeedsRehash reports whether a stored hash uses weaker parameters than
// current policy, so it can be upgraded on next successful login — the only
// moment the plaintext is available.
func NeedsRehash(encoded string, current Argon2Params) bool {
	p, _, _, err := decodeHash(encoded)
	if err != nil {
		return true // unparseable: replace it
	}
	return p.Memory < current.Memory ||
		p.Iterations < current.Iterations ||
		p.KeyLength < current.KeyLength
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("not an argon2id hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, errors.New("unreadable argon2 version")
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("unsupported argon2 version %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, errors.New("unreadable argon2 parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, errors.New("unreadable argon2 salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, errors.New("unreadable argon2 hash")
	}

	p.SaltLength = uint32(len(salt)) //nolint:gosec // bounded by the encoded form
	p.KeyLength = uint32(len(key))   //nolint:gosec
	return p, salt, key, nil
}

// DummyVerify burns a comparable amount of CPU when no user exists.
//
// Without it, login timing reveals which emails are registered: a real user
// costs ~50 ms of argon2, a missing one returns instantly. That difference is
// an account enumeration oracle, and it is measurable over the network.
func DummyVerify(p Argon2Params) {
	salt := make([]byte, p.SaltLength)
	_ = argon2.IDKey([]byte("dummy-password-for-constant-time-login"),
		salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}
