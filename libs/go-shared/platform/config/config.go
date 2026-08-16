// Package config loads typed configuration from the environment.
//
// Design rules:
//
//   - Fail fast and legibly. A service that starts with a missing required
//     value and dies later at first use is much harder to diagnose than one
//     that refuses to start with "POSTGRES_PASSWORD is required".
//
//   - Report ALL missing values at once. Discovering them one restart at a time
//     is a miserable way to configure thirteen services.
//
//   - Secrets are values, not printed. String() redacts them; see obs.
//
// No external dependency: the whole loader is ~200 lines and a config library
// would be one more thing to keep pinned across thirteen deployables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Loader accumulates lookup errors so every problem is reported in one pass.
type Loader struct {
	prefix  string
	missing []string
	invalid []string
}

// New returns a Loader. prefix is optional and applied to every key.
func New(prefix string) *Loader { return &Loader{prefix: prefix} }

func (l *Loader) key(name string) string {
	if l.prefix == "" {
		return name
	}
	return l.prefix + "_" + name
}

// Err returns a single error describing every missing or invalid value, or nil.
func (l *Loader) Err() error {
	if len(l.missing) == 0 && len(l.invalid) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("configuration error:")
	if len(l.missing) > 0 {
		fmt.Fprintf(&b, "\n  missing required: %s", strings.Join(l.missing, ", "))
	}
	if len(l.invalid) > 0 {
		fmt.Fprintf(&b, "\n  invalid: %s", strings.Join(l.invalid, ", "))
	}
	b.WriteString("\n  see .env.example for the full template")
	return fmt.Errorf("%s", b.String())
}

// String reads a required string.
func (l *Loader) String(name string) string {
	v := os.Getenv(l.key(name))
	if v == "" {
		l.missing = append(l.missing, l.key(name))
	}
	return v
}

// StringOr reads an optional string with a default.
func (l *Loader) StringOr(name, def string) string {
	if v := os.Getenv(l.key(name)); v != "" {
		return v
	}
	return def
}

// Secret reads a required secret. Identical to String at load time; the
// distinction exists so callers can wrap the value in a Secret type and keep it
// out of logs and error messages.
func (l *Loader) Secret(name string) Secret {
	return Secret(l.String(name))
}

// SecretOr reads an optional secret with a default. Use only for development
// defaults; production secrets come from Vault.
func (l *Loader) SecretOr(name, def string) Secret {
	return Secret(l.StringOr(name, def))
}

// Int reads an optional int with a default.
func (l *Loader) Int(name string, def int) int {
	raw := os.Getenv(l.key(name))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		l.invalid = append(l.invalid, fmt.Sprintf("%s (not an integer: %q)", l.key(name), raw))
		return def
	}
	return v
}

// Bool reads an optional bool with a default. Accepts 1/t/T/TRUE/true/True etc.
func (l *Loader) Bool(name string, def bool) bool {
	raw := os.Getenv(l.key(name))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		l.invalid = append(l.invalid, fmt.Sprintf("%s (not a boolean: %q)", l.key(name), raw))
		return def
	}
	return v
}

// Duration reads an optional duration with a default, e.g. "15m", "720h".
func (l *Loader) Duration(name string, def time.Duration) time.Duration {
	raw := os.Getenv(l.key(name))
	if raw == "" {
		return def
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		l.invalid = append(l.invalid, fmt.Sprintf("%s (not a duration: %q)", l.key(name), raw))
		return def
	}
	return v
}

// Enum reads an optional value constrained to a set. An out-of-set value is an
// error rather than a silent fallback — silently ignoring a typo'd
// SANDBOX_NETWORK would be a security problem, not a cosmetic one.
func (l *Loader) Enum(name string, allowed []string, def string) string {
	raw := os.Getenv(l.key(name))
	if raw == "" {
		return def
	}
	for _, a := range allowed {
		if raw == a {
			return raw
		}
	}
	l.invalid = append(l.invalid,
		fmt.Sprintf("%s (%q not in [%s])", l.key(name), raw, strings.Join(allowed, ", ")))
	return def
}

// Secret is a string that does not render in logs, errors, or printf output.
//
// Go's fmt calls String() for %v and %s, and encoding/json calls MarshalJSON,
// so the redaction holds across every accidental path a secret usually escapes
// through. Reveal() is deliberately verbose at the call site.
type Secret string

func (s Secret) String() string { return "[REDACTED]" }

// GoString covers %#v.
func (s Secret) GoString() string { return "[REDACTED]" }

// MarshalJSON covers structured logging and any accidental serialization.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// Reveal returns the underlying value. Call this only where the secret is used.
func (s Secret) Reveal() string { return string(s) }

// IsSet reports whether a secret has a value.
func (s Secret) IsSet() bool { return string(s) != "" }
