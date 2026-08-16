package obs

import (
	"log/slog"
	"regexp"
	"strings"
)

// Redaction keeps secrets out of logs.
//
// docs/05-SECURITY-MODEL.md §7: "nothing secret in an image, a log, an event
// payload, or argv". Logs are the path secrets most often escape through,
// because a wrapped error carrying a DSN gets logged by generic error handling
// that has no idea what it is holding.
//
// The filter runs in the slog handler rather than at call sites. A call site
// will eventually be added without it; a handler cannot be bypassed.
//
// Two independent mechanisms, because either alone has a gap:
//
//   - By KEY: an attribute named "password" is redacted regardless of value.
//   - By VALUE SHAPE: a value that looks like a DSN, bearer token, or private
//     key is redacted regardless of what it is called. This catches the common
//     case of a secret embedded in a free-text error message.

// sensitiveKeys are redacted wherever they appear as an attribute name.
// Matching is case-insensitive and substring-based, so "db_password" and
// "GITHUB_CLIENT_SECRET" both match.
var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"credential", "authorization", "cookie", "session", "private_key",
	"client_secret", "access_key", "refresh", "signature", "jwt",
	"dsn", "connection_string", "conn_str",
}

// sensitiveValuePatterns match secret-shaped values regardless of key name.
var sensitiveValuePatterns = []*regexp.Regexp{
	// URL with embedded credentials: scheme://user:pass@host
	regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/?#\s]+):([^@/?#\s]+)@`),
	// Bearer / token headers
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`),
	// PEM private key blocks
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	// GitHub tokens (ghp_, gho_, ghs_, ghu_, github_pat_)
	regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b`),
	// AWS access key ids
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	// JWT: three base64url segments
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
}

const redacted = "[REDACTED]"

// isSensitiveKey reports whether an attribute name should be redacted wholesale.
func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// RedactString removes secret-shaped substrings from s.
//
// Exported so non-slog paths (CLI output, diagnostics rendered into reports)
// can use the same filter.
func RedactString(s string) string {
	for _, re := range sensitiveValuePatterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			// Preserve the non-secret prefix of a DSN so the log still says
			// which host failed — "postgres://user:[REDACTED]@db:5432" is far
			// more useful for debugging than "[REDACTED]".
			if sub := sensitiveValuePatterns[0].FindStringSubmatch(m); len(sub) == 3 {
				return sub[1] + ":" + redacted + "@"
			}
			return redacted
		})
	}
	return s
}

// redactValue applies redaction to a single slog value, recursing into groups.
func redactValue(v slog.Value) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(RedactString(v.String()))
	case slog.KindGroup:
		attrs := v.Group()
		out := make([]slog.Attr, 0, len(attrs))
		for _, a := range attrs {
			out = append(out, redactAttr(a))
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		// A type with its own String() — e.g. config.Secret — has already
		// redacted itself. Resolve and filter the rendered form anyway, since
		// most Any values are ordinary structs.
		if s, ok := v.Any().(interface{ String() string }); ok {
			return slog.StringValue(RedactString(s.String()))
		}
		return v
	default:
		return v
	}
}

// redactAttr redacts one attribute by key and by value shape.
func redactAttr(a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}
	a.Value = redactValue(a.Value.Resolve())
	return a
}

// redactHandler wraps a slog.Handler and filters every record through the
// redaction rules, including the message body.
type redactHandler struct {
	inner slog.Handler
}

// NewRedactHandler wraps h so nothing secret-shaped reaches the output.
func NewRedactHandler(h slog.Handler) slog.Handler { return &redactHandler{inner: h} }

func (h *redactHandler) Enabled(ctx contextType, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx contextType, r slog.Record) error {
	// The message itself is a common leak path: fmt.Errorf("connect to %s", dsn).
	clean := slog.NewRecord(r.Time, r.Level, RedactString(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, redactAttr(a))
	}
	return &redactHandler{inner: h.inner.WithAttrs(out)}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{inner: h.inner.WithGroup(name)}
}
