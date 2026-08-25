package obs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// Every one of these is a real way a secret reaches a log: a wrapped error
// carrying a DSN, an auth header echoed into a message, a token in a struct
// field. docs/05-SECURITY-MODEL.md §7 forbids all of them.
func TestRedactString(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		mustNotHave string
		mustHave    string // context that should survive, for debuggability
	}{
		{
			name:        "postgres dsn keeps host, drops password",
			in:          "dial postgres://axebom:hunter2@db.internal:5432/axebom failed",
			mustNotHave: "hunter2",
			mustHave:    "db.internal:5432",
		},
		{
			name:        "redis url with password",
			in:          "redis://default:s3cr3tp4ss@cache:6379/0",
			mustNotHave: "s3cr3tp4ss",
			mustHave:    "cache:6379",
		},
		{
			name:        "bearer token",
			in:          "upstream rejected Authorization: Bearer eyJabc123def456ghi789",
			mustNotHave: "eyJabc123def456ghi789",
			mustHave:    "upstream rejected",
		},
		{
			name:        "github classic pat",
			in:          "clone failed with token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			mustNotHave: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			mustHave:    "clone failed",
		},
		{
			name:        "github fine-grained pat",
			in:          "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwxyz012345",
			mustNotHave: "qrstuvwxyz012345",
		},
		{
			name:        "aws access key id",
			in:          "using AKIAIOSFODNN7EXAMPLE for s3",
			mustNotHave: "AKIAIOSFODNN7EXAMPLE",
			mustHave:    "for s3",
		},
		{
			name:        "jwt",
			in:          "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			mustNotHave: "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:        "pem private key header",
			in:          "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
			mustNotHave: "BEGIN RSA PRIVATE KEY",
		},
		{
			name:     "ordinary text is untouched",
			in:       "scan completed with 1421 components across 6 engines",
			mustHave: "1421 components",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactString(tt.in)
			if tt.mustNotHave != "" && strings.Contains(got, tt.mustNotHave) {
				t.Errorf("secret survived redaction:\n  in:  %s\n  out: %s\n  found: %q",
					tt.in, got, tt.mustNotHave)
			}
			if tt.mustHave != "" && !strings.Contains(got, tt.mustHave) {
				t.Errorf("useful context was destroyed:\n  in:  %s\n  out: %s\n  want: %q",
					tt.in, got, tt.mustHave)
			}
		})
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{
		"password", "Password", "db_password", "POSTGRES_PASSWORD",
		"secret", "client_secret", "GITHUB_CLIENT_SECRET",
		"token", "refresh_token", "api_key", "apikey",
		"authorization", "cookie", "private_key", "dsn", "signature",
	}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("key %q should be treated as sensitive", k)
		}
	}
	safe := []string{"component_name", "scan_id", "engine", "tenant_id", "status", "count"}
	for _, k := range safe {
		if isSensitiveKey(k) {
			t.Errorf("key %q should NOT be redacted", k)
		}
	}
}

// The handler is where redaction must live: a call site can be added without
// it, a handler cannot be bypassed.
func TestRedactHandlerFiltersMessageAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewRedactHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Error("connection failed to postgres://app:hunter2@db:5432/axebom",
		"password", "hunter2",
		"db_password", "another-secret",
		"github_token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		"component", "lodash",
		"count", 1421,
	)

	out := buf.String()
	for _, leak := range []string{"hunter2", "another-secret", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"} {
		if strings.Contains(out, leak) {
			t.Errorf("secret %q leaked into log output:\n%s", leak, out)
		}
	}

	// Non-secret data must survive, or the logs are useless.
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if rec["component"] != "lodash" {
		t.Errorf("non-secret attr was altered: component = %v", rec["component"])
	}
	if rec["count"] != float64(1421) {
		t.Errorf("non-secret attr was altered: count = %v", rec["count"])
	}
	if !strings.Contains(rec["msg"].(string), "db:5432") {
		t.Errorf("host context destroyed in message: %v", rec["msg"])
	}
}

func TestRedactHandlerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	// Attributes bound via With must be redacted too — they are set once and
	// then attached to every subsequent record.
	logger := slog.New(NewRedactHandler(slog.NewJSONHandler(&buf, nil))).
		With("api_key", "super-secret-value")

	logger.Info("started")

	if strings.Contains(buf.String(), "super-secret-value") {
		t.Errorf("secret bound via With() leaked:\n%s", buf.String())
	}
}

func TestRedactHandlerGroups(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewRedactHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Info("config loaded",
		slog.Group("postgres",
			slog.String("host", "db.internal"),
			slog.String("password", "hunter2"),
		),
	)

	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Errorf("secret inside a group leaked:\n%s", out)
	}
	if !strings.Contains(out, "db.internal") {
		t.Errorf("non-secret group field destroyed:\n%s", out)
	}
}
