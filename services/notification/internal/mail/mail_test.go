package mail

import (
	"context"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/axebom/axebom/services/notification/internal/email"
)

var now = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestSendBuildsAMultipartMessageWithBothParts(t *testing.T) {
	var gotAddr, gotFrom string
	var gotTo []string
	var gotAuth smtp.Auth
	var gotMsg []byte

	s := New(Config{Host: "mailpit", Port: 1025, From: "noreply@axebom.test"}, func() time.Time { return now })
	s.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		gotAddr, gotAuth, gotFrom, gotTo, gotMsg = addr, auth, from, to, msg
		return nil
	}

	msg := email.Message{Subject: "Scan completed — payments-api", Text: "plain body", HTML: "<p>html body</p>"}
	if err := s.Send(context.Background(), "alice@acme.test", msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	if gotAddr != "mailpit:1025" {
		t.Errorf("addr = %q", gotAddr)
	}
	if gotAuth != nil {
		t.Error("auth should be nil when no username is configured — an empty-password AUTH would be rejected")
	}
	if gotFrom != "noreply@axebom.test" {
		t.Errorf("from = %q", gotFrom)
	}
	if len(gotTo) != 1 || gotTo[0] != "alice@acme.test" {
		t.Errorf("to = %v, want exactly one recipient", gotTo)
	}

	body := string(gotMsg)
	for _, want := range []string{
		"From: noreply@axebom.test", "To: alice@acme.test",
		"Subject: Scan completed — payments-api",
		"Content-Type: multipart/alternative",
		"plain body", "<p>html body</p>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("message does not contain %q:\n%s", want, body)
		}
	}
}

func TestSendUsesPlainAuthWhenCredentialsAreConfigured(t *testing.T) {
	var gotAuth smtp.Auth
	s := New(Config{Host: "smtp.example.com", Port: 587, Username: "svc", Password: "secret", From: "a@b.test"},
		func() time.Time { return now })
	s.send = func(_ string, auth smtp.Auth, _ string, _ []string, _ []byte) error {
		gotAuth = auth
		return nil
	}
	if err := s.Send(context.Background(), "c@d.test", email.Message{Subject: "s", Text: "t", HTML: "h"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotAuth == nil {
		t.Error("expected PLAIN auth when a username is configured")
	}
}
