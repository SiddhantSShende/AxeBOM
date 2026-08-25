// Package mail sends the messages email.Render produces.
//
// ⚠ BOTH PARTS, ALWAYS — MATCHING email.Message's OWN RULE. A recipient whose
// mail client prefers plain text (a security-conscious enterprise default)
// must not see an empty body just because this sender only wired the HTML
// part. multipart/alternative is what lets the client pick.
package mail

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/smtp"
	"net/textproto"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/notification/internal/email"
)

// Config is the SMTP connection this sender uses.
//
// ⚠ USERNAME EMPTY MEANS NO AUTH, NOT A CONFIGURATION ERROR. Mailpit — this
// repo's own dev target — accepts unauthenticated mail; sending an empty-
// password AUTH PLAIN to it or to a real relay that also allows anonymous
// submission would be answered with a rejection neither expects.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Sender delivers rendered messages over SMTP.
type Sender struct {
	cfg Config
	now func() time.Time
	// send is swapped in tests; production always uses smtp.SendMail.
	send func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

// New builds a Sender.
func New(cfg Config, now func() time.Time) *Sender {
	if now == nil {
		now = time.Now
	}
	return &Sender{cfg: cfg, now: now, send: smtp.SendMail}
}

// Send delivers one message to one recipient.
//
// ⚠ ONE RECIPIENT, NEVER A LIST. A notification subscription belongs to one
// tenant with one target address; a Bcc/Cc field here would be a way for a
// stored value nobody validated as a single address to become a mailing list.
func (s *Sender) Send(ctx context.Context, to string, msg email.Message) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}

	body, err := encode(s.cfg.From, to, msg, s.now())
	if err != nil {
		return errs.Wrap(err, errs.InternalUnexpected, "the notification email could not be built")
	}

	// net/smtp.SendMail has no context parameter — it is a synchronous dial,
	// so the caller's own timeout (the worker's per-attempt budget) is what
	// bounds this, the same way delivery.Client bounds a webhook POST with
	// its http.Client's Timeout rather than a context deadline.
	_ = ctx
	if err := s.send(addr, auth, s.cfg.From, []string{to}, body); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}

// encode builds a multipart/alternative RFC 5322 message.
//
// ⚠ HEADERS COME FROM email.Message, WHICH ALREADY SANITIZED THE SUBJECT
// (sanitizeHeader strips CR/LF/NUL). from/to are validated at subscription
// creation (subscription.validateEmail) and at config load, never here — this
// function does not re-defend against header injection because both of its
// string inputs already passed through a layer that does.
func encode(from, to string, msg email.Message, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + to + "\r\n")
	buf.WriteString("Subject: " + msg.Subject + "\r\n")
	buf.WriteString("Date: " + now.UTC().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")

	w := multipart.NewWriter(&buf)
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", w.Boundary())

	textPart, err := w.CreatePart(partHeader("text/plain; charset=utf-8"))
	if err != nil {
		return nil, err
	}
	if _, err := textPart.Write([]byte(msg.Text)); err != nil {
		return nil, err
	}

	htmlPart, err := w.CreatePart(partHeader("text/html; charset=utf-8"))
	if err != nil {
		return nil, err
	}
	if _, err := htmlPart.Write([]byte(msg.HTML)); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func partHeader(contentType string) textproto.MIMEHeader {
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", contentType)
	h.Set("Content-Transfer-Encoding", "8bit")
	return h
}
