// Package email renders notification messages.
//
// ⚠ THE SAME CONFIDENTIALITY RULE AS WEBHOOKS, FOR A DIFFERENT REASON.
//
// A webhook body lands in somebody's log aggregator. An email lands in an
// inbox, is forwarded, is synced to a phone, and passes through at least one
// mail relay in plaintext at the edges. BOM content is confidential under
// CERT-In §5.3, so the message says WHAT HAPPENED and WHERE TO LOOK — counts,
// severities, a link — and never names a component, a version or an advisory.
//
// The one apparent exception proves the rule: a critical-findings email carries
// the NUMBER of criticals, because a notification that cannot convey urgency is
// a notification people turn off. A number is not an inventory.
//
// ⚠ EVERY VALUE IS HTML-ESCAPED BY html/template, AND THAT IS NOT INCIDENTAL.
// A project name is user-controlled, it reaches this template, and an HTML mail
// client will happily render an <img src=x onerror=...> or a link that looks
// like ours and is not. text/template here would be a stored-XSS-by-email.
package email

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	texttemplate "text/template"
	"time"
)

// Kind is a message type.
type Kind string

const (
	// KindScanCompleted reports a finished scan, whatever its terminal status.
	KindScanCompleted Kind = "scan_completed"
	// KindNewCriticalFindings reports criticals a previous scan did not have.
	KindNewCriticalFindings Kind = "new_critical_findings"
	// KindCampaignFailed reports a scheduled run that could not complete.
	KindCampaignFailed Kind = "campaign_failed"
)

// Kinds returns every message this build sends.
func Kinds() []Kind {
	return []Kind{KindScanCompleted, KindNewCriticalFindings, KindCampaignFailed}
}

// Data is everything a template may reference.
//
// ⚠ NO COMPONENT, NO VERSION, NO CVE, NO PURL. There is deliberately nowhere to
// put one: TestEmailDataHasNoPlaceToPutComponentDetail asserts this struct's
// shape, so adding such a field is a visible decision rather than a convenience
// somebody reaches for while writing a template.
type Data struct {
	// ProjectName is shown so a recipient knows which of their projects this
	// is. It is USER-CONTROLLED and escaped by the template.
	ProjectName string
	// CampaignName is set for campaign messages.
	CampaignName string

	// Status is the scan or run status, from the API's vocabulary.
	Status string

	Components int
	Findings   int
	Critical   int
	High       int

	// EnginesUnavailable lets a recipient tell "clean" from "nothing ran".
	// ⚠ The same honesty rule as a report's Engine Coverage section, applied to
	// a one-paragraph email: zero findings from zero engines is not good news.
	EnginesUnavailable int
	// UnavailableEngines names them, because "1 engine unavailable" prompts a
	// question that "dependency-check unavailable" answers. Engine names are
	// OUR identifiers, not customer data.
	UnavailableEngines []string

	// URL is where the detail lives, behind authentication.
	URL string
	// OccurredAt is RFC3339 UTC.
	OccurredAt string

	// Cause is set for a failure message. It is an operator-facing string from
	// our own error taxonomy, never a scanner's raw output — which can contain
	// file paths and source fragments from a customer's repository.
	Cause string
}

// Message is a rendered email.
type Message struct {
	Subject string
	Text    string
	HTML    string
}

// ⚠ BOTH PARTS ARE RENDERED, ALWAYS. A mail client with HTML disabled — which
// in a security-conscious enterprise is the default — would otherwise show an
// empty message. A notification nobody can read is worse than none, because the
// sender believes it arrived.
var subjects = map[Kind]string{
	KindScanCompleted:       "Scan {{.Status}} — {{.ProjectName}}",
	KindNewCriticalFindings: "{{.Critical}} new critical finding(s) — {{.ProjectName}}",
	KindCampaignFailed:      "Scheduled scan failed — {{.CampaignName}}",
}

const textBody = `{{.Heading}}

Project: {{.Data.ProjectName}}
{{if .Data.CampaignName}}Campaign: {{.Data.CampaignName}}
{{end}}Status: {{.Data.Status}}
When: {{.Data.OccurredAt}}
{{if .ShowCounts}}
Components: {{.Data.Components}}
Findings: {{.Data.Findings}} ({{.Data.Critical}} critical, {{.Data.High}} high)
{{end}}{{if .Data.EnginesUnavailable}}
{{.Data.EnginesUnavailable}} engine(s) could not run{{if .Data.UnavailableEngines}}: {{join .Data.UnavailableEngines}}{{end}}.
Findings from the ecosystems those engines cover are NOT included in these numbers.
{{end}}{{if .Data.Cause}}
Cause: {{.Data.Cause}}
{{end}}
Open it: {{.Data.URL}}

--
This message carries no component or vulnerability detail. Sign in to see it.
`

const htmlBody = `<p><strong>{{.Heading}}</strong></p>
<p>
  Project: {{.Data.ProjectName}}<br>
  {{if .Data.CampaignName}}Campaign: {{.Data.CampaignName}}<br>{{end}}
  Status: {{.Data.Status}}<br>
  When: {{.Data.OccurredAt}}
</p>
{{if .ShowCounts}}<p>
  Components: {{.Data.Components}}<br>
  Findings: {{.Data.Findings}} ({{.Data.Critical}} critical, {{.Data.High}} high)
</p>{{end}}
{{if .Data.EnginesUnavailable}}<p>
  <strong>{{.Data.EnginesUnavailable}} engine(s) could not run{{if .Data.UnavailableEngines}}:
  {{join .Data.UnavailableEngines}}{{end}}.</strong><br>
  Findings from the ecosystems those engines cover are <em>not</em> included in these numbers.
</p>{{end}}
{{if .Data.Cause}}<p>Cause: {{.Data.Cause}}</p>{{end}}
<p><a href="{{.Data.URL}}">Open it</a></p>
<hr>
<p><small>This message carries no component or vulnerability detail. Sign in to see it.</small></p>
`

var headings = map[Kind]string{
	KindScanCompleted:       "A scan finished",
	KindNewCriticalFindings: "New critical findings",
	KindCampaignFailed:      "A scheduled scan did not complete",
}

type view struct {
	Heading    string
	Data       Data
	ShowCounts bool
}

var funcs = map[string]any{
	"join": func(s []string) string { return strings.Join(s, ", ") },
}

var (
	textTemplate = texttemplate.Must(
		texttemplate.New("text").Funcs(funcs).Parse(textBody))
	htmlTemplate = template.Must(
		template.New("html").Funcs(template.FuncMap(funcs)).Parse(htmlBody))
)

// Render produces a message.
func Render(kind Kind, data Data) (Message, error) {
	heading, ok := headings[kind]
	if !ok {
		return Message{}, fmt.Errorf("email: %q is not a message this build sends", kind)
	}
	if data.URL == "" {
		// ⚠ THE LINK IS THE ENTIRE POINT. Without it the recipient has a number
		// and no way to act on it, and the design — say what happened, link to
		// the detail — collapses into "say what happened".
		return Message{}, fmt.Errorf("email: %q needs a URL; the body carries no detail without it", kind)
	}
	if data.OccurredAt == "" {
		data.OccurredAt = time.Now().UTC().Format(time.RFC3339)
	}

	v := view{
		Heading: heading,
		Data:    data,
		// A failure message has no counts to show; printing "0 findings" beside
		// "the scan failed" reads as a clean result.
		ShowCounts: kind != KindCampaignFailed,
	}

	subjectTpl, err := texttemplate.New("subject").Parse(subjects[kind])
	if err != nil {
		return Message{}, err
	}

	var subject, text, html bytes.Buffer
	if err := subjectTpl.Execute(&subject, data); err != nil {
		return Message{}, err
	}
	if err := textTemplate.Execute(&text, v); err != nil {
		return Message{}, err
	}
	if err := htmlTemplate.Execute(&html, v); err != nil {
		return Message{}, err
	}

	return Message{
		// A subject line is a header. A project name containing CR or LF would
		// otherwise inject headers into the message — the same defect class as
		// the report service's Content-Disposition filename.
		Subject: sanitizeHeader(subject.String()),
		Text:    text.String(),
		HTML:    html.String(),
	}, nil
}

// sanitizeHeader makes a string safe to use as a header value.
//
// ⚠ HEADER INJECTION. A project named "x\r\nBcc: everyone@example.com" turns a
// notification into a mail relay. Folding whitespace is collapsed rather than
// stripped so the subject stays readable.
func sanitizeHeader(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")

	// RFC 5322 recommends lines under 998 octets; a very long subject is also a
	// sign somebody put content where it does not belong.
	//
	// ⚠ THE BUDGET IS BYTES AND THE CUT IS ON RUNE BOUNDARIES. Cutting a byte
	// slice mid-rune produces a replacement character in the recipient's
	// subject line, and the ellipsis itself is three bytes — so reserving one
	// character rather than three overshoots the limit it was enforcing.
	const maxSubject = 200
	if len(s) <= maxSubject {
		return s
	}

	budget := maxSubject - len(ellipsis)
	var end int
	for i := range s {
		if i > budget {
			break
		}
		end = i
	}
	return s[:end] + ellipsis
}

const ellipsis = "…"
