package handler

import (
	"net"
	"net/http"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auditexport"
	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/platform/httpx"
)

// ExportAuditLog handles GET /v1/audit-log/export?format=jsonl|csv[&from=&to=].
//
// ⚠ ZITADEL-AUTHENTICATED, like the API-key routes — see apikeys.go's own
// note on why this service has two authenticating wrappers.
func (h *Handler) ExportAuditLog(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	format := auditexport.Format(r.URL.Query().Get("format"))
	if format == "" {
		format = auditexport.FormatJSONL
	}
	if !format.Valid() {
		errs.Write(w, r, errs.Newf(errs.ValidationFieldInvalid,
			"format %q is not supported; want jsonl or csv", format))
		return
	}

	from, err := parseOptionalTime(r.URL.Query().Get("from"))
	if err != nil {
		errs.Write(w, r, errs.New(errs.ValidationFieldInvalid, "from must be an RFC3339 timestamp"))
		return
	}
	to, err := parseOptionalTime(r.URL.Query().Get("to"))
	if err != nil {
		errs.Write(w, r, errs.New(errs.ValidationFieldInvalid, "to must be an RFC3339 timestamp"))
		return
	}

	w.Header().Set("Content-Type", auditContentType(format))
	w.Header().Set("Content-Disposition",
		`attachment; filename="audit-log.`+string(format)+`"`)
	// No caching: an audit export is a point-in-time snapshot of sensitive
	// administrative history, and a cached copy would outlive any access
	// change made after it was taken.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")

	_, err = h.svc.ExportAuditLog(r.Context(), tenantID, format,
		ctxkey.UserID(r.Context()), net.ParseIP(httpx.ClientIP(r)), from, to, w)
	if err != nil {
		// ⚠ HEADERS ARE ALREADY SENT. Like report.Handler.stream, there is no
		// way to turn a mid-export failure into an error response; the client
		// sees a short read, which is what a truncated export looks like —
		// and what it is.
		return
	}
}

func auditContentType(f auditexport.Format) string {
	if f == auditexport.FormatCSV {
		return "text/csv"
	}
	return "application/x-ndjson"
}

func parseOptionalTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil //nolint:nilnil // absent is a valid, distinct answer from "invalid"
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	utc := t.UTC()
	return &utc, nil
}
