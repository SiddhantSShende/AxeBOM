// Package handler is the report service's HTTP surface.
//
// Handlers translate; the rules live in internal/service and internal/store.
// Two things they own outright:
//
//   - The tenant, which comes from auth.RequireTenant — the VERIFIED token in
//     the context and nothing else. A report id in a path is never enough to
//     identify a resource; it is always (tenant, id).
//   - The DOWNLOAD DECISION, which is not a plain matrix cell. CERT-In §5.3.2
//     requires both a public report and a private one carrying vulnerability
//     detail, and a Viewer may have only the public one. That depends on the
//     row, so the middleware cannot decide it — see Download.
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/authz"
	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/libs/go-shared/platform/httpx"
	"github.com/encorebom/encorebom/services/report/internal/service"
	"github.com/encorebom/encorebom/services/report/internal/share"
	"github.com/encorebom/encorebom/services/report/internal/store"
)

// Handler serves the report endpoints.
type Handler struct {
	svc *service.Service
	now func() time.Time
}

// New builds a handler. A nil clock uses time.Now.
func New(svc *service.Service, now func() time.Time) *Handler {
	if now == nil {
		now = time.Now
	}
	return &Handler{svc: svc, now: now}
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type reportResponse struct {
	ID       string `json:"id"`
	ScanID   string `json:"scan_id"`
	BOMType  string `json:"bom_type"`
	Level    string `json:"level"`
	Standard string `json:"standard"`
	Format   string `json:"format"`

	Visibility string `json:"visibility"`
	Status     string `json:"status"`

	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`

	SigningKeyID string `json:"signing_key_id,omitempty"`

	Truncated      bool   `json:"truncated"`
	TruncationNote string `json:"truncation_note,omitempty"`

	ErrorCode string `json:"error_code,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// toResponse maps a stored report to the wire.
//
// ⚠ storage_ref IS NOT EXPOSED. It is an object-store key, and a client that
// learns the key naming scheme learns how to guess at other tenants' keys.
// Downloads go through this service, which re-checks the tenant every time.
func toResponse(r store.Report) reportResponse {
	return reportResponse{
		ID:             r.ID,
		ScanID:         r.ScanID,
		BOMType:        r.BOMType,
		Level:          r.Level,
		Standard:       r.Standard,
		Format:         r.Format,
		Visibility:     r.Visibility,
		Status:         string(r.Status),
		SHA256:         r.SHA256,
		SizeBytes:      r.SizeBytes,
		SigningKeyID:   r.SigningKeyID,
		Truncated:      r.Truncated,
		TruncationNote: r.TruncationNote,
		ErrorCode:      r.ErrorCode,
		CreatedAt:      r.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      r.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

// Create queues a render.
//
// ⚠ IT RETURNS 202, NOT 200, AND THAT IS THE CONTRACT NOT A DETAIL. A Complete
// BOM can exceed 50k components; rendering it inline would time out, the client
// would retry, and the worker would render it twice. The response carries the
// report id and `status: queued`.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		ScanID         string   `json:"scan_id"`
		BOMDocumentIDs []string `json:"bom_document_ids"`
		BOMType        string   `json:"bom_type"`
		Level          string   `json:"level"`
		Standard       string   `json:"standard"`
		Format         string   `json:"format"`
		Visibility     string   `json:"visibility"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	report, err := h.svc.Queue(r.Context(), service.QueueRequest{
		TenantID:       tenantID,
		ScanID:         req.ScanID,
		BOMDocumentIDs: req.BOMDocumentIDs,
		BOMType:        req.BOMType,
		Level:          req.Level,
		Standard:       req.Standard,
		Format:         req.Format,
		Visibility:     req.Visibility,
	})
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	errs.WriteJSON(w, http.StatusAccepted, toResponse(report))
}

// Get returns one report's metadata.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	report, err := h.svc.Get(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, toResponse(report))
}

// List returns a tenant's reports.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	reports, err := h.svc.List(r.Context(), tenantID,
		r.URL.Query().Get("scan_id"), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]reportResponse, 0, len(reports))
	for _, rep := range reports {
		out = append(out, toResponse(rep))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"reports": out})
}

// Download streams a rendered artifact.
//
// ⚠ THE PERMISSION CHECK HERE IS NOT THE ONE THE MIDDLEWARE DID.
//
// The route is guarded by (report, download), which every role from Viewer up
// holds. But CERT-In §5.3.2 requires maintaining a public report and a private
// one containing vulnerability detail, and a Viewer may have only the public
// one. That is a decision about the ROW, so it cannot be made before the row is
// read. authz.CanDownloadReport is the single place that rule lives.
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	report, err := h.svc.Get(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	role := authz.Role(ctxkey.Role(r.Context()))
	if d := authz.CanDownloadReport(role, authz.ReportVisibility(report.Visibility)); !d.Allowed {
		// 403 and not 404: the caller is authenticated inside the owning tenant
		// and already knows the report exists — Get answered. Hiding it now
		// would be theatre, and the reason is something they can act on by
		// asking for a role.
		errs.Write(w, r, errs.New(errs.PermReportPrivate, d.Reason))
		return
	}

	h.stream(w, r, report)
}

// stream writes an artifact's bytes with the headers a download needs.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request, report store.Report) {
	if report.Status != store.StatusReady {
		errs.Write(w, r, errs.Newf(errs.ReportRenderFailed,
			"this report is %s, not ready to download", report.Status))
		return
	}

	body, err := h.svc.Open(r.Context(), report)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	defer func() { _ = body.Close() }()

	writeDownloadHeaders(w, report)
	if _, err := io.Copy(w, body); err != nil {
		// The status and headers are already sent, so there is no way to turn
		// this into an error response. The client sees a short read, which is
		// what a truncated download looks like — and what it is.
		return
	}
}

// writeDownloadHeaders sets the headers every artifact response carries.
//
// ⚠ `attachment` AND `nosniff` TOGETHER, ALWAYS.
//
// A report is attacker-influenced content served from our origin. Without
// `Content-Disposition: attachment` a browser renders it inline, and an HTML
// payload smuggled into a component description becomes stored XSS against the
// customer's own session. `X-Content-Type-Options: nosniff` closes the other
// half, where a browser ignores our content type and sniffs the bytes.
func writeDownloadHeaders(w http.ResponseWriter, report store.Report) {
	w.Header().Set("Content-Type", mediaType(report.Format))
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", filename(report)))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// No caching. A shared or revoked report must not survive in a proxy or a
	// browser cache after access is withdrawn — revocation that only applies to
	// the next cold request is not revocation.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")

	if report.SizeBytes > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(report.SizeBytes, 10))
	}
	// The digest lets a client verify without the signature, and it is the
	// value the detached signature also covers.
	if report.SHA256 != "" {
		w.Header().Set("X-EncoreBOM-SHA256", report.SHA256)
	}
	if report.SigningKeyID != "" {
		w.Header().Set("X-EncoreBOM-Signing-Key", report.SigningKeyID)
	}
	if report.Truncated {
		w.Header().Set("X-EncoreBOM-Truncated", "true")
	}
}

// Signature returns the detached signature envelope for an artifact.
//
// Served separately from the artifact so the bytes a customer verifies are the
// bytes they downloaded — an envelope wrapped around the payload would change
// what the digest describes.
func (h *Handler) Signature(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	report, err := h.svc.Get(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	if report.Signature == "" {
		errs.Write(w, r, errs.New(errs.NotFoundReport,
			"this report has no signature; it may not have finished rendering"))
		return
	}

	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", filename(report)+".sig.json"))
	w.Header().Set("Cache-Control", "no-store")
	// Written raw: the stored envelope is the exact JSON that was signed over,
	// and re-encoding it here would be the same defect that broke every
	// signature the first time the envelope was pretty-printed.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, report.Signature)
}

// ---------------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------------

type shareResponse struct {
	ID            string  `json:"id"`
	ReportID      string  `json:"report_id"`
	ExpiresAt     *string `json:"expires_at"`
	MaxDownloads  *int    `json:"max_downloads"`
	DownloadCount int     `json:"download_count"`
	RevokedAt     *string `json:"revoked_at"`
	State         string  `json:"state"`
	CreatedAt     string  `json:"created_at"`

	// Token is present ONLY in the response that created the link.
	//
	// ⚠ It is never stored and can never be recovered. A link a support agent
	// can look up is a link an attacker with read access can look up.
	Token string `json:"token,omitempty"`
	URL   string `json:"url,omitempty"`
}

func toShareResponse(l share.Link, now time.Time) shareResponse {
	out := shareResponse{
		ID:            l.ID,
		ReportID:      l.ReportID,
		MaxDownloads:  l.MaxDownloads,
		DownloadCount: l.DownloadCount,
		State:         string(l.Classify(now)),
		CreatedAt:     l.CreatedAt.UTC().Format(time.RFC3339),
	}
	if l.ExpiresAt != nil {
		s := l.ExpiresAt.UTC().Format(time.RFC3339)
		out.ExpiresAt = &s
	}
	if l.RevokedAt != nil {
		s := l.RevokedAt.UTC().Format(time.RFC3339)
		out.RevokedAt = &s
	}
	return out
}

// Share mints a link.
func (h *Handler) Share(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		ExpiresAt    *string `json:"expires_at"`
		MaxDownloads *int    `json:"max_downloads"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	opts := share.Options{MaxDownloads: req.MaxDownloads}
	if req.ExpiresAt != nil {
		t, parseErr := time.Parse(time.RFC3339, *req.ExpiresAt)
		if parseErr != nil {
			errs.Write(w, r, errs.New(errs.ValidationFieldInvalid,
				"expires_at must be an RFC3339 timestamp in UTC"))
			return
		}
		utc := t.UTC()
		opts.ExpiresAt = &utc
	}

	token, link, err := h.svc.Share(r.Context(), tenantID, r.PathValue("id"),
		ctxkey.UserID(r.Context()), opts, h.now().UTC())
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	resp := toShareResponse(link, h.now().UTC())
	// ⚠ The ONLY moment the plaintext token exists outside the creator's hands.
	resp.Token = token.Reveal()
	resp.URL = "/shared/" + token.Reveal()
	errs.WriteJSON(w, http.StatusCreated, resp)
}

// ListShares returns a report's links and their current state.
func (h *Handler) ListShares(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	links, err := h.svc.ListShares(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	now := h.now().UTC()
	out := make([]shareResponse, 0, len(links))
	for _, l := range links {
		out = append(out, toShareResponse(l, now))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"share_links": out})
}

// Revoke withdraws a link.
//
// Revoking an already-revoked link succeeds. The caller wants it withdrawn; it
// is, and returning an error would push a client into treating a safe state as
// a failure.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	if err := h.svc.Revoke(r.Context(), tenantID, r.PathValue("share_id")); err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ShareAccessLog returns a link's audit trail.
func (h *Handler) ShareAccessLog(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := h.svc.ShareAccessLog(r.Context(), tenantID, r.PathValue("share_id"), limit)
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	type row struct {
		Outcome    string `json:"outcome"`
		ClientIP   string `json:"client_ip,omitempty"`
		UserAgent  string `json:"user_agent,omitempty"`
		AccessedAt string `json:"accessed_at"`
	}
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		out = append(out, row{
			Outcome:    string(e.Outcome),
			ClientIP:   e.ClientIP,
			UserAgent:  e.UserAgent,
			AccessedAt: e.AccessedAt.UTC().Format(time.RFC3339),
		})
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"accesses": out})
}

// ---------------------------------------------------------------------------
// The anonymous download
// ---------------------------------------------------------------------------

// Shared serves a report to a share-token holder.
//
// ⚠ UNAUTHENTICATED. THIS IS THE ONLY ROUTE IN THE PRODUCT THAT SERVES TENANT
// DATA WITHOUT AN IDENTITY, AND EVERY DECISION HERE FOLLOWS FROM THAT.
//
//   - The token is parsed for SHAPE before the database is touched, so garbage
//     costs a round trip to nothing.
//   - The claim is atomic in Postgres: the download cap is checked and consumed
//     in one statement, so two concurrent requests cannot both pass a cap of one.
//   - Every attempt is audited, INCLUDING refusals — repeated refusals against
//     a revoked token mean somebody still holds it.
//   - An unknown token gets a bare 404. A holder of a real token is told whether
//     it expired or was withdrawn; they already had the token, and a 256-bit
//     value is not enumerable.
//   - The response is `attachment` + `nosniff` + `no-store`, like every other
//     download, and MORE so: this one is reachable by anyone with the link.
func (h *Handler) Shared(w http.ResponseWriter, r *http.Request) {
	token, err := share.ParseToken(r.PathValue("token"))
	if err != nil {
		notFoundShare(w, r)
		return
	}

	claim, err := h.svc.ClaimShared(r.Context(), token, clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, store.ErrUnknownToken) {
			notFoundShare(w, r)
			return
		}
		errs.Write(w, r, err)
		return
	}

	if claim.Outcome != share.OutcomeGranted {
		errs.Write(w, r, refusal(claim.Outcome))
		return
	}

	report, err := h.svc.GetShared(r.Context(), claim)
	if err != nil {
		errs.Write(w, r, mapNotFound(err))
		return
	}

	// ⚠ NO ROLE CHECK, AND NO VISIBILITY CHECK EITHER — DELIBERATELY.
	//
	// There is no role here to check: the holder is anonymous. Minting the link
	// IS the authorization, which is why (share_link, share) requires Analyst
	// and why every access is audited. Re-checking visibility would make the
	// link silently useless for exactly the reports people share for review.
	h.stream(w, r, report)
}

// refusal maps a claim outcome to the error a link holder sees.
func refusal(o share.Outcome) error {
	switch o {
	case share.OutcomeExpired:
		return errs.New(errs.ReportShareExpired, "this share link has expired")
	case share.OutcomeRevoked:
		return errs.New(errs.ReportShareRevoked, "this share link has been revoked")
	case share.OutcomeExhausted:
		return errs.New(errs.ReportShareExpired,
			"this share link has reached its download limit")
	default:
		return errs.New(errs.NotFoundReport, "no such report")
	}
}

// notFoundShare answers an unknown or malformed token.
//
// ⚠ IDENTICAL FOR BOTH. A malformed token and a well-formed unknown one get the
// same response, so the endpoint does not confirm that a given shape is the
// right shape — which would halve the work of a guesser who had none.
func notFoundShare(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	errs.Write(w, r, errs.New(errs.NotFoundReport, "no such share link"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// maxRequestBody bounds a JSON body. These endpoints take a handful of fields;
// anything larger is a mistake or an attempt to exhaust memory.
const maxRequestBody = 64 << 10

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	// ⚠ Strict here, unlike the queue envelopes. A typo'd field in a user's
	// request is a mistake worth reporting; an unrecognized field in a queue
	// message is a newer publisher (docs/02-CONTRACTS.md §2).
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errs.Newf(errs.ValidationFieldInvalid, "malformed request body: %v", err)
	}
	return nil
}

// mapNotFound turns a store miss into the 404 taxonomy code.
//
// Cross-tenant reads land here too: RLS filtered the row out, so the store saw
// nothing, and "no such report" is the honest answer. A 403 would confirm it
// exists.
func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errs.New(errs.NotFoundReport, "no such report")
	}
	return err
}

func mediaType(format string) string {
	switch format {
	case "pdf":
		return "application/pdf"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "spdx":
		return "application/spdx+json"
	case "cyclonedx":
		return "application/vnd.cyclonedx+json; version=1.6"
	default:
		return "application/json"
	}
}

// filename is what the browser saves.
//
// ⚠ BUILT FROM THE REPORT ID AND THE FORMAT, NEVER FROM THE PROJECT NAME. A
// project name is user-controlled, and a name containing a quote, a newline or
// a path separator would break out of the Content-Disposition header — the
// classic response-splitting and path-traversal pair, in one field.
func filename(r store.Report) string {
	ext := r.Format
	switch r.Format {
	case "spdx":
		ext = "spdx.json"
	case "cyclonedx":
		ext = "cdx.json"
	}
	return "encorebom-" + r.ID + "." + ext
}

// clientIP is what the audit row records and what the anonymous route is
// rate-limited by.
//
// ⚠ ONE IMPLEMENTATION, IN httpx. The proxy header is honoured only when proxy
// headers are trusted; an untrusted X-Forwarded-For lets a caller write any
// address they like into an audit trail, and a forged address in an incident
// log is worse than a missing one.
func clientIP(r *http.Request) string { return httpx.ClientIP(r) }
