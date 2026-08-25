// Package service holds the report service's rules.
//
// Two responsibilities the layers either side of it must not take on:
//
//   - Validating what may be asked for. A level the projection cannot produce
//     and a format the renderer does not have are refused HERE, before a row is
//     written — a queued report that can never render is a job the worker will
//     fail forever and a status the UI will spin on.
//   - Deciding what a share-link claim means. The handler translates the
//     outcome to HTTP; the audit write and the atomicity live here and below.
package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/report/internal/level"
	"github.com/axebom/axebom/services/report/internal/share"
	"github.com/axebom/axebom/services/report/internal/store"
)

// Service is the report domain.
type Service struct {
	store *store.Store
	blob  *blob.Store
	// queue publishes a render job. Nil in tests that only exercise reads.
	queue Queue
	log   *slog.Logger
}

// Queue publishes render jobs.
//
// An interface rather than a NATS handle so the service can be tested without a
// broker, and so a future in-process renderer is a substitution rather than a
// rewrite.
type Queue interface {
	PublishRender(ctx context.Context, tenantID, reportID string) error
}

// New builds the service.
func New(st *store.Store, bs *blob.Store, q Queue, log *slog.Logger) *Service {
	// A nil logger would panic on the first share-link mint, which is the one
	// path where losing the record matters most.
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, blob: bs, queue: q, log: log}
}

// ---------------------------------------------------------------------------
// Queueing
// ---------------------------------------------------------------------------

// QueueRequest is a render request.
type QueueRequest struct {
	TenantID       string
	ScanID         string
	BOMDocumentIDs []string
	BOMType        string
	Level          string
	Standard       string
	Format         string
	Visibility     string
}

// Queue validates a request, records it, and publishes the job.
//
// ⚠ VALIDATION BEFORE THE ROW, NOT IN THE WORKER.
//
// A queued report that can never render is worse than a rejected request: the
// customer sees `queued`, the UI spins, the worker fails it, and the reason
// arrives minutes later as an error code on a row nobody is looking at. Every
// value that can be checked without reading the BOM is checked here.
func (s *Service) Queue(ctx context.Context, req QueueRequest) (store.Report, error) {
	if req.ScanID == "" {
		return store.Report{}, errs.New(errs.ValidationFieldRequired, "scan_id is required")
	}

	bomType, err := model.ParseBOMType(req.BOMType)
	if err != nil {
		return store.Report{}, errs.Newf(errs.ValidationFieldInvalid, "%v", err)
	}

	lvl, err := parseLevel(req.Level)
	if err != nil {
		return store.Report{}, err
	}

	format, err := parseFormat(req.Format)
	if err != nil {
		return store.Report{}, err
	}

	standard, err := parseStandard(req.Standard, format)
	if err != nil {
		return store.Report{}, err
	}

	// ⚠ DEFAULTS TO `private`, AND THE ZERO VALUE MUST BE THE SAFE ONE.
	//
	// A report contains vulnerability detail unless somebody decided otherwise.
	// A client that omits the field gets the restrictive answer; the other way
	// round, one forgotten field publishes an estate's unpatched CVEs.
	visibility := req.Visibility
	if visibility == "" {
		visibility = string(authzVisibilityPrivate)
	}
	if visibility != "public" && visibility != "private" {
		return store.Report{}, errs.New(errs.ValidationFieldInvalid,
			`visibility must be "public" or "private"`)
	}

	report, err := s.store.Create(ctx, store.CreateRequest{
		TenantID:       req.TenantID,
		ScanID:         req.ScanID,
		BOMDocumentIDs: req.BOMDocumentIDs,
		BOMType:        string(bomType),
		Level:          string(lvl),
		Standard:       standard,
		Format:         format,
		Visibility:     visibility,
	})
	if err != nil {
		return store.Report{}, err
	}

	if s.queue != nil {
		if err := s.queue.PublishRender(ctx, req.TenantID, report.ID); err != nil {
			// ⚠ THE ROW SURVIVES A FAILED PUBLISH, MARKED FAILED.
			//
			// Leaving it `queued` would have it wait for a job that was never
			// published — indistinguishable, from the outside, from a busy
			// worker. A stuck report that says `failed` with a code is one an
			// operator can retry; a stuck report that says `queued` is one
			// nobody investigates until a customer asks.
			s.log.Error("publishing the render job failed",
				"report_id", report.ID, "error", err)
			if markErr := s.store.MarkFailed(ctx, req.TenantID, report.ID,
				string(errs.InternalDependency)); markErr != nil {
				s.log.Error("marking the unpublished report failed",
					"report_id", report.ID, "error", markErr)
			}
			return store.Report{}, errs.Wrap(err, errs.InternalDependency,
				"the report was recorded but could not be queued for rendering")
		}
	}

	return report, nil
}

// authzVisibilityPrivate mirrors authz.VisibilityPrivate without importing it
// here; the matrix owns the download decision, this owns the default.
const authzVisibilityPrivate = "private"

// parseLevel refuses a level the projection does not implement.
//
// n-Level, Delivery and Transitive are defined by CERT-In §3.1 and not yet
// produced. Silently rendering one as Complete would mislabel the report with
// the level the customer chose for something narrower.
func parseLevel(raw string) (level.Level, error) {
	if raw == "" {
		return level.TopLevel, nil
	}
	l := level.Level(raw)
	if level.Valid(l) {
		return l, nil
	}

	// ⚠ TWO DIFFERENT ANSWERS, because they mean different things to the
	// caller. `delivery` is a real CERT-In level we do not build yet; `top-lvl`
	// is a typo. Collapsing them would have somebody spend an afternoon
	// checking their spelling of a level that does not exist here at all.
	if level.Known(l) {
		return "", errs.Newf(errs.ValidationFieldInvalid,
			"level %q is defined by CERT-In §3.1 but this build does not produce "+
				"it; available levels are %q and %q", raw, level.TopLevel, level.Complete)
	}
	return "", errs.Newf(errs.ValidationFieldInvalid,
		"level %q is not a CERT-In BOM level", raw)
}

func parseFormat(raw string) (string, error) {
	switch raw {
	case "pdf", "xlsx", "json", "spdx", "cyclonedx":
		return raw, nil
	case "":
		return "", errs.New(errs.ValidationFieldRequired, "format is required")
	default:
		return "", errs.Newf(errs.ValidationFieldInvalid,
			"format %q is not produced; want one of pdf, xlsx, json, spdx, cyclonedx", raw)
	}
}

// parseStandard derives the standard when the format already implies it.
//
// ⚠ A MISMATCH IS REFUSED RATHER THAN CORRECTED. `{format: spdx, standard:
// CycloneDX}` is a caller that believes something false about what it will
// receive, and quietly fixing it hands them a document they will mis-parse.
func parseStandard(raw, format string) (string, error) {
	implied := map[string]string{
		"spdx":      "SPDX",
		"cyclonedx": "CycloneDX",
	}[format]

	if raw == "" {
		if implied != "" {
			return implied, nil
		}
		return "native", nil
	}
	if raw != "SPDX" && raw != "CycloneDX" && raw != "native" {
		return "", errs.Newf(errs.ValidationFieldInvalid,
			"standard %q is unknown; want SPDX, CycloneDX or native", raw)
	}
	if implied != "" && raw != implied {
		return "", errs.Newf(errs.ValidationFieldInvalid,
			"format %q always produces %s, but standard %q was requested",
			format, implied, raw)
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// Get reads one report.
func (s *Service) Get(ctx context.Context, tenantID, reportID string) (store.Report, error) {
	return s.store.Get(ctx, tenantID, reportID)
}

// List returns a tenant's reports.
func (s *Service) List(ctx context.Context, tenantID, scanID string, limit int, cursor string) ([]store.Report, error) {
	return s.store.List(ctx, tenantID, scanID, limit, cursor)
}

// Siblings returns a report's other rendered formats for the same scan and
// BOM type — a live relationship, read at request time, not data captured at
// render completion.
func (s *Service) Siblings(ctx context.Context, tenantID string, r store.Report) ([]store.ReportSibling, error) {
	return s.store.Siblings(ctx, tenantID, r.ID, r.ScanID, r.BOMType)
}

// Open streams a rendered artifact from object storage.
//
// ⚠ THE KEY COMES FROM THE ROW THE CALLER WAS ALREADY ALLOWED TO READ, never
// from the request. A caller-supplied key would be a read primitive over the
// whole bucket — the same class of bug the Vault path derivation avoids.
func (s *Service) Open(ctx context.Context, report store.Report) (io.ReadCloser, error) {
	if report.StorageRef == "" {
		return nil, errs.New(errs.ReportRenderFailed,
			"this report has no stored artifact")
	}
	body, err := s.blob.Get(ctx, report.StorageRef)
	if err != nil {
		return nil, errs.Wrap(err, errs.InternalDependency,
			"the rendered artifact could not be read from object storage")
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------------

// Share mints a link for a report.
//
// ⚠ ONLY A `ready` REPORT MAY BE SHARED. A link to a queued render is a link
// whose first use fails, and the holder cannot tell that from a revoked one.
func (s *Service) Share(
	ctx context.Context, tenantID, reportID, createdBy string,
	opts share.Options, now time.Time,
) (share.Token, share.Link, error) {
	report, err := s.store.Get(ctx, tenantID, reportID)
	if err != nil {
		return "", share.Link{}, err
	}
	if report.Status != store.StatusReady {
		return "", share.Link{}, errs.Newf(errs.ValidationFieldInvalid,
			"this report is %s; only a ready report can be shared", report.Status)
	}

	token, link, err := s.store.CreateShareLink(ctx, tenantID, reportID, createdBy, opts, now)
	if err != nil {
		return "", share.Link{}, errs.Wrap(err, errs.ValidationFieldInvalid,
			"the share link could not be created")
	}

	// ⚠ Logged WITHOUT the token, obviously — but also without the hash. The
	// hash is the lookup key for the one function that turns a token into a
	// download, and logs travel further than databases do.
	s.log.Info("share link minted",
		"report_id", reportID, "share_link_id", link.ID, "created_by", createdBy)

	return token, link, nil
}

// ListShares returns a report's links.
func (s *Service) ListShares(ctx context.Context, tenantID, reportID string) ([]share.Link, error) {
	if _, err := s.store.Get(ctx, tenantID, reportID); err != nil {
		return nil, err
	}
	return s.store.ListShareLinks(ctx, tenantID, reportID)
}

// Revoke withdraws a link.
func (s *Service) Revoke(ctx context.Context, tenantID, linkID string) error {
	if err := s.store.RevokeShareLink(ctx, tenantID, linkID); err != nil {
		return err
	}
	s.log.Info("share link revoked", "share_link_id", linkID)
	return nil
}

// ShareAccessLog returns a link's audit trail.
func (s *Service) ShareAccessLog(ctx context.Context, tenantID, linkID string, limit int) ([]store.ShareAccess, error) {
	return s.store.ListShareAccess(ctx, tenantID, linkID, limit)
}

// ClaimShared consumes one download against a token and audits the attempt.
//
// ⚠ THE AUDIT WRITE HAPPENS FOR EVERY OUTCOME, AND ITS FAILURE DOES NOT BLOCK
// A GRANTED DOWNLOAD.
//
// Two decisions worth stating, because they point in opposite directions:
//
//   - Refusals are audited too, and those are the interesting rows. Repeated
//     refusals against a revoked token mean somebody still holds it and is
//     still trying — exactly what an incident review needs, and exactly what a
//     success-only log omits.
//   - If the audit write itself fails, the download still proceeds. The claim
//     has already been consumed against the cap, so refusing now would burn a
//     download AND serve nothing. The failure is logged at ERROR, which is the
//     honest trade: a missing audit row we know about beats a silently
//     swallowed download the customer paid a cap for.
func (s *Service) ClaimShared(
	ctx context.Context, token share.Token, clientIP, userAgent string,
) (store.Claim, error) {
	claim, err := s.store.ClaimDownload(ctx, token)
	if err != nil {
		return store.Claim{}, err
	}

	if auditErr := s.store.RecordShareAccess(
		ctx, claim.ShareLinkID, claim.Outcome, clientIP, userAgent,
	); auditErr != nil {
		s.log.Error("the share-link access could not be audited",
			"share_link_id", claim.ShareLinkID,
			"outcome", string(claim.Outcome),
			"error", auditErr)
	}

	return claim, nil
}

// GetShared reads the report behind a claimed link.
func (s *Service) GetShared(ctx context.Context, claim store.Claim) (store.Report, error) {
	return s.store.GetReportForShare(ctx, claim)
}

// ---------------------------------------------------------------------------
// Rendering (called by the worker)
// ---------------------------------------------------------------------------

// Claim moves a queued report to `rendering`.
func (s *Service) Claim(ctx context.Context, tenantID, reportID string) (store.Report, error) {
	return s.store.ClaimForRender(ctx, tenantID, reportID)
}

// StorageKey is where a rendered artifact lives.
//
// ⚠ TENANT-PREFIXED AND DERIVED, NEVER SUPPLIED. The prefix means a bucket
// listing is already segmented by tenant, and deriving it from ids the caller
// was already authorized for means no request can name a key.
//
// The report id is a UUIDv7, so keys sort chronologically within a tenant,
// which makes lifecycle rules and incident triage straightforward.
func StorageKey(tenantID, reportID, format string) string {
	ext := format
	switch format {
	case "spdx":
		ext = "spdx.json"
	case "cyclonedx":
		ext = "cdx.json"
	}
	return fmt.Sprintf("reports/%s/%s.%s", tenantID, reportID, ext)
}

// Finish records a completed render.
func (s *Service) Finish(ctx context.Context, tenantID, reportID string, c store.Completion) error {
	return s.store.MarkReady(ctx, tenantID, reportID, c)
}

// Fail records a render that will not be retried.
func (s *Service) Fail(ctx context.Context, tenantID, reportID string, cause error) error {
	code := errs.From(cause).Code
	s.log.Error("render failed", "report_id", reportID, "code", string(code), "error", cause)
	return s.store.MarkFailed(ctx, tenantID, reportID, string(code))
}

// Blob exposes the object store to the worker, which uploads before marking
// ready. Kept narrow rather than handing the worker the whole service.
func (s *Service) Blob() *blob.Store { return s.blob }
