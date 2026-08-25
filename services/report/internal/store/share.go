package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/report/internal/share"
)

// CreateShareLink mints a link for a report.
//
// ⚠ THE PLAINTEXT TOKEN IS RETURNED AND NEVER STORED. Only the hash reaches the
// database, so a database read — a backup, a replica, a support query — does
// not yield a working link. Same rule as auth.sessions.
//
// The caller hands the token to the user who created the link, once. There is
// no way to recover it afterwards, which is correct: a link you can look up is
// a link an attacker with read access can look up.
func (s *Store) CreateShareLink(
	ctx context.Context, tenantID, reportID, createdBy string, opts share.Options, now time.Time,
) (share.Token, share.Link, error) {
	if err := opts.Validate(now); err != nil {
		return "", share.Link{}, err
	}

	token, err := share.NewToken()
	if err != nil {
		return "", share.Link{}, err
	}

	var link share.Link
	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		return scanLink(tx.QueryRow(ctx, `
			INSERT INTO report.share_links
				(tenant_id, report_id, token_hash, expires_at, max_downloads, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING `+linkColumns,
			tenantID, reportID, token.Hash(), opts.ExpiresAt, opts.MaxDownloads, createdBy),
			&link)
	})
	if err != nil {
		return "", share.Link{}, fmt.Errorf("create share link: %w", err)
	}
	return token, link, nil
}

const linkColumns = `
	id, tenant_id, report_id, expires_at, max_downloads, download_count,
	revoked_at, created_at, created_by`

func scanLink(row pgx.Row, l *share.Link) error {
	return row.Scan(&l.ID, &l.TenantID, &l.ReportID, &l.ExpiresAt, &l.MaxDownloads,
		&l.DownloadCount, &l.RevokedAt, &l.CreatedAt, &l.CreatedBy)
}

// ListShareLinks returns a report's links, newest first.
//
// ⚠ NO TOKEN AND NO HASH IN THE RESULT. The hash is not a working link, but it
// is a lookup key for the one function that turns a hash into a download, and a
// list endpoint is a much softer target than the database.
func (s *Store) ListShareLinks(ctx context.Context, tenantID, reportID string) ([]share.Link, error) {
	var out []share.Link
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+linkColumns+`
			  FROM report.share_links
			 WHERE report_id = $1
			 ORDER BY id DESC`, reportID)
		if err != nil {
			return fmt.Errorf("list share links: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var l share.Link
			if err := scanLink(rows, &l); err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeShareLink withdraws a link.
//
// ⚠ IMMEDIATE, AND THAT IS A PROPERTY OF THE READ PATH RATHER THAN OF THIS
// WRITE. Nothing caches a link's state: every download re-evaluates
// `revoked_at IS NULL` inside claim_share_download. A cache with any TTL would
// make "revoke" mean "revoke, eventually" — and an operator revokes a link
// because something has already gone wrong.
//
// Revoking an already-revoked link is success. The caller wants it withdrawn;
// it is.
func (s *Store) RevokeShareLink(ctx context.Context, tenantID, linkID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE report.share_links
			   SET revoked_at = COALESCE(revoked_at, now())
			 WHERE id = $1`, linkID)
		if err != nil {
			return fmt.Errorf("revoke share link: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Claim is the outcome of an anonymous download attempt.
type Claim struct {
	ShareLinkID string
	TenantID    string
	ReportID    string
	Outcome     share.Outcome

	ExpiresAt     *time.Time
	MaxDownloads  *int
	DownloadCount int
}

// ErrUnknownToken means no share link matches the presented token.
//
// Distinct from a refused claim: an unknown token gets a 404 with no detail,
// whereas a holder of a real token is told whether it expired or was withdrawn.
// They already had the token; a 256-bit value is not enumerable.
var ErrUnknownToken = errors.New("no share link matches this token")

// ClaimDownload atomically consumes one download against a token.
//
// ⚠ THE ONE PLACE IN THIS SERVICE THAT RUNS OUTSIDE db.WithTenant, AND IT IS
// DELIBERATE.
//
// `/shared/:token` is unauthenticated. The caller presents a token and nothing
// else, so there is no tenant to scope with — the tenant is what we are trying
// to recover. That is the same pre-tenant problem Phase 3 solved for login, and
// it gets the same answer: a narrow SECURITY DEFINER function taking one token
// hash, NOT pool.Raw() with RLS disabled and NOT a BYPASSRLS role.
//
// The check and the increment happen inside that function as ONE conditional
// UPDATE. Doing it here in Go would mean read-then-write, and two concurrent
// requests would both pass a download cap of one.
func (s *Store) ClaimDownload(ctx context.Context, token share.Token) (Claim, error) {
	var c Claim
	var outcome string

	err := s.pool.Raw().QueryRow(ctx,
		`SELECT share_link_id, tenant_id, report_id, outcome,
		        expires_at, max_downloads, download_count
		   FROM report.claim_share_download($1)`, token.Hash()).
		Scan(&c.ShareLinkID, &c.TenantID, &c.ReportID, &outcome,
			&c.ExpiresAt, &c.MaxDownloads, &c.DownloadCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Claim{}, ErrUnknownToken
		}
		return Claim{}, fmt.Errorf("claim share download: %w", err)
	}

	c.Outcome = share.Outcome(outcome)
	if !c.Outcome.Valid() {
		// The function and the Go enum disagreeing would mean an audit row we
		// cannot write, so it fails rather than guessing.
		return Claim{}, fmt.Errorf(
			"claim_share_download returned outcome %q, which is not one this "+
				"service knows; the migration and share.Outcome have diverged", outcome)
	}
	return c, nil
}

// RecordShareAccess writes one audit row.
//
// ⚠ WRITTEN FOR REFUSALS TOO, AND THOSE ARE THE INTERESTING ONES. Repeated
// refusals against a revoked token mean somebody still holds it and is still
// trying — which is exactly what an incident review needs and exactly what a
// success-only log would omit.
//
// Same pre-tenant exemption as ClaimDownload: at the moment of an anonymous
// download there is no app.current_tenant_id to satisfy the policy. The function
// derives the tenant from the link rather than accepting one, so this cannot
// write into another tenant's log.
func (s *Store) RecordShareAccess(
	ctx context.Context, linkID string, outcome share.Outcome, clientIP, userAgent string,
) error {
	if !outcome.Valid() {
		return fmt.Errorf("refusing to audit an unknown outcome %q", outcome)
	}

	var id *string
	err := s.pool.Raw().QueryRow(ctx,
		`SELECT report.record_share_access($1, $2, $3, $4)`,
		linkID, string(outcome), normalizeIP(clientIP), userAgent).Scan(&id)
	if err != nil {
		return fmt.Errorf("record share access: %w", err)
	}
	if id == nil {
		return ErrNotFound
	}
	return nil
}

// normalizeIP turns a request's address into something the `inet` column
// accepts, or NULL.
//
// ⚠ NULL RATHER THAN A GUESS. The address arrives from a proxy header or a
// socket and can be absent, malformed or a port-suffixed pair. Storing a
// mangled value would put a fabricated address in an audit trail, which is
// worse than recording that we did not know — the log is read during an
// incident, and an address nobody can trace is a false lead.
func normalizeIP(raw string) *string {
	if raw == "" {
		return nil
	}
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		s := addrPort.Addr().Unmap().String()
		return &s
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		s := addr.Unmap().String()
		return &s
	}
	return nil
}

// ShareAccess is one audit row.
type ShareAccess struct {
	ID          string
	ShareLinkID string
	ReportID    string
	Outcome     share.Outcome
	ClientIP    string
	UserAgent   string
	AccessedAt  time.Time
}

// ListShareAccess returns a link's audit trail, newest first.
//
// Scoped by tenant like every other read: the anonymous WRITE path needs the
// SECURITY DEFINER exemption, the authenticated READ path does not.
func (s *Store) ListShareAccess(
	ctx context.Context, tenantID, linkID string, limit int,
) ([]ShareAccess, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var out []ShareAccess
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, fmt.Sprintf(`
			SELECT id, share_link_id, report_id, outcome,
			       COALESCE(host(client_ip), ''), COALESCE(user_agent, ''), accessed_at
			  FROM report.share_access_log
			 WHERE share_link_id = $1
			 ORDER BY accessed_at DESC, id DESC
			 LIMIT %d`, limit), linkID)
		if err != nil {
			return fmt.Errorf("list share access: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var a ShareAccess
			var outcome string
			if err := rows.Scan(&a.ID, &a.ShareLinkID, &a.ReportID, &outcome,
				&a.ClientIP, &a.UserAgent, &a.AccessedAt); err != nil {
				return err
			}
			a.Outcome = share.Outcome(outcome)
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetReportForShare reads the report behind a claimed link.
//
// ⚠ SCOPED TO THE TENANT THE CLAIM RETURNED, not to a caller-supplied one. The
// anonymous path has no tenant of its own, so the link is what establishes it —
// and it comes from the database, not from the request.
func (s *Store) GetReportForShare(ctx context.Context, c Claim) (Report, error) {
	return s.Get(ctx, c.TenantID, c.ReportID)
}
