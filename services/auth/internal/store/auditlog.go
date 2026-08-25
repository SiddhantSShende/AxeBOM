package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auditexport"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// AuditLogEntries returns a tenant's audit log within [from, to] (either may
// be nil, meaning unbounded), oldest first — the order a reviewer replaying
// what happened actually wants.
//
// ⚠ ORDINARY WithTenant, NO EXPLICIT tenant_id FILTER. RLS scopes this the
// same way it scopes every other tenant-owned read (CLAUDE.md invariant 6);
// this is the one export function in this file that is NOT pre-tenant,
// because exporting requires an authenticated session that already knows
// its tenant.
func (s *Store) AuditLogEntries(ctx context.Context, tenantID string, from, to *time.Time) ([]auditexport.Entry, error) {
	var out []auditexport.Entry
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, COALESCE(actor_user_id::text, ''), action,
			       COALESCE(entity_type, ''), COALESCE(entity_id::text, ''),
			       metadata, COALESCE(host(ip), ''), COALESCE(user_agent, ''),
			       created_at
			  FROM auth.audit_log
			 WHERE ($1::timestamptz IS NULL OR created_at >= $1)
			   AND ($2::timestamptz IS NULL OR created_at <= $2)
			 ORDER BY created_at`, from, to)
		if err != nil {
			return fmt.Errorf("list audit log: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				e           auditexport.Entry
				metadataRaw []byte
				createdAt   time.Time
			)
			if err := rows.Scan(&e.ID, &e.TenantID, &e.ActorUserID, &e.Action,
				&e.EntityType, &e.EntityID, &metadataRaw, &e.IP, &e.UserAgent,
				&createdAt); err != nil {
				return fmt.Errorf("scan audit entry: %w", err)
			}
			e.CreatedAt = createdAt.UTC().Format(time.RFC3339)
			// ⚠ MALFORMED METADATA DOES NOT FAIL THE EXPORT. This column is
			// written only by this service's own record functions; a row this
			// cannot parse should still appear in the export with its other
			// fields intact, the same tolerance bomsource.go's coverage
			// breakdown already applies.
			if len(metadataRaw) > 0 {
				_ = json.Unmarshal(metadataRaw, &e.Metadata) //nolint:errcheck // see above
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
