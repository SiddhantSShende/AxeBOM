package service

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auditexport"
	"github.com/axebom/axebom/services/auth/internal/store"
)

// ExportAuditLog streams a tenant's audit log and returns how many rows it
// wrote.
//
// ⚠ THE EXPORT ITSELF IS RECORDED BEFORE THE STREAM STARTS, NOT AFTER. See
// auditexport.ExportRecord's own doc comment: an export that fails halfway
// still copied rows out of the system, and recording only completed exports
// would make the interesting case — a large export that was cut off — the
// one that leaves no trace.
func (s *Service) ExportAuditLog(
	ctx context.Context, tenantID string, format auditexport.Format,
	actorUserID string, clientIP net.IP, from, to *time.Time, w io.Writer,
) (int, error) {
	rangeFrom, rangeTo := time.Time{}, s.now()
	if from != nil {
		rangeFrom = *from
	}
	if to != nil {
		rangeTo = *to
	}

	rec := auditexport.ExportRecord(actorUserID, format, rangeFrom, rangeTo)
	if err := s.store.RecordAuthEvent(ctx, store.AuthEvent{
		TenantID: tenantID, ActorID: actorUserID, Action: rec.Action,
		Metadata: rec.Metadata, IP: clientIP,
	}); err != nil {
		return 0, err
	}

	entries, err := s.store.AuditLogEntries(ctx, tenantID, from, to)
	if err != nil {
		return 0, err
	}

	ew, err := auditexport.NewWriter(w, format)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if err := ew.Write(e); err != nil {
			return 0, err
		}
	}
	return ew.Close()
}
