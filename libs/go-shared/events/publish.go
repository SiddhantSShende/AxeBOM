package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// AdvisoryPublisher is the minimal surface ScanEventV1 publishing needs —
// satisfied by *bus.Bus without this package importing it, so any advisory
// producer (services/scan-orchestrator, services/webrecon, and any future
// one) shares this one construction path instead of each reimplementing
// seq/ts/sanitize/validate and inevitably drifting.
type AdvisoryPublisher interface {
	PublishAdvisory(ctx context.Context, subject string, payload []byte) error
}

// PublishScanEvent fills in every field a caller must not forget to set
// (schema version, event id, a monotonic seq, ts), sanitizes and validates,
// then publishes.
//
// ⚠ ERRORS ARE LOGGED, NEVER RETURNED. An event is advisory — the database
// remains the source of truth (this package's own doc comment) — so failing
// a scan because a progress message could not be published would invert the
// priority. log may be nil; a nil logger just means no log line, not a
// panic.
//
// seq is the caller's own counter, shared across every event it publishes in
// its process lifetime — monotonic overall, not reset per scan or per job,
// which is sufficient for a consumer to reorder and detect a gap within one
// job's own sub-sequence (the doc requirement) even though it is not
// contiguous starting from 1 for each one.
func PublishScanEvent(ctx context.Context, pub AdvisoryPublisher, seq *atomic.Int64, log *slog.Logger, e ScanEventV1) {
	e.SchemaVersion = SchemaScanEventV1
	if e.EventID == "" {
		e.EventID = uuid.NewString()
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if e.Seq == 0 {
		e.Seq = seq.Add(1)
	}
	e.Sanitize()

	if err := e.Validate(); err != nil {
		if log != nil {
			log.Warn("refusing to publish an invalid scan event", "cause", err.Error())
		}
		return
	}

	payload, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := pub.PublishAdvisory(ctx, e.Subject(), payload); err != nil {
		if log != nil {
			log.Debug("advisory event not published; the database remains authoritative",
				"scan_id", e.ScanID, "cause", err.Error())
		}
	}
}
