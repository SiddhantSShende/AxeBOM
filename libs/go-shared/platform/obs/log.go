// Package obs provides logging, metrics and tracing.
//
// docs/08-OPERATIONS.md §5. Three rules that shape this package:
//
//   - Structured JSON, one line per event, always carrying request_id,
//     tenant_id, service and trace_id.
//
//   - NEVER secrets, tokens, full request bodies, or component/finding detail.
//     BOM content is confidential under CERT-In §5.3. Redaction lives in the
//     handler (see redact.go), not at call sites, because a call site will
//     eventually be added without it.
//
//   - Trace context propagates through HTTP, gRPC and NATS so one trace spans
//     API -> orchestrator -> fetch -> N engine jobs -> normalize -> render.
package obs

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel/trace"

	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
)

// contextType aliases context.Context so the handler signatures in redact.go
// stay readable without importing context there.
type contextType = context.Context

// LogConfig configures the logger.
type LogConfig struct {
	Service string
	Level   string // debug | info | warn | error
	Format  string // json | text
	Output  io.Writer
}

// InitLogger builds the logger and installs it as the slog default.
//
// Handler chain, outermost first:
//
//	trace-correlating -> redacting -> JSON/text
//
// Redaction sits inside trace correlation so trace ids (not secret) survive,
// and outside the encoder so nothing secret is ever encoded.
func InitLogger(cfg LogConfig) *slog.Logger {
	out := cfg.Output
	if out == nil {
		out = os.Stdout
	}

	opts := &slog.HandlerOptions{
		Level:     parseLevel(cfg.Level),
		AddSource: parseLevel(cfg.Level) == slog.LevelDebug,
	}

	var base slog.Handler
	if strings.EqualFold(cfg.Format, "text") {
		base = slog.NewTextHandler(out, opts)
	} else {
		base = slog.NewJSONHandler(out, opts)
	}

	h := NewRedactHandler(base)
	h = &traceHandler{inner: h}

	logger := slog.New(h).With("service", cfg.Service)
	slog.SetDefault(logger)
	return logger
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// traceHandler injects trace_id, span_id, request_id and tenant_id from the
// context so correlation does not depend on every call site remembering.
type traceHandler struct{ inner slog.Handler }

func (h *traceHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	if id := ctxkey.RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	if id, ok := ctxkey.TenantID(ctx); ok && id != "" {
		r.AddAttrs(slog.String("tenant_id", id))
	}
	return h.inner.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &traceHandler{inner: h.inner.WithAttrs(a)}
}

func (h *traceHandler) WithGroup(n string) slog.Handler {
	return &traceHandler{inner: h.inner.WithGroup(n)}
}

// Context values come from platform/ctxkey — one definition for the whole
// platform, so a request id set by HTTP middleware is visible here. See that
// package's doc for why duplicating the key type would silently break this.
