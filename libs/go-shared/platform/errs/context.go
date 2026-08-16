package errs

import (
	"context"

	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
)

// These are thin re-exports of platform/ctxkey.
//
// Context values live in exactly one package because context keys compare by
// TYPE as well as value: two packages each defining their own key type produce
// values that are mutually invisible. The symptom is a request id that vanishes
// between the HTTP layer and the logger. See ctxkey's package doc.

// WithRequestID attaches a request id to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return ctxkey.WithRequestID(ctx, id)
}

// RequestIDFromContext returns the request id, or "" if unset.
func RequestIDFromContext(ctx context.Context) string {
	return ctxkey.RequestID(ctx)
}

// WithTenantID attaches the verified tenant id.
func WithTenantID(ctx context.Context, id string) context.Context {
	return ctxkey.WithTenantID(ctx, id)
}

// TenantIDFromContext returns the tenant id and whether it was present.
func TenantIDFromContext(ctx context.Context) (string, bool) {
	return ctxkey.TenantID(ctx)
}
