// Package ctxkey holds the request-scoped context values shared across the
// platform packages.
//
// This package exists to prevent a specific and easy bug: if errs and obs each
// define their own unexported key type, a request id set by HTTP middleware is
// invisible to the logger, because context keys compare by TYPE as well as
// value. The symptom is silently missing correlation ids in production logs —
// which you notice at exactly the wrong moment.
//
// One definition, imported by everyone. This package imports nothing but
// context, so it can never create a cycle.
package ctxkey

import "context"

type key int

const (
	requestID key = iota
	tenantID
	userID
	role
	sessionID
)

// WithRequestID attaches a request id.
//
// Set once by httpx middleware at the edge and propagated everywhere — into
// logs, traces and error responses. It is what support asks the user for.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestID, id)
}

// RequestID returns the request id, or "".
func RequestID(ctx context.Context) string { return str(ctx, requestID) }

// WithTenantID attaches the verified tenant id.
//
// This value comes from a verified JWT and nowhere else — never a header,
// query parameter, or body field. See docs/05-SECURITY-MODEL.md §2.
func WithTenantID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, tenantID, id)
}

// TenantID returns the tenant id and whether it was present.
//
// Callers must treat !ok as fatal for any tenant-scoped operation. The database
// layer additionally fails closed via RLS, but a missing tenant here means the
// request bypassed auth middleware — a bug worth surfacing loudly rather than
// defaulting to anything.
func TenantID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantID).(string)
	return v, ok
}

// WithUserID attaches the authenticated user id.
func WithUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, userID, id)
}

// UserID returns the user id, or "".
func UserID(ctx context.Context) string { return str(ctx, userID) }

// WithRole attaches the caller's role within the tenant.
func WithRole(ctx context.Context, r string) context.Context {
	return context.WithValue(ctx, role, r)
}

// Role returns the caller's role, or "".
func Role(ctx context.Context) string { return str(ctx, role) }

// WithSessionID attaches the session the access token was minted from.
//
// Logout needs it: revoking "the current session" requires knowing which one
// that is, and asking the client to name it would let any caller revoke
// somebody else's.
func WithSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionID, id)
}

// SessionID returns the session id, or "".
func SessionID(ctx context.Context) string { return str(ctx, sessionID) }

func str(ctx context.Context, k key) string {
	if v, ok := ctx.Value(k).(string); ok {
		return v
	}
	return ""
}
