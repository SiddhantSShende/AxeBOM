package errs

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// DocsBaseURL is where error-code documentation lives. The `docs` field in
// every error response points here so a developer hitting an unfamiliar code
// has somewhere to go.
var DocsBaseURL = "https://docs.axebom.io/errors/"

// wireError is the serialized shape. Contract: docs/02-CONTRACTS.md §9.
//
//	{"error": {"code","message","details","request_id","docs"}}
type wireError struct {
	Error wireBody `json:"error"`
}

type wireBody struct {
	Code      Code     `json:"code"`
	Message   string   `json:"message"`
	Details   []Detail `json:"details,omitempty"`
	RequestID string   `json:"request_id,omitempty"`
	Docs      string   `json:"docs,omitempty"`
}

// Write renders err as the canonical JSON error response.
//
// The wrapped cause is logged, never serialized. Internal causes leak
// implementation detail and occasionally credentials, so the client sees only
// the code and the human message.
func Write(w http.ResponseWriter, r *http.Request, err error) {
	e := From(err)
	status := e.HTTPStatus()
	reqID := RequestIDFromContext(r.Context())

	// ⚠ EVERY ENVELOPE THIS FUNCTION WRITES IS LOGGED, 4xx INCLUDED.
	//
	// 4xx used to be logged at DEBUG, and services run at info — so the whole
	// class was invisible. That is not merely thin logging: the body written
	// immediately below carries a request_id, and the UI renders it under
	// "quote the code and request id above — they are what identifies this
	// exact failure in our logs" (frontend/src/components/States.tsx). For
	// every 400, 401, 403, 404, 409 and 422 the product has ever returned,
	// that sentence was false, and the id it told the user to quote appeared
	// in no log line anywhere. A support instruction that cannot be honoured
	// is worse than none: it sends someone to collect evidence that was
	// discarded before they read the message.
	//
	// The flood the old comment guarded against is real but is the rate
	// limiter's problem, not something to solve by dropping the record: a
	// scanner hammering 404s costs exactly as many lines as one hammering
	// 200s, which are logged at info already.
	//
	// WARN, not INFO, for 4xx: it is the caller's fault rather than ours, so
	// it does not belong in the error log next to the failures we must act on,
	// but it is the line somebody goes looking for with an id in their hand.
	logAttrs := []any{
		"code", string(e.Code),
		"status", status,
		"request_id", reqID,
		"method", r.Method,
		"path", r.URL.Path,
	}
	if e.Err != nil {
		logAttrs = append(logAttrs, "cause", e.Err.Error())
	}
	if status >= 500 {
		slog.ErrorContext(r.Context(), e.Message, logAttrs...)
	} else {
		slog.WarnContext(r.Context(), e.Message, logAttrs...)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	body := wireError{Error: wireBody{
		Code:      e.Code,
		Message:   e.Message,
		Details:   e.Details,
		RequestID: reqID,
		Docs:      DocsBaseURL + string(e.Code),
	}}
	if encErr := json.NewEncoder(w).Encode(body); encErr != nil {
		// Headers are already sent; nothing to do but record it.
		slog.ErrorContext(r.Context(), "failed to encode error response",
			"request_id", reqID, "cause", encErr.Error())
	}
}

// WriteJSON renders a successful JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode response", "cause", err.Error())
	}
}
