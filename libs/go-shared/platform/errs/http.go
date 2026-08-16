package errs

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// DocsBaseURL is where error-code documentation lives. The `docs` field in
// every error response points here so a developer hitting an unfamiliar code
// has somewhere to go.
var DocsBaseURL = "https://docs.encorebom.io/errors/"

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

	// 5xx is our fault and is logged at error; 4xx is the caller's and is logged
	// at debug so a scanner hammering 404s cannot flood the error log.
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
		slog.DebugContext(r.Context(), e.Message, logAttrs...)
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
