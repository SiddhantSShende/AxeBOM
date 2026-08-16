// Package errs implements the EncoreBOM error taxonomy.
//
// Contract: docs/02-CONTRACTS.md §9. That document is the SSOT; this package
// implements it and must not diverge.
//
// Two rules that are easy to get wrong and expensive to fix later:
//
//   - Code is the API contract, Message is not. Clients branch on Code, which
//     is stable forever. Message is human-facing and may be reworded freely.
//
//   - Cross-tenant access returns NOTFOUND_*, never PERM_*. A 403 confirms the
//     resource exists, which is itself a disclosure to anyone enumerating ids.
package errs

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Code is a stable, machine-readable error identifier. SCREAMING_SNAKE, grouped
// by prefix. Never reuse a code with a different meaning — add a new one.
type Code string

// Auth — 401.
const (
	AuthTokenExpired      Code = "AUTH_TOKEN_EXPIRED"
	AuthTokenInvalid      Code = "AUTH_TOKEN_INVALID"
	AuthInvalidCreds      Code = "AUTH_INVALID_CREDENTIALS"
	AuthMFARequired       Code = "AUTH_MFA_REQUIRED"
	AuthRefreshReused     Code = "AUTH_REFRESH_REUSED"
	AuthStateMismatch     Code = "AUTH_STATE_MISMATCH"
	AuthProviderError     Code = "AUTH_PROVIDER_ERROR"
	AuthTenantContextMiss Code = "AUTH_TENANT_CONTEXT_MISSING"
)

// Perm — 403. Note: never used for cross-tenant. See package doc.
const (
	PermRoleInsufficient Code = "PERM_ROLE_INSUFFICIENT"
	PermReportPrivate    Code = "PERM_REPORT_PRIVATE"
	PermNoMatrixEntry    Code = "PERM_NO_MATRIX_ENTRY"
)

// NotFound — 404. Also the correct response for cross-tenant access.
const (
	NotFoundProject  Code = "NOTFOUND_PROJECT"
	NotFoundScan     Code = "NOTFOUND_SCAN"
	NotFoundReport   Code = "NOTFOUND_REPORT"
	NotFoundCampaign Code = "NOTFOUND_CAMPAIGN"
	NotFoundUser     Code = "NOTFOUND_USER"
	NotFoundResource Code = "NOTFOUND_RESOURCE"
)

// Validation — 422.
const (
	ValidationFieldRequired Code = "VALIDATION_FIELD_REQUIRED"
	ValidationFieldInvalid  Code = "VALIDATION_FIELD_INVALID"
	ValidationFilterUnknown Code = "VALIDATION_FILTER_UNKNOWN"
	ValidationBodyMalformed Code = "VALIDATION_BODY_MALFORMED"
)

// Scan — 422 / 409.
const (
	ScanEngineCombinationInvalid Code = "SCAN_ENGINE_COMBINATION_INVALID"
	ScanAlreadyRunning           Code = "SCAN_ALREADY_RUNNING"
	ScanSourceUnreachable        Code = "SCAN_SOURCE_UNREACHABLE"
	ScanNoEnginesAvailable       Code = "SCAN_NO_ENGINES_AVAILABLE"
	ScanCancelled                Code = "SCAN_CANCELLED"
)

// Fetch — 422. The untrusted-input boundary; see docs/05-SECURITY-MODEL.md §4.
const (
	FetchURLSchemeForbidden    Code = "FETCH_URL_SCHEME_FORBIDDEN"
	FetchPrivateAddressBlocked Code = "FETCH_PRIVATE_ADDRESS_BLOCKED"
	FetchArchiveTooLarge       Code = "FETCH_ARCHIVE_TOO_LARGE"
	FetchInflationRatio        Code = "FETCH_INFLATION_RATIO_EXCEEDED"
	FetchTooManyFiles          Code = "FETCH_TOO_MANY_FILES"
	FetchPathTraversal         Code = "FETCH_PATH_TRAVERSAL"
	FetchSymlinkEscape         Code = "FETCH_SYMLINK_ESCAPE"
	FetchCloneTimeout          Code = "FETCH_CLONE_TIMEOUT"
	FetchAuthFailed            Code = "FETCH_AUTH_FAILED"
)

// Engine — usually a diagnostic attached to a result, not an HTTP response.
const (
	EngineUnavailable      Code = "ENGINE_UNAVAILABLE"
	EnginePartialEcosystem Code = "ENGINE_PARTIAL_ECOSYSTEM"
	EngineTimeout          Code = "ENGINE_TIMEOUT"
	EngineDBStale          Code = "ENGINE_DB_STALE"
	EngineOutputMalformed  Code = "ENGINE_OUTPUT_MALFORMED"
	EngineCrashed          Code = "ENGINE_CRASHED"
)

// Normalize — usually a diagnostic attached to a result.
const (
	NormalizeIdentityOpaque       Code = "NORMALIZE_IDENTITY_OPAQUE"
	NormalizeAliasClusterOversize Code = "NORMALIZE_ALIAS_CLUSTER_OVERSIZE"
	NormalizeLicenseAmbiguous     Code = "NORMALIZE_LICENSE_AMBIGUOUS"
	NormalizeNoVersionComparator  Code = "NORMALIZE_NO_VERSION_COMPARATOR"
	NormalizeComponentCapExceeded Code = "NORMALIZE_COMPONENT_CAP_EXCEEDED"
)

// Report — 422 / 500.
const (
	ReportTooLargeForPDF  Code = "REPORT_TOO_LARGE_FOR_PDF"
	ReportRenderFailed    Code = "REPORT_RENDER_FAILED"
	ReportSignatureFailed Code = "REPORT_SIGNATURE_FAILED"
	ReportShareExpired    Code = "REPORT_SHARE_EXPIRED"
	ReportShareRevoked    Code = "REPORT_SHARE_REVOKED"
)

// Rate — 429. Internal — 500.
const (
	RateLimitExceeded  Code = "RATE_LIMIT_EXCEEDED"
	InternalUnexpected Code = "INTERNAL_UNEXPECTED"
	InternalDependency Code = "INTERNAL_DEPENDENCY_UNAVAILABLE"
)

// statusOverride holds codes whose HTTP status differs from their prefix default.
var statusOverride = map[Code]int{
	ScanAlreadyRunning:    http.StatusConflict,
	ReportRenderFailed:    http.StatusInternalServerError,
	ReportSignatureFailed: http.StatusInternalServerError,
}

// prefixStatus maps a code prefix to its default HTTP status.
var prefixStatus = []struct {
	prefix string
	status int
}{
	{"AUTH_", http.StatusUnauthorized},
	{"PERM_", http.StatusForbidden},
	{"NOTFOUND_", http.StatusNotFound},
	{"VALIDATION_", http.StatusUnprocessableEntity},
	{"SCAN_", http.StatusUnprocessableEntity},
	{"FETCH_", http.StatusUnprocessableEntity},
	{"REPORT_", http.StatusUnprocessableEntity},
	{"RATE_", http.StatusTooManyRequests},
	{"ENGINE_", http.StatusInternalServerError},
	{"NORMALIZE_", http.StatusInternalServerError},
	{"INTERNAL_", http.StatusInternalServerError},
}

// HTTPStatus returns the HTTP status for a code. Unknown codes are 500 —
// failing closed is correct here: a code nobody registered should not
// accidentally render as a 2xx or leak as a 404.
func (c Code) HTTPStatus() int {
	if s, ok := statusOverride[c]; ok {
		return s
	}
	for _, p := range prefixStatus {
		if strings.HasPrefix(string(c), p.prefix) {
			return p.status
		}
	}
	return http.StatusInternalServerError
}

// Detail is a structured hint accompanying an error. Must never contain
// secrets, credentials, or content read from a scanned repository.
type Detail map[string]any

// Error is the canonical EncoreBOM error.
type Error struct {
	Code    Code
	Message string
	Details []Detail
	// Err is the wrapped cause. It is available to logs via errors.Unwrap but
	// is NEVER serialized to a client — internal causes leak implementation
	// detail and sometimes credentials.
	Err error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// HTTPStatus implements the status lookup for this error's code.
func (e *Error) HTTPStatus() int { return e.Code.HTTPStatus() }

// New builds an error from a code and message.
func New(code Code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// Newf builds an error with a formatted message.
func Newf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap attaches a cause to a new error.
func Wrap(err error, code Code, msg string) *Error {
	return &Error{Code: code, Message: msg, Err: err}
}

// WithDetail appends a structured detail and returns the error for chaining.
func (e *Error) WithDetail(d Detail) *Error {
	e.Details = append(e.Details, d)
	return e
}

// From extracts an *Error from any error. A non-EncoreBOM error becomes
// INTERNAL_UNEXPECTED with a generic message, so an unhandled error can never
// leak an internal string to a client.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{
		Code:    InternalUnexpected,
		Message: "an unexpected error occurred",
		Err:     err,
	}
}

// Is reports whether err carries the given code.
func Is(err error, code Code) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}
