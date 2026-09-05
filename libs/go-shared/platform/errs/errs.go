// Package errs implements the AxeBOM error taxonomy.
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

	// AuthOrgAmbiguous means the caller holds a role in more than one
	// organisation and named none of them.
	//
	// ⚠ IT IS AN ERROR RATHER THAN A DEFAULT ON PURPOSE. Picking one would
	// make the answer depend on map iteration order, so a consultant working
	// for two customers would see whichever tenant's data came up first — a
	// cross-tenant read that looks like a normal response. The client selects,
	// and this code is what tells it to.
	//
	// ⚠ IT ANSWERS 409, NOT 401 — see statusOverride. The token is valid and
	// re-authenticating would produce an identical one.
	AuthOrgAmbiguous Code = "AUTH_ORG_AMBIGUOUS"

	// AuthOrgNameTaken means a self-service signup (services/gateway/internal/
	// signup) asked for an organisation name that already exists.
	//
	// ⚠ 409, NOT 422 — see statusOverride. The request is well-formed; it
	// conflicts with existing state, not with a validation rule.
	AuthOrgNameTaken Code = "AUTH_ORG_NAME_TAKEN"

	// AuthEmailTaken means a self-service signup asked for an email that
	// already has an account, in this organisation or any other. Also 409.
	AuthEmailTaken Code = "AUTH_EMAIL_TAKEN"
)

// Perm — 403. Note: never used for cross-tenant. See package doc.
const (
	PermRoleInsufficient Code = "PERM_ROLE_INSUFFICIENT"
	PermReportPrivate    Code = "PERM_REPORT_PRIVATE"
	PermNoMatrixEntry    Code = "PERM_NO_MATRIX_ENTRY"

	// PermNoRoleInOrg means the identity provider authenticated the caller but
	// granted them nothing in the organisation they asked for.
	PermNoRoleInOrg Code = "PERM_NO_ROLE_IN_ORG"

	// PermCommentNotOwner means the caller holds a role sufficient to edit or
	// delete SOME comment (the authz matrix grants comment:update/delete to
	// every Viewer) but is not the author of THIS one.
	//
	// ⚠ THIS IS NOT THE CROSS-TENANT CASE. RLS already makes another tenant's
	// comment invisible, which is a 404 (see NotFoundResource). This code fires
	// only within the caller's own tenant, on a real row they can see but did
	// not write — a genuine 403, checked by the handler because the authz
	// matrix has no concept of row ownership (libs/go-shared/authz/matrix.go).
	PermCommentNotOwner Code = "PERM_COMMENT_NOT_OWNER"
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

// Project — 409.
const (
	// ProjectDeviceIdentifierTaken means a serial number or asset tag is
	// already registered to another device in this tenant.
	//
	// ⚠ 409, NOT 422. The request is well-formed and the value is legal; it
	// conflicts with a row that already exists. A 422 would tell the caller to
	// fix their input when the right answer is usually "you already registered
	// this unit" — a serial number identifies one physical device, so a
	// duplicate is a statement about the world, not about the form.
	ProjectDeviceIdentifierTaken Code = "PROJECT_DEVICE_IDENTIFIER_TAKEN"

	// ProjectNotClassified means an operation specific to one BOM type was
	// attempted on a project not classified for that type — registering a
	// hardware device against a project that produces only an SBOM, for
	// instance.
	//
	// ⚠ 409, NOT 422, ON THE SAME REASONING AS THE CODE ABOVE. The body is
	// well-formed and every field in it is legal; what is wrong is the state of
	// the TARGET. Telling the caller to fix a field would be misleading — the
	// fix is to classify the project, or to address a different one.
	//
	// ⚠ AND NOT 404. The project exists and the caller may see it; pretending
	// otherwise would send someone hunting for a missing project. That is the
	// opposite of the cross-tenant case, where 404 is required precisely
	// BECAUSE the caller must not learn the resource exists (invariant 6).
	ProjectNotClassified Code = "PROJECT_NOT_CLASSIFIED"
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

	// ScanFamilyNotDirectlyScannable means every registered engine for a
	// requested family is metadata-only (policy.Engine.Derived or
	// .RequiresImport) — QBOM alone today, derived from CBOM discovery.
	//
	// ⚠ THIS COMMENT USED TO NAME HBOM TOO, AND STOPPED BEING TRUE WHEN
	// hbom-ecad SHIPPED. That engine parses committed KiCad, Altium and OrCAD
	// design files and has a live worker, so the family is scannable and is no
	// longer in familyRedirect. QBOM still has no worker by design.
	//
	// Resolving a genuinely unscannable family into a scan publishes a job
	// nothing ever acks. Rejected at create time, never discovered at worker
	// time.
	ScanFamilyNotDirectlyScannable Code = "SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE"
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

	// FetchUnsupportedArchiveFormat means an uploaded source_archive's filename
	// extension does not match any format ExtractArchive knows how to open
	// safely (.zip, .tar, .tar.gz, .tar.zst). Refused rather than guessed at:
	// sniffing magic bytes to "be helpful" is exactly how a parser ends up
	// extracting a format it never validated the guards for.
	FetchUnsupportedArchiveFormat Code = "FETCH_UNSUPPORTED_ARCHIVE_FORMAT"
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
	ReportTooLargeForPDF Code = "REPORT_TOO_LARGE_FOR_PDF"
	// ReportTooLargeForXLSX is a worksheet row-limit overflow. Distinct from
	// the PDF cap: that one is a product decision about page count, this one
	// is a hard format limit, and the remedy differs — JSON, not a narrower
	// BOM level.
	ReportTooLargeForXLSX Code = "REPORT_TOO_LARGE_FOR_XLSX"
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
	// ⚠ NOT 401, DESPITE THE AUTH_ PREFIX.
	//
	// The caller authenticated perfectly; they just hold roles in more than one
	// organisation and named none. A 401 would tell every generic client — ours
	// included — to discard the token and start a login, which returns an
	// identical token and asks the identical question. 409 says "your request
	// conflicts with the state of your account", which is exactly the case, and
	// keeps the retry loop from existing at all.
	AuthOrgAmbiguous:   http.StatusConflict,
	AuthOrgNameTaken:   http.StatusConflict,
	AuthEmailTaken:     http.StatusConflict,
	ScanAlreadyRunning: http.StatusConflict,
	// See the code's own comment: a duplicate serial is a conflict with the
	// world, not a malformed field.
	ProjectDeviceIdentifierTaken: http.StatusConflict,
	ProjectNotClassified:         http.StatusConflict,
	ReportRenderFailed:           http.StatusInternalServerError,
	ReportSignatureFailed:        http.StatusInternalServerError,
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

// Error is the canonical AxeBOM error.
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

// From extracts an *Error from any error. A non-AxeBOM error becomes
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
