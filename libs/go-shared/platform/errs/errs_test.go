package errs

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCodeHTTPStatus(t *testing.T) {
	tests := []struct {
		code Code
		want int
	}{
		{AuthTokenExpired, http.StatusUnauthorized},
		{AuthInvalidCreds, http.StatusUnauthorized},
		{PermRoleInsufficient, http.StatusForbidden},
		{NotFoundProject, http.StatusNotFound},
		{ValidationFieldRequired, http.StatusUnprocessableEntity},
		{ScanEngineCombinationInvalid, http.StatusUnprocessableEntity},
		{FetchURLSchemeForbidden, http.StatusUnprocessableEntity},
		{ReportTooLargeForPDF, http.StatusUnprocessableEntity},
		{RateLimitExceeded, http.StatusTooManyRequests},
		{EngineUnavailable, http.StatusInternalServerError},
		{NormalizeIdentityOpaque, http.StatusInternalServerError},
		{InternalUnexpected, http.StatusInternalServerError},

		// Overrides: status differs from the prefix default.
		{ScanAlreadyRunning, http.StatusConflict},
		{ReportRenderFailed, http.StatusInternalServerError},
		{ReportSignatureFailed, http.StatusInternalServerError},

		// An unregistered code must fail closed at 500, never 2xx and never 404.
		{Code("WAT_UNKNOWN"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		if got := tt.code.HTTPStatus(); got != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.code, got, tt.want)
		}
	}
}

// Every exported code must map to a status via its prefix. A code added without
// a registered prefix silently becomes a 500, which is safe but wrong — this
// catches the typo at build time rather than in production.
func TestAllPrefixesRegistered(t *testing.T) {
	all := []Code{
		AuthTokenExpired, PermRoleInsufficient, NotFoundProject,
		ValidationFieldRequired, ScanEngineCombinationInvalid,
		FetchURLSchemeForbidden, EngineUnavailable, NormalizeIdentityOpaque,
		ReportTooLargeForPDF, RateLimitExceeded, InternalUnexpected,
	}
	for _, c := range all {
		matched := false
		for _, p := range prefixStatus {
			if strings.HasPrefix(string(c), p.prefix) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("code %s has no registered prefix", c)
		}
	}
}

func TestFromHidesInternalCause(t *testing.T) {
	// A plain error must never surface its text to a client.
	raw := errors.New("pq: password authentication failed for user \"encorebom\"")
	e := From(raw)

	if e.Code != InternalUnexpected {
		t.Fatalf("code = %s, want %s", e.Code, InternalUnexpected)
	}
	if strings.Contains(e.Message, "password") {
		t.Fatalf("internal cause leaked into client message: %q", e.Message)
	}
	if !errors.Is(e, raw) {
		t.Error("wrapped cause should remain available to logs via errors.Is")
	}
}

func TestWriteShape(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/projects/abc", nil)
	req = req.WithContext(WithRequestID(req.Context(), "req-123"))

	err := New(ScanEngineCombinationInvalid,
		"cbomkit-theia cannot process source kind 'image' for this project").
		WithDetail(Detail{"engine": "cbomkit-theia", "source_kind": "image"})

	Write(rec, req, err)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}

	var got wireError
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got.Error.Code != ScanEngineCombinationInvalid {
		t.Errorf("code = %s", got.Error.Code)
	}
	if got.Error.RequestID != "req-123" {
		t.Errorf("request_id = %q, want req-123", got.Error.RequestID)
	}
	if got.Error.Docs != DocsBaseURL+string(ScanEngineCombinationInvalid) {
		t.Errorf("docs = %q", got.Error.Docs)
	}
	if len(got.Error.Details) != 1 || got.Error.Details[0]["engine"] != "cbomkit-theia" {
		t.Errorf("details = %+v", got.Error.Details)
	}
}

// The wrapped cause must not appear in the response body under any circumstance.
func TestWriteDoesNotLeakCause(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	secret := "postgres://user:hunter2@db:5432/encorebom"
	Write(rec, req, Wrap(errors.New(secret), InternalDependency, "database unavailable"))

	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("wrapped cause leaked into response body: %s", rec.Body.String())
	}
}

func TestIs(t *testing.T) {
	e := New(NotFoundProject, "no such project")
	if !Is(e, NotFoundProject) {
		t.Error("Is should match the code")
	}
	if Is(e, NotFoundReport) {
		t.Error("Is should not match a different code")
	}
	if Is(errors.New("plain"), NotFoundProject) {
		t.Error("Is should not match a non-Error")
	}
}

func TestTenantContext(t *testing.T) {
	ctx := t.Context()
	if _, ok := TenantIDFromContext(ctx); ok {
		t.Fatal("empty context must not yield a tenant id")
	}
	ctx = WithTenantID(ctx, "tenant-a")
	got, ok := TenantIDFromContext(ctx)
	if !ok || got != "tenant-a" {
		t.Fatalf("got (%q,%v), want (tenant-a,true)", got, ok)
	}
}
