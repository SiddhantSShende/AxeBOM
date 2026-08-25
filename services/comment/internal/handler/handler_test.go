package handler

import (
	"errors"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/comment/internal/store"
)

// TestMapStoreErrDistinguishesNotFoundFromNotOwner is the one property that
// matters most in this package: a same-tenant caller editing somebody else's
// comment must get 403 (PermCommentNotOwner), and everything RLS or the
// nesting rules already ruled out must get 404 or 422 — never the other way
// around. Getting this backwards either leaks that a cross-tenant id exists
// (403 where 404 is required) or hides a real permission failure behind a
// misleading "not found".
func TestMapStoreErrDistinguishesNotFoundFromNotOwner(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   errs.Code
		wantStatus int
	}{
		{"not owner is 403", store.ErrNotOwner, errs.PermCommentNotOwner, 403},
		{"not found is 404", store.ErrNotFound, errs.NotFoundResource, 404},
		{"unknown parent is 422", store.ErrParentNotFound, errs.ValidationFieldInvalid, 422},
		{"cross-report parent is 422", store.ErrParentCrossReport, errs.ValidationFieldInvalid, 422},
		{"depth exceeded is 422", store.ErrDepthExceeded, errs.ValidationFieldInvalid, 422},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := mapStoreErr(tt.err)
			e := errs.From(mapped)
			if e.Code != tt.wantCode {
				t.Errorf("code = %s, want %s", e.Code, tt.wantCode)
			}
			if status := e.HTTPStatus(); status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
		})
	}
}

func TestMapStoreErrPassesThroughUnknownErrors(t *testing.T) {
	original := errs.New(errs.InternalUnexpected, "boom")
	got := mapStoreErr(original)
	if !errors.Is(got, original) {
		t.Errorf("mapStoreErr changed an error it does not recognise: got %v, want %v", got, original)
	}
}
