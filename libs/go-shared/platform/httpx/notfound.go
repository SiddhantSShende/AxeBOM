package httpx

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// NotFound answers unmatched routes with the canonical error shape.
//
// Without this, http.ServeMux answers with its own `text/plain` body:
//
//	404 page not found
//
// which violates docs/02-CONTRACTS.md §9 — every error carries a stable machine
// `code`, and clients branch on it. A client that receives plain text where it
// expects JSON fails in a way that looks like a network fault rather than a
// routing mistake.
//
// It also matters for the tenancy rule in docs/05-SECURITY-MODEL.md §2: a
// cross-tenant fetch must be indistinguishable from an ordinary not-found. If
// unmatched routes return one 404 shape and cross-tenant returns another, the
// difference is an oracle for probing which resource ids exist.
//
// Mount as the mux's catch-all:
//
//	mux.HandleFunc("/", httpx.NotFound)
func NotFound(w http.ResponseWriter, r *http.Request) {
	errs.Write(w, r, errs.New(errs.NotFoundResource, "no such endpoint"))
}

// MethodNotAllowed answers a known path with an unsupported method.
//
// Go's ServeMux emits 405 automatically when a pattern matches the path but not
// the method, so this is only needed for hand-rolled routing.
func MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	errs.Write(w, r, errs.New(errs.ValidationFieldInvalid, "method not allowed for this endpoint"))
}
