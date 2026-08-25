// Package handler is the comment service's HTTP surface.
//
// Handlers translate; the store enforces ownership and depth. The one thing
// this package owns outright is turning a store error into the right HTTP
// response — in particular, distinguishing "you cannot see this" (404,
// RLS-backed) from "you can see this but did not write it" (403,
// PermCommentNotOwner) — see mapStoreErr.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/comment/internal/store"
)

// deletedPlaceholder is what a soft-deleted comment's body becomes on the
// wire. See toCommentResponse.
const deletedPlaceholder = "[deleted]"

const maxRequestBody = 64 << 10

// Store is the persistence this handler needs. Matches *store.Store's
// signatures exactly, so the real store satisfies it with no adapter — the
// interface exists purely so a handler test can substitute a fake without a
// live database, the same shape notification's handler.Store interface uses.
type Store interface {
	Create(ctx context.Context, tenantID, reportID, userID, parentID, body string) (store.Comment, error)
	List(ctx context.Context, tenantID, reportID string) ([]store.Comment, error)
	Update(ctx context.Context, tenantID, commentID, userID, body string) (store.Comment, error)
	Delete(ctx context.Context, tenantID, commentID, userID string) error
}

// Handler serves the comment endpoints.
type Handler struct {
	store Store
}

// New builds a handler.
func New(s Store) *Handler { return &Handler{store: s} }

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

// commentResponse is the wire shape of one comment.
type commentResponse struct {
	ID       string `json:"id"`
	ReportID string `json:"report_id"`
	UserID   string `json:"user_id"`
	// ParentID is omitted (not null-valued) for a top-level comment — omitempty
	// on a string zero value gives exactly that.
	ParentID string `json:"parent_id,omitempty"`
	Depth    int    `json:"depth"`
	Body     string `json:"body"`

	// Mentions is computed at READ TIME from Body, never stored, and never
	// resolved to a real user — see ParseMentions's package doc for why this
	// is scoped down to raw handle tokens.
	Mentions []string `json:"mentions"`

	Edited   bool   `json:"edited"`
	EditedAt string `json:"edited_at,omitempty"`

	// Deleted and the placeholder Body travel together: a client that only
	// checked one would either show "[deleted]" without knowing why line-item
	// controls (edit/delete) should be hidden, or hide controls without
	// explaining the blank body.
	Deleted bool `json:"deleted"`

	CreatedAt string `json:"created_at"`
}

func toCommentResponse(c store.Comment) commentResponse {
	deleted := c.DeletedAt != nil

	// ⚠ THE PLACEHOLDER IS APPLIED HERE, NOT IN THE STORE. The store returns
	// the real body — deliberately, it is the audit trail (see
	// store.Comment's doc) — and this is the one place that decides a deleted
	// comment's content stops being served to clients, while its position in
	// the thread (parent_id, depth) is preserved so live replies are never
	// orphaned in the UI.
	body := c.Body
	var mentions []string
	if deleted {
		body = deletedPlaceholder
		mentions = []string{}
	} else {
		mentions = ParseMentions(c.Body)
	}

	out := commentResponse{
		ID: c.ID, ReportID: c.ReportID, UserID: c.UserID, ParentID: c.ParentID,
		Depth: c.Depth, Body: body, Mentions: mentions, Deleted: deleted,
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
	}
	if c.EditedAt != nil {
		out.Edited = true
		out.EditedAt = c.EditedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// List handles GET /v1/comments?report_id={id}.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	reportID := strings.TrimSpace(r.URL.Query().Get("report_id"))
	if reportID == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired,
			"the report_id query parameter is required"))
		return
	}

	comments, err := h.store.List(r.Context(), tenantID, reportID)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	items := make([]commentResponse, 0, len(comments))
	for _, c := range comments {
		items = append(items, toCommentResponse(c))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"comments": items})
}

type createCommentRequest struct {
	ReportID string `json:"report_id"`
	ParentID string `json:"parent_id,omitempty"`
	Body     string `json:"body"`
}

// Create handles POST /v1/comments.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req createCommentRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}
	req.ReportID = strings.TrimSpace(req.ReportID)
	req.ParentID = strings.TrimSpace(req.ParentID)
	req.Body = strings.TrimSpace(req.Body)

	if req.ReportID == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired, "report_id is required"))
		return
	}
	if req.Body == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired, "body must not be empty"))
		return
	}

	userID := ctxkey.UserID(r.Context())
	c, err := h.store.Create(r.Context(), tenantID, req.ReportID, userID, req.ParentID, req.Body)
	if err != nil {
		errs.Write(w, r, mapStoreErr(err))
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toCommentResponse(c))
}

type updateCommentRequest struct {
	Body string `json:"body"`
}

// Update handles PUT /v1/comments/{id}.
//
// ⚠ 403, NOT 404, WHEN THE CALLER IS THE WRONG AUTHOR — mapStoreErr is what
// makes that distinction rather than this handler.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req updateCommentRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired, "body must not be empty"))
		return
	}

	userID := ctxkey.UserID(r.Context())
	c, err := h.store.Update(r.Context(), tenantID, r.PathValue("id"), userID, body)
	if err != nil {
		errs.Write(w, r, mapStoreErr(err))
		return
	}
	errs.WriteJSON(w, http.StatusOK, toCommentResponse(c))
}

// Delete handles DELETE /v1/comments/{id}. Soft delete — see store.Delete.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	userID := ctxkey.UserID(r.Context())
	if err := h.store.Delete(r.Context(), tenantID, r.PathValue("id"), userID); err != nil {
		errs.Write(w, r, mapStoreErr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mapStoreErr turns a store sentinel into the canonical taxonomy.
//
// ⚠ ErrNotOwner IS THE ONLY ONE THAT BECOMES A 403. Every other store error
// here is either a 404 (the row is not visible to this tenant, or is already
// gone — RLS made those the same case before this ever ran, CLAUDE.md
// invariant 6) or a 422 (the request describes an impossible thread shape).
// Getting ErrNotOwner and ErrNotFound swapped would either leak that a
// cross-tenant id exists (403 where 404 is required) or hide a same-tenant
// permission failure behind a confusing "not found" for a comment the caller
// can plainly see in the list they just loaded.
func mapStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errs.New(errs.NotFoundResource, "no such comment")
	case errors.Is(err, store.ErrNotOwner):
		return errs.New(errs.PermCommentNotOwner,
			"you can only edit or delete your own comments")
	case errors.Is(err, store.ErrParentNotFound):
		return errs.New(errs.ValidationFieldInvalid,
			"parent_id does not refer to a comment you can see")
	case errors.Is(err, store.ErrParentCrossReport):
		return errs.New(errs.ValidationFieldInvalid,
			"a comment cannot be threaded onto a different report's comment")
	case errors.Is(err, store.ErrDepthExceeded):
		return errs.Newf(errs.ValidationFieldInvalid,
			"this thread has reached its maximum depth (%d)", store.MaxDepth)
	default:
		return err
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errs.New(errs.ValidationBodyMalformed, "request body is empty")
		}
		return errs.Wrap(err, errs.ValidationBodyMalformed, "request body is not valid JSON")
	}
	return nil
}
