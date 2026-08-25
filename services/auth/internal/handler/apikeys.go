package handler

import (
	"net/http"
	"time"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/auth/internal/service"
)

// ---------------------------------------------------------------------------
// API keys
//
// ⚠ AUTHENTICATED THE ZITADEL WAY, UNLIKE EVERY OTHER ROUTE IN THIS FILE.
// register/login/refresh/invitations predate ZITADEL and still run on the
// local issuer (Config.issuer); a person managing their tenant's API keys
// today signs in through ZITADEL like every other screen, so these three
// routes are mounted with oidcauth.Guard instead — see routes.go.
// ---------------------------------------------------------------------------

type apiKeyResponse struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	KeyID      string   `json:"key_id"`
	Scopes     []string `json:"scopes"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at"`
	LastUsedAt *string  `json:"last_used_at,omitempty"`
	RevokedAt  *string  `json:"revoked_at,omitempty"`

	// Key is the plaintext credential.
	//
	// ⚠ PRESENT ONLY IN THE RESPONSE THAT CREATES IT. It is never stored and
	// can never be recovered — a customer who loses it mints a new one, which
	// is safe; showing it again is not.
	Key string `json:"key,omitempty"`
}

func toAPIKeyResponse(k auth.APIKey) apiKeyResponse {
	resp := apiKeyResponse{
		ID:        k.ID,
		Name:      k.Name,
		KeyID:     k.KeyID,
		Scopes:    auth.ScopeStrings(k.Scopes),
		CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: k.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if k.LastUsed != nil {
		s := k.LastUsed.UTC().Format(time.RFC3339)
		resp.LastUsedAt = &s
	}
	if k.RevokedAt != nil {
		s := k.RevokedAt.UTC().Format(time.RFC3339)
		resp.RevokedAt = &s
	}
	return resp
}

type createAPIKeyRequest struct {
	Name    string   `json:"name"`
	Scopes  []string `json:"scopes"`
	TTLDays int      `json:"ttl_days,omitempty"`
}

// CreateAPIKey handles POST /v1/api-keys.
func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req createAPIKeyRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	minted, err := h.svc.CreateAPIKey(r.Context(), tenantID, service.CreateAPIKeyRequest{
		Name:      req.Name,
		Scopes:    req.Scopes,
		TTLDays:   req.TTLDays,
		CreatedBy: ctxkey.UserID(r.Context()),
	})
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	resp := toAPIKeyResponse(minted.Record)
	resp.Key = minted.Key
	errs.WriteJSON(w, http.StatusCreated, resp)
}

// ListAPIKeys handles GET /v1/api-keys.
func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	keys, err := h.svc.ListAPIKeys(r.Context(), tenantID)
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	out := make([]apiKeyResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAPIKeyResponse(k))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"api_keys": out})
}

// RevokeAPIKey handles DELETE /v1/api-keys/{id}.
func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	if err := h.svc.RevokeAPIKey(r.Context(), tenantID, r.PathValue("id")); err != nil {
		errs.Write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
