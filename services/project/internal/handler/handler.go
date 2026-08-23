// Package handler is the project service's HTTP surface.
//
// Handlers translate; the rules live in internal/service. The one thing they
// own outright is the tenant: it comes from auth.RequireTenant, which reads the
// VERIFIED token in the context and nothing else. A project id in the path is
// never enough to identify a resource — it is always (tenant, id).
package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/auth"
	"github.com/encorebom/encorebom/libs/go-shared/model"
	"github.com/encorebom/encorebom/libs/go-shared/platform/ctxkey"
	"github.com/encorebom/encorebom/libs/go-shared/platform/errs"
	"github.com/encorebom/encorebom/services/project/internal/github"
	"github.com/encorebom/encorebom/services/project/internal/service"
	"github.com/encorebom/encorebom/services/project/internal/store"
)

// Handler serves the project endpoints.
type Handler struct {
	svc *service.Service
	gh  *github.Client
}

func New(svc *service.Service, gh *github.Client) *Handler {
	return &Handler{svc: svc, gh: gh}
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type ownerDTO struct {
	Name   string `json:"name,omitempty"`
	Email  string `json:"email,omitempty"`
	GitHub string `json:"github,omitempty"`
	Phone  string `json:"phone,omitempty"`
}

type projectRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	SourceType      string   `json:"source_type,omitempty"`
	SDLCStage       string   `json:"sdlc_stage,omitempty"`
	ValidityStart   *string  `json:"validity_start,omitempty"`
	ValidityEnd     *string  `json:"validity_end,omitempty"`
	Owner           ownerDTO `json:"owner"`
	Classifications []string `json:"classifications"`
}

type projectResponse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	SourceType      string   `json:"source_type"`
	SDLCStage       string   `json:"sdlc_stage"`
	ValidityStart   *string  `json:"validity_start,omitempty"`
	ValidityEnd     *string  `json:"validity_end,omitempty"`
	Owner           ownerDTO `json:"owner"`
	Classifications []string `json:"classifications"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// practicesResponse carries the six values AND the compliance gap.
//
// Returned together on purpose: a client that has to make a second call to
// learn a project is incomplete will not make it, and the gap will surface as a
// coverage surprise in a generated report instead.
type practicesResponse struct {
	Frequency     *string `json:"frequency"`
	Depth         *string `json:"depth"`
	KnownUnknowns *string `json:"known_unknowns"`
	Distribution  *string `json:"distribution"`
	AccessControl *string `json:"access_control"`
	ErrataPolicy  *string `json:"errata_policy"`

	Compliance complianceDTO `json:"compliance"`
}

type complianceDTO struct {
	Recorded int                   `json:"recorded"`
	Total    int                   `json:"total"`
	Complete bool                  `json:"complete"`
	Gaps     []service.PracticeGap `json:"gaps"`
	// Note explains what the numbers mean, so a client cannot render "2/6"
	// as a score without the reason it is not compliance.
	Note string `json:"note"`
}

type connectRequest struct {
	Provider       string `json:"provider"`
	RepoURL        string `json:"repo_url,omitempty"`
	RepoFullName   string `json:"repo_full_name,omitempty"`
	RepoExternalID string `json:"repo_external_id"`
	DefaultBranch  string `json:"default_branch,omitempty"`
	Token          string `json:"token,omitempty"`
}

type connectionResponse struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	RepoURL        string `json:"repo_url"`
	RepoExternalID string `json:"repo_external_id,omitempty"`
	DefaultBranch  string `json:"default_branch,omitempty"`
	// HasCredential reports whether a credential is stored. The REFERENCE is
	// deliberately not exposed: it is a path into the vault, and a client has
	// no use for it that is not also a way to probe it.
	HasCredential bool   `json:"has_credential"`
	CreatedAt     string `json:"created_at"`
}

type uploadResponse struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	SHA256           string `json:"sha256"`
	SizeBytes        int64  `json:"size_bytes"`
	OriginalFilename string `json:"original_filename,omitempty"`
	CreatedAt        string `json:"created_at"`
	// Extracted is always false and always present. It documents in the API
	// itself that this phase stores bytes and never opens them.
	Extracted bool `json:"extracted"`
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// Create handles POST /v1/projects.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req projectRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	start, err := parseDate(req.ValidityStart, "validity_start")
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	end, err := parseDate(req.ValidityEnd, "validity_end")
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	p, err := h.svc.Create(r.Context(), tenantID, ctxkey.UserID(r.Context()), service.CreateInput{
		Name: req.Name, Description: req.Description,
		SourceType: req.SourceType, SDLCStage: req.SDLCStage,
		ValidityStart: start, ValidityEnd: end,
		Owner:           store.Owner(req.Owner),
		Classifications: req.Classifications,
	})
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toProjectResponse(p))
}

// List handles GET /v1/projects.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	projects, err := h.svc.List(r.Context(), tenantID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	items := make([]projectResponse, 0, len(projects))
	for _, p := range projects {
		items = append(items, toProjectResponse(p))
	}

	// The cursor is the LAST id, because ids are UUIDv7 and therefore ordered.
	// Offset pagination would skip or repeat rows whenever a project is created
	// mid-listing.
	var next string
	if len(projects) > 0 && len(projects) == effectiveLimit(limit) {
		next = projects[len(projects)-1].ID
	}

	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"projects":    items,
		"next_cursor": next,
	})
}

func effectiveLimit(requested int) int {
	if requested <= 0 || requested > 200 {
		return 50
	}
	return requested
}

// Get handles GET /v1/projects/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	p, err := h.svc.Get(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toProjectResponse(p))
}

// Update handles PUT /v1/projects/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req projectRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}
	start, err := parseDate(req.ValidityStart, "validity_start")
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	end, err := parseDate(req.ValidityEnd, "validity_end")
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	p, err := h.svc.Update(r.Context(), tenantID, r.PathValue("id"), service.UpdateInput{
		Name: req.Name, Description: req.Description, SDLCStage: req.SDLCStage,
		ValidityStart: start, ValidityEnd: end,
		Owner:           store.Owner(req.Owner),
		Classifications: req.Classifications,
	})
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toProjectResponse(p))
}

// Delete handles DELETE /v1/projects/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	if err := h.svc.Delete(r.Context(), tenantID, r.PathValue("id")); err != nil {
		errs.Write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Practices
// ---------------------------------------------------------------------------

// GetPractices handles GET /v1/projects/{id}/practices.
func (h *Handler) GetPractices(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	report, err := h.svc.GetPractices(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toPracticesResponse(report))
}

// SetPractices handles PUT /v1/projects/{id}/practices.
func (h *Handler) SetPractices(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req struct {
		Frequency     *string `json:"frequency"`
		Depth         *string `json:"depth"`
		KnownUnknowns *string `json:"known_unknowns"`
		Distribution  *string `json:"distribution"`
		AccessControl *string `json:"access_control"`
		ErrataPolicy  *string `json:"errata_policy"`
	}
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	report, err := h.svc.SetPractices(r.Context(), tenantID, r.PathValue("id"),
		service.PracticesInput(req))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toPracticesResponse(report))
}

// ---------------------------------------------------------------------------
// Repository connections
// ---------------------------------------------------------------------------

// Connect handles POST /v1/projects/{id}/connections.
func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	var req connectRequest
	if err := decode(r, &req); err != nil {
		errs.Write(w, r, err)
		return
	}

	repoURL := req.RepoURL
	if repoURL == "" && req.RepoFullName != "" {
		built, err := github.RepoURLFor(req.RepoFullName)
		if err != nil {
			errs.Write(w, r, errs.New(errs.ValidationFieldInvalid, err.Error()))
			return
		}
		repoURL = built
	}

	conn, err := h.svc.Connect(r.Context(), tenantID, r.PathValue("id"), service.ConnectInput{
		Provider: req.Provider, RepoURL: repoURL,
		RepoExternalID: req.RepoExternalID, DefaultBranch: req.DefaultBranch,
		Token: req.Token,
	})
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toConnectionResponse(conn))
}

// ListConnections handles GET /v1/projects/{id}/connections.
func (h *Handler) ListConnections(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	conns, err := h.svc.ListConnections(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	items := make([]connectionResponse, 0, len(conns))
	for _, c := range conns {
		items = append(items, toConnectionResponse(c))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"connections": items})
}

// Source handles GET /v1/projects/{id}/source.
//
// ⚠ SERVICE PRINCIPALS ONLY, AND THAT IS THE POINT OF THE ENDPOINT.
//
// It returns `credential_ref` — a Vault PATH, which is a read primitive: the
// holder of a token scoped to the mount can exchange it for the repository
// token. The public connections endpoint deliberately returns only
// `has_credential: bool`, and this route would undo that if a person could
// reach it. The route is wrapped in auth.RequireService, which answers 404 to
// anyone else so the endpoint does not advertise itself.
//
// The only caller is the fetcher, which is the one component permitted to hold
// a git credential (ADR-0008).
func (h *Handler) Source(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	conns, err := h.svc.ListConnections(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	if len(conns) == 0 {
		// Not an internal error: a project with no repository connection is a
		// legitimate state (manual registration, upload-only). The fetcher
		// turns this into a stated reason on the scan rather than a crash.
		errs.Write(w, r, errs.New(errs.NotFoundResource,
			"the project has no repository connection to fetch from"))
		return
	}

	// The FIRST connection. Multi-repository projects are not modelled — the
	// table is UNIQUE(project_id, repo_url) so several rows are possible, but
	// nothing upstream chooses between them, and silently picking one while
	// pretending otherwise would be worse than the explicit limitation.
	c := conns[0]
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"connection_id":  c.ID,
		"provider":       c.Provider,
		"repo_url":       c.RepoURL,
		"default_branch": c.DefaultBranch,
		// The PATH, which the caller re-derives from (tenant, kind,
		// connection_id) and uses only as a mismatch check. vault.Get refuses a
		// ref that does not match its owner before Vault is contacted, so a
		// tampered row cannot become a read of somebody else's secret.
		"credential_ref": c.CredentialRef,
	})
}

// ListRepos handles GET /v1/github/repos.
//
// The token comes from the Authorization-bearing GitHub session, supplied by
// the caller per request. It is used and discarded — this endpoint stores
// nothing.
func (h *Handler) ListRepos(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}

	token := strings.TrimSpace(r.Header.Get("X-GitHub-Token"))
	if token == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired,
			"supply the GitHub token in the X-GitHub-Token header"))
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))

	result, err := h.gh.ListRepos(r.Context(), token, github.ListOptions{
		Query:           r.URL.Query().Get("q"),
		Page:            page,
		PerPage:         perPage,
		IncludeArchived: r.URL.Query().Get("include_archived") == "true",
	})
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

// Upload handles POST /v1/projects/{id}/uploads as multipart/form-data.
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	// Bound the whole request body before parsing. Without this, a multipart
	// body streams until the disk or memory runs out.
	r.Body = http.MaxBytesReader(w, r.Body, service.MaxUploadBytes+(1<<20))

	// 8 MiB in memory, the rest to a temp file. Parsing multipart does NOT
	// interpret the content — it separates parts. No archive is opened here.
	//nolint:gosec // G120: the body is already bounded by the MaxBytesReader
	// installed immediately above, which gosec cannot see across statements.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		errs.Write(w, r, errs.Wrap(err, errs.ValidationBodyMalformed,
			"could not read the upload; it may exceed the size limit"))
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired,
			"attach the file in a form field named 'file'"))
		return
	}
	defer func() { _ = file.Close() }()

	u, err := h.svc.Upload(r.Context(), tenantID, r.PathValue("id"),
		ctxkey.UserID(r.Context()), service.UploadInput{
			Kind:     r.FormValue("kind"),
			Filename: header.Filename,
			Size:     header.Size,
			Content:  file,
		})
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, toUploadResponse(u))
}

// ListUploads handles GET /v1/projects/{id}/uploads.
func (h *Handler) ListUploads(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	uploads, err := h.svc.ListUploads(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	items := make([]uploadResponse, 0, len(uploads))
	for _, u := range uploads {
		items = append(items, toUploadResponse(u))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"uploads": items})
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Options handles GET /v1/projects/options.
//
// Serves the enums the wizard renders. They come FROM THE COMPLIANCE PROFILE,
// so a CERT-In revision changes the UI without a frontend release — and, more
// importantly, the frontend cannot drift from the profile by hardcoding a list
// that was accurate when it was written.
func (h *Handler) Options(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}

	bomTypes := make([]map[string]any, 0, len(model.AllBOMTypes()))
	for _, t := range model.AllBOMTypes() {
		bomTypes = append(bomTypes, map[string]any{
			"id": string(t),
			// The honest labels travel with the data, so the UI cannot imply
			// discovery where there is none.
			"requires_import": t.RequiresImport(),
			"is_derived":      t.IsDerived(),
		})
	}

	practices := make([]map[string]any, 0, len(model.PracticeFields))
	for _, f := range model.PracticeFields {
		practices = append(practices, map[string]any{"id": f.ID, "name": f.Name})
	}

	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"bom_types":    bomTypes,
		"sdlc_stages":  model.SDLCClassifications,
		"bom_depths":   model.BOMLevels,
		"source_types": []string{"github", "gitlab", "bitbucket", "upload", "image", "manual"},
		"practices":    practices,
	})
}

// ---------------------------------------------------------------------------
// Mapping and helpers
// ---------------------------------------------------------------------------

func toProjectResponse(p store.Project) projectResponse {
	types := make([]string, 0, len(p.Classifications))
	for _, t := range p.Classifications {
		types = append(types, string(t))
	}
	return projectResponse{
		ID: p.ID, Name: p.Name, Description: p.Description,
		SourceType: p.SourceType, SDLCStage: p.SDLCStage,
		ValidityStart: formatDate(p.ValidityStart),
		ValidityEnd:   formatDate(p.ValidityEnd),
		Owner: ownerDTO{
			Name: p.Owner.Name, Email: p.Owner.Email,
			GitHub: p.Owner.GitHub, Phone: p.Owner.Phone,
		},
		Classifications: types,
		// RFC3339 with a literal Z. No local time anywhere, ever.
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func toPracticesResponse(rep service.PracticesReport) practicesResponse {
	note := "Practices and Processes is one of CERT-In's three minimum-element " +
		"categories. A project with gaps here cannot produce a complete " +
		"compliance report, however complete its component data is."
	if rep.Complete {
		note = "All Practices and Processes sub-elements are recorded."
	}
	gaps := rep.Gaps
	if gaps == nil {
		gaps = []service.PracticeGap{} // [] not null, so clients can length-check
	}
	return practicesResponse{
		Frequency:     rep.Practices.Frequency,
		Depth:         rep.Practices.Depth,
		KnownUnknowns: rep.Practices.KnownUnknowns,
		Distribution:  rep.Practices.Distribution,
		AccessControl: rep.Practices.AccessControl,
		ErrataPolicy:  rep.Practices.ErrataPolicy,
		Compliance: complianceDTO{
			Recorded: rep.Recorded, Total: rep.Total,
			Complete: rep.Complete, Gaps: gaps, Note: note,
		},
	}
}

func toConnectionResponse(c store.RepoConnection) connectionResponse {
	return connectionResponse{
		ID: c.ID, Provider: c.Provider, RepoURL: c.RepoURL,
		RepoExternalID: c.RepoExternalID, DefaultBranch: c.DefaultBranch,
		HasCredential: c.CredentialRef != "",
		CreatedAt:     c.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func toUploadResponse(u store.Upload) uploadResponse {
	return uploadResponse{
		ID: u.ID, Kind: u.Kind, SHA256: u.SHA256, SizeBytes: u.SizeBytes,
		OriginalFilename: u.OriginalFilename,
		CreatedAt:        u.CreatedAt.UTC().Format(time.RFC3339),
		Extracted:        false,
	}
}

const maxBodyBytes = 1 << 20

func decode(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	// A typo'd field silently becoming its zero value is worse than an error:
	// a project created with a mistyped `classifications` would scan nothing.
	dec.DisallowUnknownFields()

	if err := dec.Decode(into); err != nil {
		if errors.Is(err, io.EOF) {
			return errs.New(errs.ValidationBodyMalformed, "request body is empty")
		}
		return errs.Wrap(err, errs.ValidationBodyMalformed, "request body is not valid JSON")
	}
	return nil
}

// parseDate reads a YYYY-MM-DD validity boundary.
//
// Date, not timestamp: a validity window is a calendar fact, and parsing it as
// an instant would make it shift by a day depending on the reader's timezone —
// in a compliance document.
func parseDate(s *string, field string) (*time.Time, error) {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", strings.TrimSpace(*s))
	if err != nil {
		return nil, errs.Newf(errs.ValidationFieldInvalid,
			"%s must be a date in YYYY-MM-DD form", field)
	}
	return &t, nil
}

func formatDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02")
	return &s
}
