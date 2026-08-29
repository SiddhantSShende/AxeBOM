// Package service holds the project service's business logic.
//
// Its scope boundary is worth stating up front, because the temptation to cross
// it is constant: THIS PHASE STORES A REPOSITORY URL AND VALIDATES ITS SHAPE.
// It does not fetch it, clone it, or resolve its DNS. Anything that touches an
// untrusted URL belongs in the Phase 5 sandbox, behind the fetcher that holds
// the only credentials (ADR-0008).
//
// Likewise uploads: bytes are hashed and stored, never opened. Extraction is
// untrusted-input handling — zip slip, symlink escape, decompression bombs —
// and putting it here would mean doing it outside the sandbox.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/project/internal/store"
)

// Service implements project registration and management.
type Service struct {
	store *store.Store
	blob  *blob.Store
	vault vault.Store
	now   func() time.Time
}

// Config configures the service.
type Config struct {
	Store *store.Store
	Blob  *blob.Store
	Vault vault.Store
	Now   func() time.Time
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{store: cfg.Store, blob: cfg.Blob, vault: cfg.Vault, now: cfg.Now}
}

// mapStoreError translates a store error into the canonical taxonomy.
//
// store.ErrNotFound covers both "absent" and "belongs to another tenant",
// because RLS makes them the same query result. Both become 404 —
// a 403 would confirm the id exists (CLAUDE.md invariant 6).
func mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return errs.New(errs.NotFoundProject, "no such project")
	case errors.Is(err, store.ErrNameTaken):
		return errs.New(errs.ValidationFieldInvalid,
			"a project with this name already exists in your organisation")
	default:
		return err
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// CreateInput is the request to register a project.
type CreateInput struct {
	Name        string
	Description string
	SourceType  string
	SDLCStage   string

	ValidityStart *time.Time
	ValidityEnd   *time.Time

	Owner store.Owner

	Classifications []string
}

// sourceTypes are the registration paths.
//
// Matches the CHECK constraint on project.projects. `manual` is a first-class
// path, not a fallback: HBOM has no scanner (CLAUDE.md honest labels), so a
// hardware project is registered with structured metadata and no repository.
var sourceTypes = map[string]bool{
	"github": true, "gitlab": true, "bitbucket": true,
	"upload": true, "image": true, "manual": true, "url": true,
}

// Create registers a project.
func (s *Service) Create(ctx context.Context, tenantID, userID string, in CreateInput) (store.Project, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return store.Project{}, errs.New(errs.ValidationFieldRequired, "project name is required")
	}
	if len(name) > 200 {
		return store.Project{}, errs.New(errs.ValidationFieldInvalid,
			"project name must be 200 characters or fewer")
	}
	if !sourceTypes[in.SourceType] {
		return store.Project{}, errs.Newf(errs.ValidationFieldInvalid,
			"source_type must be one of github, gitlab, bitbucket, upload, image, manual, url (got %q)",
			in.SourceType)
	}

	stage := in.SDLCStage
	if stage == "" {
		// CERT-In §3.2. Defaulting to `source` matches the column default and
		// is the honest answer for a repository connection: we see the
		// development tree, not the built artifact.
		stage = "source"
	}
	if !model.SDLCStageValid(stage) {
		return store.Project{}, errs.Newf(errs.ValidationFieldInvalid,
			"sdlc_stage must be one of %v", model.SDLCClassifications)
	}

	types, err := parseClassifications(in.Classifications)
	if err != nil {
		return store.Project{}, err
	}

	// Checked here for a clear message AND enforced by the schema constraint
	// validity_window_ordered. The database check is the one that matters: a
	// handler check is bypassed by any other write path.
	if in.ValidityStart != nil && in.ValidityEnd != nil && in.ValidityEnd.Before(*in.ValidityStart) {
		return store.Project{}, errs.New(errs.ValidationFieldInvalid,
			"validity_end must not be earlier than validity_start")
	}

	if in.Owner.Email != "" && !strings.Contains(in.Owner.Email, "@") {
		return store.Project{}, errs.New(errs.ValidationFieldInvalid,
			"owner email is not a valid address")
	}

	p, err := s.store.CreateProject(ctx, store.Project{
		TenantID:        tenantID,
		Name:            name,
		Description:     strings.TrimSpace(in.Description),
		SourceType:      in.SourceType,
		SDLCStage:       stage,
		ValidityStart:   in.ValidityStart,
		ValidityEnd:     in.ValidityEnd,
		Owner:           in.Owner,
		Classifications: types,
		CreatedBy:       userID,
	})
	return p, mapStoreError(err)
}

// parseClassifications validates the BOM-type set.
//
// At least one is required. A project classified into nothing would be
// registered, scannable, and produce no BOM at all — a silent no-op the user
// only discovers when a report comes back empty.
func parseClassifications(raw []string) ([]model.BOMType, error) {
	if len(raw) == 0 {
		return nil, errs.New(errs.ValidationFieldRequired,
			"select at least one BOM type; a project with no classification produces no BOM")
	}

	seen := make(map[model.BOMType]bool, len(raw))
	out := make([]model.BOMType, 0, len(raw))
	for _, r := range raw {
		t, err := model.ParseBOMType(strings.TrimSpace(r))
		if err != nil {
			return nil, errs.New(errs.ValidationFieldInvalid, err.Error())
		}
		if seen[t] {
			continue // idempotent rather than an error; the set is what matters
		}
		seen[t] = true
		out = append(out, t)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Read, update, delete
// ---------------------------------------------------------------------------

// Get returns one project.
func (s *Service) Get(ctx context.Context, tenantID, projectID string) (store.Project, error) {
	p, err := s.store.GetProject(ctx, tenantID, projectID)
	return p, mapStoreError(err)
}

// List returns a page of the tenant's projects.
func (s *Service) List(ctx context.Context, tenantID string, limit int, cursor string) ([]store.Project, error) {
	p, err := s.store.ListProjects(ctx, tenantID, limit, cursor)
	return p, mapStoreError(err)
}

// UpdateInput is the request to change a project.
type UpdateInput struct {
	Name            string
	Description     string
	SDLCStage       string
	ValidityStart   *time.Time
	ValidityEnd     *time.Time
	Owner           store.Owner
	Classifications []string
}

// Update changes a project.
//
// SourceType is deliberately NOT updatable: it determines how every scan
// acquires its input, and changing it under an existing scan history would make
// old results uninterpretable. Register a new project instead.
func (s *Service) Update(ctx context.Context, tenantID, projectID string, in UpdateInput) (store.Project, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return store.Project{}, errs.New(errs.ValidationFieldRequired, "project name is required")
	}
	stage := in.SDLCStage
	if stage == "" {
		stage = "source"
	}
	if !model.SDLCStageValid(stage) {
		return store.Project{}, errs.Newf(errs.ValidationFieldInvalid,
			"sdlc_stage must be one of %v", model.SDLCClassifications)
	}
	types, err := parseClassifications(in.Classifications)
	if err != nil {
		return store.Project{}, err
	}
	if in.ValidityStart != nil && in.ValidityEnd != nil && in.ValidityEnd.Before(*in.ValidityStart) {
		return store.Project{}, errs.New(errs.ValidationFieldInvalid,
			"validity_end must not be earlier than validity_start")
	}

	p, err := s.store.UpdateProject(ctx, store.Project{
		ID: projectID, TenantID: tenantID,
		Name: name, Description: strings.TrimSpace(in.Description),
		SDLCStage:     stage,
		ValidityStart: in.ValidityStart, ValidityEnd: in.ValidityEnd,
		Owner:           in.Owner,
		Classifications: types,
	})
	return p, mapStoreError(err)
}

// Delete soft-deletes a project.
func (s *Service) Delete(ctx context.Context, tenantID, projectID string) error {
	return mapStoreError(s.store.DeleteProject(ctx, tenantID, projectID))
}

// ---------------------------------------------------------------------------
// Repository connections
// ---------------------------------------------------------------------------

// ConnectInput is the request to attach a repository.
type ConnectInput struct {
	Provider       string
	RepoURL        string
	RepoExternalID string
	DefaultBranch  string

	// Token is the credential for private repositories. It is written to Vault
	// and NEVER persisted in Postgres — see Connect.
	Token string
}

// Connect attaches a repository to a project.
//
// THE ORDER HERE IS THE SECURITY PROPERTY: the token goes to Vault first, and
// only the PATH Vault returns is passed to the store. There is no code path in
// which a token reaches an INSERT, because the store's RepoConnection struct
// has no field that could carry one.
func (s *Service) Connect(ctx context.Context, tenantID, projectID string, in ConnectInput) (store.RepoConnection, error) {
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	switch provider {
	case "github", "gitlab", "bitbucket":
	default:
		return store.RepoConnection{}, errs.Newf(errs.ValidationFieldInvalid,
			"provider must be github, gitlab or bitbucket (got %q)", in.Provider)
	}

	repoURL, err := ValidateRepoURL(in.RepoURL)
	if err != nil {
		return store.RepoConnection{}, err
	}

	// repo_external_id is the provider's NUMERIC id, and it is what later
	// phases key on. Repository names change — a rename would otherwise
	// silently detach a project from its source.
	if strings.TrimSpace(in.RepoExternalID) == "" && provider == "github" {
		return store.RepoConnection{}, errs.New(errs.ValidationFieldRequired,
			"repo_external_id is required: repository names change, the numeric id does not")
	}

	// The connection id must exist before the Vault path can be derived, and
	// the path must exist before the row can store it. Resolve by writing the
	// row first WITHOUT a credential, then writing Vault, then attaching.
	conn, err := s.store.CreateConnection(ctx, store.RepoConnection{
		TenantID: tenantID, ProjectID: projectID,
		Provider: provider, RepoURL: repoURL,
		RepoExternalID: strings.TrimSpace(in.RepoExternalID),
		DefaultBranch:  strings.TrimSpace(in.DefaultBranch),
	})
	if err != nil {
		return store.RepoConnection{}, mapStoreError(err)
	}

	if in.Token == "" {
		return conn, nil // a public repository needs no credential
	}

	ref := vault.Ref{TenantID: tenantID, Kind: vault.KindRepoToken, ID: conn.ID}
	path, err := s.vault.Put(ctx, ref, map[string]string{"token": in.Token})
	if err != nil {
		// The connection row exists without a credential. That is the safe
		// failure: a connection that cannot authenticate fails visibly at scan
		// time, whereas storing the token anywhere else to "not lose it" is
		// precisely the outcome this design forbids.
		return store.RepoConnection{}, errs.Wrap(err, errs.InternalDependency,
			"could not store the repository credential securely; the connection was created without it")
	}

	conn.CredentialRef = path
	if _, err := s.store.CreateConnection(ctx, conn); err != nil {
		return store.RepoConnection{}, mapStoreError(err)
	}
	return conn, nil
}

// ListConnections returns a project's repository connections.
func (s *Service) ListConnections(ctx context.Context, tenantID, projectID string) ([]store.RepoConnection, error) {
	c, err := s.store.ListConnections(ctx, tenantID, projectID)
	return c, mapStoreError(err)
}

// ValidateRepoURL checks the SHAPE of a repository URL. It does not resolve or
// fetch it.
//
// ⚠ THIS IS NOT AN SSRF DEFENCE, AND MUST NOT BE MISTAKEN FOR ONE.
//
// Parse-time checks are defeated by DNS rebinding: a hostname that resolves to
// a public address now can resolve to 169.254.169.254 when the fetcher connects
// seconds later. The real defence is blocking private ranges AT CONNECTION
// TIME, in the Phase 5 fetcher (CLAUDE.md invariant 7).
//
// What this DOES do is reject inputs that are wrong on their face, so a user
// gets an immediate error instead of a scan that fails twenty minutes in. The
// scheme allowlist matters most: git's `ext::` transport is arbitrary command
// execution, and `file://` reads the server's disk.
func ValidateRepoURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errs.New(errs.ValidationFieldRequired, "repository URL is required")
	}
	if len(raw) > 2048 {
		return "", errs.New(errs.ValidationFieldInvalid, "repository URL is too long")
	}
	if strings.ContainsAny(raw, "\x00\n\r \t") {
		return "", errs.New(errs.ValidationFieldInvalid,
			"repository URL contains whitespace or control characters")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", errs.New(errs.ValidationFieldInvalid, "repository URL is not a valid URL")
	}

	// HTTPS ONLY. Not http (credentials and content in the clear), not ssh
	// (a key we would have to hold), and emphatically not ext:: or file://.
	if u.Scheme != "https" {
		return "", errs.Newf(errs.FetchURLSchemeForbidden,
			"repository URL must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return "", errs.New(errs.ValidationFieldInvalid, "repository URL has no host")
	}
	// Credentials in the URL would be stored in a database column in plaintext
	// — the exact outcome credential_ref exists to prevent.
	if u.User != nil {
		return "", errs.New(errs.ValidationFieldInvalid,
			"remove the credentials from the URL; supply a token instead, which is stored in the vault")
	}
	return u.String(), nil
}

// ---------------------------------------------------------------------------
// Web sources
// ---------------------------------------------------------------------------

// ValidateWebSourceURL checks the SHAPE of a URL source. Deliberately
// parallel to ValidateRepoURL — same rules (https-only, no embedded
// credentials, reasonable length), reworded messages — rather than a shared
// call, because "repository URL must use https" is a confusing thing to tell
// someone who typed a plain web page. See ValidateRepoURL's own warning: this
// is shape validation, NOT an SSRF defence. The real defence is connection-
// time IP blocking, in the fetcher (CLAUDE.md invariant 7).
func ValidateWebSourceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errs.New(errs.ValidationFieldRequired, "a URL is required")
	}
	if len(raw) > 2048 {
		return "", errs.New(errs.ValidationFieldInvalid, "URL is too long")
	}
	if strings.ContainsAny(raw, "\x00\n\r \t") {
		return "", errs.New(errs.ValidationFieldInvalid,
			"URL contains whitespace or control characters")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", errs.New(errs.ValidationFieldInvalid, "not a valid URL")
	}
	if u.Scheme != "https" {
		return "", errs.Newf(errs.FetchURLSchemeForbidden, "URL must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return "", errs.New(errs.ValidationFieldInvalid, "URL has no host")
	}
	if u.User != nil {
		return "", errs.New(errs.ValidationFieldInvalid, "remove any credentials embedded in the URL")
	}
	return u.String(), nil
}

// CreateWebSource attaches a URL source to a project.
func (s *Service) CreateWebSource(ctx context.Context, tenantID, projectID string, in WebSourceInput) (store.WebSource, error) {
	rootURL, err := ValidateWebSourceURL(in.RootURL)
	if err != nil {
		return store.WebSource{}, err
	}

	maxHosts := in.MaxHosts
	if maxHosts == 0 {
		maxHosts = 25 // matches the column default; explicit so the row is honest about what was chosen
	}
	if maxHosts < 1 || maxHosts > 100 {
		return store.WebSource{}, errs.Newf(errs.ValidationFieldInvalid,
			"max_hosts must be between 1 and 100 (got %d)", maxHosts)
	}

	w, err := s.store.CreateWebSource(ctx, store.WebSource{
		TenantID: tenantID, ProjectID: projectID,
		RootURL: rootURL,
		// DiscoveryEnabled defaults true unless explicitly turned off — the
		// common case is "scan what subfinder finds", per docs/07's wizard
		// spec; a tenant who wants only the one submitted page turns it off.
		DiscoveryEnabled: !in.DiscoveryDisabled,
		MaxHosts:         maxHosts,
	})
	return w, mapStoreError(err)
}

// ListWebSources returns a project's URL sources.
func (s *Service) ListWebSources(ctx context.Context, tenantID, projectID string) ([]store.WebSource, error) {
	w, err := s.store.ListWebSources(ctx, tenantID, projectID)
	return w, mapStoreError(err)
}

// WebSourceInput is the request to attach a URL source.
type WebSourceInput struct {
	RootURL  string
	MaxHosts int
	// DiscoveryDisabled, not DiscoveryEnabled: the zero value of a bool
	// defaults to false, and the zero value of this field must mean "leave
	// discovery on" — inverting the name is what makes an omitted field in a
	// JSON body do the right thing instead of silently disabling discovery.
	DiscoveryDisabled bool
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

// uploadKinds matches the CHECK constraint on project.uploads.
var uploadKinds = map[string]bool{
	"source_archive": true, "manifest": true, "lockfile": true,
	"sbom": true, "hbom_csv": true, "image_tarball": true,
}

// UploadInput describes an incoming file.
type UploadInput struct {
	Kind     string
	Filename string
	Size     int64
	Content  interface {
		Read([]byte) (int, error)
	}
}

// MaxUploadBytes caps a single upload.
const MaxUploadBytes = 256 << 20 // 256 MiB

// Upload stores a file against a project.
//
// ⚠ STORES. DOES NOT EXTRACT. No archive is opened, no member is enumerated, no
// path is joined. Extraction is where zip slip, symlink escape and
// decompression bombs live, and it happens in the Phase 5 sandbox or nowhere.
//
// The sha256 is computed from the bytes actually written (see blob.Put), never
// taken from the client — a caller-supplied digest would let any content claim
// any hash and defeat every integrity check built on it later.
func (s *Service) Upload(ctx context.Context, tenantID, projectID, userID string, in UploadInput) (store.Upload, error) {
	if !uploadKinds[in.Kind] {
		return store.Upload{}, errs.Newf(errs.ValidationFieldInvalid,
			"kind must be one of source_archive, manifest, lockfile, sbom, hbom_csv, image_tarball (got %q)",
			in.Kind)
	}
	if in.Size > MaxUploadBytes {
		return store.Upload{}, errs.Newf(errs.FetchArchiveTooLarge,
			"upload exceeds the %d MiB limit", MaxUploadBytes>>20)
	}

	// Confirm the project is visible IN THIS TENANT before writing bytes.
	// Without it, a cross-tenant project id would still consume storage — a
	// write primitive against another tenant's quota.
	if _, err := s.store.GetProject(ctx, tenantID, projectID); err != nil {
		return store.Upload{}, mapStoreError(err)
	}

	filename := sanitizeFilename(in.Filename)

	// Key layout is tenant/project/kind/timestamp-filename. The tenant prefix
	// makes per-tenant lifecycle rules and deletion possible without a scan of
	// the whole bucket.
	key := fmt.Sprintf("uploads/%s/%s/%s/%d-%s",
		tenantID, projectID, in.Kind, s.now().UTC().UnixNano(), filename)

	obj, err := s.blob.Put(ctx, key, in.Content, blob.PutOptions{MaxBytes: MaxUploadBytes})
	if err != nil {
		if errors.Is(err, blob.ErrTooLarge) {
			return store.Upload{}, errs.Newf(errs.FetchArchiveTooLarge,
				"upload exceeds the %d MiB limit", MaxUploadBytes>>20)
		}
		return store.Upload{}, errs.Wrap(err, errs.InternalDependency,
			"could not store the uploaded file")
	}

	// Bytes first, row second. A crash between them leaves an orphaned object,
	// which a lifecycle rule sweeps. The reverse leaves a row pointing at
	// nothing, which breaks every scan that later reads it.
	u, err := s.store.CreateUpload(ctx, store.Upload{
		TenantID: tenantID, ProjectID: projectID,
		Kind: in.Kind, StorageRef: obj.Key, SHA256: obj.SHA256,
		SizeBytes: obj.Size, OriginalFilename: filename, UploadedBy: userID,
	})
	return u, mapStoreError(err)
}

// ListUploads returns a project's uploads.
func (s *Service) ListUploads(ctx context.Context, tenantID, projectID string) ([]store.Upload, error) {
	u, err := s.store.ListUploads(ctx, tenantID, projectID)
	return u, mapStoreError(err)
}

// sanitizeFilename makes a user-supplied filename safe to store and echo.
//
// User filenames genuinely contain newlines, NUL bytes, 8KB paths and
// directory traversal. A NUL silently truncates a Postgres text value, a
// newline forges a log line, and a traversal sequence escapes an object-key
// prefix. Only the base name survives, and only from a safe alphabet.
func sanitizeFilename(name string) string {
	// Cut at the last separator of EITHER convention: an upload from Windows
	// carries backslashes that path.Base does not treat as separators.
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		out = "upload"
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}
