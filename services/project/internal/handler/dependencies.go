package handler

import (
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/store"
)

// ---------------------------------------------------------------------------
// Dependencies and findings
//
// Wire shapes here mirror frontend/src/routes/dependencies/Dependencies.tsx's
// DependencyRow, frontend/src/routes/dependencies/ComponentDrawer.tsx's
// ComponentDetail, and frontend/src/routes/findings/Findings.tsx's Finding —
// field for field, so those files are the reference for any future change
// here rather than this file being restated as its own spec.
// ---------------------------------------------------------------------------

type dependencyRowDTO struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Ecosystem    string   `json:"ecosystem"`
	License      string   `json:"license"`
	IsDirect     bool     `json:"isDirect"`
	IsOrphan     bool     `json:"isOrphan"`
	Depth        *int     `json:"depth"`
	Criticality  string   `json:"criticality"`
	TopSeverity  string   `json:"topSeverity"`
	FindingCount int      `json:"findingCount"`
	DetectedBy   []string `json:"detectedBy"`
}

func toDependencyRowDTO(r store.DependencyRow) dependencyRowDTO {
	return dependencyRowDTO{
		Key: r.Key, Name: r.Name, Version: r.Version, Ecosystem: r.Ecosystem,
		License: r.License, IsDirect: r.IsDirect, IsOrphan: r.IsOrphan, Depth: r.Depth,
		Criticality:  r.Criticality,
		TopSeverity:  r.TopSeverity,
		FindingCount: r.FindingCount,
		DetectedBy:   emptyIfNil(r.DetectedBy),
	}
}

// ListDependencies handles GET /v1/projects/{id}/dependencies.
func (h *Handler) ListDependencies(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	rows, err := h.svc.ListDependencies(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	items := make([]dependencyRowDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDependencyRowDTO(row))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"components": items})
}

// ListCryptoAssets handles GET /v1/projects/{id}/crypto-assets.
//
// ⚠ NO SEPARATE DTO — store.CryptoAsset ALREADY CARRIES ITS OWN `json` TAGS.
// Every other handler in this file re-shapes its store type (renaming
// fields, dropping/adding `emptyIfNil`); this one does neither, because
// there is no transformation to do — the wire shape and the store shape are
// the same shape. Introducing a DTO here would be a field-for-field copy
// with no logic in it, which is the abstraction CLAUDE.md says not to add.
func (h *Handler) ListCryptoAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	assets, err := h.svc.ListCryptoAssets(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"crypto_assets": assets})
}

type profileFieldValueDTO struct {
	FieldID    string `json:"fieldId"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	SourcePage int    `json:"sourcePage"`
	Scored     bool   `json:"scored"`
}

type candidateIdentityDTO struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
}

type provenanceEntryDTO struct {
	Engine        string `json:"engine"`
	EngineVersion string `json:"engineVersion"`
	ObservedAt    string `json:"observedAt"`
	Rule          string `json:"rule"`
}

type componentDetailDTO struct {
	Key                 string                 `json:"key"`
	Purl                string                 `json:"purl"`
	CertinIdentifier    string                 `json:"certinIdentifier"`
	Ecosystem           string                 `json:"ecosystem"`
	Fields              []profileFieldValueDTO `json:"fields"`
	Locations           []string               `json:"locations"`
	CandidateIdentities []candidateIdentityDTO `json:"candidateIdentities"`
	Provenance          []provenanceEntryDTO   `json:"provenance"`
}

func toComponentDetailDTO(d store.ComponentDetail) componentDetailDTO {
	out := componentDetailDTO{
		Key: d.Key, Purl: d.Purl, CertinIdentifier: d.CertinIdentifier, Ecosystem: d.Ecosystem,
		Locations: emptyIfNil(d.Locations),
	}
	out.Fields = make([]profileFieldValueDTO, 0, len(d.Fields))
	for _, f := range d.Fields {
		out.Fields = append(out.Fields, profileFieldValueDTO{
			FieldID: f.FieldID, Name: f.Name, Value: f.Value,
			SourcePage: f.SourcePage, Scored: f.Scored,
		})
	}
	out.CandidateIdentities = make([]candidateIdentityDTO, 0, len(d.CandidateIdentities))
	for _, c := range d.CandidateIdentities {
		out.CandidateIdentities = append(out.CandidateIdentities, candidateIdentityDTO{
			Kind: c.Kind, Value: c.Value, Confidence: c.Confidence, Source: c.Source,
		})
	}
	out.Provenance = make([]provenanceEntryDTO, 0, len(d.Provenance))
	for _, p := range d.Provenance {
		out.Provenance = append(out.Provenance, provenanceEntryDTO{
			Engine: p.Engine, EngineVersion: p.EngineVersion, ObservedAt: p.ObservedAt, Rule: p.Rule,
		})
	}
	return out
}

// GetComponentDetail handles GET /v1/projects/{id}/dependencies/{key}.
func (h *Handler) GetComponentDetail(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	detail, err := h.svc.GetComponentDetail(r.Context(), tenantID, r.PathValue("id"), r.PathValue("key"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, toComponentDetailDTO(detail))
}

type severitySourceDTO struct {
	Engine      string `json:"engine"`
	Severity    string `json:"severity"`
	CVSSVersion string `json:"cvssVersion"`
	CVSSScore   string `json:"cvssScore"`
	CVSSVector  string `json:"cvssVector"`
}

type findingComponentDTO struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type findingDTO struct {
	ClusterID        string                `json:"clusterId"`
	DisplayID        string                `json:"displayId"`
	Aliases          []string              `json:"aliases"`
	Severity         string                `json:"severity"`
	CVSSVersion      string                `json:"cvssVersion"`
	CVSSScore        string                `json:"cvssScore"`
	SeverityConflict bool                  `json:"severityConflict"`
	SeveritySources  []severitySourceDTO   `json:"severitySources"`
	Components       []findingComponentDTO `json:"components"`
	FixedInMin       string                `json:"fixedInMin"`
	FixOrdering      string                `json:"fixOrdering"`
	DetectedBy       []string              `json:"detectedBy"`
	VEXStatus        string                `json:"vexStatus"`
	VEXJustification string                `json:"vexJustification"`
}

func toFindingDTO(f store.Finding) findingDTO {
	out := findingDTO{
		ClusterID: f.ClusterID, DisplayID: f.DisplayID, Aliases: emptyIfNil(f.Aliases),
		Severity: f.Severity, CVSSVersion: f.CVSSVersion, CVSSScore: f.CVSSScore,
		SeverityConflict: f.SeverityConflict,
		FixedInMin:       f.FixedInMin,
		FixOrdering:      f.FixOrdering,
		DetectedBy:       emptyIfNil(f.DetectedBy),
		VEXStatus:        f.VEXStatus,
		VEXJustification: f.VEXJustification,
	}
	out.SeveritySources = make([]severitySourceDTO, 0, len(f.SeveritySources))
	for _, s := range f.SeveritySources {
		out.SeveritySources = append(out.SeveritySources, severitySourceDTO{
			Engine: s.Engine, Severity: s.Severity, CVSSVersion: s.CVSSVersion,
			CVSSScore: s.CVSSScore, CVSSVector: s.CVSSVector,
		})
	}
	out.Components = make([]findingComponentDTO, 0, len(f.Components))
	for _, c := range f.Components {
		out.Components = append(out.Components, findingComponentDTO{Key: c.Key, Name: c.Name, Version: c.Version})
	}
	return out
}

// ListFindings handles GET /v1/projects/{id}/findings.
func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	findings, err := h.svc.ListFindings(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	items := make([]findingDTO, 0, len(findings))
	for _, f := range findings {
		items = append(items, toFindingDTO(f))
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"findings": items})
}
