// Package handler is services/aibom's HTTP surface.
//
// Four things, and they are four because each answers a different question a
// scanner cannot:
//
//	models        what was discovered, plus what a person said about it
//	policy        whether this project consents to sending code to a third party
//	tags          how a person classifies it under EU AI Act / NIST / ISO 42001
//	attestations  what a verification of the model's signature actually returned
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/axebom/axebom/libs/go-shared/auth"
	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/ctxkey"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/aibom/internal/store"
)

// Handler serves this service's routes.
type Handler struct{ store *Store }

// Store is the subset of the concrete store this handler uses.
type Store = store.Store

// New constructs a Handler.
func New(s *Store) *Handler { return &Handler{store: s} }

// ---------------------------------------------------------------------------
// Form fields — which Table 10 elements a person may fill in
// ---------------------------------------------------------------------------

// FormField describes one operator-suppliable element.
type FormField struct {
	FieldID       string `json:"field_id"`
	Name          string `json:"name"`
	CanonicalPath string `json:"canonical_path"`
	SourcePage    int    `json:"source_page"`
}

// Form handles GET /v1/aibom/{projectId}/form.
//
// ⚠ GENERATED FROM THE COMPLIANCE PROFILE, NEVER HAND-TYPED, AND NO COUNT IS
// WRITTEN ANYWHERE. `user_supplied: true` in `certin-v2.0.yaml` is what says
// which elements these are; a CERT-In revision that changes the set changes
// this response with no Go edit (CLAUDE.md invariant 2). The last time this was
// a hand-written list it omitted `environmental_impact`, which left that element
// in the coverage denominator with no way for anyone to fill it.
func (h *Handler) Form(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.RequireTenant(r.Context()); err != nil {
		errs.Write(w, r, err)
		return
	}
	out := make([]FormField, 0)
	for _, f := range model.AIBOMFields {
		if !f.UserSupplied {
			continue
		}
		out = append(out, FormField{
			FieldID:       f.ID,
			Name:          f.Name,
			CanonicalPath: f.CanonicalPath,
			SourcePage:    f.SourcePage,
		})
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"fields": out})
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

// Inventory handles GET /v1/aibom/{projectId}/models.
//
// ⚠ MOVED OFF `GET /v1/projects/{id}/ai-models`. The AI BOM is this service's
// domain; it was on the project service only because that is where the first
// handler happened to be written, and the same service was then also UPDATE-ing
// normalized rows (see the schema migration's header for why that had to stop).
func (h *Handler) Inventory(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	inv, err := h.store.GetInventory(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	values, err := h.store.ListUserFields(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}

	// ⚠ OVERLAID AT READ TIME, NOT WRITTEN INTO THE DOCUMENT. The normalized row
	// holds whatever the last normalization knew; the operator's answer is the
	// newer fact and lives in this service's own table. Merging here means a
	// person's answer shows up immediately, without a re-scan and without
	// anything mutating `normalize.ai_models`.
	for i := range inv.Models {
		v, ok := values[inv.Models[i].ModelKey]
		if !ok {
			continue
		}
		applyUserValues(&inv.Models[i], v.UserFields)
	}

	errs.WriteJSON(w, http.StatusOK, inv)
}

// applyUserValues overlays an operator's answers onto a discovered row.
//
// ⚠ ONLY WHERE THEY SAID SOMETHING. An empty answer leaves the normalized
// value — which is the explicit `not-provided` sentinel (invariant 3) — rather
// than blanking it, so "nobody answered" keeps reading as a stated gap instead
// of becoming an empty cell that looks like a rendering bug.
func applyUserValues(m *store.AIModel, f store.UserFields) {
	set := func(dst *string, value, fieldID string) {
		if value == "" {
			return
		}
		*dst = value
		m.FieldStatus[fieldID] = "provided"
	}
	set(&m.SecurityRequirements, f.SecurityRequirements, model.FieldCertinAibom12SecurityRequirements)
	set(&m.IntendedUsage, f.IntendedUsage, model.FieldCertinAibom15IntendedUsage)
	set(&m.OutOfScopeUsage, f.OutOfScopeUsage, model.FieldCertinAibom16OutOfScopeUsage)
	set(&m.EnvironmentalImpact, f.EnvironmentalImpact, model.FieldCertinAibom17EnvironmentalImpact)
	set(&m.AttestationSignature, f.AttestationSignature, model.FieldCertinAibom19Attestations)
}

// SaveUserFields handles PUT /v1/aibom/{projectId}/models/{modelKey}/fields.
//
// ⚠ KEYED BY `model_key`, NOT BY A ROW ID. Every re-normalization writes new
// rows (invariant 10), so a row id is valid for exactly one document and an
// answer attached to one would be orphaned by the next scan. The key is stable
// across documents by construction — it is what the identity ladder produces.
func (h *Handler) SaveUserFields(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	var fields store.UserFields
	if err := decode(r, &fields); err != nil {
		errs.Write(w, r, err)
		return
	}
	if err := h.store.SaveUserFields(r.Context(), tenantID, r.PathValue("projectId"),
		r.PathValue("modelKey"), ctxkey.UserID(r.Context()), fields); err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// GetPolicy handles GET /v1/aibom/{projectId}/policy.
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	p, err := h.store.GetPolicy(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, p)
}

// SetPolicy handles PUT /v1/aibom/{projectId}/policy.
//
// ⚠ THIS IS A CONSENT RECORD, NOT A FEATURE FLAG. Both switches send CUSTOMER
// CODE to a third-party LLM — `ai-bom --llm-enrich` and `cisco-aibom
// --llm-model`. Who turned it on and when is stored, because "we consented" is
// a claim somebody has to be able to check.
//
// ⚠ AND TURNING IT ON DOES NOT TURN AN ENGINE ON. Scan engines run with no
// network and there is no egress allowlist yet, so the response carries
// `effective: false` and the blocker. A UI that showed a toggle without that
// would be telling a customer something started that did not.
func (h *Handler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	var body struct {
		LLMEnrichEnabled bool `json:"llm_enrich_enabled"`
		CiscoEnabled     bool `json:"cisco_enabled"`
	}
	if err := decode(r, &body); err != nil {
		errs.Write(w, r, err)
		return
	}
	p, err := h.store.SetPolicy(r.Context(), tenantID, r.PathValue("projectId"),
		ctxkey.UserID(r.Context()), body.LLMEnrichEnabled, body.CiscoEnabled)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, p)
}

// ---------------------------------------------------------------------------
// Compliance tagging
// ---------------------------------------------------------------------------

// ListTags handles GET /v1/aibom/{projectId}/tags.
func (h *Handler) ListTags(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	tags, err := h.store.ListTags(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{
		"tags": tags,
		// The closed sets, so the UI renders a chooser rather than a text box —
		// and so a reader can see that "undetermined" is a real answer.
		"vocabulary": map[string]any{
			"eu_ai_act_tier": model.EUAIActTiers,
			"nist_ai_rmf":    model.NISTAIRMFFunctions,
			"iso_42001":      model.ISO42001Controls,
		},
	})
}

// SaveTag handles PUT /v1/aibom/{projectId}/tags.
//
// ⚠ THE OPERATOR'S CLASSIFICATION, RECORDED AS THEIRS. AxeBOM does not infer a
// risk tier: whether a system is high-risk under the EU AI Act depends on what
// it is USED FOR, which no repository shows. Inferring one would manufacture a
// legal conclusion out of a dependency graph, and a customer would carry it
// into an audit.
func (h *Handler) SaveTag(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	var tag store.ComplianceTag
	if err := decode(r, &tag); err != nil {
		errs.Write(w, r, err)
		return
	}
	if err := model.ValidateComplianceTag(tag.EUAIActTier, tag.NISTAIRMF, tag.ISO42001); err != nil {
		errs.Write(w, r, err)
		return
	}
	if err := h.store.SaveTag(r.Context(), tenantID, r.PathValue("projectId"),
		ctxkey.UserID(r.Context()), tag); err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

// ListAttestations handles GET /v1/aibom/{projectId}/attestations.
func (h *Handler) ListAttestations(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	out, err := h.store.ListAttestations(r.Context(), tenantID, r.PathValue("projectId"))
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusOK, map[string]any{"attestations": out})
}

// RecordAttestation handles POST /v1/aibom/{projectId}/attestations.
//
// ⚠ AxeBOM DOES NOT RUN THE VERIFICATION, AND SAYING SO IS THE POINT.
//
// `model_signing verify` needs the model FILES — it recomputes their digests
// and checks them against the signed manifest. AxeBOM never holds customer
// model weights: the scan sandbox sees a source tree, and the enrichment plane
// sees a model identifier. So the honest shape is the one `hbom-host-report`
// already established for hardware inventories: the customer runs the verifier
// where the artifact is, and AxeBOM ingests the RESULT.
//
// What that buys over the free-text element 19 field is real: this parses the
// verifier's own output, so `verified` is read rather than typed, a failure is
// recorded as a failure, and the signer identity and digest are on the record.
// What it does not buy is AxeBOM having checked a signature, and no UI string
// may say it did.
func (h *Handler) RecordAttestation(w http.ResponseWriter, r *http.Request) {
	tenantID, err := auth.RequireTenant(r.Context())
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	var body struct {
		ModelKey string          `json:"model_key"`
		Output   json.RawMessage `json:"model_signing_output"`
	}
	if err := decode(r, &body); err != nil {
		errs.Write(w, r, err)
		return
	}
	if body.ModelKey == "" {
		errs.Write(w, r, errs.New(errs.ValidationFieldRequired, "model_key is required"))
		return
	}
	att, err := ParseModelSigningOutput(body.Output)
	if err != nil {
		errs.Write(w, r, err)
		return
	}
	att.ModelKey = body.ModelKey
	if err := h.store.RecordAttestation(r.Context(), tenantID, r.PathValue("projectId"),
		ctxkey.UserID(r.Context()), att); err != nil {
		errs.Write(w, r, err)
		return
	}
	errs.WriteJSON(w, http.StatusCreated, att)
}

// decode reads a JSON body, refusing unknown fields.
//
// ⚠ THE OPPOSITE OF THE QUEUE DECODER, DELIBERATELY. A typo'd field in a user's
// API request is a mistake to report; an unrecognized field in a queue message
// is a newer publisher. See events.Decode's own note.
func decode(r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errs.Wrap(err, errs.ValidationBodyMalformed, "could not read the request body")
	}
	return nil
}
