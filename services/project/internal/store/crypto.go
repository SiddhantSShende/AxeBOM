package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// ---------------------------------------------------------------------------
// Crypto assets — normalize.crypto_assets, read cross-schema.
//
// ⚠ SAME PATTERN AS ListDependencies (dependencies.go): this service owns
// project.* only, not normalize.*. One query, no cross-schema SQL JOIN
// (CLAUDE.md invariant 11), scoped by the project's current CBOM
// bom_document via resolveCurrentBOMDocument. The engines list reads
// normalize.crypto_asset_provenance in the same statement — same schema, so
// invariant 11 does not apply, and RLS scopes both tables.
//
// ⚠ THIS IS THE INTERACTIVE READ PATH, DISTINCT FROM services/report'S
// RENDERING. The report service (render.CryptoAsset / CBOMSheets) builds a
// downloadable XLSX/PDF/JSON artifact for one point in time. This is the
// live "Crypto inventory" screen the CBOM sidebar section links to — same
// underlying table, same type-discrimination discipline, a different
// consumer with a different shape need (JSON over HTTP, not a workbook).
// ---------------------------------------------------------------------------

// CryptoAsset is one row of the crypto inventory screen
// (frontend/src/routes/boms/CryptoInventory.tsx's CryptoAssetRow).
//
// ⚠ TYPE-DISCRIMINATED, NOT ONE FLAT COLUMN SET RENDERED FOR EVERY TYPE.
// CERT-In Table 9 gives Algorithms/Keys/Protocols/Certificates different
// field sets (CLAUDE.md invariant 5); the JSON omits a field entirely
// (`omitempty`) rather than send an empty string for a column that asset
// type never had, so the frontend can tell "not applicable to this type"
// from "applicable and not-provided" the same way the Go struct already
// does by leaving the Go field its zero value only where the DB column is
// NULL.
//
// ⚠ THE IDENTITY AND EVIDENCE FIELDS ARE NEVER OMITTED. They apply to every
// asset type, so an empty `[]` / `{}` is an answer ("no engine reported a
// location"), and a consumer can rely on the key being there.
type CryptoAsset struct {
	// AssetKey is the asset's identity — the docs/03-NORMALIZER-SPEC.md §1.6
	// merge key (`algorithm:…`, `key:fp:sha256:…`, `cert:…`, `protocol:…`,
	// `opaque:…`). Unlike the row id it survives re-normalization, so it is
	// what a QBOM references and what the CBOM export uses as the bom-ref.
	AssetKey string `json:"asset_key"`
	// IdentityRule is the §1.6 ladder rule that produced AssetKey, and
	// IdentityConfidence how much weight it bears (high / medium / low).
	IdentityRule       string `json:"identity_rule"`
	IdentityConfidence string `json:"identity_confidence"`

	ComponentKey string `json:"component_key,omitempty"`
	AssetType    string `json:"asset_type"`
	Name         string `json:"name"`

	// ---- algorithm ----
	Primitive              string   `json:"primitive,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	CryptoFunctions        []string `json:"crypto_functions,omitempty"`
	ClassicalSecurityLevel *int     `json:"classical_security_level,omitempty"`
	AlgorithmList          []string `json:"algorithm_list,omitempty"`

	// ---- key ----
	KeyID          string `json:"key_id,omitempty"`
	KeyState       string `json:"key_state,omitempty"`
	KeySize        *int   `json:"key_size,omitempty"`
	CreationDate   string `json:"creation_date,omitempty"`
	ActivationDate string `json:"activation_date,omitempty"`

	// ---- protocol ----
	ProtocolVersion string   `json:"protocol_version,omitempty"`
	CipherSuites    []string `json:"cipher_suites,omitempty"`

	// ---- shared by algorithm and protocol ----
	OID string `json:"oid,omitempty"`

	// ---- certificate ----
	CertSubject         string `json:"cert_subject,omitempty"`
	CertIssuer          string `json:"cert_issuer,omitempty"`
	NotValidBefore      string `json:"not_valid_before,omitempty"`
	NotValidAfter       string `json:"not_valid_after,omitempty"`
	SignatureAlgoRef    string `json:"signature_algo_ref,omitempty"`
	SubjectPublicKeyRef string `json:"subject_public_key_ref,omitempty"`
	CertFormat          string `json:"cert_format,omitempty"`
	CertExtension       string `json:"cert_extension,omitempty"`

	// ---- AxeBOM analysis — NOT CERT-In fields, excluded from coverage
	// (migrations/normalize/0003, 0005) ----
	QuantumVulnerable     bool   `json:"quantum_vulnerable"`
	QuantumFamily         string `json:"quantum_family,omitempty"`
	QuantumReadinessGroup string `json:"quantum_readiness_group,omitempty"`
	QuantumRationale      string `json:"quantum_rationale,omitempty"`
	GroverNote            string `json:"grover_note,omitempty"`
	EffectiveQuantumBits  *int   `json:"effective_quantum_bits,omitempty"`
	PQCRecommendation     string `json:"pqc_recommendation,omitempty"`
	DeprecationStatus     string `json:"deprecation_status,omitempty"`
	DeprecationRationale  string `json:"deprecation_rationale,omitempty"`
	DeprecationReference  string `json:"deprecation_reference,omitempty"`

	// ---- evidence and provenance — never scored (migrations/normalize/0019,
	// 0020) ----

	// Evidence is where engines saw the asset, repository-relative and
	// verbatim. Location is evidence, never identity: one certificate in two
	// folders is one asset with two entries here.
	Evidence []CryptoEvidence `json:"evidence"`
	// Attributes are the non-CERT-In facts the normalizer kept — padding,
	// curve, parameter set, NIST quantum category, key-material type, whether
	// a private key was committed. Passed through as stored.
	Attributes map[string]any `json:"attributes"`
	// Derivations names the CERT-In columns AxeBOM filled from a cited
	// reference table rather than an engine reporting them:
	// {column: reference_id}.
	Derivations map[string]string `json:"derivations"`
	// Engines are the distinct engines that reported this asset, sorted — read
	// from normalize.crypto_asset_provenance, one row per (asset, engine).
	Engines []string `json:"engines"`
}

// CryptoEvidence is one place an engine saw a crypto asset.
//
// Line is null when the engine reported a file but no line — a certificate
// file, a key file. Never 0 for "unknown": 0 is not a line.
type CryptoEvidence struct {
	Path   string `json:"path"`
	Line   *int   `json:"line"`
	Engine string `json:"engine"`
}

// ListCryptoAssets returns the project's current CBOM crypto-asset inventory.
func (s *Store) ListCryptoAssets(ctx context.Context, tenantID, projectID string) ([]CryptoAsset, error) {
	out := []CryptoAsset{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "CBOM")
		if err != nil {
			return err
		}
		if docID == "" {
			return nil // no CBOM normalized yet — an honest empty list
		}

		// ⚠ THE ENGINES ARE A CORRELATED SUBQUERY, NOT A SECOND ROUND TRIP PER
		// ROW. One statement returns every asset with its engine list, so the
		// screen costs one query however large the inventory is.
		rows, err := tx.Query(ctx, `
			SELECT a.asset_key, a.identity_rule, a.identity_confidence,
			       a.component_key, a.asset_type, a.name,
			       a.primitive, a.mode, a.crypto_functions, a.classical_security_level, a.algorithm_list,
			       a.key_id, a.key_state, a.key_size,
			       to_char(a.creation_date, 'YYYY-MM-DD'), to_char(a.activation_date, 'YYYY-MM-DD'),
			       a.protocol_version, a.cipher_suites, a.oid,
			       a.cert_subject, a.cert_issuer,
			       to_char(a.not_valid_before, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			       to_char(a.not_valid_after, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			       a.signature_algo_ref, a.subject_public_key_ref, a.cert_format, a.cert_extension,
			       a.quantum_vulnerable, a.quantum_family, a.quantum_readiness_group,
			       a.quantum_rationale, a.grover_note, a.effective_quantum_bits,
			       a.pqc_recommendation, a.deprecation_status, a.deprecation_rationale,
			       a.deprecation_reference,
			       a.evidence, a.attributes, a.derivations,
			       COALESCE((SELECT array_agg(DISTINCT p.engine_id ORDER BY p.engine_id)
			                   FROM normalize.crypto_asset_provenance p
			                  WHERE p.crypto_asset_id = a.id), '{}')
			  FROM normalize.crypto_assets a
			 WHERE a.bom_document_id = $1
			 -- ⚠ id LAST, SO THE ORDER IS TOTAL. Two assets can share a type and
			 -- a name (theia reports two RSA algorithms from one certificate), and
			 -- without a tiebreak their order changed between requests.
			 ORDER BY a.asset_type, a.name, a.id`, docID)
		if err != nil {
			return fmt.Errorf("list crypto assets: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				a                                            CryptoAsset
				assetKey, identityRule, identityConfidence   *string
				componentKey                                 *string
				primitive, mode                              *string
				cryptoFunctions, algorithmList               []string
				keyID, keyState                              *string
				creationDate, activationDate                 *string
				protocolVersion                              *string
				cipherSuites                                 []string
				oid                                          *string
				certSubject, certIssuer                      *string
				notValidBefore, notValidAfter                *string
				sigRef, pubKeyRef                            *string
				certFormat, certExtension                    *string
				quantumFamily, quantumGroup                  *string
				quantumRationale, groverNote                 *string
				pqcRecommendation                            *string
				deprecationStatus                            *string
				deprecationRationale                         *string
				deprecationReference                         *string
				evidenceJSON, attributesJSON, derivationJSON []byte
				engines                                      []string
			)
			if err := rows.Scan(
				&assetKey, &identityRule, &identityConfidence,
				&componentKey, &a.AssetType, &a.Name,
				&primitive, &mode, &cryptoFunctions, &a.ClassicalSecurityLevel, &algorithmList,
				&keyID, &keyState, &a.KeySize,
				&creationDate, &activationDate,
				&protocolVersion, &cipherSuites, &oid,
				&certSubject, &certIssuer, &notValidBefore, &notValidAfter,
				&sigRef, &pubKeyRef, &certFormat, &certExtension,
				&a.QuantumVulnerable, &quantumFamily, &quantumGroup,
				&quantumRationale, &groverNote, &a.EffectiveQuantumBits,
				&pqcRecommendation, &deprecationStatus, &deprecationRationale,
				&deprecationReference,
				&evidenceJSON, &attributesJSON, &derivationJSON,
				&engines,
			); err != nil {
				return fmt.Errorf("scan crypto asset: %w", err)
			}

			// ⚠ A MALFORMED COLUMN FAILS THE REQUEST RATHER THAN BEING DROPPED.
			// All three are jsonb written only by the normalizer, so a decode
			// failure is corruption — and a derivation label silently lost would
			// present AxeBOM's lookup as an engine's claim.
			if err := decodeCryptoJSON(evidenceJSON, &a.Evidence); err != nil {
				return fmt.Errorf("decode crypto asset evidence: %w", err)
			}
			if err := decodeCryptoJSON(attributesJSON, &a.Attributes); err != nil {
				return fmt.Errorf("decode crypto asset attributes: %w", err)
			}
			if err := decodeCryptoJSON(derivationJSON, &a.Derivations); err != nil {
				return fmt.Errorf("decode crypto asset derivations: %w", err)
			}
			if a.Evidence == nil {
				a.Evidence = []CryptoEvidence{}
			}
			if a.Attributes == nil {
				a.Attributes = map[string]any{}
			}
			if a.Derivations == nil {
				a.Derivations = map[string]string{}
			}
			a.Engines = engines
			if a.Engines == nil {
				a.Engines = []string{}
			}

			a.AssetKey = deref(assetKey)
			a.IdentityRule = deref(identityRule)
			a.IdentityConfidence = deref(identityConfidence)
			a.ComponentKey = deref(componentKey)
			a.Primitive = deref(primitive)
			a.Mode = deref(mode)
			a.CryptoFunctions = cryptoFunctions
			a.AlgorithmList = algorithmList
			a.KeyID = deref(keyID)
			a.KeyState = deref(keyState)
			a.CreationDate = deref(creationDate)
			a.ActivationDate = deref(activationDate)
			a.ProtocolVersion = deref(protocolVersion)
			a.CipherSuites = cipherSuites
			a.OID = deref(oid)
			a.CertSubject = deref(certSubject)
			a.CertIssuer = deref(certIssuer)
			a.NotValidBefore = deref(notValidBefore)
			a.NotValidAfter = deref(notValidAfter)
			a.SignatureAlgoRef = deref(sigRef)
			a.SubjectPublicKeyRef = deref(pubKeyRef)
			a.CertFormat = deref(certFormat)
			a.CertExtension = deref(certExtension)
			a.QuantumFamily = deref(quantumFamily)
			a.QuantumReadinessGroup = deref(quantumGroup)
			a.QuantumRationale = deref(quantumRationale)
			a.GroverNote = deref(groverNote)
			a.PQCRecommendation = deref(pqcRecommendation)
			a.DeprecationStatus = deref(deprecationStatus)
			a.DeprecationRationale = deref(deprecationRationale)
			a.DeprecationReference = deref(deprecationReference)

			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// decodeCryptoJSON unmarshals one jsonb column; NULL leaves v untouched.
func decodeCryptoJSON(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}
