package store

import (
	"context"
	"fmt"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// ---------------------------------------------------------------------------
// Crypto assets — normalize.crypto_assets, read cross-schema.
//
// ⚠ SAME PATTERN AS ListDependencies (dependencies.go): this service owns
// project.* only, not normalize.*. One query, no cross-schema SQL JOIN
// (CLAUDE.md invariant 11), scoped by the project's current CBOM
// bom_document via resolveCurrentBOMDocument.
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
type CryptoAsset struct {
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

		rows, err := tx.Query(ctx, `
			SELECT component_key, asset_type, name,
			       primitive, mode, crypto_functions, classical_security_level, algorithm_list,
			       key_id, key_state, key_size,
			       to_char(creation_date, 'YYYY-MM-DD'), to_char(activation_date, 'YYYY-MM-DD'),
			       protocol_version, cipher_suites, oid,
			       cert_subject, cert_issuer,
			       to_char(not_valid_before, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			       to_char(not_valid_after, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			       signature_algo_ref, subject_public_key_ref, cert_format, cert_extension,
			       quantum_vulnerable, quantum_family, quantum_readiness_group,
			       quantum_rationale, grover_note, effective_quantum_bits,
			       pqc_recommendation, deprecation_status, deprecation_rationale,
			       deprecation_reference
			  FROM normalize.crypto_assets
			 WHERE bom_document_id = $1
			 ORDER BY asset_type, name`, docID)
		if err != nil {
			return fmt.Errorf("list crypto assets: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				a                              CryptoAsset
				componentKey                   *string
				primitive, mode                *string
				cryptoFunctions, algorithmList []string
				keyID, keyState                *string
				creationDate, activationDate   *string
				protocolVersion                *string
				cipherSuites                   []string
				oid                            *string
				certSubject, certIssuer        *string
				notValidBefore, notValidAfter  *string
				sigRef, pubKeyRef              *string
				certFormat, certExtension      *string
				quantumFamily, quantumGroup    *string
				quantumRationale, groverNote   *string
				pqcRecommendation              *string
				deprecationStatus              *string
				deprecationRationale           *string
				deprecationReference           *string
			)
			if err := rows.Scan(
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
			); err != nil {
				return fmt.Errorf("scan crypto asset: %w", err)
			}

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
