package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/vex"
	"github.com/axebom/axebom/services/report/internal/level"
	"github.com/axebom/axebom/services/report/internal/render"
)

// LoadBOM assembles the canonical BOM a renderer needs.
//
// ⚠ SEVERAL QUERIES ACROSS THREE SCHEMAS, JOINED IN GO. NOT ONE SQL JOIN.
//
// `report`, `normalize` and `scan` are separate service domains (ADR-0001). A
// SQL join across them costs nothing today and makes the services impossible to
// separate later — the one discipline that cannot be retrofitted. So each
// schema is queried on its own and the results are stitched here, which is also
// why the component and finding queries are scoped by bom_document_id: that is
// the partition key, so each stays inside its own partitions.
//
// Everything runs inside ONE db.WithTenant, so RLS scopes every read and a
// cross-tenant report id simply finds nothing.
// Load satisfies worker.Source. The interface is named for what the worker
// needs; this is the one implementation, reading the normalizer's own tables.
func (s *Store) Load(ctx context.Context, r Report) (render.BOM, error) {
	return s.LoadBOM(ctx, r)
}

func (s *Store) LoadBOM(ctx context.Context, r Report) (render.BOM, error) {
	bomType, err := model.ParseBOMType(r.BOMType)
	if err != nil {
		return render.BOM{}, err
	}

	out := render.BOM{
		ReportID:           r.ID,
		BOMType:            bomType,
		Level:              r.Level,
		ProfileID:          model.ProfileID,
		ProfileRevision:    model.ProfileRevision,
		ProfileAllVerified: model.ProfileAllVerified,
		ToolName:           "AxeBOM",
	}

	err = s.pool.WithTenant(ctx, r.TenantID, func(ctx context.Context, tx db.Tx) error {
		docID, err := s.resolveDocument(ctx, tx, r)
		if err != nil {
			return err
		}

		if err := loadDocumentMeta(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadProjectName(ctx, tx, r.ScanID, &out); err != nil {
			return err
		}
		if err := loadComponents(ctx, tx, docID, &out); err != nil {
			return err
		}
		// ⚠ RUN UNCONDITIONALLY, LIKE EVERY OTHER LOAD ABOVE. The crypto_assets
		// and quantum_components tables hold nothing for a SBOM/AIBOM/HBOM
		// document, so these are a no-op there — gating them on bomType would
		// duplicate the type list Sheets() already branches on, and the two lists
		// would drift the day a sixth BOM type is added.
		if err := loadCryptoAssets(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadCompanionCryptoAssets(ctx, tx, r, &out); err != nil {
			return err
		}
		if err := loadHardware(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadQuantumDevice(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadAIAssets(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadAIModels(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadFindings(ctx, tx, docID, r.ScanID, &out); err != nil {
			return err
		}
		if err := loadEngineCoverage(ctx, tx, r.ScanID, &out); err != nil {
			return err
		}
		if err := loadPractices(ctx, tx, r.ScanID, &out); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return render.BOM{}, err
	}

	applyLevel(&out)
	out.Licenses = licenseInventory(out.Components)
	out.Notes = methodologyNotes()

	return out, nil
}

// resolveDocument picks the BOM document this report describes.
//
// ⚠ THE LATEST NORMALIZATION VERSION, unless the report names a document.
//
// Re-normalization writes version N+1 and never overwrites N (ADR-0003), so
// "the document for this scan and BOM type" is ambiguous by design. A report
// created before a re-normalization pinned its document ids and keeps them, so
// re-rendering it produces the same report; a report created without them gets
// the current best answer.
func (s *Store) resolveDocument(ctx context.Context, tx db.Tx, r Report) (string, error) {
	if len(r.BOMDocumentIDs) > 0 {
		return r.BOMDocumentIDs[0], nil
	}

	var id string
	err := tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE scan_id = $1 AND bom_type = $2
		 ORDER BY normalization_version DESC
		 LIMIT 1`, r.ScanID, r.BOMType).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("resolve bom document: %w", err)
	}

	// ⚠ SECOND LOOKUP, BY PROJECT — AND WITHOUT IT QBOM COULD NEVER RENDER AT
	// ALL, NOR COULD AN IMPORTED HBOM.
	//
	// Not every BOM document is produced by a scan. A QBOM comes from the
	// Table 8 device form and an HBOM can come from a CSV or the structured
	// form, and both are written keyed on the PROJECT they describe
	// (services/project/internal/store/{qbom,hbom}.go). This resolver is
	// handed a report, and a report names a scan — so the first lookup above
	// asks a question those documents can never answer. A real scan id is
	// never a project id, so it did not return the wrong row; it returned no
	// row, and every QBOM report failed with "no normalized QBOM exists for
	// this scan".
	//
	// The scan lookup stays FIRST and stays authoritative. A project whose
	// hardware was both imported and scanned has two documents, and a report
	// generated from a scan must describe that scan — falling back only on
	// ErrNoRows is what keeps that true.
	projectID, perr := resolveProjectIDForScan(ctx, tx, r.ScanID)
	if perr != nil {
		// The scan itself is unreadable, so there is no project to fall back
		// to. Report the original miss, which is the more useful error.
		return "", notFoundDocument(r.BOMType)
	}

	err = tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE project_id = $1 AND bom_type = $2
		 ORDER BY normalization_version DESC
		 LIMIT 1`, projectID, r.BOMType).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", notFoundDocument(r.BOMType)
		}
		return "", fmt.Errorf("resolve bom document by project: %w", err)
	}
	return id, nil
}

// notFoundDocument is the one message both lookups fail with.
//
// ⚠ IT NAMES BOTH PATHS, because by the time a user sees it we have checked
// two genuinely different things: a scan produced nothing for this type, AND
// nothing was imported or entered for the project either. Saying only the
// first would send someone to look at a scan when the answer is that they
// never filled in the form.
func notFoundDocument(bomType string) error {
	return fmt.Errorf(
		"%w: no normalized %s exists for this scan or its project; the scan may "+
			"still be running or may have produced nothing, and nothing has been "+
			"imported or entered for this project", ErrNotFound, bomType)
}

func loadDocumentMeta(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	var (
		generatedAt               time.Time
		completeness, declaration *float64
		breakdown                 []byte
		normalizeDiagnostics      []byte
		supplementary             []byte
	)

	err := tx.QueryRow(ctx, `
		SELECT generated_at, completeness_pct, declaration_pct, coverage_breakdown,
		       ruleset_version, normalization_version, normalize_diagnostics,
		       supplementary_coverage
		  FROM normalize.bom_documents WHERE id = $1`, docID).
		Scan(&generatedAt, &completeness, &declaration, &breakdown,
			&out.RulesetVersion, &out.NormalizationVersion, &normalizeDiagnostics,
			&supplementary)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load bom document: %w", err)
	}

	// ⚠ UTC WITH A LITERAL Z, AND IT IS THE SCAN'S TIME. Every renderer dates
	// its output from this, so a re-render describes the same moment rather
	// than today (ADR-0003).
	out.GeneratedAt = generatedAt.UTC().Format("2006-01-02T15:04:05Z")

	// ⚠ NIL IS NOT ZERO. A document whose coverage was never computed must not
	// render as 0.00% — that reads as "we scored it and it failed" rather than
	// "it has not been scored". The sheets below still print a plain float and
	// have no "unscored" state of their own, so CoverageComputed is what lets
	// a caller further downstream (the worker, persisting to report.reports)
	// tell the two apart rather than storing a lying zero.
	// ⚠ WHAT NORMALIZATION COULD NOT DO, CARRIED INTO THE REPORT. Until
	// migration 0017 this column did not exist and the list was discarded at
	// writer.write_bom_document, so a customer's model count could change with
	// nothing anywhere explaining why. CLAUDE.md invariant 12 requires the
	// report to state what it could not see; these are that statement for the
	// normalizer, as Engine Coverage is for the engines.
	out.NormalizeDiagnostics = decodeNormalizeDiagnostics(normalizeDiagnostics)

	out.SupplementaryCoverage = decodeSupplementaryCoverage(supplementary)

	out.CoverageComputed = completeness != nil || declaration != nil
	if completeness != nil {
		out.Coverage.CompletenessPct = *completeness
	}
	if declaration != nil {
		out.Coverage.DeclarationPct = *declaration
	}

	return applyCoverageBreakdown(breakdown, out)
}

// decodeSupplementaryCoverage reads the scored, NON-compliance field sets.
//
// ⚠ THESE WERE WRITTEN FOR A WHOLE PHASE AND READ BY NOTHING. The HBOM
// manufacturing score has been in this column since migration 0011 and appeared
// in no report; the AI operational surface joined it. A number a customer cannot
// see is a number that does not exist.
//
// ⚠ MALFORMED JSON COSTS THE SUPPLEMENTARY NUMBERS, NEVER THE REPORT. These are
// additional context; the compliance numbers and the inventory are the report.
// Failing the render because an extra score would not parse would trade the
// whole document for a footnote.
func decodeSupplementaryCoverage(raw []byte) []render.SupplementaryCoverage {
	if len(raw) == 0 {
		return nil
	}
	var sets map[string]struct {
		ProfileID       string  `json:"profile_id"`
		ProfileRevision int     `json:"profile_revision"`
		Label           string  `json:"label"`
		IsCompliance    bool    `json:"is_compliance"`
		CompletenessPct float64 `json:"completeness_pct"`
		DeclarationPct  float64 `json:"declaration_pct"`
	}
	if err := json.Unmarshal(raw, &sets); err != nil {
		return nil
	}

	out := make([]render.SupplementaryCoverage, 0, len(sets))
	for key, v := range sets {
		id := v.ProfileID
		if id == "" {
			// The map key IS the profile id (the normalizer writes it that way);
			// the nested field is belt and braces. An entry with neither is
			// unrenderable — a number with no name is worse than no number.
			id = key
		}
		if id == "" || v.Label == "" {
			continue
		}
		out = append(out, render.SupplementaryCoverage{
			ProfileID:       id,
			ProfileRevision: v.ProfileRevision,
			Label:           v.Label,
			IsCompliance:    v.IsCompliance,
			CompletenessPct: v.CompletenessPct,
			DeclarationPct:  v.DeclarationPct,
		})
	}
	// Sorted so a re-render of the same document is byte-identical (ADR-0003).
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out
}

// applyCoverageBreakdown reads the per-field counts the normalizer wrote.
//
// ⚠ THE FORMULA IS CARRIED, NOT RE-DERIVED. Re-computing the percentage here
// would be a second implementation of the scoring rules, and the two would
// disagree the first time one changed. The renderer prints what the normalizer
// asserted, which is what makes the number auditable.
func applyCoverageBreakdown(raw []byte, out *render.BOM) error {
	if len(raw) == 0 {
		return nil
	}

	// ⚠ A LIST, NOT A MAP — AND DECODING IT AS A MAP EMPTIED THE PER-FIELD
	// COVERAGE TABLE IN EVERY REPORT THIS PRODUCT HAS EVER RENDERED.
	//
	// `CoverageResult.as_dict()` (libs/py-shared/.../coverage.py) emits
	// `"fields"` as a JSON ARRAY of objects, each carrying its own `field_id`.
	// This decoded it into `map[string]struct{...}`, so `json.Unmarshal`
	// returned an UnmarshalTypeError — and the deliberate `//nolint:nilerr`
	// below swallowed it and returned early, discarding the formula string
	// (which had decoded perfectly well) along with the fields.
	//
	// The result was not a visible failure. It was a coverage table that was
	// always empty and a formula line that was always blank, in the section of
	// the report an auditor actually reads, with no error anywhere. Verified
	// against the real serializer output rather than inferred.
	//
	// The tolerant error handling below is kept — it was right, and it is what
	// let the bug hide, which is exactly why the SHAPE has to be correct rather
	// than the handling strict.
	var breakdown struct {
		Formula string `json:"formula"`
		Fields  []struct {
			FieldID  string `json:"field_id"`
			Present  int    `json:"present"`
			Declared int    `json:"declared"`
			Total    int    `json:"total"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &breakdown); err != nil {
		// ⚠ NOT AN ERROR, DELIBERATELY. The two headline numbers are already
		// loaded and correct; only the per-field detail is unreadable, and it
		// renders as `not-provided`, which is the honest presentation of "we
		// could not read the detail". Failing the whole report over a
		// malformed breakdown would withhold a correct coverage number.
		return nil //nolint:nilerr // see above
	}

	out.Coverage.Formula = breakdown.Formula
	for _, fc := range breakdown.Fields {
		if fc.FieldID == "" {
			// A row that names no field cannot be joined to a profile element,
			// so it would render as an unlabelled line in the coverage table.
			continue
		}
		out.Coverage.Fields = append(out.Coverage.Fields, render.FieldCoverage{
			FieldID: fc.FieldID, Present: fc.Present, Declared: fc.Declared, Total: fc.Total,
		})
	}
	// Deterministic order: the serializer's array order is Python dict order,
	// and the artifact has to be byte-reproducible (ADR-0003).
	sort.Slice(out.Coverage.Fields, func(i, j int) bool {
		return out.Coverage.Fields[i].FieldID < out.Coverage.Fields[j].FieldID
	})
	return nil
}

// loadProjectName reads the project this scan belongs to.
//
// ⚠ TWO QUERIES, NOT A JOIN ACROSS scan AND project. Reuses
// resolveProjectIDForScan rather than writing `FROM project.projects p JOIN
// scan.scans s ON s.project_id = p.id` — the exact cross-schema SQL join
// loadPractices below is already flagged as a pre-existing violation of, not
// a precedent to repeat (CLAUDE.md invariant 11).
func loadProjectName(ctx context.Context, tx db.Tx, scanID string, out *render.BOM) error {
	projectID, err := resolveProjectIDForScan(ctx, tx, scanID)
	if err != nil {
		return err
	}

	var name string
	err = tx.QueryRow(ctx, `SELECT name FROM project.projects WHERE id = $1`, projectID).Scan(&name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The project was removed after the scan ran. The report still
			// renders; the name renders `not-provided` rather than failing the
			// whole BOM over a project that no longer exists.
			return nil
		}
		return fmt.Errorf("load project name: %w", err)
	}
	out.ProjectName = name
	return nil
}

// loadComponents reads the canonical components into profile-keyed fields.
//
// ⚠ THE MAPPING IS FROM COLUMN TO PROFILE FIELD ID, one place, here. The
// renderers never name a column, so a CERT-In revision that renames a field is
// a change to the profile plus this map — not a change to four renderers.
func loadComponents(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	rows, err := tx.Query(ctx, `
		SELECT component_key, purl, certin_identifier, ecosystem, name, version_raw,
		       description, supplier, license_effective, origin, patch_status,
		       release_date, eol_date, criticality, usage_restrictions, hashes,
		       comments, author_of_sbom_data, executable_property, archive_property,
		       structured_property, scope, is_direct, depth, is_orphan
		  FROM normalize.components
		 WHERE bom_document_id = $1
		 ORDER BY component_key`, docID)
	if err != nil {
		return fmt.Errorf("load components: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			c                                        render.Component
			purl, certinID, ecosystem, versionRaw    *string
			description, supplier, license, origin   *string
			patchStatus, usageRestrictions, comments *string
			author, executable, archive, structured  *string
			criticality                              *string
			releaseDate, eolDate                     *time.Time
			hashes                                   []byte
			name                                     string
			depth                                    *int
		)

		if err := rows.Scan(&c.Key, &purl, &certinID, &ecosystem, &name, &versionRaw,
			&description, &supplier, &license, &origin, &patchStatus,
			&releaseDate, &eolDate, &criticality, &usageRestrictions, &hashes,
			&comments, &author, &executable, &archive, &structured,
			&c.Scope, &c.IsDirect, &depth, &c.IsOrphan); err != nil {
			return fmt.Errorf("scan component: %w", err)
		}

		c.Purl = deref(purl)
		c.Ecosystem = deref(ecosystem)
		c.Depth = depth

		c.Fields = map[string]string{
			model.FieldCertinSbom01ComponentName:        name,
			model.FieldCertinSbom02ComponentVersion:     deref(versionRaw),
			model.FieldCertinSbom03ComponentDescription: deref(description),
			model.FieldCertinSbom04ComponentSupplier:    deref(supplier),
			model.FieldCertinSbom05ComponentLicense:     deref(license),
			model.FieldCertinSbom06ComponentOrigin:      deref(origin),
			model.FieldCertinSbom09PatchStatus:          deref(patchStatus),
			model.FieldCertinSbom10ReleaseDate:          formatDate(releaseDate),
			model.FieldCertinSbom11EolDate:              formatDate(eolDate),
			model.FieldCertinSbom12Criticality:          deref(criticality),
			model.FieldCertinSbom13UsageRestrictions:    deref(usageRestrictions),
			model.FieldCertinSbom14Checksums:            summariseHashes(hashes),
			model.FieldCertinSbom15Comments:             deref(comments),
			model.FieldCertinSbom16AuthorOfSbomData:     deref(author),
			model.FieldCertinSbom17Timestamp:            out.GeneratedAt,
			model.FieldCertinSbom18ExecutableProperty:   deref(executable),
			model.FieldCertinSbom19ArchiveProperty:      deref(archive),
			model.FieldCertinSbom20StructuredProperty:   deref(structured),
			model.FieldCertinSbom21UniqueIdentifier:     deref(certinID),
		}

		out.Components = append(out.Components, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Fields 7 and 8 are per-component ref lists. They are filled after the
	// findings and dependencies are known, not guessed at here.
	return loadComponentRelations(ctx, tx, docID, out)
}

// loadComponentRelations fills the dependency and vulnerability count fields,
// the structured edge list export formats need, and derives Roots.
func loadComponentRelations(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	counts := map[string]int{}
	rows, err := tx.Query(ctx, `
		SELECT fc.component_key, tc.component_key
		  FROM normalize.component_dependencies d
		  JOIN normalize.components fc
		    ON fc.id = d.from_component_id AND fc.bom_document_id = d.bom_document_id
		  JOIN normalize.components tc
		    ON tc.id = d.to_component_id AND tc.bom_document_id = d.bom_document_id
		 WHERE d.bom_document_id = $1
		   AND d.relationship = 'depends_on'`, docID)
	if err != nil {
		// The dependency table may legitimately be empty for a lockfile-only
		// scan. A missing graph is a gap in the report, not a failed render.
		deriveRoots(out)
		return nil //nolint:nilerr // see above
	}
	defer rows.Close()

	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			return err
		}
		out.Dependencies = append(out.Dependencies, render.Dependency{From: from, To: to})
		counts[from]++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range out.Components {
		if n, ok := counts[out.Components[i].Key]; ok && n > 0 {
			out.Components[i].Fields[model.FieldCertinSbom07ComponentDependencies] =
				fmt.Sprintf("%d direct dependencies", n)
		}
	}
	deriveRoots(out)
	return nil
}

// deriveRoots computes the export-layer root-element list from the
// already-loaded per-component Depth/IsOrphan — see the Roots field's doc
// comment on render.BOM for why this deliberately includes orphans.
func deriveRoots(out *render.BOM) {
	for _, c := range out.Components {
		if c.Depth == nil || *c.Depth == 0 {
			out.Roots = append(out.Roots, c.Key)
		}
	}
}

// loadCryptoAssets reads a CBOM's crypto inventory, type-discrimination and
// all.
//
// ⚠ EVERY COLUMN, REGARDLESS OF THIS ROW'S asset_type — SAME AS loadComponents
// SELECTS EVERY COLUMN REGARDLESS OF ECOSYSTEM. render.CryptoAsset carries
// every type's fields for the same reason normalize.crypto_assets is one wide
// table (migrations/normalize/0003): this loader does not need to know which
// asset types exist any more than loadComponents needs to know which
// ecosystems do. CBOMSheets is what branches on AssetType and renders only
// the applicable fields; duplicating that branch here would mean two places
// agree on the same list, and the two would drift the day CERT-In Table 9
// changes.
func loadCryptoAssets(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	rows, err := tx.Query(ctx, `
		SELECT component_key, asset_type, name,
		       primitive, mode, crypto_functions, classical_security_level, algorithm_list,
		       key_id, key_state, key_size, creation_date, activation_date,
		       protocol_version, cipher_suites, oid,
		       cert_subject, cert_issuer, not_valid_before, not_valid_after,
		       signature_algo_ref, subject_public_key_ref, cert_format, cert_extension,
		       quantum_vulnerable, pqc_recommendation, deprecation_status,
		       quantum_family, grover_note, quantum_rationale, deprecation_rationale,
		       deprecation_reference, effective_quantum_bits, quantum_readiness_group
		  FROM normalize.crypto_assets
		 WHERE bom_document_id = $1
		 ORDER BY asset_type, name`, docID)
	if err != nil {
		return fmt.Errorf("load crypto assets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			a                                                 render.CryptoAsset
			componentKey, primitive, mode                     *string
			keyID, keyState, protocolVersion, oid             *string
			certSubject, certIssuer, sigAlgoRef, subjectPKRef *string
			certFormat, certExtension                         *string
			pqcRecommendation, deprecationStatus              *string
			quantumFamily, groverNote, quantumRationale       *string
			deprecationRationale, deprecationReference        *string
			readinessGroup                                    *string
			classicalSecurityLevel, keySize, effectiveBits    *int
			creationDate, activationDate                      *time.Time
			notValidBefore, notValidAfter                     *time.Time
		)

		if err := rows.Scan(
			&componentKey, &a.AssetType, &a.Name,
			&primitive, &mode, &a.CryptoFunctions, &classicalSecurityLevel, &a.AlgorithmList,
			&keyID, &keyState, &keySize, &creationDate, &activationDate,
			&protocolVersion, &a.CipherSuites, &oid,
			&certSubject, &certIssuer, &notValidBefore, &notValidAfter,
			&sigAlgoRef, &subjectPKRef, &certFormat, &certExtension,
			&a.QuantumVulnerable, &pqcRecommendation, &deprecationStatus,
			&quantumFamily, &groverNote, &quantumRationale, &deprecationRationale,
			&deprecationReference, &effectiveBits, &readinessGroup,
		); err != nil {
			return fmt.Errorf("scan crypto asset: %w", err)
		}

		a.ComponentKey = deref(componentKey)
		a.Primitive = deref(primitive)
		a.Mode = deref(mode)
		a.ClassicalSecurityLevel = classicalSecurityLevel
		a.KeyID = deref(keyID)
		a.KeyState = deref(keyState)
		a.KeySize = keySize
		a.CreationDate = formatDate(creationDate)
		a.ActivationDate = formatDate(activationDate)
		a.ProtocolVersion = deref(protocolVersion)
		a.OID = deref(oid)
		a.CertSubject = deref(certSubject)
		a.CertIssuer = deref(certIssuer)
		// ⚠ FULL TIMESTAMPS, NOT JUST A DATE. Table 9's certificate validity
		// window is `datetime`, not `date` (CanonicalPath type in the profile) —
		// formatDate would silently drop the time of day from a value CERT-In
		// asks for at full precision.
		a.NotValidBefore = formatDateTime(notValidBefore)
		a.NotValidAfter = formatDateTime(notValidAfter)
		a.SignatureAlgoRef = deref(sigAlgoRef)
		a.SubjectPublicKeyRef = deref(subjectPKRef)
		a.CertFormat = deref(certFormat)
		a.CertExtension = deref(certExtension)
		a.PQCRecommendation = deref(pqcRecommendation)
		a.DeprecationStatus = deref(deprecationStatus)
		a.QuantumFamily = deref(quantumFamily)
		a.GroverNote = deref(groverNote)
		a.QuantumRationale = deref(quantumRationale)
		a.DeprecationRationale = deref(deprecationRationale)
		a.DeprecationReference = deref(deprecationReference)
		a.EffectiveQuantumBits = effectiveBits
		a.QuantumReadinessGroup = deref(readinessGroup)

		out.CryptoAssets = append(out.CryptoAssets, a)
	}
	return rows.Err()
}

// loadAIModels reads the current AIBOM model inventory for this document,
// including each model's datasets and SBOM dependency references.
//
// ⚠ THREE TABLE 10 ELEMENTS HAVE NO normalize.ai_models COLUMN, BY DESIGN, AND
// TWO OF THEM ARE STILL ANSWERABLE.
//
// `software_dependencies` (6) and `data_sets` (10) are RELATIONS in this schema —
// ai_model_dependencies and ai_datasets — not text blobs duplicated onto the
// model row. Both are derived below from rows this function already loads.
// Element 6 used to render `not-provided` in every report while its own
// dependency list sat in the adjacent variable.
//
// ⚠ `vulnerabilities` (18) IS STILL `not-provided`, AND THAT IS AN OPEN
// QUESTION RATHER THAN AN OVERSIGHT. An AI model has no findings of its own:
// AxeBOM matches no advisories against model weights, and there is no feed that
// would. What exists is findings against the model's DEPENDENCIES, which live on
// the project's SBOM document, not this one. Copying them here would assert that
// a vulnerability in `transformers` is a vulnerability OF `Llama-3-8B` — a
// defensible reading of element 18 and a decision with compliance consequences,
// so it is made deliberately (M4, with attestations) rather than by whoever
// happened to write this query. Until then the element is honestly absent and
// scores zero.
func loadAIModels(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	rows, err := tx.Query(ctx, `
		SELECT id, COALESCE(model_key,''), COALESCE(identity_rule,''),
		       COALESCE(identity_confidence,''), verified,
		       model_name, COALESCE(model_version,''), COALESCE(model_type,''),
		       COALESCE(model_developer,''), COALESCE(licensing,''),
		       ml_models_algorithms, performance_metrics, COALESCE(data_source,''),
		       COALESCE(hardware,''), COALESCE(security_requirements,''),
		       COALESCE(input,''), COALESCE(output,''), COALESCE(intended_usage,''),
		       COALESCE(out_of_scope_usage,''), COALESCE(environmental_impact,''),
		       COALESCE(attestation_signature,''), risk_score, owasp_llm_top10,
		       evidence
		  FROM normalize.ai_models
		 WHERE bom_document_id = $1
		 ORDER BY model_name`, docID)
	if err != nil {
		return fmt.Errorf("load ai models: %w", err)
	}
	defer rows.Close()

	type modelRow struct {
		id                                                  string
		modelKey, identityRule, identityConfidence          string
		verified                                            bool
		name, version, mtype, developer, licensing          string
		algorithms                                          []string
		metricsJSON                                         []byte
		dataSource, hardware, securityReqs                  string
		input, output, intendedUsage, outOfScope, envImpact string
		attestation                                         string
		riskScore                                           *float64
		owaspTop10                                          []string
		evidence                                            []string
	}
	var loaded []modelRow
	for rows.Next() {
		var m modelRow
		var evidenceJSON []byte
		if err := rows.Scan(
			&m.id, &m.modelKey, &m.identityRule, &m.identityConfidence, &m.verified,
			&m.name, &m.version, &m.mtype, &m.developer, &m.licensing,
			&m.algorithms, &m.metricsJSON, &m.dataSource,
			&m.hardware, &m.securityReqs,
			&m.input, &m.output, &m.intendedUsage,
			&m.outOfScope, &m.envImpact, &m.attestation, &m.riskScore, &m.owaspTop10,
			&evidenceJSON,
		); err != nil {
			return fmt.Errorf("scan ai model: %w", err)
		}
		// file:line, exactly as an engine reported it. A malformed array is
		// dropped rather than failing the report — the model row is worth more
		// than its evidence list.
		_ = json.Unmarshal(evidenceJSON, &m.evidence)
		loaded = append(loaded, m)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, m := range loaded {
		datasets, err := loadAIDatasets(ctx, tx, m.id)
		if err != nil {
			return err
		}
		deps, err := loadAIModelDependencies(ctx, tx, m.id)
		if err != nil {
			return err
		}

		foundBy, err := loadAIModelProvenance(ctx, tx, m.id)
		if err != nil {
			return err
		}

		datasetNames := make([]string, 0, len(datasets))
		for _, d := range datasets {
			datasetNames = append(datasetNames, d.Name)
		}

		out.AIModels = append(out.AIModels, render.AIModel{
			Name:               m.name,
			ModelKey:           m.modelKey,
			IdentityRule:       m.identityRule,
			IdentityConfidence: m.identityConfidence,
			Verified:           m.verified,
			Datasets:           datasets,
			Dependencies:       deps,
			FoundBy:            foundBy,
			Evidence:           m.evidence,
			RiskScore:          m.riskScore,
			OwaspLLMTop10:      m.owaspTop10,
			Fields: map[string]string{
				model.FieldCertinAibom01ModelName:      m.name,
				model.FieldCertinAibom02ModelVersion:   m.version,
				model.FieldCertinAibom03ModelType:      m.mtype,
				model.FieldCertinAibom04ModelDeveloper: m.developer,
				model.FieldCertinAibom05Licensing:      m.licensing,
				// ⚠ ELEMENT 6 RENDERED `not-provided` IN EVERY REPORT EVER
				// GENERATED, and the data was already in hand. It is derived from
				// this model's own `ai_model_dependencies` rows — exactly as
				// element 10 is derived from its `ai_datasets` rows two lines
				// below — rather than from a column, because the schema
				// deliberately represents a dependency as a relation and not as a
				// text blob duplicated onto the model.
				model.FieldCertinAibom06SoftwareDependencies: strings.Join(deps, ", "),
				model.FieldCertinAibom07MlModelsAlgorithms:   strings.Join(m.algorithms, ", "),
				model.FieldCertinAibom08PerformanceMetrics:   metricsText(m.metricsJSON),
				model.FieldCertinAibom09DataSource:           m.dataSource,
				model.FieldCertinAibom10DataSets:             strings.Join(datasetNames, ", "),
				model.FieldCertinAibom11Hardware:             m.hardware,
				model.FieldCertinAibom12SecurityRequirements: m.securityReqs,
				model.FieldCertinAibom13Input:                m.input,
				model.FieldCertinAibom14Output:               m.output,
				model.FieldCertinAibom15IntendedUsage:        m.intendedUsage,
				model.FieldCertinAibom16OutOfScopeUsage:      m.outOfScope,
				model.FieldCertinAibom17EnvironmentalImpact:  m.envImpact,
				model.FieldCertinAibom19Attestations:         m.attestation,
			},
		})
	}
	return nil
}

// loadAIModelProvenance returns every AIBOM engine that reported this model.
//
// ⚠ THE ROW'S `source_engine` COLUMN IS SINGULAR AND THE ANSWER IS NOT. Three
// AI discovery engines run independently and converge on the same model_key, so
// "who found this" has up to three answers — and one engine alone versus three
// agreeing is the most useful single fact a reviewer has for weighing a Table 10
// row. See migration 0018.
func loadAIModelProvenance(ctx context.Context, tx db.Tx, aiModelID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT engine_id
		  FROM normalize.ai_model_provenance
		 WHERE ai_model_id = $1
		 ORDER BY engine_id`, aiModelID)
	if err != nil {
		return nil, fmt.Errorf("load ai model provenance: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var engineID string
		if err := rows.Scan(&engineID); err != nil {
			return nil, fmt.Errorf("scan ai model provenance: %w", err)
		}
		out = append(out, engineID)
	}
	return out, rows.Err()
}

// loadAIAssets reads the prompts, vector stores, RAG pipelines and inference
// endpoints this document recorded.
//
// ⚠ NONE OF THESE IS A CERT-In TABLE 10 ELEMENT, AND THEY ARE STILL REPORTED.
// Table 10 asks about models. `airom` and `cdxgen-ai` find prompts, vector
// stores, RAG pipelines and the inference services a repository talks to, with
// file:line evidence — six of them on one small real tree. Storing those and
// rendering nothing is the silence invariant 12 exists to prevent, and scoring
// them into `completeness_pct` would move a compliance percentage using
// something the guideline never asked for. So: rendered, in their own section,
// scored into neither number.
func loadAIAssets(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	rows, err := tx.Query(ctx, `
		SELECT asset_type, asset_key, name, COALESCE(provider,''),
		       COALESCE(serves_model_key,''), evidence, attributes
		  FROM normalize.ai_assets
		 WHERE bom_document_id = $1
		 ORDER BY asset_type, name`, docID)
	if err != nil {
		return fmt.Errorf("load ai assets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a render.AIAsset
		var evidenceJSON, attributesJSON []byte
		if err := rows.Scan(
			&a.Type, &a.Key, &a.Name, &a.Provider, &a.ServesModel, &evidenceJSON, &attributesJSON,
		); err != nil {
			return fmt.Errorf("scan ai asset: %w", err)
		}
		// Malformed JSON drops that one field rather than failing the report:
		// an asset with no evidence list is still an asset that was found.
		_ = json.Unmarshal(evidenceJSON, &a.Evidence)
		var attributes struct {
			FoundBy []string `json:"found_by"`
		}
		_ = json.Unmarshal(attributesJSON, &attributes)
		a.FoundBy = attributes.FoundBy
		out.AIAssets = append(out.AIAssets, a)
	}
	return rows.Err()
}

func loadAIDatasets(ctx context.Context, tx db.Tx, aiModelID string) ([]render.AIDataset, error) {
	rows, err := tx.Query(ctx, `
		SELECT name, COALESCE(version,''), COALESCE(format,''),
		       COALESCE(limitations,''), COALESCE(license,''), COALESCE(source,'')
		  FROM normalize.ai_datasets
		 WHERE ai_model_id = $1
		 ORDER BY name`, aiModelID)
	if err != nil {
		return nil, fmt.Errorf("load ai datasets: %w", err)
	}
	defer rows.Close()

	var out []render.AIDataset
	for rows.Next() {
		var d render.AIDataset
		if err := rows.Scan(&d.Name, &d.Version, &d.Format, &d.Limitations, &d.License, &d.Source); err != nil {
			return nil, fmt.Errorf("scan ai dataset: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// loadAIModelDependencies returns the SBOM component keys this model
// depends on — component_key is plain text, not a foreign key; see
// docs/01-DATA-MODEL.md's ai_model_dependencies entry.
func loadAIModelDependencies(ctx context.Context, tx db.Tx, aiModelID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT component_key FROM normalize.ai_model_dependencies
		 WHERE ai_model_id = $1
		 ORDER BY component_key`, aiModelID)
	if err != nil {
		return nil, fmt.Errorf("load ai model dependencies: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan ai model dependency: %w", err)
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// metricsText renders performance_metrics jsonb compactly for the flat field
// table — the map-shaped value profile field 08 carries has no natural
// single-string form, so this is a readable summary, not a lossless one; the
// full JSON survives untouched in the JSON export's Canonical.AIModels.
func metricsText(raw []byte) string {
	if len(raw) == 0 || string(raw) == "{}" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// loadQuantumDevice reads the current device-metadata row for this document.
//
// ⚠ NIL IS A LEGITIMATE ANSWER, NOT AN ERROR. There is no quantum-hardware
// scanner (CLAUDE.md); every value on normalize.quantum_components is
// captured by form or import, and a project classified QBOM before anybody
// filled the form in has genuinely recorded nothing yet. render.BOM.
// QuantumDevice stays nil and the QBOM sheets render that as a stated gap —
// see render.quantumDeviceSheet — rather than this function inventing a
// zero-value device that would look like an empty form was submitted.
func loadQuantumDevice(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	var (
		d                                              render.QuantumDevice
		version, vendorOrigin, licenseInfo, commsProto *string
		hardware, environmentalImpact, attestation     *string
	)

	err := tx.QueryRow(ctx, `
		SELECT model_name, version, vendor_origin, license_info,
		       communication_protocol, hardware, software_dependencies,
		       environmental_impact, attestation_signature
		  FROM normalize.quantum_components
		 WHERE bom_document_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`, docID).
		Scan(&d.ModelName, &version, &vendorOrigin, &licenseInfo,
			&commsProto, &hardware, &d.SoftwareDependencies,
			&environmentalImpact, &attestation)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("load quantum device: %w", err)
	}

	d.Version = deref(version)
	d.VendorOrigin = deref(vendorOrigin)
	d.LicenseInfo = deref(licenseInfo)
	d.CommunicationProtocol = deref(commsProto)
	d.Hardware = deref(hardware)
	d.EnvironmentalImpact = deref(environmentalImpact)
	d.AttestationSignature = deref(attestation)
	out.QuantumDevice = &d
	return nil
}

func loadFindings(ctx context.Context, tx db.Tx, docID, scanID string, out *render.BOM) error {
	// ⚠ RESOLVED BEFORE THE FINDINGS QUERY OPENS, NOT AFTER — A SINGLE tx IS ONE
	// CONNECTION. Issuing either of these two queries while the findings Query's
	// Rows are still open (unclosed and undrained) fails every single call with
	// pgx's "conn busy": one transaction cannot interleave two in-flight
	// statements. This is not a JOIN across scan.scans either — the same
	// "several single-schema queries, joined in Go" discipline LoadBOM's own doc
	// comment states for this whole file (a discipline `loadPractices` above
	// does not actually follow — pre-existing, not a precedent to repeat).
	projectID, err := resolveProjectIDForScan(ctx, tx, scanID)
	if err != nil {
		return err
	}
	vexStatements := loadVEXStatementsForReport(ctx, tx, projectID)
	csafMitigation := loadCSAFMitigationForReport(ctx, tx, projectID)

	rows, err := tx.Query(ctx, `
		SELECT f.display_id_at_render, f.cluster_id, c.component_key,
		       f.severity_effective, f.cvss_primary_score, f.severity_conflict,
		       f.fixed_in_min, f.fix_version_ordering, f.detected_by
		  FROM normalize.findings f
		  JOIN normalize.components c
		    ON c.id = f.component_id AND c.bom_document_id = f.bom_document_id
		 WHERE f.bom_document_id = $1
		 ORDER BY f.display_id_at_render, c.component_key`, docID)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	defer rows.Close()

	byComponent := map[string]int{}
	for rows.Next() {
		var (
			f          render.Finding
			severity   *string
			score      *float64
			conflict   bool
			fixedIn    *string
			ordering   string
			detectedBy []string
		)
		if err := rows.Scan(&f.DisplayID, &f.ClusterID, &f.ComponentKey,
			&severity, &score, &conflict, &fixedIn, &ordering, &detectedBy); err != nil {
			return fmt.Errorf("scan finding: %w", err)
		}

		f.Severity = deref(severity)
		f.DetectedBy = detectedBy
		if score != nil {
			f.CVSSScore = fmt.Sprintf("%.1f", *score)
		}
		// ⚠ SURFACED, NEVER RESOLVED. v2, v3.1 and v4.0 are different scales;
		// a reviewer will ask why one engine said High and another Critical,
		// and the answer has to be visible rather than averaged away.
		if conflict {
			f.SeverityConflict = "sources disagreed; every source is retained"
		}
		// ⚠ `unknown` ORDERING MEANS WE HAVE NO COMPARATOR, so the minimum is
		// not a claim we can make. Reporting the raw value would assert an
		// ordering that a lexical sort gets wrong for every ecosystem.
		if fixedIn != nil && ordering == "known" {
			f.FixedInMin = *fixedIn
		}

		// ⚠ RESOLVED PER (cluster, component) — THE EXACT PAIR vex.Resolve
		// TAKES. Unlike services/project's Finding (one row per CLUSTER,
		// spanning every affected component, which forces picking a winner
		// across several possible resolutions), this render.Finding is
		// already one row per (cluster, component), so there is no
		// aggregation ambiguity to resolve here at all.
		if effective := vex.Resolve(vexStatements, f.ClusterID, f.ComponentKey); effective != nil {
			f.VEXStatus = string(effective.Status)
			f.VEXJustification = effective.Justification
			f.VEXRemediation = effective.Remediation
			f.VEXWorkarounds = effective.Workarounds
			f.VEXDowntime = effective.Downtime
			// ⚠ ONLY WHEN A CSAF ADVISORY WAS ACTUALLY GENERATED for the
			// WINNING statement. A finding with a VEX statement but no
			// generated advisory renders `not-provided` here, honestly — see
			// loadCSAFMitigationForReport.
			f.CSAFMitigation = csafMitigation[effective.StatementID]
		}

		byComponent[f.ComponentKey]++
		out.Findings = append(out.Findings, f)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range out.Components {
		if n, ok := byComponent[out.Components[i].Key]; ok {
			out.Components[i].Fields[model.FieldCertinSbom08Vulnerabilities] =
				fmt.Sprintf("%d", n)
		}
	}
	return nil
}

// resolveProjectIDForScan looks up the project a scan belongs to.
//
// ⚠ normalize.vex_statements KEYS ON project_id, NOT scan_id — a triage
// decision is a fact about a project's vulnerability landscape that survives
// across re-scans (services/scan-orchestrator/internal/orchestr/vex_store.go's
// own doc comment), so resolving it for a REPORT (which describes one scan)
// means going through the scan it belongs to.
func resolveProjectIDForScan(ctx context.Context, tx db.Tx, scanID string) (string, error) {
	var projectID string
	err := tx.QueryRow(ctx, `SELECT project_id FROM scan.scans WHERE id = $1`, scanID).Scan(&projectID)
	if err != nil {
		return "", fmt.Errorf("resolve project for scan: %w", err)
	}
	return projectID, nil
}

// loadCompanionCryptoAssets fills a QBOM's crypto inventory from the project's
// CBOM, because a QBOM has none of its own and never did.
//
// ⚠ WITHOUT THIS, EVERY QBOM REPORT EVER RENDERED SAID "No cryptographic assets
// were discovered" — IN EVERY FORMAT, REGARDLESS OF WHAT THE CBOM FOUND.
//
// A QBOM's document is written by the Table 8 device form
// (services/project/internal/store/qbom.go) and holds exactly one row: the
// device. Crypto assets only ever exist under the CBOM document — verified
// against a live database, where all 214 of them carried bom_type = 'CBOM' and
// no other type had a single one. `loadCryptoAssets` above is scoped
// `WHERE bom_document_id = $1`, so for a QBOM it correctly returns nothing, and
// `quantumReadinessSheet` then rendered its zero-asset branch every time.
//
// That branch's own words are what made this so damaging: "No cryptographic
// assets were discovered … check Engine Coverage for whether a CBOM engine ran
// at all." It sent the reader to look at the engine, when the engine had run
// and found plenty.
//
// render.BOM's own doc comment has always said CryptoAssets is "READ (never
// re-discovered) by a QBOM's readiness view". This is the read that was missing.
//
// ⚠ IT NEVER OVERWRITES. If the document somehow has its own assets, they win —
// borrowing is the fallback, not the rule.
func loadCompanionCryptoAssets(ctx context.Context, tx db.Tx, r Report, out *render.BOM) error {
	if out.BOMType != model.BOMTypeQBOM || len(out.CryptoAssets) > 0 {
		return nil
	}

	projectID, err := resolveProjectIDForScan(ctx, tx, r.ScanID)
	if err != nil {
		// No project, no companion. A QBOM with no readiness data is a
		// legitimate state (nobody has run a CBOM yet); a failed render is not.
		return nil //nolint:nilerr // absence is a valid outcome, see above
	}

	var docID, generatedAt string
	err = tx.QueryRow(ctx, `
		SELECT id, to_char(generated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		  FROM normalize.bom_documents
		 WHERE project_id = $1 AND bom_type = 'CBOM'
		 ORDER BY generated_at DESC, normalization_version DESC
		 LIMIT 1`, projectID).Scan(&docID, &generatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// ⚠ A SECOND LOOKUP, BY SCAN, BECAUSE project_id IS ONLY POPULATED FOR
		// DOCUMENTS THAT NEEDED IT. Migrations 0012 and 0014 backfilled HBOM and
		// QBOM — the two types whose scan_id literally held a project id. A CBOM
		// comes from a real scan and keeps project_id NULL, so it is reachable
		// only through the scans that belong to this project.
		err = tx.QueryRow(ctx, `
			SELECT d.id,
			       to_char(d.generated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			  FROM normalize.bom_documents d
			  JOIN scan.scans s ON s.id = d.scan_id
			 WHERE s.project_id = $1 AND d.bom_type = 'CBOM'
			 ORDER BY d.generated_at DESC, d.normalization_version DESC
			 LIMIT 1`, projectID).Scan(&docID, &generatedAt)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("resolve companion CBOM document: %w", err)
	}

	if err := loadCryptoAssets(ctx, tx, docID, out); err != nil {
		return err
	}
	out.CryptoAssetsFrom = render.CryptoAssetSource{
		BOMType:     "CBOM",
		DocumentID:  docID,
		GeneratedAt: generatedAt,
	}
	return nil
}

// loadVEXStatementsForReport reads every VEX statement for a project.
//
// ⚠ ERRORS ARE SWALLOWED, DELIBERATELY — mirrors services/project's own
// loadClusterVEX precedent. VEX is optional; a project with none recorded is
// the ordinary case, not a reason to fail an entire report render over a
// section that would legitimately render empty anyway.
func loadVEXStatementsForReport(ctx context.Context, tx db.Tx, projectID string) []vex.Statement {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, project_id, COALESCE(component_key,''), cluster_id,
		       status, COALESCE(justification,''), COALESCE(remediation,''),
		       COALESCE(workarounds,''), COALESCE(downtime,''), scope, version,
		       COALESCE(superseded_by::text,''), COALESCE(author_user_id::text,''), created_at
		  FROM normalize.vex_statements
		 WHERE project_id = $1
		 ORDER BY created_at`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []vex.Statement
	for rows.Next() {
		var st vex.Statement
		var status, scope string
		if err := rows.Scan(
			&st.ID, &st.TenantID, &st.ProjectID, &st.ComponentKey, &st.ClusterID,
			&status, &st.Justification, &st.Remediation, &st.Workarounds, &st.Downtime,
			&scope, &st.Version, &st.SupersededBy, &st.AuthorUserID, &st.CreatedAt,
		); err != nil {
			return nil
		}
		st.Status = vex.Status(status)
		st.Scope = vex.Scope(scope)
		out = append(out, st)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// loadCSAFMitigationForReport reads certin.csaf.mitigation, keyed by the
// vex_statement_id it was generated for.
//
// ⚠ MIRRORS store/csaf.go's ListCSAFAdvisories JOIN, NOT A NEW PATTERN — same
// schema (normalize), same join shape, same project-scoping. Errors are
// swallowed like loadVEXStatementsForReport above: a project with no CSAF
// advisories generated is the ordinary case (CSAF is generated per statement,
// on demand, from the Findings UI), not a reason to fail the whole render.
func loadCSAFMitigationForReport(ctx context.Context, tx db.Tx, projectID string) map[string]string {
	rows, err := tx.Query(ctx, `
		SELECT a.vex_statement_id, COALESCE(a.mitigation_steps,'')
		  FROM normalize.csaf_advisories a
		  JOIN normalize.vex_statements v ON v.id = a.vex_statement_id
		 WHERE v.project_id = $1`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var statementID, mitigation string
		if err := rows.Scan(&statementID, &mitigation); err != nil {
			return nil
		}
		out[statementID] = mitigation
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// loadEngineCoverage reads the mandatory Engine Coverage section.
//
// ⚠ A SEPARATE QUERY AGAINST THE `scan` SCHEMA, joined in Go. And a failure
// here is NOT swallowed: a report whose Engine Coverage section is missing
// cannot state what it could not see, which is the one thing this product
// promises.
func loadEngineCoverage(ctx context.Context, tx db.Tx, scanID string, out *render.BOM) error {
	rows, err := tx.Query(ctx, `
		SELECT engine_id, COALESCE(engine_version,''), status,
		       COALESCE(engine_db_version,''), ecosystems_covered,
		       COALESCE(error_code,'')
		  FROM scan.engine_runs
		 WHERE scan_id = $1
		 ORDER BY engine_id`, scanID)
	if err != nil {
		return fmt.Errorf("load engine coverage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e render.EngineCoverage
		if err := rows.Scan(&e.EngineID, &e.Version, &e.Status,
			&e.DatabaseVersion, &e.Ecosystems, &e.Diagnostic); err != nil {
			return fmt.Errorf("scan engine run: %w", err)
		}
		out.Engines = append(out.Engines, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	out.EcosystemsWithNoEngine = ecosystemsWithNoEngine(out)
	return nil
}

// ecosystemsWithNoEngine names what was detected and could not be scanned.
//
// ⚠ THE MOST IMPORTANT LINE IN ANY REPORT WE PRODUCE. An SBOM that silently
// omits an ecosystem converts an unknown into a false negative the customer
// trusts. An ecosystem appears here when a component was catalogued in it and
// no engine reported covering it.
func ecosystemsWithNoEngine(b *render.BOM) []string {
	covered := map[string]bool{}
	for _, e := range b.Engines {
		for _, eco := range e.Ecosystems {
			covered[eco] = true
		}
	}

	seen := map[string]bool{}
	var out []string
	for _, c := range b.Components {
		if c.Ecosystem == "" || covered[c.Ecosystem] || seen[c.Ecosystem] {
			continue
		}
		seen[c.Ecosystem] = true
		out = append(out, c.Ecosystem)
	}
	sort.Strings(out)
	return out
}

// loadPractices reads the six CERT-In Table 5 category-3 settings.
//
// They live on the PROJECT, which this service reaches through the scan. A
// missing row is not an error: it means the project never recorded them, which
// is itself the gap the Practices sheet reports.
func loadPractices(ctx context.Context, tx db.Tx, scanID string, out *render.BOM) error {
	var (
		frequency, depth, knownUnknowns *string
		distribution, accessControl     *string
		errata                          *string
	)

	err := tx.QueryRow(ctx, `
		SELECT p.frequency, p.depth, p.known_unknowns,
		       p.distribution, p.access_control, p.errata_policy
		  FROM project.practices p
		  JOIN scan.scans s ON s.project_id = p.project_id
		 WHERE s.id = $1`, scanID).
		Scan(&frequency, &depth, &knownUnknowns, &distribution, &accessControl, &errata)
	if err != nil {
		// Never recorded, or the project was removed. The Practices sheet
		// renders every sub-element as `not-provided` with a stated gap, which
		// is the correct report rather than a failed render.
		return nil //nolint:nilerr // see above
	}

	pairs := []struct {
		id    string
		value *string
	}{
		{model.FieldCertinSbomPpFrequency, frequency},
		{model.FieldCertinSbomPpDepth, depth},
		{model.FieldCertinSbomPpKnownUnknowns, knownUnknowns},
		{model.FieldCertinSbomPpDistributionAndDelivery, distribution},
		{model.FieldCertinSbomPpAccessControl, accessControl},
		{model.FieldCertinSbomPpAccommodationOfMistakes, errata},
	}
	for _, p := range pairs {
		value := deref(p.value)
		gap := ""
		// ⚠ `not-provided` IS RECORDED AND STILL A GAP. It is a declaration,
		// not a substantive value, and scores zero for completeness
		// (CLAUDE.md invariant 3).
		switch value {
		case "":
			gap = "Never recorded for this project."
		case model.NotProvided:
			gap = "Recorded as `" + model.NotProvided + "`, which is a declaration " +
				"rather than a substantive value."
		}
		out.Practices = append(out.Practices, render.Practice{
			FieldID: p.id, Value: value, Gap: gap,
		})
	}
	return nil
}

// flatInventoryLevelNote states that a level does not narrow a flat inventory.
//
// ⚠ CRYPTO ASSETS AND AI MODELS WERE PROJECTED BY NOTHING, AND THE REPORT SAID
// NOTHING ABOUT IT. `level.Project` walks software components and
// `applyLevelToHardware` walks the hardware tree; a CBOM's assets and an
// AIBOM's models were simply rendered in full under a heading that said
// "Top-Level", so the level label on those two report types meant nothing at
// all.
//
// ⚠ THE FIX IS A STATEMENT, NOT AN INVENTED PROJECTION. Neither inventory has a
// depth: Table 9's assets are attached to components when an engine could
// attribute them and stand alone when it could not, and Table 10's models are a
// flat list. Filtering them by some derived notion of "top level" would drop
// rows on a rule this product made up, in a compliance document — far worse
// than rendering all of them and saying why.
//
// This is the third entity kind the level has had to account for. If a fourth
// arrives, it belongs here or in applyLevelToHardware, never in a new branch of
// its own — that is how the first two came to disagree.
func flatInventoryLevelNote(out *render.BOM, l level.Level) string {
	if l != level.TopLevel {
		return ""
	}
	switch {
	// ⚠ NOT GATED ON BOMTypeCBOM — IT WAS, AND A QBOM FELL THROUGH TO SILENCE.
	// The gate was written when a CBOM was the only report that carried Table 9
	// assets. A QBOM now carries them too (they are resolved from the companion
	// CBOM document, which is the whole of its readiness half), so a Top-Level
	// QBOM matched no case and said nothing at all about its own level. The
	// REASON in this note — Table 9 assets have no depth to narrow by — is a
	// fact about the assets, not about which report renders them, so the
	// condition is now the presence of the assets, like the AI-model case below.
	case len(out.CryptoAssets) > 0:
		return fmt.Sprintf(
			"All %d cryptographic asset(s) are listed. A CERT-In §3.1 level "+
				"narrows a dependency tree by depth, and Table 9's assets have "+
				"none — so Top-Level does not omit any of them here.",
			len(out.CryptoAssets))
	case len(out.AIModels) > 0:
		return fmt.Sprintf(
			"All %d AI model(s) are listed. A CERT-In §3.1 level narrows a "+
				"dependency tree by depth, and Table 10's inventory is flat — so "+
				"Top-Level does not omit any of them here.",
			len(out.AIModels))
	default:
		return ""
	}
}

// applyLevelToHardware narrows the hardware tree the same way.
//
// ⚠ WITHOUT THIS, A REPORT LABELLED "Top-Level" RENDERED THE ENTIRE ASSEMBLY.
//
// level.Project walks `render.BOM.Components` — software — and nothing applied
// the same rule to `render.BOM.Hardware`. So a customer who asked for a
// Top-Level hardware BOM got every one of 900 parts under a heading promising
// the top level only. That is not a rendering nuisance: the level is a CERT-In
// §3.1 projection the customer CHOSE, and a document that silently ignores the
// choice misdescribes its own scope.
//
// ⚠ THE SUB-ASSEMBLIES ARE KEPT AND THEIR CONTENTS ARE NOT. Depth ≤ 1 is the
// product plus the assemblies it is built from — which is exactly what a
// top-level view of hardware means, and matches what depth ≤ 1 means for
// software. Everything dropped is COUNTED and stated in the note, because "42
// components" without "and 858 omitted" is indistinguishable from a product
// that genuinely has 42 parts.
func applyLevelToHardware(out *render.BOM, l level.Level) string {
	if len(out.Hardware) == 0 || l != level.TopLevel {
		return ""
	}

	kept := make([]render.HardwareComponent, 0, len(out.Hardware))
	var excluded int
	for _, h := range out.Hardware {
		if h.Depth <= 1 {
			kept = append(kept, h)
			continue
		}
		excluded++
	}
	if excluded == 0 {
		return ""
	}

	out.Hardware = kept
	return fmt.Sprintf(
		"%d sub-component(s) below the top level are omitted from this Top-Level "+
			"hardware BOM; they appear in the Complete BOM.", excluded)
}

// appendLevelNote adds to the level note rather than replacing it.
//
// Two projections write into one field — software components and the hardware
// tree — and a report can in principle carry both. Assigning would drop
// whichever ran first, and the dropped one is an omission the reader is
// entitled to know about.
func appendLevelNote(out *render.BOM, note string) {
	if note == "" {
		return
	}
	if out.LevelNote == "" {
		out.LevelNote = note
		return
	}
	out.LevelNote += " " + note
}

// applyLevel narrows the component set to the report's level.
//
// ⚠ EVERYTHING EXCLUDED IS COUNTED AND SAID. A Top-Level report claiming "42
// components" without stating it omitted 900 is indistinguishable from a
// project that genuinely has 42.
func applyLevel(out *render.BOM) {
	l := level.Level(out.Level)
	if !level.Valid(l) {
		return
	}

	// ⚠ THE HARDWARE NOTE IS HELD, NOT WRITTEN, UNTIL AFTER THE SOFTWARE
	// PROJECTION. The software path ASSIGNS out.LevelNote from its own
	// projection, so a note written here would be silently overwritten a few
	// lines down — which is exactly what happened the first time, and the test
	// caught it. Filtering happens now; the note is appended at the end.
	hardwareNote := applyLevelToHardware(out, l)
	flatNote := flatInventoryLevelNote(out, l)

	byKey := make(map[string]render.Component, len(out.Components))
	projectable := make([]level.Component, 0, len(out.Components))
	for _, c := range out.Components {
		byKey[c.Key] = c
		projectable = append(projectable, level.Component{
			Key: c.Key, Depth: c.Depth, IsDirect: c.IsDirect,
			IsOrphan: c.IsOrphan, Scope: c.Scope,
		})
	}

	projection, err := level.Project(projectable, l)
	if err != nil {
		// The hardware was still projected above, and its note must not be lost
		// because the software projection refused a level it does not implement.
		appendLevelNote(out, hardwareNote)
		appendLevelNote(out, flatNote)
		return
	}

	kept := make([]render.Component, 0, len(projection.Components))
	keptKeys := make(map[string]bool, len(projection.Components))
	for _, c := range projection.Components {
		kept = append(kept, byKey[c.Key])
		keptKeys[c.Key] = true
	}
	out.Components = kept
	out.LevelNote = projection.Note
	appendLevelNote(out, hardwareNote)
	appendLevelNote(out, flatNote)

	// Findings for components the level dropped go with them; keeping them
	// would list a vulnerability against a component the report does not
	// contain.
	filtered := out.Findings[:0]
	for _, f := range out.Findings {
		if keptKeys[f.ComponentKey] {
			filtered = append(filtered, f)
		}
	}
	out.Findings = filtered

	// Roots and edges referencing a component the level dropped must drop
	// with it — an export root or edge endpoint pointing at a component the
	// document no longer contains is a dangling reference, not a smaller BOM.
	rootsFiltered := out.Roots[:0]
	for _, r := range out.Roots {
		if keptKeys[r] {
			rootsFiltered = append(rootsFiltered, r)
		}
	}
	out.Roots = rootsFiltered

	depsFiltered := out.Dependencies[:0]
	for _, d := range out.Dependencies {
		if keptKeys[d.From] && keptKeys[d.To] {
			depsFiltered = append(depsFiltered, d)
		}
	}
	out.Dependencies = depsFiltered

	// A declared root can itself be scope-excluded while a non-root
	// descendant survives — the projection above correctly drops the root's
	// key from out.Roots along with the component, but a document with
	// components and zero roots is unexportable. Rather than guess which
	// survivor should inherit the missing root's place (Roots does not
	// recompute from edges here — see its doc comment on why "no incoming
	// edge" is not a safe stand-in for "is a root" once cycles are in play),
	// fall back to the same honest answer used when there was never a graph
	// at all: list every survivor independently.
	if len(out.Roots) == 0 && len(out.Components) > 0 {
		out.Roots = make([]string, len(out.Components))
		for i, c := range out.Components {
			out.Roots[i] = c.Key
		}
	}

	if note := level.OrphanNote(projectable); note != "" && l == level.Complete {
		out.Notes = append(out.Notes, note)
	}
}

// licenseInventory aggregates the effective licences across components.
//
// ⚠ `declared`, `concluded` AND `observed` STAY SEPARATE in the data model;
// this inventory reports the EFFECTIVE value and labels it as such, so a reader
// does not take an aggregate as evidence that the three agreed.
func licenseInventory(components []render.Component) []render.License {
	counts := map[string]int{}
	for _, c := range components {
		expr := c.Fields[model.FieldCertinSbom05ComponentLicense]
		if expr == "" {
			expr = "NOASSERTION"
		}
		counts[expr]++
	}

	out := make([]render.License, 0, len(counts))
	for expr, n := range counts {
		l := render.License{Expression: expr, Kind: "effective", ComponentCount: n}
		switch expr {
		case "NOASSERTION":
			l.Note = "No licence was asserted. Different from `NONE`, which is a " +
				"substantive claim that there is no licence."
		case "NONE":
			l.Note = "A substantive assertion that there is no licence. Counts as " +
				"present for coverage; `NOASSERTION` does not."
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expression < out[j].Expression })
	return out
}

// methodologyNotes are the footnotes every report carries.
func methodologyNotes() []string {
	return []string{
		"Component counts are post-deduplication. The same package reported by " +
			"several engines is one component, merged on its canonical ecosystem " +
			"PURL, with every engine that saw it listed.",
		"Vulnerability counts are post-deduplication across identifier schemes. " +
			"GHSA, CVE, OSV and distro identifiers for one issue are a single " +
			"finding; counting them separately inflates a total roughly threefold.",
	}
}

// ---------------------------------------------------------------------------

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func formatDate(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

// formatDateTime renders a full timestamp, UTC with a literal Z (CLAUDE.md's
// time convention) — for a `datetime`-typed profile field like a
// certificate's validity window, where formatDate's date-only truncation
// would silently drop the time of day CERT-In asks for.
func formatDateTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// summariseHashes renders the checksum list for the field-14 column.
func summariseHashes(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var hashes []struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
	}
	if err := json.Unmarshal(raw, &hashes); err != nil || len(hashes) == 0 {
		return ""
	}

	sort.Slice(hashes, func(i, j int) bool { return hashes[i].Algorithm < hashes[j].Algorithm })
	out := ""
	for i, h := range hashes {
		if i > 0 {
			out += "; "
		}
		out += h.Algorithm + ":" + h.Value
	}
	return out
}

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------

// loadHardware fills render.BOM.Hardware.
//
// ⚠ THIS LOADER DID NOT EXIST, AND ITS ABSENCE WAS THE WHOLE REASON EVERY HBOM
// REPORT RENDERED EMPTY.
//
// `render.HBOMSheets` and `docxHardware` have been wired into the renderer
// since Phase 15 and read `b.Hardware`, which nothing ever populated — so a
// customer who imported a 400-line parts list got a report with two blank
// hardware sheets and no error anywhere. That is the silent-emptiness failure
// invariant 12 exists to prevent, sitting in the product's own output path.
//
// ⚠ ORDERED PARENTS-BEFORE-CHILDREN BY A RECURSIVE CTE, NOT BY A SORT.
//
// The renderer indents by `Depth` and the exporter emits `contains` edges, and
// both need the tree walked in a stable, parent-first order. Sorting by any
// column would put a child before its parent whenever names happen to sort
// that way, which reads as a mangled assembly in the spreadsheet and produces
// an unresolvable reference in the export. The CTE computes depth from the
// actual parent links, so the order is the tree's, not the data's.
func loadHardware(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE tree AS (
		    SELECT id, parent_id, 0 AS depth, ARRAY[product_name, id::text] AS path
		      FROM normalize.hardware_components
		     WHERE bom_document_id = $1 AND parent_id IS NULL
		    UNION ALL
		    SELECT c.id, c.parent_id, t.depth + 1,
		           t.path || c.product_name || c.id::text
		      FROM normalize.hardware_components c
		      JOIN tree t ON c.parent_id = t.id
		     WHERE c.bom_document_id = $1
		)
		SELECT h.id, COALESCE(h.parent_id::text, ''), t.depth,
		       h.product_name, COALESCE(h.product_version,''), COALESCE(h.product_details,''),
		       COALESCE(h.model_number,''), COALESCE(h.serial_number,''),
		       COALESCE(h.manufacturer_name,''), COALESCE(h.manufacturer_location,''),
		       COALESCE(h.origin,''),
		       COALESCE(h.supplier_info,''), COALESCE(h.supplier_location,''),
		       COALESCE(h.component_supplier_info,''), COALESCE(h.component_supplier_location,''),
		       COALESCE(h.criticality,''), COALESCE(h.firmware_version,''), h.compliance,
		       h.quantity, h.designators, COALESCE(h.package_footprint,''),
		       COALESCE(h.supplier_sku,''), COALESCE(h.preferred_supplier,''),
		       COALESCE(h.unit_price::text,''), COALESCE(h.currency,''),
		       COALESCE(h.extended_price::text,''),
		       h.do_not_populate, COALESCE(h.assembly_type,''), COALESCE(h.lifecycle_status,''),
		       COALESCE(h.datasheet_url,''), COALESCE(h.technical_specification,''),
		       COALESCE(h.source_engine,''), h.enriched_fields,
		       COALESCE(h.vuln_match_status,'not-attempted'), h.cpe23_candidates
		  FROM tree t
		  JOIN normalize.hardware_components h ON h.id = t.id
		 ORDER BY t.path`, docID)
	if err != nil {
		return fmt.Errorf("load hardware components: %w", err)
	}
	defer rows.Close()

	index := map[string]int{}
	for rows.Next() {
		var (
			c           render.HardwareComponent
			enriched    []byte
			designators []string
			compliance  []string
			candidates  []string
		)
		if err := rows.Scan(
			&c.ID, &c.ParentID, &c.Depth,
			&c.Name, &c.Version, &c.Description, &c.ModelNumber, &c.SerialNumber,
			&c.ManufacturerName, &c.ManufacturerLocation, &c.Origin,
			&c.SupplierInfo, &c.SupplierLocation,
			&c.ComponentSupplierInfo, &c.ComponentSupplierLocation,
			&c.Criticality, &c.FirmwareVersion, &compliance,
			&c.Quantity, &designators, &c.PackageFootprint,
			&c.SupplierSKU, &c.PreferredSupplier,
			&c.UnitPrice, &c.Currency, &c.ExtendedPrice,
			&c.DoNotPopulate, &c.AssemblyType, &c.LifecycleStatus,
			&c.DatasheetURL, &c.TechnicalSpecification,
			&c.SourceEngine, &enriched,
			&c.VulnMatchStatus, &candidates,
		); err != nil {
			return fmt.Errorf("scan hardware component: %w", err)
		}
		c.Compliance = compliance
		c.Designators = designators
		c.CPE23Candidates = candidates
		c.EnrichedFields = decodeStringMap(enriched)
		index[c.ID] = len(out.Hardware)
		out.Hardware = append(out.Hardware, c)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate hardware components: %w", err)
	}

	if err := loadHardwareAlternates(ctx, tx, docID, out, index); err != nil {
		return err
	}
	return loadHardwareFindings(ctx, tx, docID, out, index)
}

// loadHardwareFindings attaches CERT-In element 24's advisory matches.
//
// ⚠ A SEPARATE TABLE AND A SEPARATE LOADER FROM loadFindings, AND THAT IS THE
// POINT. loadFindings is an INNER JOIN against normalize.components; a hardware
// finding routed through it would match nothing and vanish from the report with
// no error anywhere — the silent false negative invariant 12 exists to prevent.
// Migration 0013 records the same reasoning on the schema side.
//
// ⚠ THESE SEVERITIES ARE NEVER ADDED TO out.Findings. The software counts a
// report quotes are exact; these are advisory. One blended "3 critical" figure
// of which part is a fact and part is a guess, with nothing saying which, is
// worse than two honest numbers.
func loadHardwareFindings(
	ctx context.Context, tx db.Tx, docID string, out *render.BOM, index map[string]int,
) error {
	if len(index) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT f.hardware_component_id, f.display_id, f.cpe23,
		       f.match_basis, f.match_confidence,
		       COALESCE(f.severity,''), COALESCE(f.cvss_score::text,''),
		       COALESCE(f.cvss_vector,''), COALESCE(f.description,''),
		       f.source
		  FROM normalize.hardware_findings f
		 WHERE f.bom_document_id = $1
		 ORDER BY f.hardware_component_id, f.cvss_score DESC NULLS LAST, f.display_id`, docID)
	if err != nil {
		return fmt.Errorf("load hardware findings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			componentID string
			f           render.HardwareFinding
		)
		if err := rows.Scan(&componentID, &f.CVEID, &f.CPE23,
			&f.MatchBasis, &f.MatchConfidence,
			&f.Severity, &f.CVSSScore, &f.CVSSVector, &f.Description, &f.Source); err != nil {
			return fmt.Errorf("scan hardware finding: %w", err)
		}
		at, ok := index[componentID]
		if !ok {
			continue
		}
		out.Hardware[at].Vulnerabilities = append(out.Hardware[at].Vulnerabilities, f)
		// ⚠ Findings IS DERIVED HERE, not loaded separately. It is what the
		// CERT-In element 24 column renders and what the export emits; two
		// independent reads of the same rows would eventually disagree.
		out.Hardware[at].Findings = append(out.Hardware[at].Findings, f.CVEID)
	}
	return rows.Err()
}

// loadHardwareAlternates attaches second sources to the parts they belong to.
//
// A separate query rather than a join: an alternate is 1:N against a component
// and joining would multiply every hardware row by its alternate count, which
// the scan loop above would then have to de-duplicate — the classic shape that
// silently doubles a component count in a compliance document.
func loadHardwareAlternates(
	ctx context.Context, tx db.Tx, docID string, out *render.BOM, index map[string]int,
) error {
	if len(index) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT a.hardware_component_id, a.ordinal,
		       COALESCE(a.manufacturer_name,''), COALESCE(a.model_number,''),
		       COALESCE(a.supplier_info,''), COALESCE(a.supplier_sku,''),
		       COALESCE(a.lifecycle_status,''), a.equivalence,
		       COALESCE(a.approval_note,'')
		  FROM normalize.hardware_component_alternates a
		  JOIN normalize.hardware_components h ON h.id = a.hardware_component_id
		 WHERE h.bom_document_id = $1
		 ORDER BY a.hardware_component_id, a.ordinal`, docID)
	if err != nil {
		return fmt.Errorf("load hardware alternates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			componentID string
			alt         render.HardwareAlternate
		)
		if err := rows.Scan(&componentID, &alt.Ordinal,
			&alt.ManufacturerName, &alt.ModelNumber, &alt.SupplierInfo, &alt.SupplierSKU,
			&alt.LifecycleStatus, &alt.Equivalence, &alt.ApprovalNote); err != nil {
			return fmt.Errorf("scan hardware alternate: %w", err)
		}
		if at, ok := index[componentID]; ok {
			out.Hardware[at].Alternates = append(out.Hardware[at].Alternates, alt)
		}
	}
	return rows.Err()
}

// decodeStringMap reads a jsonb map of strings, tolerating anything else.
//
// ⚠ NEVER FAILS THE LOAD. enriched_fields is provenance — useful, not
// load-bearing — and refusing to render a whole parts list because one
// provenance blob is malformed would withhold a correct report over a
// decorative field.
func decodeStringMap(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// decodeNormalizeDiagnostics turns the stored jsonb into renderable lines.
//
// ⚠ A MALFORMED VALUE YIELDS NOTHING, NEVER AN ERROR. A report must still
// render when this column holds something unexpected — losing the whole
// document because its footnotes did not parse would be a far worse failure
// than losing the footnotes.
func decodeNormalizeDiagnostics(raw []byte) []render.NormalizeDiagnostic {
	if len(raw) == 0 {
		return nil
	}
	var entries []struct {
		Severity string `json:"severity"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	out := make([]render.NormalizeDiagnostic, 0, len(entries))
	for _, e := range entries {
		if e.Code == "" && e.Message == "" {
			continue
		}
		out = append(out, render.NormalizeDiagnostic{
			Severity: e.Severity,
			Code:     e.Code,
			Message:  e.Message,
		})
	}
	return out
}
