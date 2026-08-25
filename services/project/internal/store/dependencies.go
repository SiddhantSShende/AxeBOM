package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// ---------------------------------------------------------------------------
// Dependencies — normalize.components and normalize.findings, read
// cross-schema.
//
// ⚠ SEVERAL QUERIES ACROSS THREE SCHEMAS (`project`, `scan`, `normalize`),
// JOINED IN GO — NOT ONE SQL JOIN. This service owns project.* only; it does
// not own scan.* or normalize.*. Mirrors
// services/scan-orchestrator/internal/orchestr/findings.go and
// services/report/internal/store/bomsource.go, the two existing precedents
// for a service reading another domain's schema directly instead of a
// cross-schema SQL join (CLAUDE.md invariant 11).
// ---------------------------------------------------------------------------

// DependencyRow is one row of the Dependencies explorer
// (frontend/src/routes/dependencies/Dependencies.tsx's DependencyRow).
type DependencyRow struct {
	Key          string
	Name         string
	Version      string
	Ecosystem    string
	License      string
	IsDirect     bool
	IsOrphan     bool
	Depth        *int
	Criticality  string
	TopSeverity  string
	FindingCount int
	DetectedBy   []string
}

// ProfileFieldValue is one CERT-In field rendered for a component drawer.
//
// ⚠ EVERY FIELD IN THE PROFILE IS RENDERED, present or not — see
// buildProfileFields. Omitting an absent field would look complete at partial
// coverage; CLAUDE.md invariant 3.
type ProfileFieldValue struct {
	FieldID    string
	Name       string
	Value      string
	SourcePage int
	Scored     bool
}

// CandidateIdentity is a match NOT merged into the canonical component.
type CandidateIdentity struct {
	Kind       string
	Value      string
	Confidence string
	Source     string
}

// ProvenanceEntry is one engine's observation of a component.
type ProvenanceEntry struct {
	Engine        string
	EngineVersion string
	ObservedAt    string
	Rule          string
}

// ComponentDetail is the full drawer payload for one component
// (frontend/src/routes/dependencies/ComponentDrawer.tsx's ComponentDetail).
type ComponentDetail struct {
	Key                 string
	Purl                string
	CertinIdentifier    string
	Ecosystem           string
	Fields              []ProfileFieldValue
	Locations           []string
	CandidateIdentities []CandidateIdentity
	Provenance          []ProvenanceEntry
}

// ListDependencies returns the project's current SBOM component inventory.
//
// Reads the SBOM document from the project's most recent scan — vulnerability
// matching and the dependency graph both key off SBOM components; CBOM,
// QBOM, AIBOM and HBOM have no component table of their own
// (docs/03-NORMALIZER-SPEC.md).
func (s *Store) ListDependencies(ctx context.Context, tenantID, projectID string) ([]DependencyRow, error) {
	out := []DependencyRow{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "SBOM")
		if err != nil {
			return err
		}
		if docID == "" {
			return nil // no SBOM normalized yet — an honest empty list
		}

		rows, err := loadComponentRows(ctx, tx, docID)
		if err != nil {
			return err
		}
		severities, err := loadComponentSeverities(ctx, tx, docID)
		if err != nil {
			return err
		}
		provenance, err := loadComponentProvenanceEngines(ctx, tx, docID)
		if err != nil {
			return err
		}

		for _, r := range rows {
			sev := severities[r.id]
			out = append(out, DependencyRow{
				Key: r.componentKey, Name: r.name, Version: r.versionRaw,
				Ecosystem: r.ecosystem, License: r.license,
				IsDirect: r.isDirect, IsOrphan: r.isOrphan, Depth: r.depth,
				Criticality:  r.criticality,
				TopSeverity:  sev.top,
				FindingCount: sev.count,
				DetectedBy:   provenance[r.id],
			})
		}
		return nil
	})
	return out, err
}

// GetComponentDetail returns one component's full drawer payload.
func (s *Store) GetComponentDetail(ctx context.Context, tenantID, projectID, componentKey string) (ComponentDetail, error) {
	var out ComponentDetail
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "SBOM")
		if err != nil {
			return err
		}
		if docID == "" {
			return ErrNotFound
		}

		var generatedAt time.Time
		if err := tx.QueryRow(ctx,
			`SELECT generated_at FROM normalize.bom_documents WHERE id = $1`, docID).
			Scan(&generatedAt); err != nil {
			return fmt.Errorf("load bom document: %w", err)
		}

		var (
			id                                      string
			purlPtr, certinIDPtr, ecosystemPtr      *string
			name                                    string
			versionRaw, description, supplier       *string
			license, origin, patchStatus            *string
			usageRestrictions, comments             *string
			author, executable, archive, structured *string
			criticality                             *string
			releaseDate, eolDate                    *time.Time
			hashes                                  []byte
		)

		err = tx.QueryRow(ctx, `
			SELECT id, purl, certin_identifier, ecosystem, name, version_raw,
			       description, supplier, license_effective, origin, patch_status,
			       release_date, eol_date, criticality, usage_restrictions, hashes,
			       comments, author_of_sbom_data, executable_property, archive_property,
			       structured_property
			  FROM normalize.components
			 WHERE bom_document_id = $1 AND component_key = $2`, docID, componentKey).
			Scan(&id, &purlPtr, &certinIDPtr, &ecosystemPtr, &name, &versionRaw,
				&description, &supplier, &license, &origin, &patchStatus,
				&releaseDate, &eolDate, &criticality, &usageRestrictions, &hashes,
				&comments, &author, &executable, &archive, &structured)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("load component: %w", err)
		}

		out.Key = componentKey
		out.Purl = deref(purlPtr)
		out.CertinIdentifier = deref(certinIDPtr)
		out.Ecosystem = deref(ecosystemPtr)

		fieldValues := map[string]string{
			model.FieldCertinSbom01ComponentName:        name,
			model.FieldCertinSbom02ComponentVersion:     deref(versionRaw),
			model.FieldCertinSbom03ComponentDescription: deref(description),
			model.FieldCertinSbom04ComponentSupplier:    deref(supplier),
			model.FieldCertinSbom05ComponentLicense:     deref(license),
			model.FieldCertinSbom06ComponentOrigin:      deref(origin),
			model.FieldCertinSbom09PatchStatus:          deref(patchStatus),
			model.FieldCertinSbom10ReleaseDate:          formatDatePtr(releaseDate),
			model.FieldCertinSbom11EolDate:              formatDatePtr(eolDate),
			model.FieldCertinSbom12Criticality:          deref(criticality),
			model.FieldCertinSbom13UsageRestrictions:    deref(usageRestrictions),
			model.FieldCertinSbom14Checksums:            summariseHashes(hashes),
			model.FieldCertinSbom15Comments:             deref(comments),
			model.FieldCertinSbom16AuthorOfSbomData:     deref(author),
			model.FieldCertinSbom17Timestamp:            generatedAt.UTC().Format(time.RFC3339),
			model.FieldCertinSbom18ExecutableProperty:   deref(executable),
			model.FieldCertinSbom19ArchiveProperty:      deref(archive),
			model.FieldCertinSbom20StructuredProperty:   deref(structured),
			model.FieldCertinSbom21UniqueIdentifier:     deref(certinIDPtr),
		}

		depCount, err := countComponentDependencies(ctx, tx, id)
		if err != nil {
			return err
		}
		if depCount > 0 {
			fieldValues[model.FieldCertinSbom07ComponentDependencies] =
				fmt.Sprintf("%d direct dependencies", depCount)
		}

		findingCount, err := countComponentFindings(ctx, tx, docID, id)
		if err != nil {
			return err
		}
		if findingCount > 0 {
			fieldValues[model.FieldCertinSbom08Vulnerabilities] = fmt.Sprintf("%d", findingCount)
		}

		out.Fields = buildProfileFields(fieldValues)

		if out.Locations, err = loadComponentLocations(ctx, tx, id); err != nil {
			return err
		}
		if out.CandidateIdentities, err = loadCandidateIdentities(ctx, tx, id); err != nil {
			return err
		}
		if out.Provenance, err = loadComponentProvenance(ctx, tx, id); err != nil {
			return err
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Cross-schema document resolution
// ---------------------------------------------------------------------------

// resolveCurrentBOMDocument finds the current normalize.bom_documents id for
// a project's most recent scan of the given bom_type.
//
// ⚠ TWO QUERIES, ONE PER SCHEMA, JOINED HERE — NOT A SQL JOIN. This service
// owns neither `scan` nor `normalize`. Mirrors
// services/report/internal/store/bomsource.go's resolveDocument, generalized
// to work from a project id rather than an already-known scan id (a report
// is always created against one scan; this reads live, so it has to find the
// scan itself).
//
// The most recent SCAN wins, and within it the highest normalization_version
// — re-normalization writes version N+1 and never overwrites N (ADR-0003),
// so "the document" is ambiguous by design and the current one is always the
// latest for the latest scan.
func resolveCurrentBOMDocument(ctx context.Context, tx db.Tx, projectID, bomType string) (string, error) {
	// UUIDv7 scan ids are time-ordered, so DESC is newest first. Capped at a
	// generous window rather than every scan a project has ever run — a
	// project with thousands of historical scans should not turn a live page
	// load into an unbounded IN-list.
	const scanWindow = 200

	rows, err := tx.Query(ctx, `
		SELECT id FROM scan.scans
		 WHERE project_id = $1
		 ORDER BY id DESC
		 LIMIT $2`, projectID, scanWindow)
	if err != nil {
		return "", fmt.Errorf("list project scans: %w", err)
	}
	scanIDs := make([]string, 0, scanWindow)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return "", err
		}
		scanIDs = append(scanIDs, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	rows.Close()
	if len(scanIDs) == 0 {
		return "", nil
	}

	docRows, err := tx.Query(ctx, `
		SELECT scan_id, id, normalization_version
		  FROM normalize.bom_documents
		 WHERE scan_id = ANY($1) AND bom_type = $2`, scanIDs, bomType)
	if err != nil {
		return "", fmt.Errorf("list bom documents: %w", err)
	}
	defer docRows.Close()

	type doc struct {
		id      string
		version int
	}
	bestByScan := make(map[string]doc)
	for docRows.Next() {
		var scanID string
		var d doc
		if err := docRows.Scan(&scanID, &d.id, &d.version); err != nil {
			return "", err
		}
		if cur, ok := bestByScan[scanID]; !ok || d.version > cur.version {
			bestByScan[scanID] = d
		}
	}
	if err := docRows.Err(); err != nil {
		return "", err
	}

	// scanIDs is newest-first; the first one with a document wins.
	for _, scanID := range scanIDs {
		if d, ok := bestByScan[scanID]; ok {
			return d.id, nil
		}
	}
	return "", nil
}

// ---------------------------------------------------------------------------
// normalize.components
// ---------------------------------------------------------------------------

type componentRow struct {
	id           string
	componentKey string
	name         string
	versionRaw   string
	ecosystem    string
	license      string
	isDirect     bool
	isOrphan     bool
	depth        *int
	criticality  string
}

func loadComponentRows(ctx context.Context, tx db.Tx, docID string) ([]componentRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, component_key, name, COALESCE(version_raw,''), COALESCE(ecosystem,''),
		       COALESCE(license_effective,''), is_direct, is_orphan, depth, COALESCE(criticality,'')
		  FROM normalize.components
		 WHERE bom_document_id = $1
		 ORDER BY component_key`, docID)
	if err != nil {
		return nil, fmt.Errorf("load components: %w", err)
	}
	defer rows.Close()

	var out []componentRow
	for rows.Next() {
		var r componentRow
		if err := rows.Scan(&r.id, &r.componentKey, &r.name, &r.versionRaw, &r.ecosystem,
			&r.license, &r.isDirect, &r.isOrphan, &r.depth, &r.criticality); err != nil {
			return nil, fmt.Errorf("scan component: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// normalize.findings — severities per component
// ---------------------------------------------------------------------------

// severityRank orders severities most-severe first, matching
// frontend/src/design/theme.ts's SEVERITIES table exactly so the backend and
// the UI agree on which finding is "the" top severity for a component.
var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"none":     1,
	"unknown":  0,
}

type severitySummary struct {
	top   string
	count int
}

func loadComponentSeverities(ctx context.Context, tx db.Tx, docID string) (map[string]severitySummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT component_id, severity_effective
		  FROM normalize.findings
		 WHERE bom_document_id = $1`, docID)
	if err != nil {
		return nil, fmt.Errorf("load finding severities: %w", err)
	}
	defer rows.Close()

	out := make(map[string]severitySummary)
	for rows.Next() {
		var componentID string
		var severityPtr *string
		if err := rows.Scan(&componentID, &severityPtr); err != nil {
			return nil, err
		}
		var severity string
		if severityPtr != nil {
			severity = *severityPtr
		}
		cur, ok := out[componentID]
		cur.count++
		if !ok || severityRank[severity] > severityRank[cur.top] {
			cur.top = severity
		}
		out[componentID] = cur
	}
	return out, rows.Err()
}

func countComponentFindings(ctx context.Context, tx db.Tx, docID, componentID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM normalize.findings
		 WHERE bom_document_id = $1 AND component_id = $2`, docID, componentID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count component findings: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// normalize.component_provenance
// ---------------------------------------------------------------------------

func loadComponentProvenanceEngines(ctx context.Context, tx db.Tx, docID string) (map[string][]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT cp.component_id, cp.engine_id
		  FROM normalize.component_provenance cp
		  JOIN normalize.components c ON c.id = cp.component_id
		 WHERE c.bom_document_id = $1
		 ORDER BY cp.component_id, cp.engine_id`, docID)
	if err != nil {
		// A component with no provenance recorded is possible for an early
		// or partial normalization; treat it as "nothing to report" rather
		// than fail the whole listing.
		return map[string][]string{}, nil //nolint:nilerr // see above
	}
	defer rows.Close()

	out := make(map[string][]string)
	for rows.Next() {
		var componentID, engineID string
		if err := rows.Scan(&componentID, &engineID); err != nil {
			return nil, err
		}
		out[componentID] = append(out[componentID], engineID)
	}
	return out, rows.Err()
}

func loadComponentProvenance(ctx context.Context, tx db.Tx, componentID string) ([]ProvenanceEntry, error) {
	rows, err := tx.Query(ctx, `
		SELECT engine_id, COALESCE(engine_version,''), observed_at, COALESCE(rule_id,'')
		  FROM normalize.component_provenance
		 WHERE component_id = $1
		 ORDER BY observed_at`, componentID)
	if err != nil {
		return nil, fmt.Errorf("load component provenance: %w", err)
	}
	defer rows.Close()

	var out []ProvenanceEntry
	for rows.Next() {
		var e ProvenanceEntry
		var observedAt time.Time
		if err := rows.Scan(&e.Engine, &e.EngineVersion, &observedAt, &e.Rule); err != nil {
			return nil, err
		}
		e.ObservedAt = observedAt.UTC().Format(time.RFC3339)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// normalize.component_locations, component_candidate_identities,
// component_dependencies
// ---------------------------------------------------------------------------

func loadComponentLocations(ctx context.Context, tx db.Tx, componentID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT path FROM normalize.component_locations
		 WHERE component_id = $1
		 ORDER BY path`, componentID)
	if err != nil {
		return nil, fmt.Errorf("load component locations: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func loadCandidateIdentities(ctx context.Context, tx db.Tx, componentID string) ([]CandidateIdentity, error) {
	rows, err := tx.Query(ctx, `
		SELECT kind, value, confidence, source_engine
		  FROM normalize.component_candidate_identities
		 WHERE component_id = $1
		 ORDER BY kind, value`, componentID)
	if err != nil {
		return nil, fmt.Errorf("load candidate identities: %w", err)
	}
	defer rows.Close()

	var out []CandidateIdentity
	for rows.Next() {
		var c CandidateIdentity
		if err := rows.Scan(&c.Kind, &c.Value, &c.Confidence, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func countComponentDependencies(ctx context.Context, tx db.Tx, componentID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM normalize.component_dependencies
		 WHERE from_component_id = $1 AND relationship = 'depends_on'`, componentID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count component dependencies: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildProfileFields(values map[string]string) []ProfileFieldValue {
	out := make([]ProfileFieldValue, 0, len(model.SBOMFields))
	for _, f := range model.SBOMFields {
		out = append(out, ProfileFieldValue{
			FieldID: f.ID, Name: f.Name, Value: values[f.ID],
			SourcePage: f.SourcePage, Scored: f.Scored,
		})
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func formatDatePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

// summariseHashes renders the checksum list for field 14, matching
// services/report/internal/store/bomsource.go's summariseHashes exactly —
// the two must agree on what a component's checksum field looks like.
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
	out := ""
	for i, h := range hashes {
		if i > 0 {
			out += "; "
		}
		out += h.Algorithm + ":" + h.Value
	}
	return out
}
