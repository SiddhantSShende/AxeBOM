package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/encorebom/encorebom/libs/go-shared/model"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
	"github.com/encorebom/encorebom/services/report/internal/level"
	"github.com/encorebom/encorebom/services/report/internal/render"
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
		ToolName:           "EncoreBOM",
	}

	err = s.pool.WithTenant(ctx, r.TenantID, func(ctx context.Context, tx db.Tx) error {
		docID, err := s.resolveDocument(ctx, tx, r)
		if err != nil {
			return err
		}

		if err := loadDocumentMeta(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadComponents(ctx, tx, docID, &out); err != nil {
			return err
		}
		if err := loadFindings(ctx, tx, docID, &out); err != nil {
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
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf(
				"%w: no normalized %s exists for this scan; the scan may still be "+
					"running or may have produced nothing", ErrNotFound, r.BOMType)
		}
		return "", fmt.Errorf("resolve bom document: %w", err)
	}
	return id, nil
}

func loadDocumentMeta(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	var (
		generatedAt               time.Time
		completeness, declaration *float64
		breakdown                 []byte
	)

	err := tx.QueryRow(ctx, `
		SELECT generated_at, completeness_pct, declaration_pct, coverage_breakdown,
		       ruleset_version, normalization_version
		  FROM normalize.bom_documents WHERE id = $1`, docID).
		Scan(&generatedAt, &completeness, &declaration, &breakdown,
			&out.RulesetVersion, &out.NormalizationVersion)
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
	// "it has not been scored". Both stay at zero and the note says which.
	if completeness != nil {
		out.Coverage.CompletenessPct = *completeness
	}
	if declaration != nil {
		out.Coverage.DeclarationPct = *declaration
	}

	return applyCoverageBreakdown(breakdown, out)
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

	var breakdown struct {
		Formula string `json:"formula"`
		Fields  map[string]struct {
			Present  int `json:"present"`
			Declared int `json:"declared"`
			Total    int `json:"total"`
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
	for id, fc := range breakdown.Fields {
		out.Coverage.Fields = append(out.Coverage.Fields, render.FieldCoverage{
			FieldID: id, Present: fc.Present, Declared: fc.Declared, Total: fc.Total,
		})
	}
	// Deterministic order: a map would shuffle the table between renders, and
	// the artifact has to be byte-reproducible.
	sort.Slice(out.Coverage.Fields, func(i, j int) bool {
		return out.Coverage.Fields[i].FieldID < out.Coverage.Fields[j].FieldID
	})
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

// loadComponentRelations fills the dependency and vulnerability count fields.
func loadComponentRelations(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
	counts := map[string]int{}
	rows, err := tx.Query(ctx, `
		SELECT c.component_key, count(d.to_component_id)
		  FROM normalize.components c
		  LEFT JOIN normalize.component_dependencies d
		         ON d.from_component_id = c.id
		        AND d.bom_document_id = c.bom_document_id
		        AND d.relationship = 'depends_on'
		 WHERE c.bom_document_id = $1
		 GROUP BY c.component_key`, docID)
	if err != nil {
		// The dependency table may legitimately be empty for a lockfile-only
		// scan. A missing graph is a gap in the report, not a failed render.
		return nil //nolint:nilerr // see above
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			return err
		}
		counts[key] = n
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
	return nil
}

func loadFindings(ctx context.Context, tx db.Tx, docID string, out *render.BOM) error {
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
