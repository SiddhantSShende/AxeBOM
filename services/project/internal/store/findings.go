package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/libs/go-shared/vex"
)

// ---------------------------------------------------------------------------
// Findings — normalize.findings, normalize.vuln_ids, normalize.vex_statements,
// read cross-schema. Same discipline as dependencies.go: several
// single-schema queries, joined in Go, never one SQL statement crossing
// `normalize` (docs/03-NORMALIZER-SPEC.md, CLAUDE.md invariant 11).
// ---------------------------------------------------------------------------

// FindingComponent is one affected component, as shown in a finding row.
type FindingComponent struct {
	Key     string
	Name    string
	Version string
}

// SeveritySource is one engine's assessment of a finding.
//
// ⚠ DERIVED FROM `normalize.findings.cvss_vectors`, NOT A SEPARATE
// PER-SOURCE SEVERITY COLUMN. The schema stores every CVSS vector a source
// asserted (docs/01-DATA-MODEL.md §5: "all of them: [{version, vector,
// score, source}]"), but not a free-text severity label per source — only
// the single winning `severity_effective` for the finding as a whole. A
// source that asserted a severity with no CVSS vector at all (a vendor
// string, per 03-NORMALIZER-SPEC's precedence list) will not appear here —
// it is still counted in DetectedBy. Severity is therefore a CVSS-score-band
// approximation (see cvssScoreToSeverity), not a value any single source
// wrote down. Flagging this rather than presenting it as authoritative:
// worth revisiting once the normalizer records a real per-source severity.
type SeveritySource struct {
	Engine      string
	Severity    string
	CVSSVersion string
	CVSSScore   string
	CVSSVector  string
}

// Finding is one cluster of deduplicated advisories
// (frontend/src/routes/findings/Findings.tsx's Finding).
type Finding struct {
	ClusterID        string
	DisplayID        string
	Aliases          []string
	Severity         string
	CVSSVersion      string
	CVSSScore        string
	SeverityConflict bool
	SeveritySources  []SeveritySource
	Components       []FindingComponent
	FixedInMin       string
	FixOrdering      string
	DetectedBy       []string
	VEXStatus        string
	VEXJustification string
}

// ListFindings returns the project's findings, one row per vulnerability
// cluster (never per raw advisory identifier — the same CVE reported by four
// engines against three components is one row).
func (s *Store) ListFindings(ctx context.Context, tenantID, projectID string) ([]Finding, error) {
	out := []Finding{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := projectExists(ctx, tx, projectID); err != nil {
			return err
		}

		docID, err := resolveCurrentBOMDocument(ctx, tx, projectID, "SBOM")
		if err != nil {
			return err
		}
		if docID == "" {
			return nil // no SBOM normalized yet
		}

		rows, err := loadFindingRows(ctx, tx, docID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}

		componentsByID, err := loadComponentSummaries(ctx, tx, docID)
		if err != nil {
			return err
		}

		grouped := groupFindingsByCluster(rows, componentsByID)

		clusterIDs := make([]string, 0, len(grouped))
		for id := range grouped {
			clusterIDs = append(clusterIDs, id)
		}

		aliases, err := loadClusterAliases(ctx, tx, clusterIDs)
		if err != nil {
			return err
		}
		vexByCluster := loadClusterVEX(ctx, tx, projectID, grouped)

		for clusterID, f := range grouped {
			f.Aliases = filterOutDisplayID(aliases[clusterID], f.DisplayID)
			if v, ok := vexByCluster[clusterID]; ok {
				f.VEXStatus = string(v.Status)
				f.VEXJustification = v.Justification
			}
			out = append(out, f)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].DisplayID < out[j].DisplayID })
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// normalize.findings
// ---------------------------------------------------------------------------

type findingRow struct {
	clusterID   string
	componentID string
	displayID   string
	severity    string
	conflict    bool
	cvssVectors []byte
	cvssPrimary *float64
	fixedInMin  string
	fixOrdering string
	detectedBy  []string
}

func loadFindingRows(ctx context.Context, tx db.Tx, docID string) ([]findingRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT cluster_id, component_id, display_id_at_render, COALESCE(severity_effective,''),
		       severity_conflict, cvss_vectors, cvss_primary_score,
		       COALESCE(fixed_in_min,''), fix_version_ordering, detected_by
		  FROM normalize.findings
		 WHERE bom_document_id = $1
		 ORDER BY cluster_id, component_id`, docID)
	if err != nil {
		return nil, fmt.Errorf("load findings: %w", err)
	}
	defer rows.Close()

	var out []findingRow
	for rows.Next() {
		var r findingRow
		if err := rows.Scan(&r.clusterID, &r.componentID, &r.displayID, &r.severity,
			&r.conflict, &r.cvssVectors, &r.cvssPrimary, &r.fixedInMin, &r.fixOrdering,
			&r.detectedBy); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type componentSummary struct {
	key     string
	name    string
	version string
}

func loadComponentSummaries(ctx context.Context, tx db.Tx, docID string) (map[string]componentSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, component_key, name, COALESCE(version_raw,'')
		  FROM normalize.components
		 WHERE bom_document_id = $1`, docID)
	if err != nil {
		return nil, fmt.Errorf("load component summaries: %w", err)
	}
	defer rows.Close()

	out := make(map[string]componentSummary)
	for rows.Next() {
		var id string
		var c componentSummary
		if err := rows.Scan(&id, &c.key, &c.name, &c.version); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

type cvssVector struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	Source  string  `json:"source"`
}

// groupFindingsByCluster collapses per-component finding rows into one
// Finding per cluster, unioning the affected components and the engines
// that detected it, and taking the FIRST row's severity/CVSS/fix data as
// representative — a real normalizer's severity determination for one
// vulnerability does not vary by which component it is attached to.
func groupFindingsByCluster(rows []findingRow, components map[string]componentSummary) map[string]Finding {
	out := make(map[string]Finding)
	detectedBySeen := make(map[string]map[string]bool)
	componentSeen := make(map[string]map[string]bool)

	for _, r := range rows {
		f, exists := out[r.clusterID]
		if !exists {
			f = Finding{
				ClusterID:   r.clusterID,
				DisplayID:   r.displayID,
				Severity:    r.severity,
				FixedInMin:  r.fixedInMin,
				FixOrdering: r.fixOrdering,
			}
			f.SeverityConflict = r.conflict
			if r.cvssPrimary != nil {
				f.CVSSScore = formatScore(*r.cvssPrimary)
			}
			f.SeveritySources = parseCVSSVectors(r.cvssVectors)
			if len(f.SeveritySources) > 0 {
				f.CVSSVersion = f.SeveritySources[0].CVSSVersion
			}
			detectedBySeen[r.clusterID] = map[string]bool{}
			componentSeen[r.clusterID] = map[string]bool{}
		}
		// severity_conflict is asserted PER ROW by the normalizer, but a
		// cluster is a conflict if ANY of its member rows says so — a
		// representative that happened to be conflict-free must not hide a
		// disagreement recorded on a sibling component's row.
		f.SeverityConflict = f.SeverityConflict || r.conflict

		for _, engine := range r.detectedBy {
			if !detectedBySeen[r.clusterID][engine] {
				detectedBySeen[r.clusterID][engine] = true
				f.DetectedBy = append(f.DetectedBy, engine)
			}
		}
		if c, ok := components[r.componentID]; ok && !componentSeen[r.clusterID][r.componentID] {
			componentSeen[r.clusterID][r.componentID] = true
			f.Components = append(f.Components, FindingComponent{Key: c.key, Name: c.name, Version: c.version})
		}

		out[r.clusterID] = f
	}

	for id, f := range out {
		sort.Strings(f.DetectedBy)
		sort.Slice(f.Components, func(i, j int) bool { return f.Components[i].Key < f.Components[j].Key })
		out[id] = f
	}
	return out
}

func parseCVSSVectors(raw []byte) []SeveritySource {
	if len(raw) == 0 {
		return nil
	}
	var vectors []cvssVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		return nil
	}
	out := make([]SeveritySource, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, SeveritySource{
			Engine:      v.Source,
			Severity:    cvssScoreToSeverity(v.Score),
			CVSSVersion: v.Version,
			CVSSScore:   formatScore(v.Score),
			CVSSVector:  v.Vector,
		})
	}
	return out
}

// cvssScoreToSeverity bands a numeric CVSS score using the standard v3.x/v4
// thresholds (FIRST.org). Used only to label a per-source SeveritySource —
// see that type's doc comment for why this is an approximation, not a value
// any source asserted directly.
func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func formatScore(score float64) string {
	return fmt.Sprintf("%.1f", score)
}

// ---------------------------------------------------------------------------
// normalize.vuln_ids — aliases
// ---------------------------------------------------------------------------

func loadClusterAliases(ctx context.Context, tx db.Tx, clusterIDs []string) (map[string][]string, error) {
	if len(clusterIDs) == 0 {
		return map[string][]string{}, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT cluster_id, value FROM normalize.vuln_ids
		 WHERE cluster_id = ANY($1)
		 ORDER BY cluster_id, namespace, value`, clusterIDs)
	if err != nil {
		return nil, fmt.Errorf("load cluster aliases: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]string)
	for rows.Next() {
		var clusterID, value string
		if err := rows.Scan(&clusterID, &value); err != nil {
			return nil, err
		}
		out[clusterID] = append(out[clusterID], value)
	}
	return out, rows.Err()
}

func filterOutDisplayID(aliases []string, displayID string) []string {
	out := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if a != displayID {
			out = append(out, a)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// normalize.vex_statements
// ---------------------------------------------------------------------------

// loadClusterVEX resolves the effective VEX statement per cluster, using the
// real libs/go-shared/vex.Resolve rule (most specific scope, then latest
// timestamp) rather than a hand-rolled approximation.
//
// ⚠ A Finding HERE IS ALREADY A CLUSTER-WIDE ROW SPANNING EVERY AFFECTED
// COMPONENT (see groupFindingsByCluster), so this resolves against EACH
// member component in turn and keeps the single most-specific-then-most-
// recent result across all of them — the same two-rule ranking vex.Resolve
// itself uses internally, applied one level up because this shape has no
// single component to resolve against. A prior version of this function
// picked "whichever statement has the highest id" without regard to scope at
// all, which could let a broad, ACCIDENTALLY newer project-wide statement
// outrank a genuinely more specific, slightly older component-scoped one —
// exactly the ordering vex.Resolve's own doc comment says is a decision, not
// an accident, and the previous code got backwards. Fixed once vex.Resolve
// became importable here (libs/go-shared/vex, not scan-orchestrator's
// internal package) rather than reimplemented a second time.
// ⚠ NO ERROR RETURN. loadVEXStatements already swallows its own — VEX is
// optional, and a project with none recorded is a normal state, not a
// reason to fail the whole findings listing — so every path through this
// function succeeds. golangci-lint's unparam check is what caught the
// dead return value; trust it over "an error return looks more careful."
func loadClusterVEX(ctx context.Context, tx db.Tx, projectID string, byCluster map[string]Finding) map[string]*vex.Effective {
	if len(byCluster) == 0 {
		return map[string]*vex.Effective{}
	}
	clusterIDs := make([]string, 0, len(byCluster))
	for id := range byCluster {
		clusterIDs = append(clusterIDs, id)
	}

	statements := loadVEXStatements(ctx, tx, projectID, clusterIDs)

	out := make(map[string]*vex.Effective, len(byCluster))
	for clusterID, f := range byCluster {
		var winner *vex.Effective
		for _, c := range f.Components {
			candidate := vex.Resolve(statements, clusterID, c.Key)
			if candidate == nil {
				continue
			}
			// ⚠ A NOT-DE-EMPHASIZED RESULT (affected / under_investigation)
			// ALWAYS WINS OVER A DE-EMPHASIZED ONE (not_affected / fixed), same
			// reasoning groupFindingsByCluster already uses for
			// SeverityConflict: "a cluster is a conflict if ANY of its member
			// rows says so." A vulnerable library used in three places is not
			// safe because a reviewer cleared one of the three call sites —
			// showing the cleared verdict for the whole cluster would hide the
			// two components still needing attention.
			if winner == nil || (vex.DeEmphasized(winner) && !vex.DeEmphasized(candidate)) {
				winner = candidate
			}
		}
		if winner != nil {
			out[clusterID] = winner
		}
	}
	return out
}

// loadVEXStatements swallows its own errors — VEX is optional, and a
// project with none recorded (or a query that fails for any reason) simply
// leaves every finding with no VEX status rather than failing the whole
// listing. Mirrors services/report/internal/store/bomsource.go's
// loadVEXStatementsForReport, the identical decision made for the same
// reason on the report side of this same table.
func loadVEXStatements(ctx context.Context, tx db.Tx, projectID string, clusterIDs []string) []vex.Statement {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, project_id, COALESCE(component_key,''), cluster_id,
		       status, COALESCE(justification,''), COALESCE(remediation,''),
		       COALESCE(workarounds,''), COALESCE(downtime,''), scope, version,
		       COALESCE(superseded_by::text,''), COALESCE(author_user_id::text,''), created_at
		  FROM normalize.vex_statements
		 WHERE project_id = $1 AND cluster_id = ANY($2)
		 ORDER BY created_at`, projectID, clusterIDs)
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
