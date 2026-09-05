package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/store"
)

// sbomFixture is a hand-inserted, minimal-but-complete SBOM: one scan, one
// bom_document, two components (one direct, one transitive with a finding),
// provenance, a vulnerability cluster with an alias, and a VEX statement.
//
// There is no store API to create scan.scans or normalize.* rows — those
// schemas belong to scan-orchestrator and the normalizer, not this service —
// so the fixture inserts directly via SQL, exactly as a real scan pipeline
// would, to exercise ListDependencies/GetComponentDetail/ListFindings against
// data shaped the way production data actually is.
type sbomFixture struct {
	scanID           string
	docID            string
	directComponent  string // id
	directKey        string
	transComponentID string
	transKey         string
	clusterID        string
	displayID        string
	alias            string
}

func seedSBOM(t *testing.T, pool *db.Pool, tenantID, projectID string) sbomFixture {
	t.Helper()
	var f sbomFixture

	// normalize.vuln_ids is GLOBAL reference data with a UNIQUE(namespace,
	// value) constraint (docs/01-DATA-MODEL.md §5) — not tenant-scoped, so a
	// fixed literal CVE id would collide across test runs. A suffix unique to
	// this test invocation keeps every run's rows distinct without relying on
	// cleanup running first, which matters here: normalize.vex_statements is
	// iterative and append-only by design (§7) and this service's DB role has
	// no DELETE grant on it at all, so a VEX row this fixture inserts is never
	// cleaned up — exactly like production.
	cve := "CVE-2024-" + uniqueSuffix(t)
	ghsa := "GHSA-" + uniqueSuffix(t)

	err := pool.WithTenant(t.Context(), tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO scan.scans (tenant_id, project_id, triggered_by, source_kind)
			VALUES ($1, $2, 'user', 'git') RETURNING id`, tenantID, projectID).Scan(&f.scanID); err != nil {
			return err
		}

		// ⚠ A REAL normalize.alias_snapshot ROW, NOT A MINTED UUID. Migration
		// 0012 gave bom_documents.alias_snapshot_id the foreign key it never
		// had, so an invented id is rejected. SBOM is the one BOM type the
		// column exists FOR — its snapshot is what makes a finding's alias
		// cluster explainable at re-normalization time — so the fixture mints
		// the snapshot rather than passing NULL, which writer.py refuses for
		// an SBOM for exactly that reason.
		if err := tx.QueryRow(ctx, `
			WITH snap AS (
				INSERT INTO normalize.alias_snapshot (ruleset_version)
				VALUES ('test-1') RETURNING id
			)
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version, generated_at)
			SELECT $1, $2, 'SBOM', 1, 'test-1', snap.id, 'test-1', now() FROM snap
			RETURNING id`, tenantID, f.scanID).Scan(&f.docID); err != nil {
			return err
		}

		f.directKey = "pkg:npm/left-pad@1.3.0"
		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.components
				(tenant_id, bom_document_id, component_key, identity_rule, purl,
				 certin_identifier, ecosystem, name, version_raw, license_effective,
				 is_direct, depth, is_orphan, criticality)
			VALUES ($1,$2,$3,'purl',$3,'pkg:supplier/Unknown/left-pad@1.3.0','npm',
			        'left-pad','1.3.0','MIT', true, 0, false, 'low')
			RETURNING id`, tenantID, f.docID, f.directKey).Scan(&f.directComponent); err != nil {
			return err
		}

		f.transKey = "pkg:npm/vulnerable-dep@2.0.0"
		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.components
				(tenant_id, bom_document_id, component_key, identity_rule, purl,
				 certin_identifier, ecosystem, name, version_raw, license_effective,
				 is_direct, depth, is_orphan, criticality)
			VALUES ($1,$2,$3,'purl',$3,'pkg:supplier/Unknown/vulnerable-dep@2.0.0','npm',
			        'vulnerable-dep','2.0.0','Apache-2.0', false, 1, false, 'high')
			RETURNING id`, tenantID, f.docID, f.transKey).Scan(&f.transComponentID); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.component_provenance
				(tenant_id, bom_document_id, component_id, engine_id, engine_version, observed_at)
			VALUES ($1,$2,$3,'syft','1.0.0', now())`,
			tenantID, f.docID, f.directComponent); err != nil {
			return err
		}
		for _, engine := range []string{"syft", "grype"} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO normalize.component_provenance
					(tenant_id, bom_document_id, component_id, engine_id, engine_version, observed_at)
				VALUES ($1,$2,$3,$4,'1.0.0', now())`,
				tenantID, f.docID, f.transComponentID, engine); err != nil {
				return err
			}
		}

		f.displayID = cve
		f.alias = ghsa
		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.vuln_clusters (display_id) VALUES ($1)
			RETURNING id`, cve).Scan(&f.clusterID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.vuln_ids (cluster_id, namespace, value)
			VALUES ($1, 'CVE', $2), ($1, 'GHSA', $3)`,
			f.clusterID, cve, ghsa); err != nil {
			return err
		}

		cvssVectors := `[{"version":"3.1","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":9.8,"source":"grype"}]`
		// fix_version_ordering='comparator': findings.py's resolve_fix_version()
		// (the only real producer of this column) returns 'comparator' when a
		// fix version was reported AND an ecosystem-correct comparator exists —
		// never 'known', which the CHECK constraint no longer even permits
		// (migrations/normalize/0009_fix_version_ordering_values.sql).
		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.findings
				(tenant_id, bom_document_id, component_id, cluster_id,
				 display_id_at_render, severity_effective, severity_conflict,
				 cvss_vectors, cvss_primary_score, fixed_in_min, fix_version_ordering, detected_by)
			VALUES ($1,$2,$3,$4,$5,'critical', false, $6, 9.8, '2.0.1', 'comparator',
			        ARRAY['syft','grype'])`,
			tenantID, f.docID, f.transComponentID, f.clusterID, cve, cvssVectors); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.vex_statements (tenant_id, project_id, component_key, cluster_id, status, justification)
			VALUES ($1,$2,$3,$4,'affected','under active exploitation, patch scheduled')`,
			tenantID, projectID, f.transKey, f.clusterID); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		t.Fatalf("seed sbom fixture: %v", err)
	}

	t.Cleanup(func() {
		// ⚠ THE ERROR USED TO BE DISCARDED WITH `_ =`, SO A CLEANUP THAT FAILED
		// SAID NOTHING AT ALL — and this one was failing on every run, leaking
		// six scan rows a time. A silent cleanup is worse than none: the rows
		// accumulate and the test suite looks tidy.
		err := pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			// ⚠ ORDER IS LOAD-BEARING, AND GETTING IT WRONG WAS SILENT.
			//
			// This block used to delete bom_documents and vuln_clusters with
			// `_, _ =`, on the reasoning that findings and components "have no
			// FK to bom_documents and so become harmless orphans". The first
			// half is true. The second is not: `findings.cluster_id` DOES have
			// a foreign key to vuln_clusters, so deleting the cluster while its
			// findings still exist fails with 23503 — which aborted the whole
			// transaction, made every later statement a no-op, and was
			// discarded, so the scan row leaked on every single run.
			//
			// The findings therefore go first, explicitly. vuln_clusters then
			// cascades to vuln_ids on its own.
			//
			// vex_statements is DELIBERATELY NOT cleaned up: it is iterative
			// and append-only by design (docs/01-DATA-MODEL.md §7), and this
			// service's role holds no DELETE grant on it at all — attempting
			// one aborts the transaction in exactly the way described above.
			if _, err := tx.Exec(ctx,
				`DELETE FROM normalize.findings WHERE bom_document_id = $1`, f.docID); err != nil {
				return fmt.Errorf("findings: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM normalize.components WHERE bom_document_id = $1`, f.docID); err != nil {
				return fmt.Errorf("components: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM normalize.bom_documents WHERE id = $1`, f.docID); err != nil {
				return fmt.Errorf("bom_documents: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM normalize.vuln_clusters WHERE id = $1`, f.clusterID); err != nil {
				return fmt.Errorf("vuln_clusters: %w", err)
			}
			_, err := tx.Exec(ctx, `DELETE FROM scan.scans WHERE id = $1`, f.scanID)
			return err
		})
		if err != nil {
			t.Logf("cleanup sbom fixture (scan %s): %v", f.scanID, err)
		}
	})

	return f
}

// uniqueSuffix distinguishes this test invocation's global vuln_ids/
// vuln_clusters rows from any other run's, past or concurrent.
func uniqueSuffix(t *testing.T) string {
	t.Helper()
	return time.Now().UTC().Format("150405.000000000")
}

func TestListDependenciesReturnsTheCurrentSBOM(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	f := seedSBOM(t, pool, tenantA, projectID)

	rows, err := st.ListDependencies(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListDependencies: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}

	byKey := map[string]store.DependencyRow{}
	for _, r := range rows {
		byKey[r.Key] = r
	}

	direct, ok := byKey[f.directKey]
	if !ok {
		t.Fatalf("missing direct component row: %+v", rows)
	}
	if !direct.IsDirect || direct.FindingCount != 0 {
		t.Errorf("direct component = %+v, want isDirect=true, findingCount=0", direct)
	}
	if got, want := direct.DetectedBy, []string{"syft"}; !equalStrings(got, want) {
		t.Errorf("direct detectedBy = %v, want %v", got, want)
	}

	trans, ok := byKey[f.transKey]
	if !ok {
		t.Fatalf("missing transitive component row: %+v", rows)
	}
	if trans.IsDirect {
		t.Error("transitive component reported as direct")
	}
	if trans.Depth == nil || *trans.Depth != 1 {
		t.Errorf("depth = %v, want 1", trans.Depth)
	}
	if trans.FindingCount != 1 || trans.TopSeverity != "critical" {
		t.Errorf("trans = %+v, want findingCount=1, topSeverity=critical", trans)
	}
	if got, want := trans.DetectedBy, []string{"grype", "syft"}; !equalStrings(got, want) {
		t.Errorf("trans detectedBy = %v, want %v", got, want)
	}
}

func TestListDependenciesIsEmptyBeforeAnySBOM(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)

	rows, err := st.ListDependencies(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListDependencies: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %v, want none", rows)
	}
}

func TestGetComponentDetailRendersEveryProfileFieldAndProvenance(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	f := seedSBOM(t, pool, tenantA, projectID)

	detail, err := st.GetComponentDetail(t.Context(), tenantA, projectID, f.transKey)
	if err != nil {
		t.Fatalf("GetComponentDetail: %v", err)
	}
	if detail.Purl != f.transKey {
		t.Errorf("purl = %q, want %q", detail.Purl, f.transKey)
	}
	if len(detail.Fields) == 0 {
		t.Fatal("expected every profile field to be rendered, present or not")
	}
	foundVulnField := false
	for _, field := range detail.Fields {
		if field.FieldID == "certin.sbom.08.vulnerabilities" {
			foundVulnField = true
			if field.Value != "1" {
				t.Errorf("vulnerabilities field = %q, want 1", field.Value)
			}
		}
	}
	if !foundVulnField {
		t.Error("vulnerabilities field (08) not present in the rendered profile fields")
	}
	if len(detail.Provenance) != 2 {
		t.Errorf("provenance entries = %d, want 2 (syft, grype)", len(detail.Provenance))
	}
}

func TestGetComponentDetailUnknownKeyIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedSBOM(t, pool, tenantA, projectID)

	_, err := st.GetComponentDetail(t.Context(), tenantA, projectID, "pkg:npm/does-not-exist@1.0.0")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestListFindingsGroupsByClusterWithAliasesAndVEX(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	f := seedSBOM(t, pool, tenantA, projectID)

	findings, err := st.ListFindings(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (one cluster)", len(findings))
	}
	finding := findings[0]

	if finding.ClusterID != f.clusterID {
		t.Errorf("cluster id = %q, want %q", finding.ClusterID, f.clusterID)
	}
	if finding.DisplayID != f.displayID {
		t.Errorf("display id = %q, want %q", finding.DisplayID, f.displayID)
	}
	if got, want := finding.Aliases, []string{f.alias}; !equalStrings(got, want) {
		t.Errorf("aliases = %v, want %v (the display id itself must be excluded)", got, want)
	}
	if finding.Severity != "critical" {
		t.Errorf("severity = %q, want critical", finding.Severity)
	}
	if finding.FixedInMin != "2.0.1" || finding.FixOrdering != "comparator" {
		t.Errorf("fix = %q/%q, want 2.0.1/comparator", finding.FixedInMin, finding.FixOrdering)
	}
	if len(finding.Components) != 1 || finding.Components[0].Key != f.transKey {
		t.Errorf("components = %+v, want just %q", finding.Components, f.transKey)
	}
	if len(finding.SeveritySources) != 1 || finding.SeveritySources[0].Engine != "grype" {
		t.Errorf("severity sources = %+v", finding.SeveritySources)
	}
	if finding.VEXStatus != "affected" {
		t.Errorf("vex status = %q, want affected", finding.VEXStatus)
	}
	if finding.VEXJustification == "" {
		t.Error("expected a VEX justification")
	}
}

// TestListFindingsNeverLetsAClearedComponentHideAStillAffectedOne is the
// regression test for a real bug: loadClusterVEX used to pick "whichever
// statement has the highest id" for a cluster with no regard for which
// component it applied to, or to scope. Two components in the same cluster —
// one already vex.transKey ("affected", from seedSBOM), one f.directKey
// cleared LATER with "not_affected" — must still show the cluster as
// affected, because the vulnerable dependency is still vulnerable at the
// component the reviewer never looked at. Before the fix (using
// libs/go-shared/vex.Resolve/DeEmphasized instead of `ORDER BY id DESC`),
// this test would have shown "not_affected" for the whole cluster, because
// the clearing statement was inserted — and so has a later id — second.
func TestListFindingsNeverLetsAClearedComponentHideAStillAffectedOne(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	f := seedSBOM(t, pool, tenantA, projectID)

	err := pool.WithTenant(t.Context(), tenantA, func(ctx context.Context, tx db.Tx) error {
		// A second finding row: the SAME cluster, the OTHER (direct) component.
		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.findings
				(tenant_id, bom_document_id, component_id, cluster_id,
				 display_id_at_render, severity_effective, severity_conflict,
				 fixed_in_min, fix_version_ordering, detected_by)
			VALUES ($1,$2,$3,$4,$5,'critical', false, '2.0.1', 'comparator', ARRAY['syft'])`,
			tenantA, f.docID, f.directComponent, f.clusterID, f.displayID); err != nil {
			return err
		}
		// Inserted AFTER seedSBOM's "affected" statement, so its id (UUIDv7,
		// time-ordered) sorts LATER — exactly the case the old `ORDER BY id
		// DESC` rule got wrong.
		_, err := tx.Exec(ctx, `
			INSERT INTO normalize.vex_statements
				(tenant_id, project_id, component_key, cluster_id, status, justification, scope)
			VALUES ($1,$2,$3,$4,'not_affected','vulnerable code path not present','component')`,
			tenantA, projectID, f.directKey, f.clusterID)
		return err
	})
	if err != nil {
		t.Fatalf("seed second component + clearing statement: %v", err)
	}

	findings, err := st.ListFindings(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (still one cluster)", len(findings))
	}
	finding := findings[0]
	if len(finding.Components) != 2 {
		t.Fatalf("components = %+v, want both %q and %q", finding.Components, f.transKey, f.directKey)
	}
	if finding.VEXStatus != "affected" {
		t.Errorf("VEXStatus = %q, want affected — %q was cleared but %q was not, "+
			"and a cluster with any still-affected component must not read as cleared",
			finding.VEXStatus, f.directKey, f.transKey)
	}
}

func TestDependenciesCrossTenantAccessIsNotFound(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedSBOM(t, pool, tenantA, projectID)

	_, err := st.ListDependencies(t.Context(), tenantB, projectID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ListDependencies cross-tenant error = %v, want ErrNotFound", err)
	}

	_, err = st.ListFindings(t.Context(), tenantB, projectID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ListFindings cross-tenant error = %v, want ErrNotFound", err)
	}
}

// cleanupSeededScan removes a fixture's scan row and its BOM document.
//
// ⚠ EVERY FIXTURE IN THIS PACKAGE THAT SEEDS A SCAN MUST CALL THIS, AND TWO OF
// THEM DID NOT.
//
// `seedCryptoAssets` and `seedAIModels` inserted a `scan.scans` row each and
// registered no cleanup at all, so **twelve scan rows leaked on every run of
// this package**. Measured, not guessed: 771 rows before `go test`, 783 after.
// Across sessions that reached 732 scans stuck in `queued` — rows no product
// code created, that no worker will ever pick up (no fetch job was ever
// published for them), and that make the scans list and every "is anything
// running?" question unreadable.
//
// ⚠ THE PROJECT'S OWN CLEANUP CANNOT DO THIS. store.DeleteProject is a SOFT
// delete, so `ON DELETE CASCADE` never fires — the same trap that left 44
// devices behind, in the same package, for the same reason.
//
// Deliberately NOT deleted here: findings, components and provenance have no FK
// to bom_documents, so they become harmless orphans scoped to a document id
// nothing will resolve again; and `vex_statements` is append-only by design
// (docs/01-DATA-MODEL.md §7) with no DELETE grant for this role at all —
// attempting one aborts the whole cleanup transaction, which is what originally
// left every other table uncleaned too.
func cleanupSeededScan(t *testing.T, pool *db.Pool, tenantID, scanID, docID string) {
	t.Helper()
	t.Cleanup(func() {
		err := pool.WithTenant(context.Background(), tenantID,
			func(ctx context.Context, tx db.Tx) error {
				if docID != "" {
					_, _ = tx.Exec(ctx, `DELETE FROM normalize.bom_documents WHERE id = $1`, docID)
				}
				if scanID == "" {
					return nil
				}
				_, err := tx.Exec(ctx, `DELETE FROM scan.scans WHERE id = $1`, scanID)
				return err
			})
		if err != nil {
			t.Logf("cleanup seeded scan %s: %v", scanID, err)
		}
	})
}
