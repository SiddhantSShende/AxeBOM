package orchestr_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/orchestr"
)

// insertBOMDocument writes a normalize.bom_documents row directly — this
// package owns scan.*, not normalize.*, so there is no service-level API to
// create one through. bom_documents has no FK to scan.scans (cross-schema,
// ADR-0001), so this needs nothing from the scan beyond its id.
func insertBOMDocument(t *testing.T, f *fixture, tenantID, scanID string, version int) string {
	t.Helper()
	var docID string
	err := f.pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version)
			VALUES ($1, $2, 'SBOM', $3, 'test-ruleset-1', $4, '3.24')
			RETURNING id`,
			tenantID, scanID, version, uuid.NewString()).Scan(&docID)
	})
	if err != nil {
		t.Fatalf("insert bom document: %v", err)
	}

	// ⚠ NO FK FROM findings OR bom_documents BACK TO scan.scans — that is the
	// cross-schema boundary this whole file exists to respect (ADR-0001), and
	// it means cleanupScan's DELETE ... CASCADE on scan.scans reaches neither
	// table. Clean up explicitly, or every run of this test leaves rows a
	// future count-based assertion elsewhere in this suite would trip over.
	t.Cleanup(func() {
		_ = f.pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			if _, err := tx.Exec(ctx, `DELETE FROM normalize.findings WHERE bom_document_id = $1`, docID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM normalize.bom_documents WHERE id = $1`, docID)
			return err
		})
	})
	return docID
}

// insertFinding writes one normalize.findings row with the given severity.
// severity == "" writes SQL NULL — the NotProvided bucket.
//
// ⚠ INSERTS A MATCHING normalize.vuln_clusters ROW FIRST. Since
// migrations/normalize/0007_findings_cluster_fk.sql, findings.cluster_id is
// a real FK — a fabricated uuid with no backing row now fails loudly at
// insert time (the whole point of the FK: ADR-0005). vuln_clusters is
// GLOBAL, not tenant-scoped (migration 0002), so this goes through the raw
// pool rather than WithTenant.
func insertFinding(t *testing.T, f *fixture, tenantID, docID, severity string) {
	t.Helper()

	clusterID := uuid.New()
	if _, err := f.pool.Raw().Exec(context.Background(), `
		INSERT INTO normalize.vuln_clusters (id, display_id)
		VALUES ($1, $2)`,
		clusterID, "CVE-TEST-"+clusterID.String()[:8]); err != nil {
		t.Fatalf("insert vuln cluster: %v", err)
	}
	// vuln_clusters is GLOBAL reference data with no cascade back to
	// anything scan/tenant-scoped cleanupScan reaches — clean it up
	// explicitly or every run of this test leaks a row into it.
	//
	// ⚠ ALSO DELETES THE REFERENCING findings ROW FIRST, IN THE SAME
	// CLEANUP — t.Cleanup runs LIFO, and insertBOMDocument's own cleanup
	// (which deletes normalize.findings by bom_document_id) was registered
	// BEFORE this one, so it would otherwise run AFTER this one and this
	// DELETE would hit the findings_cluster_id_fkey constraint while a
	// finding still points at this cluster.
	t.Cleanup(func() {
		_ = f.pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM normalize.findings WHERE cluster_id = $1`, clusterID)
			return err
		})
		_, _ = f.pool.Raw().Exec(context.Background(),
			`DELETE FROM normalize.vuln_clusters WHERE id = $1`, clusterID)
	})

	err := f.pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
		var sev any
		if severity != "" {
			sev = severity
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO normalize.findings
				(tenant_id, bom_document_id, component_id, cluster_id,
				 display_id_at_render, severity_effective)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			tenantID, docID, uuid.New(), clusterID, "CVE-TEST-"+uuid.NewString()[:8], sev)
		return err
	})
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

// The three ambiguous states must land in three different buckets: an
// explicit "none", an explicit "unknown", and SQL NULL (nothing computed at
// all). Collapsing any two of them either invents an assertion nobody made or
// hides a measurement gap — see orchestr.SeverityCounts.
func TestFindingsSummaryKeepsNoneUnknownAndNotProvidedApart(t *testing.T) {
	f := newFixture(t)
	scan := createListScan(t, f, tenantA, projectList)
	doc := insertBOMDocument(t, f, tenantA, scan.ID, 1)

	insertFinding(t, f, tenantA, doc, "critical")
	insertFinding(t, f, tenantA, doc, "critical")
	insertFinding(t, f, tenantA, doc, "high")
	insertFinding(t, f, tenantA, doc, "none")
	insertFinding(t, f, tenantA, doc, "unknown")
	insertFinding(t, f, tenantA, doc, "") // NULL

	got, err := f.store.FindingsSummary(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("findings summary: %v", err)
	}
	if got.BOMDocumentID != doc {
		t.Errorf("bom_document_id = %q, want %q", got.BOMDocumentID, doc)
	}
	want := orchestr.SeverityCounts{
		Critical: 2, High: 1, Medium: 0, Low: 0,
		None: 1, Unknown: 1, NotProvided: 1,
	}
	if got.Severities != want {
		t.Errorf("severities = %+v, want %+v", got.Severities, want)
	}
}

// Re-normalization writes a NEW document version and never overwrites the
// old one (ADR-0003) — the summary must follow the latest version, exactly
// like report.resolveDocument does for a rendered report.
func TestFindingsSummaryFollowsTheLatestNormalizationVersion(t *testing.T) {
	f := newFixture(t)
	scan := createListScan(t, f, tenantA, projectList)

	v1 := insertBOMDocument(t, f, tenantA, scan.ID, 1)
	insertFinding(t, f, tenantA, v1, "critical")
	insertFinding(t, f, tenantA, v1, "critical")
	insertFinding(t, f, tenantA, v1, "critical")

	v2 := insertBOMDocument(t, f, tenantA, scan.ID, 2)
	insertFinding(t, f, tenantA, v2, "low")

	got, err := f.store.FindingsSummary(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("findings summary: %v", err)
	}
	if got.BOMDocumentID != v2 {
		t.Errorf("bom_document_id = %q, want the v2 document %q, not v1 %q", got.BOMDocumentID, v2, v1)
	}
	if got.Severities.Critical != 0 || got.Severities.Low != 1 {
		t.Errorf("severities = %+v, want the re-normalized counts (0 critical, 1 low), "+
			"not the superseded version's", got.Severities)
	}
}

// A scan with nothing normalized yet — still running, or it produced no SBOM
// — gets zero counts, not an error. That is a legitimate answer a live
// dashboard tile must be able to render without treating it as a failure.
func TestFindingsSummaryIsZeroWhenNothingIsNormalizedYet(t *testing.T) {
	f := newFixture(t)
	scan := createListScan(t, f, tenantA, projectList)

	got, err := f.store.FindingsSummary(t.Context(), tenantA, scan.ID)
	if err != nil {
		t.Fatalf("findings summary: %v", err)
	}
	if got.BOMDocumentID != "" {
		t.Errorf("bom_document_id = %q, want empty — nothing was normalized", got.BOMDocumentID)
	}
	if got.Severities != (orchestr.SeverityCounts{}) {
		t.Errorf("severities = %+v, want all zero", got.Severities)
	}
}

// RLS, not a WHERE clause this code could forget to write: tenant B must
// never see tenant A's counts, even indirectly through a document id.
func TestFindingsSummaryIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	scan := createListScan(t, f, tenantA, projectList)
	doc := insertBOMDocument(t, f, tenantA, scan.ID, 1)
	insertFinding(t, f, tenantA, doc, "critical")

	got, err := f.store.FindingsSummary(t.Context(), tenantB, scan.ID)
	if err != nil {
		t.Fatalf("findings summary: %v", err)
	}
	if got.BOMDocumentID != "" || got.Severities.Critical != 0 {
		t.Fatalf("tenant B's summary = %+v, want empty — tenant A's document must not be visible", got)
	}
}
