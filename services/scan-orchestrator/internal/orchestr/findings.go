package orchestr

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// FindingsSummary is the finding count for one scan, by severity.
//
// ⚠ SEVERAL QUERIES ACROSS TWO SCHEMAS, JOINED IN GO — NOT ONE SQL JOIN.
//
// `scan` and `normalize` are separate service domains (ADR-0001), and this
// file's whole reason to exist separately from store.go is that boundary:
// store.go touches scan.* only, this touches normalize.* only, and nothing
// here joins the two in SQL. Precedent: report's bomsource.go does the same
// thing for the same reason.
type FindingsSummary struct {
	ScanID string
	// BOMDocumentID is "" when nothing has been normalized yet for this scan
	// — still running, or it produced no SBOM. That is a legitimate, honest
	// zero, and distinct from the scan itself not existing (which the caller
	// must have already ruled out; see Handler.FindingsSummary).
	BOMDocumentID string
	Severities    SeverityCounts
}

// SeverityCounts covers every state normalize.findings.severity_effective can
// hold, keeping three that are easy to collapse into one another apart.
//
// ⚠ None, Unknown AND NotProvided ARE THREE DIFFERENT FACTS, NOT SYNONYMS.
//
//   - None    — a source asserted, explicitly, that this finding has no
//     severity (an informational advisory, for instance). A real answer.
//   - Unknown — a source asserted, explicitly, that it could not determine a
//     severity. Also a real answer, just a negative one.
//   - NotProvided — severity_effective is SQL NULL: nothing computed a
//     severity at all. This is the CLAUDE.md invariant-3 "not-provided"
//     state applied to findings — reported, never silently folded into
//     "none" zero, because "nobody looked" and "we looked and there is
//     nothing" are different facts in a compliance product.
//
// Collapsing any of the three into another either invents a severity nobody
// asserted, or hides a gap in what was actually measured.
type SeverityCounts struct {
	Critical    int
	High        int
	Medium      int
	Low         int
	None        int
	Unknown     int
	NotProvided int
}

// FindingsSummary counts a scan's findings by severity.
//
// ⚠ THE CALLER MUST HAVE ALREADY CONFIRMED THE SCAN EXISTS FOR THIS TENANT.
//
// This function does not re-check: a scan id belonging to no tenant and a
// scan id that simply has nothing normalized yet look IDENTICAL from inside
// normalize.* alone — both are zero rows. Resolving the ambiguity needs
// scan.scans, which is store.go's job (GetScan), so Handler.FindingsSummary
// calls that FIRST and only reaches here once the 404 case is ruled out.
// Skipping that step would turn a cross-tenant scan id into a 200 with an
// all-zero summary instead of a 404 — an oracle for probing which ids exist.
func (s *Store) FindingsSummary(ctx context.Context, tenantID, scanID string) (FindingsSummary, error) {
	out := FindingsSummary{ScanID: scanID}

	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		docID, err := resolveSBOMDocument(ctx, tx, scanID)
		if err != nil {
			return err
		}
		if docID == "" {
			// Nothing normalized yet. Zero counts is the honest answer for a
			// scan that is still running or produced no SBOM — it is not an
			// error, and it must not be confused with the scan not existing.
			return nil
		}
		out.BOMDocumentID = docID

		rows, err := tx.Query(ctx, `
			SELECT severity_effective, count(*)
			  FROM normalize.findings
			 WHERE bom_document_id = $1
			 GROUP BY severity_effective`, docID)
		if err != nil {
			return fmt.Errorf("count findings: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var severity *string
			var count int
			if err := rows.Scan(&severity, &count); err != nil {
				return err
			}
			assignSeverityCount(&out.Severities, severity, count)
		}
		return rows.Err()
	})
	if err != nil {
		return FindingsSummary{}, err
	}
	return out, nil
}

// resolveSBOMDocument picks the current SBOM document for a scan.
//
// ⚠ SBOM, NOT WHATEVER BOM TYPES THE SCAN REQUESTED. Vulnerability matching
// runs against SBOM components; CBOM, QBOM, AIBOM and HBOM have no findings
// table of their own (docs/03-NORMALIZER-SPEC.md). And the HIGHEST
// normalization_version, unless there is none: re-normalization writes
// version N+1 and never overwrites N (ADR-0003), so "the document" is
// ambiguous by design and the current one is always the latest.
//
// Returns "" rather than an error when no SBOM document exists yet — that is
// a normal, honest state (see FindingsSummary), not resolveDocument's
// ErrNotFound in report/bomsource.go, which exists because a REPORT genuinely
// cannot be produced without a document. A live summary tile can.
func resolveSBOMDocument(ctx context.Context, tx db.Tx, scanID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		SELECT id FROM normalize.bom_documents
		 WHERE scan_id = $1 AND bom_type = 'SBOM'
		 ORDER BY normalization_version DESC
		 LIMIT 1`, scanID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve sbom document: %w", err)
	}
	return id, nil
}

func assignSeverityCount(c *SeverityCounts, severity *string, count int) {
	if severity == nil {
		c.NotProvided = count
		return
	}
	switch *severity {
	case "critical":
		c.Critical = count
	case "high":
		c.High = count
	case "medium":
		c.Medium = count
	case "low":
		c.Low = count
	case "none":
		c.None = count
	case "unknown":
		c.Unknown = count
	}
}
