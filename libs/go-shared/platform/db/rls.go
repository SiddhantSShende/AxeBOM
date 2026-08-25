package db

import (
	"context"
	"fmt"
	"sort"
)

// RLS coverage verification.
//
// The point of this file is that "every tenant-scoped table has a policy" is
// checked MECHANICALLY, against the live catalog, rather than trusted because
// the migration looked right. A table added without a policy is not a style
// problem: it is a table any tenant can read in full.
//
// The same code backs `axebom db verify-rls` and TestRLSCoverage, so the
// test that guards development and the command that guards production cannot
// disagree.

// TenantSchemas are the schemas whose tables are expected to be tenant-scoped.
var TenantSchemas = []string{
	"auth", "project", "scan", "normalize", "report", "campaign", "comment", "notify",
}

// exemption is a table that is deliberately NOT tenant-scoped.
//
// ⚠ ADDING TO THIS LIST IS A SECURITY DECISION.
//
// Every entry must state why the table holds no tenant data. "It was awkward
// to add tenant_id" is not a reason. If you cannot write a convincing sentence
// here, the table needs a tenant_id and a policy.
type exemption struct {
	table  string
	reason string
}

var exemptions = []exemption{
	{
		table: "auth.tenants",
		reason: "the tenancy ROOT — it is the table every policy keys on. " +
			"Access is gated at the application layer by membership.",
	},
	{
		table: "auth.users",
		reason: "GLOBAL identity: one user may belong to several tenants, so there " +
			"is no single tenant_id. Application code reaches users only through a " +
			"membership join, never by scanning this table.",
	},
	{
		table: "normalize.vuln_clusters",
		reason: "the alias graph is shared knowledge about the world, not tenant " +
			"data. Cluster identity must be stable across all tenants or the same " +
			"CVE would fragment per tenant (ADR-0005).",
	},
	{
		table:  "normalize.vuln_cluster_merges",
		reason: "forwarding table for the global alias graph; carries no tenant data.",
	},
	{
		table:  "normalize.vuln_ids",
		reason: "namespaced identifiers (CVE, GHSA, OSV) belonging to global clusters.",
	},
	{
		table: "normalize.vuln_alias_edges",
		reason: "GLOBAL, monotonically growing alias-edge set. Per-tenant edges would " +
			"mean each tenant rediscovering that CVE-2021-44228 and GHSA-jfh8-c2jp-5v3q " +
			"are the same vulnerability.",
	},
	{
		table: "normalize.licenses",
		reason: "SPDX reference data, identical for everyone. Tenant-specific " +
			"unrecognized license text lives in normalize.license_refs, which IS scoped.",
	},
}

func exemptionFor(table string) (exemption, bool) {
	for _, e := range exemptions {
		if e.table == table {
			return e, true
		}
	}
	return exemption{}, false
}

// TableRLS describes one table's row-level-security state.
type TableRLS struct {
	Table  string
	Policy string
	Reason string
}

// RLSReport is the outcome of a coverage check.
type RLSReport struct {
	Checked int
	Covered []TableRLS
	Exempt  []TableRLS
	Gaps    []TableRLS
}

// OK reports whether every non-exempt table is protected.
func (r RLSReport) OK() bool { return len(r.Gaps) == 0 }

// VerifyRLS inspects the live catalog.
//
// Three things must all hold for a table to count as covered:
//
//	relrowsecurity      ENABLE ROW LEVEL SECURITY
//	relforcerowsecurity FORCE  ROW LEVEL SECURITY   <- the one people forget
//	at least one policy
//
// FORCE is the subtle one. Without it the table OWNER bypasses every policy —
// and the migration role IS the owner, so a check that only looked at ENABLE
// would pass on a table that leaks in production.
//
// Leaf partitions are skipped: they are covered through their parent, and the
// helper applies policies to them anyway. A partition WITHOUT its parent
// covered would be caught by the parent's own check.
func (m *Migrator) VerifyRLS(ctx context.Context) (RLSReport, error) {
	var report RLSReport

	rows, err := m.db.QueryContext(ctx, `
		SELECT n.nspname || '.' || c.relname       AS table_name,
		       c.relrowsecurity                     AS rls_enabled,
		       c.relforcerowsecurity                AS rls_forced,
		       c.relispartition                     AS is_partition,
		       COALESCE((SELECT string_agg(p.polname, ',')
		                   FROM pg_policy p
		                  WHERE p.polrelid = c.oid), '') AS policies,
		       EXISTS (SELECT 1 FROM pg_attribute a
		                WHERE a.attrelid = c.oid
		                  AND a.attname  = 'tenant_id'
		                  AND NOT a.attisdropped)   AS has_tenant_id
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = ANY($1)
		   AND c.relkind IN ('r', 'p')
		   AND c.relname NOT LIKE 'goose_%'
		 ORDER BY 1`, TenantSchemas)
	if err != nil {
		return report, fmt.Errorf("query catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			name        string
			enabled     bool
			forced      bool
			isPartition bool
			policies    string
			hasTenantID bool
		)
		if err := rows.Scan(&name, &enabled, &forced, &isPartition, &policies, &hasTenantID); err != nil {
			return report, err
		}

		// Leaf partitions inherit protection through the parent, which is
		// checked in its own right.
		if isPartition {
			continue
		}

		report.Checked++

		if ex, ok := exemptionFor(name); ok {
			report.Exempt = append(report.Exempt, TableRLS{Table: name, Reason: ex.reason})
			continue
		}

		// A table in a tenant schema with no tenant_id and no exemption is
		// the interesting case: someone added a table and did not think about
		// tenancy at all.
		if !hasTenantID {
			report.Gaps = append(report.Gaps, TableRLS{
				Table: name,
				Reason: "no tenant_id column and no entry in the exemption list — " +
					"add tenant_id and a policy, or document why it holds no tenant data",
			})
			continue
		}

		switch {
		case !enabled:
			report.Gaps = append(report.Gaps, TableRLS{
				Table:  name,
				Reason: "row-level security is NOT enabled",
			})
		case !forced:
			report.Gaps = append(report.Gaps, TableRLS{
				Table: name,
				Reason: "row-level security is enabled but NOT FORCED — the table owner " +
					"bypasses every policy, and the migration role is the owner",
			})
		case policies == "":
			report.Gaps = append(report.Gaps, TableRLS{
				Table:  name,
				Reason: "row-level security is forced but no policy exists (deny-all, likely unintended)",
			})
		default:
			report.Covered = append(report.Covered, TableRLS{Table: name, Policy: policies})
		}
	}
	if err := rows.Err(); err != nil {
		return report, err
	}

	sort.Slice(report.Covered, func(i, j int) bool { return report.Covered[i].Table < report.Covered[j].Table })
	sort.Slice(report.Exempt, func(i, j int) bool { return report.Exempt[i].Table < report.Exempt[j].Table })
	sort.Slice(report.Gaps, func(i, j int) bool { return report.Gaps[i].Table < report.Gaps[j].Table })

	return report, nil
}
