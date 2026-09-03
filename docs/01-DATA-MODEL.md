# 01 — Canonical Data Model

> **⚑ SSOT for schema.** Every table, column, type and enum in AxeBOM is defined here and **nowhere else**. No other document may define a column. If you need a field that is not here, add it here first, in the same change that adds the migration.

**Related:** field semantics come from `reference/certin-v2.0.yaml`. Merge and dedup rules come from `03-NORMALIZER-SPEC.md`. Envelopes crossing process boundaries come from `02-CONTRACTS.md`.

---

## 0. Conventions that apply to every table

| Rule | Detail |
|---|---|
| **Primary keys** | `id UUID PRIMARY KEY` — **UUIDv7** (time-ordered, so index locality is good and pagination by id is chronological). |
| **Timestamps** | `TIMESTAMPTZ`, always UTC. Every table has `created_at`; mutable tables have `updated_at`. Never a naive timestamp, never local time. |
| **Tenancy** | Every tenant-scoped table has `tenant_id UUID NOT NULL` **and** an RLS policy. A migration adding a tenant-scoped table without a policy is incomplete and `TestRLSCoverage` fails. |
| **Soft delete** | `deleted_at TIMESTAMPTZ NULL` on user-facing entities. RLS policies include `deleted_at IS NULL`. Scan and finding data is never soft-deleted — it is compliance evidence. |
| **Schema per service** | `auth`, `project`, `scan`, `normalize`, `report`, `campaign`, `comment`, `notify`. **No cross-schema JOIN in SQL, ever** — cross-domain joins happen in Go. This is what keeps services extractable and costs nothing today. |
| **Enums** | Postgres `TEXT` + `CHECK` constraint, not native `ENUM` types. Native enums cannot have values removed and make migrations painful. |
| **JSONB** | Used only for genuinely open-ended data (tool-specific properties, CVSS vectors, provenance). Never for anything queried in a hot path or subject to a constraint. |
| **Money/scores** | `NUMERIC`, never `FLOAT`. CVSS scores are `NUMERIC(3,1)`. |
| **Text from user repos** | Filenames may contain newlines, NULs, 4-byte emoji and 8 KB paths. Sanitize and truncate **before** insert. Column limits are enforced, not aspirational. |

### Tables deliberately NOT tenant-scoped

Seven tables have no `tenant_id` and no policy, each for a stated reason. The list is enforced in code (`libs/go-shared/platform/db/rls.go`), and `TestRLSCoverage` fails on any table that is neither scoped nor exempt — so an unlisted table cannot slip through unnoticed.

| Table | Why |
|---|---|
| `auth.tenants` | the tenancy root — the table every policy keys on |
| `auth.users` | global identity; one user may belong to several tenants |
| `normalize.vuln_clusters` | the alias graph is shared knowledge, not tenant data (ADR-0005) |
| `normalize.vuln_cluster_merges` | forwarding table for the global graph |
| `normalize.vuln_ids` | namespaced ids belonging to global clusters |
| `normalize.vuln_alias_edges` | global edge set; per-tenant would mean rediscovering every alias |
| `normalize.licenses` | SPDX reference data, identical for everyone |

**Adding to that list is a security decision.** "It was awkward to add `tenant_id`" is not a reason.

### Tenancy pattern (exact)

```sql
ALTER TABLE project.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.projects FORCE ROW LEVEL SECURITY;   -- applies to table owner too

CREATE POLICY tenant_isolation ON project.projects
  USING      (tenant_id = current_setting('app.current_tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

`FORCE` matters: without it the table owner bypasses the policy, and the migration role usually *is* the owner. The application role must not be superuser and must not have `BYPASSRLS`. The connection wrapper in `libs/go-shared/platform/db` issues `SET LOCAL app.current_tenant_id` at the start of every transaction; `SET LOCAL` (not `SET`) so it cannot leak across pooled connections.

---

## 1. Identity & tenancy — schema `auth`

### `auth.tenants`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `name` | TEXT NOT NULL | |
| `slug` | TEXT NOT NULL UNIQUE | URL-safe |
| `plan` | TEXT NOT NULL DEFAULT `'free'` | CHECK in (`free`,`team`,`enterprise`) |
| `created_at` | TIMESTAMPTZ NOT NULL | |

Not itself RLS-protected — it *is* the tenancy root. Access is gated at the application layer by membership.

### `auth.users`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `email` | CITEXT NOT NULL UNIQUE | case-insensitive |
| `name` | TEXT | |
| `password_hash` | TEXT NULL | argon2id. NULL for SSO-only users |
| `github_login` | TEXT NULL | |
| `github_user_id` | BIGINT NULL UNIQUE | stable across renames — **key on this, not the login** |
| `auth_provider` | TEXT NOT NULL | CHECK in (`local`,`github`,`oidc`,`saml`) |
| `status` | TEXT NOT NULL | CHECK in (`active`,`invited`,`suspended`) |
| `last_login_at` | TIMESTAMPTZ NULL | |

A user is global; membership binds them to tenants. This allows one identity across several tenants without duplicate accounts.

### `auth.memberships`
`(id, tenant_id, user_id, role, invited_by, invited_at, accepted_at, created_at)`
`role` CHECK in (`owner`,`admin`,`analyst`,`viewer`). `UNIQUE (tenant_id, user_id)`.

### `auth.sessions`
`(id, tenant_id, user_id, refresh_token_hash, user_agent, ip, expires_at, revoked_at, created_at)`
Store only the **hash** of the refresh token. Access tokens are stateless JWTs and are not stored.

### `auth.audit_log`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | UUID NULL | NULL for pre-tenant events (login attempt) |
| `actor_user_id` | UUID NULL | NULL for system actions |
| `action` | TEXT NOT NULL | e.g. `project.create`, `report.download`, `vex.update` |
| `entity_type` | TEXT | |
| `entity_id` | UUID NULL | |
| `metadata` | JSONB | never contains secrets or full request bodies |
| `ip`, `user_agent` | INET, TEXT | |
| `created_at` | TIMESTAMPTZ NOT NULL | |

**Append-only.** No `UPDATE`, no `DELETE` grant to the application role. Required by CERT-In §5.3.6 (p.33): log and review access to BOM data.

---

## 2. Projects — schema `project`

### `project.projects`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | UUID NOT NULL | RLS |
| `name` | TEXT NOT NULL | `UNIQUE (tenant_id, name)` |
| `description` | TEXT | |
| `source_type` | TEXT NOT NULL | CHECK in (`github`,`gitlab`,`bitbucket`,`upload`,`image`,`manual`,`url`) |
| `sdlc_stage` | TEXT NOT NULL | CHECK in (`design`,`source`,`build`,`analyzed`,`deployed`,`runtime`) — CERT-In §3.2, p.12–13 |
| `validity_start` | DATE NULL | |
| `validity_end` | DATE NULL | CHECK `validity_end >= validity_start` |
| `owner_name` | TEXT | |
| `owner_email` | CITEXT | |
| `owner_github` | TEXT | |
| `owner_phone` | TEXT | |
| `created_by` | UUID NOT NULL | → `auth.users.id`, **no FK** (cross-schema) |
| `created_at`, `updated_at`, `deleted_at` | TIMESTAMPTZ | |

> Cross-schema references are stored as plain UUIDs with **no foreign key constraint**, because an FK is a JOIN dependency and would prevent extracting the service later. Referential integrity across schemas is the application's job.

### `project.project_classifications`
`(project_id, bom_type)` — composite PK. `bom_type` CHECK in (`SBOM`,`CBOM`,`QBOM`,`AIBOM`,`HBOM`). A project may carry any subset.

### `project.practices`  ← CERT-In Table 5, category 3 (p.22)

This is the commonly-missed minimum-element category. **Not a report section — a per-project setting captured at registration.** One row per project.

| Column | Type | Notes |
|---|---|---|
| `project_id` | UUID PK | |
| `tenant_id` | UUID NOT NULL | RLS |
| `frequency` | TEXT | cron expression or human cadence; links to Campaigns |
| `depth` | TEXT | CHECK in (`top_level`,`n_level`,`delivery`,`transitive`,`complete`) |
| `known_unknowns` | TEXT | auto-seeded from engine-coverage gaps; user may extend |
| `distribution` | TEXT | how BOMs are delivered to consumers |
| `access_control` | TEXT | CHECK in (`public`,`private`) — CERT-In §5.3.2 requires **both** versions be maintainable |
| `errata_policy` | TEXT | the "Accommodation of Mistakes" mechanism |

### `project.repository_connections`
`(id, tenant_id, project_id, provider, repo_url, repo_external_id, default_branch, credential_ref, last_synced_at, created_at)`

`credential_ref` is a **Vault path**, never a token. `repo_external_id` is the provider's numeric id — stable across renames.

### `project.uploads`
`(id, tenant_id, project_id, kind, storage_ref, sha256, size_bytes, original_filename, uploaded_by, created_at)`
`kind` CHECK in (`source_archive`,`manifest`,`lockfile`,`sbom`,`hbom_csv`,`image_tarball`).

### `project.web_sources`
`(id, tenant_id, project_id, root_url, discovery_enabled, max_hosts, last_scanned_at, created_at)`

A project registered by URL rather than a repository connection or an upload. No `credential_ref` — nothing here is ever authenticated. `discovery_enabled` (default `true`) and `max_hosts` (default `25`, CHECK `BETWEEN 1 AND 100`) are the abuse-guard knobs `services/webrecon`'s subdomain-discovery pass reads (`05-SECURITY-MODEL.md` §1); they exist ahead of that service so its landing is a pure application change, not a schema change. A project may have more than one row here — nothing caps it to one, and `ListWebSources` returns a slice.

---

## 3. Scans — schema `scan`

### `scan.scans`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id`, `project_id` | UUID NOT NULL | |
| `triggered_by` | TEXT NOT NULL | CHECK in (`user`,`campaign`,`api`,`webhook`) |
| `trigger_ref` | UUID NULL | user id or campaign id |
| `status` | TEXT NOT NULL | CHECK in (`queued`,`fetching`,`running`,`normalizing`,`completed`,`completed_with_errors`,`failed`,`cancelled`) |
| `source_kind` | TEXT NOT NULL | CHECK in (`git`,`upload`,`image`,`url`); denormalized from the project at create time — cross-schema JOINs are forbidden, and a project changing `source_type` later must not retroactively change what an old scan claims to have scanned |
| `bom_types` | TEXT[] NOT NULL | requested families — never `hbom` or `qbom`; both are rejected at scan-create time (`SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE`, `02-CONTRACTS.md` §7/§9) because neither has a worker (HBOM is a CSV/form import, QBOM is derived from CBOM) |
| `report_levels` | TEXT[] NOT NULL | |
| `standards` | TEXT[] NOT NULL | `SPDX`, `CycloneDX` |
| `formats` | TEXT[] NOT NULL | |
| `engines_requested` | TEXT[] NOT NULL | resolved from families + policy at create time |
| `source_commit_sha` | TEXT NULL | **set once by the fetcher** — see below |
| `source_archive_ref` | TEXT NULL | content-addressed object key |
| `source_archive_sha256` | TEXT NULL | |
| `provenance_manifest` | JSONB NULL | resolved tool versions/digests, SPDX list version, ruleset version, alias snapshot id |
| `started_at`, `finished_at` | TIMESTAMPTZ NULL | |
| `error_code`, `error_message` | TEXT NULL | |

> **`source_commit_sha` is written exactly once, by the fetcher, before any engine job is dispatched.** Every engine reads the same archive. If engines cloned independently they could land on different commits and the resulting report would describe a codebase that never existed. See ADR-0008.

**Status derivation is mechanical**, never hand-set: all engine runs `succeeded` → `completed`; ≥1 succeeded and ≥1 not → `completed_with_errors`; zero succeeded → `failed`.

### `scan.engine_runs`
One row per (scan, engine). This is where partial failure lives.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id`, `scan_id` | UUID NOT NULL | |
| `job_id` | UUID NOT NULL UNIQUE | idempotency key; also the artifact path segment |
| `engine_id` | TEXT NOT NULL | `syft`, `trivy-fs`, `trivy-image`, `grype`, … — **(tool, mode) is the unit** |
| `engine_version` | TEXT | |
| `engine_db_version` | TEXT NULL | **required for vulnerability engines.** Without it a finding is undatable and the report indefensible |
| `attempt` | INT NOT NULL DEFAULT 1 | |
| `status` | TEXT NOT NULL | CHECK in (`queued`,`running`,`succeeded`,`partial`,`failed`,`timeout`,`unavailable`,`skipped`) |
| `weight` | INT NOT NULL DEFAULT 1 | drives weighted overall progress |
| `ecosystems_covered` | TEXT[] | what this engine actually saw |
| `argv_redacted` | TEXT[] | reproducibility; secrets stripped |
| `image_digest` | TEXT NULL | |
| `exit_code` | INT NULL | |
| `duration_ms` | INT NULL | |
| `summary` | JSONB | `{components, vulnerabilities, licenses, crypto_assets}` |
| `diagnostics` | JSONB | `[{severity, code, ecosystem, message, hint}]` — NON-FATAL problems; how `partial` explains itself |
| `error_code`, `error_message` | TEXT NULL | terminal failure cause. Deliberately separate from `diagnostics`: mixing a fatal failure into non-fatal warnings makes "did this engine work?" unanswerable without reading prose |
| `started_at`, `finished_at` | TIMESTAMPTZ | |

`partial` is a **first-class status, not an error** — e.g. Grype covered 11 of 12 ecosystems because one lockfile was malformed.

### `scan.raw_artifacts`
`(id, tenant_id, scan_id, engine_run_id, producer, role, storage_ref, media_type, sha256, size_bytes, created_at)`
`role` CHECK in (`native_output`,`log`,`stderr`,`sarif`,`source_archive`).

`engine_run_id` and `producer` are **mutually exclusive** (CHECK `(engine_run_id IS NULL) <> (producer IS NULL)`): an artifact belongs either to a dispatched engine's run, or to a named producer component that never gets an `engine_runs` row — today `fetcher` (a source archive, plus an optional `native_output` like a GitHub Dependency Graph SBOM) and `webrecon` (a url source's discovery + JS-fingerprint result, `native_output`). `LoadRawArtifactsForEngines` resolves both kinds by the same id.

**Immutable. Never updated, never deleted.** This is what makes normalization replayable: a dedup bug is fixed by re-normalizing these, not by re-running scanners. Retention is a compliance decision, not a storage one.

### `scan.ecosystems_detected`
`(scan_id, ecosystem, detected_by, engine_available BOOLEAN)`

Feeds the **Engine Coverage** report section and auto-seeds `project.practices.known_unknowns`. `engine_available = false` is the honest denominator most tools hide.

### `scan.normalize_triggers`
`(scan_id, tenant_id, family, trigger_id UUID DEFAULT app.uuid_v7(), triggered_at)` — `PRIMARY KEY (scan_id, family)`.

**The write-once guard** for "this scan's engines are done, normalize it": `scan-orchestrator` inserts a row (`ON CONFLICT DO NOTHING`, mirroring `SetSourceOnce`'s idiom) the moment every engine dispatched for one `(scan, family)` reaches a terminal state, and publishes exactly one `NormalizeTriggerV1` (`docs/02-CONTRACTS.md` §6a) when the insert actually fires. `trigger_id` doubles as the NATS dedup key. **Immutable by grant** — `UPDATE`/`DELETE` revoked from `axebom_app`, same as `scan.raw_artifacts`. Currently wired for `sbom` only; the per-family design lets `cbom`/`aibom` gain their own trigger later with no schema change.

---

## 4. Normalized BOM — schema `normalize`

### `normalize.bom_documents`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id`, `scan_id` | UUID NOT NULL | |
| `bom_type` | TEXT NOT NULL | CHECK in (`SBOM`,`CBOM`,`QBOM`,`AIBOM`,`HBOM`) |
| `normalization_version` | INT NOT NULL DEFAULT 1 | **bumped on re-normalization; old rows retained** |
| `ruleset_version` | TEXT NOT NULL | e.g. `2026.08.1` |
| `alias_snapshot_id` | UUID **NULL**, FK → `normalize.alias_snapshot.id` | which alias graph produced this. **Nullable with a real FK since migration `0012`** — resolved the gap this row used to describe. It was `NOT NULL` with *no* FK, the weakest possible pairing: it enforced "some uuid is present" and nothing about whether it meant anything, so `qbom.go`/`hbom.go` and the CBOM/AIBOM pipelines all minted a throwaway to satisfy it. Now: **NULL** for the BOM types that run no alias closure (CBOM, AIBOM, QBOM, HBOM) — declining to assert, where a fabricated id asserted to anyone joining `bom_documents → alias_snapshot` that a snapshot had been consulted — and a real, resolvable id for SBOM, which `writer.write_bom_document` **refuses to write without**. Same gap migration `0007` closed for `findings.cluster_id`. |
| `spdx_license_list_version` | TEXT NOT NULL | ids get deprecated; a report must say which list it validated against |
| `project_id` | UUID NULL | HBOM's second lineage key, added in migration `0012`. `services/project` has always borrowed `scan_id` for the project id on imported hardware BOMs (an import has no scan to point at, and `scan_id` has no FK by design). Once `hbom-ecad` produces real scans both meanings are live in that one column — they cannot collide, but resolving by `scan_id` would find only half of them. Both writers set `project_id`; `resolveHBOMDocument` reads it, ordering **newest-first** rather than highest-version-first, because `normalization_version` counts within a lineage and an import at v3 would otherwise outrank a fresh scan at v1. NULL for every other BOM type. |
| `supplementary_coverage` | JSONB NOT NULL DEFAULT `{}` | scored field sets that are **not** compliance, keyed by profile id. HBOM's manufacturing readiness today (`hbom-manufacturing-v1`); the shape carries its own `label` and an `is_compliance: false` flag so no consumer has to know which profile ids are standards. ⚠ A keyed JSONB rather than another pair of `numeric` columns **on purpose**: `completeness_pct`/`declaration_pct` are load-bearing precisely *because* they are the compliance numbers, and giving a non-compliance percentage the same column shape one schema-tab away is how it eventually gets picked up by a query that meant the other one. |
| `completeness_pct` | NUMERIC(5,2) | substantive values only — **the honest signal** |
| `declaration_pct` | NUMERIC(5,2) | includes explicit `not-provided` — a representation check |
| `coverage_breakdown` | JSONB | per-field presence counts, rendered as a table |
| `unidentified_count` | INT NOT NULL DEFAULT 0 | components that fell to `opaque` identity — never dropped from the denominator |
| `generated_at` | TIMESTAMPTZ NOT NULL | |

`UNIQUE (scan_id, bom_type, normalization_version)`.

> Two coverage numbers, always both. `not-provided`, `NOASSERTION`, `unknown`, `""` and `[]` score present = 0 for `completeness_pct`. Publishing only `declaration_pct` and calling it "coverage" is how tools ship misleading 100% scores.

### `normalize.alias_snapshot`
`(id, edge_count, source, ruleset_version, created_at)` — **global**, not tenant-scoped, same reasoning as `vuln_clusters` below: a provenance marker for the vulnerability alias graph state a normalization run consulted. `source` is honest about what it actually is today — `'scan-local'`, meaning the edges came from that one run's own grype/osv-scanner artifacts, not a read of an independently-versioned, persisted global edge snapshot. A future snapshot mechanism that pins a point-in-time copy of `vuln_alias_edges` would use a different `source` value; the column exists now so that distinction never needs a schema change.

### `normalize.components`  ← CERT-In Table 5 §4.2 data fields

> The `CERT-In` column below gives each field's **ordinal in the source table**, for cross-reading against the PDF. It is not a count and nothing may derive a count from it — the authoritative list is `reference/certin-v2.0.yaml`, and code renders the count from there (invariant 2).

| Column | Type | CERT-In | Notes |
|---|---|---|---|
| `id` | UUID PK | | |
| `tenant_id`, `bom_document_id` | UUID NOT NULL | | |
| `component_key` | TEXT NOT NULL | | **the merge key** — see `03-NORMALIZER-SPEC.md` |
| `identity_rule` | TEXT NOT NULL | | CHECK in (`purl`,`cpe`,`swid`,`hash`,`file`,`name`,`opaque`) |
| `identity_confidence` | TEXT NOT NULL | | CHECK in (`high`,`medium`,`low`) |
| `purl` | TEXT NULL | — | canonical **ecosystem** PURL |
| `certin_identifier` | TEXT NULL | 21 | **derived, render-only, NEVER a merge key** |
| `ecosystem` | TEXT NULL | | npm, pypi, maven, golang, deb, rpm, … |
| `name` | TEXT NOT NULL | 1 | |
| `version_raw` | TEXT | 2 | verbatim. **Never merge components differing here** |
| `version_normalized` | TEXT | | computed per ecosystem; display and ordering only |
| `description` | TEXT | 3 | |
| `supplier` | TEXT | 4 | |
| `license_declared` | TEXT | 5 | from manifest metadata |
| `license_concluded` | TEXT | 5 | from license-file scan or human decision |
| `license_observed` | TEXT | 5 | |
| `license_effective` | TEXT | 5 | + `license_rule` recording which produced it |
| `license_ambiguous` | BOOLEAN | | e.g. `GPL-2.0` → `-only` vs `-or-later`. **Flag, never resolve** |
| `origin` | TEXT | 6 | CHECK in (`proprietary`,`open-source`,`third-party-vendor`,`unknown`) |
| `patch_status` | TEXT | 9 | derived; `unknown` when no ecosystem comparator exists |
| `release_date` | DATE | 10 | |
| `eol_date` | DATE | 11 | |
| `criticality` | TEXT | 12 | CHECK in (`critical`,`high`,`medium`,`low`) |
| `usage_restrictions` | TEXT | 13 | |
| `hashes` | JSONB | 14 | `[{alg, value}]` |
| `comments` | TEXT | 15 | |
| `author_of_sbom_data` | TEXT | 16 | engine + tenant |
| `executable_property` | TEXT | 18 | tristate: `yes`/`no`/`not-provided` |
| `archive_property` | TEXT | 19 | tristate |
| `structured_property` | TEXT | 20 | tristate |
| `scope` | TEXT | | CHECK in (`required`,`optional`,`excluded`) |
| `is_direct` | BOOLEAN NOT NULL | | **explicit from the root set — never inferred from depth** |
| `depth` | INT NULL | | NULL for orphans |
| `is_orphan` | BOOLEAN NOT NULL DEFAULT false | | unreachable from any root. **Never forced to depth 1** — that silently inflates the direct count |
| `field_status` | JSONB NOT NULL | | per-field `provided` / `not-provided` + reason. Drives both coverage numbers |

Fields 7 (dependencies), 8 (vulnerabilities) and 17 (timestamp) live in related tables — `component_dependencies`, `findings`, and `bom_documents.generated_at` respectively.

`UNIQUE (bom_document_id, component_key)`. Indexes on `purl`, `ecosystem`, `license_effective`, `criticality`.

### `normalize.component_locations`
`(id, component_id, path, layer, sha256)` — **identity is the package; locations are 1:N.** The same jar vendored twice is one component at two paths, not two components.

### `normalize.component_candidate_identities`
`(id, component_id, kind, value, source_engine, confidence)`

Where a low-confidence Dependency-Check CPE attaches **without merging** into a PURL-identified component. Merging it would inherit its false positives into otherwise-clean data.

### `normalize.component_provenance`
`(id, component_id, engine_id, engine_version, engine_db_version, job_id, raw_finding_id, artifact_uri, artifact_sha256, rule_id, rule_version, confidence, observed_at)`

Every normalized fact records which engine saw it, which artifact it came from, and which rule produced it. This is what makes a report explainable.

### `normalize.component_dependencies`
`(bom_document_id, from_component_id, to_component_id, relationship, scope, owning_engine, confidence)`
`relationship` CHECK in (`depends_on`,`contains`,`describes`,`generated_from`,`variant_of`).

> **Graph edges are REPLACED per ecosystem by the highest-trust engine, not unioned.** Unioning invents phantom transitive edges and corrupts direct-vs-transitive counts — exactly the number a Top-Level report is built on. `owning_engine` records who supplied that ecosystem's subgraph. **Cycles are real** (Go, npm workspaces); never assume a DAG.

---

## 5. Vulnerabilities — schema `normalize`

### `normalize.vuln_clusters`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | **durable surrogate. NEVER derived from member ids** |
| `display_id` | TEXT NOT NULL | lowest-rank member: CVE < GHSA < OSV-native < vendor |
| `member_count` | INT NOT NULL | |
| `flagged_for_review` | BOOLEAN | true when > 12 members — a cluster that large is probably an over-merge |
| `created_at`, `updated_at` | TIMESTAMPTZ | |

> **The trap this design avoids:** deriving the cluster id from a hash of its members means the id mutates the moment a new alias is discovered — breaking every foreign key and invalidating every previously issued report. Merges write a forwarding row instead.

> **Written by `libs/py-shared/axebom_shared/normalize/cluster_store.py`**, under a Postgres advisory lock (`pg_advisory_xact_lock`, key registered in `libs/go-shared/platform/leader/leader.go`'s `NormalizeClusterGraph`) so concurrent scans touching overlapping CVEs cannot race. Enforces the cross-scan member-count cap (>12 refuses the merge and flags for review, per the `flagged_for_review` column above) by reading the TRUE persisted membership via `resolve_cluster()` — a check the in-memory union-find alone cannot make, since it only ever sees one scan's local group. `workers/sbom/normalize_consumer.py` is the one caller in production, using the `axebom_normalize_writer` role (SELECT/INSERT on `normalize` schema, plus one column-scoped `UPDATE (member_count, flagged_for_review, display_id, updated_at)` grant on this table specifically — `migrations/normalize/0006_alias_snapshot.sql`).

### `normalize.vuln_cluster_merges`
`(from_cluster_id, into_cluster_id, evidence_edge_id, merged_at)` — a view resolves old ids forward. **Every merge is logged with its evidence.** A compliance product must be able to explain why two findings became one.

### `normalize.vuln_ids`
`(id, cluster_id, namespace, value)` — `namespace` CHECK in (`CVE`,`GHSA`,`OSV`,`GO`,`PYSEC`,`RUSTSEC`,`GSD`,`MAL`,`SNYK`,`RHSA`,`DSA`,`USN`,`ALAS`,`ELSA`,`DLA`,`NPM`) — matches `aliases.py`'s `_NAMESPACE_RANK` vocabulary exactly (widened in `migrations/normalize/0008_vuln_ids_namespace_widen.sql`; `GO`/`PYSEC`/`RUSTSEC` are osv-scanner's own ecosystem-native id prefixes and are routinely a finding's PRIMARY id, not just an alias). `UNIQUE (namespace, value)`.

### `normalize.vuln_alias_edges`
`(id, id_a, id_b, source, authoritative BOOLEAN, first_seen, last_seen)`

**Global, not per-scan.** Undirected. Union-find over this set yields clusters. `authoritative` is true only for OSV and GHSA — a CVE↔CVE merge requires an authoritative edge, because OSV aliases are not always equivalence-safe (batched advisories, broad `MAL-` ids).

### `normalize.findings`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id`, `bom_document_id`, `component_id`, `cluster_id` | UUID NOT NULL | `cluster_id` REFERENCES `normalize.vuln_clusters(id)` (`migrations/normalize/0007_findings_cluster_fk.sql`) — a finding referencing a cluster that was never persisted fails loudly at insert time |
| `display_id_at_render` | TEXT NOT NULL | **pinned** — reports must stay stable as clusters evolve |
| `severity_effective` | TEXT | CHECK in (`critical`,`high`,`medium`,`low`,`none`,`unknown`) |
| `severity_source` | TEXT | which rule won |
| `severity_conflict` | BOOLEAN NOT NULL | true when engines disagreed — **surfaced in the UI, not hidden** |
| `cvss_vectors` | JSONB | all of them: `[{version, vector, score, source}]` |
| `cvss_primary_score` | NUMERIC(3,1) NULL | from the highest available v3.1+ vector |
| `fixed_versions` | TEXT[] | |
| `fixed_in_min` | TEXT NULL | ecosystem-correct comparator |
| `fix_version_ordering` | TEXT | CHECK in (`comparator`,`unknown`,`none`) — `comparator` when a fix version was reported and an ecosystem-correct comparator exists; **`unknown` when a fix version was reported but no comparator exists — never guess with a lexical sort**; `none` when no fix version was reported at all |
| `detected_by` | TEXT[] NOT NULL | every engine that saw it |
| `references` | JSONB | |
| `first_seen_at`, `last_seen_at` | TIMESTAMPTZ | |

`UNIQUE (bom_document_id, cluster_id, component_id)` — same CVE + same component + two paths = one finding.

> **Severity is never averaged.** Precedence: tenant policy override > CVSS v4 vector > NVD v3.1 > advisory v3.1 > vendor string > max of remaining strings. **CVSS v2 / v3.1 / v4.0 are not comparable** — store all, rank on v3.1+, never max across versions.

### `normalize.raw_findings`
`(id, tenant_id, scan_id, engine_run_id, engine_id, native_vuln_id, component_key, severity_raw, cvss_vectors, fix_versions, aliases_raw, references, created_at)`

**Ingested verbatim, never deduped at ingest.** Deduping here would destroy the audit trail. `normalize.findings` is derived from these.

### `normalize.licenses`
`(id, spdx_id, name, category, is_deprecated, is_osi_approved, obligations, text_ref, list_version)` — **global reference data, NOT tenant-scoped.** The SPDX list is identical for every tenant; scoping it would mean each tenant re-seeding the same 600 licences. Tenant-specific unrecognized licence text lives in `license_refs`, which *is* scoped.

### `normalize.license_refs`
`(id, tenant_id, slug, raw_text, first_seen_scan_id, mapped_spdx_id NULL, reviewed_by NULL)`

Unrecognized license text becomes `LicenseRef-AxeBOM-<slug>` with the raw text preserved for later human mapping.

---

## 6. Crypto, quantum, AI, hardware — schema `normalize`

### `normalize.crypto_assets`  ← CERT-In Table 9 (p.45–48)

> **Type-discriminated.** Four asset types with **different** field sets. Storage is one wide table; **coverage must be scored against the field set for the row's `asset_type`.** Scoring a certificate against `key_size` would report every CBOM at ~30% coverage — falsely, in a compliance document. The coverage checker branches on `asset_type`.

`(id, tenant_id, bom_document_id, component_id NULL, asset_type, name, …)`
`asset_type` CHECK in (`algorithm`,`key`,`protocol`,`certificate`).

| Applies to | Columns |
|---|---|
| **algorithm** | `primitive`, `mode`, `crypto_functions TEXT[]`, `classical_security_level INT`, `oid`, `algorithm_list TEXT[]` |
| **key** | `key_id`, `key_state` (`active`/`revoked`/`expired`/`unknown`), `key_size INT`, `creation_date`, `activation_date` |
| **protocol** | `protocol_version`, `cipher_suites TEXT[]`, `oid` |
| **certificate** | `cert_subject`, `cert_issuer`, `not_valid_before`, `not_valid_after`, `signature_algo_ref`, `subject_public_key_ref`, `cert_format`, `cert_extension` |
| **AxeBOM analysis** (not CERT-In fields — excluded from coverage) | `quantum_vulnerable BOOLEAN`, `pqc_recommendation TEXT`, `deprecation_status` (`current`/`deprecated`/`weak`/`broken`) |

`quantum_vulnerable` is true for Shor-vulnerable primitives: RSA, ECC/ECDSA/ECDH, DH, DSA.

### `normalize.quantum_components`  ← Table 8 (p.44–45)
`(id, tenant_id, bom_document_id, model_name, version, vendor_origin, license_info, communication_protocol, hardware, software_dependencies, environmental_impact, attestation_signature, field_status JSONB)` + `crypto_assets` via `bom_document_id`, findings via `normalize.findings`.

> Populated by **form/import**, not discovery. There is no quantum-hardware scanner. Crypto assets are derived from CBOM discovery with quantum-vulnerability rules applied.

### `normalize.ai_models`  ← Table 10 (p.54–55)
`(id, tenant_id, bom_document_id, model_name, model_version, model_type, model_developer, licensing, ml_models_algorithms TEXT[], performance_metrics JSONB, data_source, hardware, security_requirements, input, output, intended_usage, out_of_scope_usage, environmental_impact, attestation_signature, risk_score NUMERIC, owasp_llm_top10 TEXT[], field_status JSONB)`

Plus `normalize.ai_datasets` `(id, ai_model_id, name, version, format, limitations, license, source)` and `normalize.ai_model_dependencies` `(ai_model_id, component_key)`.

> `component_key` is a plain `text` column, **not** a foreign key into `normalize.components` — the referenced SBOM component usually lives in a different `bom_document_id` (a different `bom_type` document entirely) than this AIBOM, so there is no in-transaction id to reference. A reader resolves the join by string match at read time, the same situation as `crypto_assets.component_key` above.

`risk_score` and `owasp_llm_top10` are AxeBOM extensions from Trusera ai-bom — excluded from coverage scoring.

### `normalize.hardware_components`  ← Table 11 (p.60–61) + §10.4.1.4 (p.62)

Recursive: `parent_id UUID NULL` self-reference.

`(id, tenant_id, bom_document_id, parent_id, product_name, product_version, product_details, warranty_amc, manufacturer_name, manufacturer_location, manufacturing_date, supplier_info, supplier_location, model_number, serial_number, technical_specification, component_supplier_info, component_supplier_location, technology_node, compliance TEXT[], power_supply, license_info, test_result, firmware_version, origin, criticality, field_status JSONB)`

Two things Table 11 alone would get wrong:

- **`supplier_info`/`supplier_location` vs `component_supplier_info`/`component_supplier_location`.** Table 11 lists "Supplier Information" and "Supplier Location" *twice* with different descriptions — the product's supplier, and the component's supplier to the manufacturer. Different relationships, distinct columns.
- **`firmware_version`, `origin`, `criticality` and vulnerabilities** appear nowhere in Table 11 but are mandated by §10.4.1.4 (p.62). They are required.

Depth is capped (default 10) with a diagnostic rather than unbounded recursion.

The `parent_id` self-reference is **`DEFERRABLE INITIALLY DEFERRED`** (migration `0011`). The Go store inserts one node at a time, parents first, so a per-row check was always satisfiable there — but the Python bulk path chunks at 500 rows per `INSERT`, and a non-deferrable FK is validated at the end of each statement. A 700-node assembly whose parent lands in chunk 2 while its child lands in chunk 1 would fail, and only above 500 nodes. `bulk.py` still emits parents before children (a deferred check buffers to commit time and costs memory on a large tree); the constraint is the correctness floor, the ordering is the fast path.

#### Manufacturing and procurement columns — **not CERT-In elements**

`(quantity, designators TEXT[], package_footprint, supplier_sku, preferred_supplier, unit_price NUMERIC(18,6), currency, extended_price NUMERIC GENERATED, do_not_populate BOOLEAN, assembly_type, lifecycle_status, datasheet_url, enriched_fields JSONB, manufacturing_field_status JSONB, source_engine)`

> ⚠ **None of these may move `completeness_pct` or `declaration_pct`.** Table 11 describes a component's identity and provenance; it says nothing about how many are fitted, where they sit on the board, what they cost, or whether the part can still be bought. These are scored **separately**, against `reference/hbom-manufacturing-v1.yaml`, into `bom_documents.supplementary_coverage`. Same shape as the AxeBOM analysis columns already sitting beside CERT-In ones on `crypto_assets` and `ai_models`.

- **`quantity` and `enriched_fields` closed real gaps.** Both were modelled in the Go and Python component types and in the TypeScript client since Phase 15 with no column to land in — `store/hbom.go`'s read path hardcoded `Quantity: 1`, so an imported quantity of 100 rendered as 1.
- **`extended_price` is `GENERATED ALWAYS AS (quantity * unit_price) STORED`.** It cannot disagree with its inputs, there is one implementation of the arithmetic, and it stays `SUM`-able in SQL. `NULL` when either input is `NULL` — the extended price of an unknown unit price is not zero. **Writers must not name this column**; Postgres rejects an explicit value.
- **`currency` is CHECKed on shape (`^[A-Z]{3}$`), not membership**, and is never defaulted. ISO 4217 gains and retires codes, and guessing a currency turns an unusable number into a wrong one.
- **`lifecycle_status`'s `unknown` is storable and scores zero.** It is in `coverage.NON_SUBSTANTIVE`, so a distributor that answered "unknown" is reported without counting as knowledge. `nrnd` is a distinct value from both neighbours — Not Recommended for New Designs is buyable today and refused at the next respin, which is the one status that prompts a redesign before the part goes away.
- **`manufacturing_field_status` is a second JSONB, not a namespaced key inside `field_status`.** `field_status` records which CERT-In elements held a substantive value; nesting a non-CERT-In block inside it would make every reader parse a discriminator to find out whether a key is a compliance fact.

### `normalize.hardware_component_alternates`  ← not a CERT-In element

`(id, tenant_id, hardware_component_id, ordinal, manufacturer_name, model_number, supplier_info, supplier_sku, lifecycle_status, equivalence, approval_note, created_at)`

Approved second sources — the supply-chain field that decides whether an obsolete part delays a build or stops it. A child table rather than a JSONB array because the question it exists to answer ("which boards have a second source for this obsolete part?") needs a b-tree index on the alternate's MPN.

`equivalence` CHECK in (`drop-in`,`functional`,`unverified`), **defaulting to `unverified`**. Asserting that a part is a drop-in replacement is a substitution decision about somebody's hardware; defaulting to the flattering value would make AxeBOM the author of a claim it never checked.

`CONSTRAINT hardware_alternate_identifiable` — an alternate naming no manufacturer, no MPN and no SKU is not an alternate.

### `normalize.hardware_findings`  ← CERT-In §10.4.1.4 element 24 (p.62)

`(id, tenant_id, bom_document_id, hardware_component_id, cluster_id, display_id, cpe23, match_basis, match_confidence, severity, cvss_score NUMERIC(3,1), cvss_vector, description, source, source_version, first_seen_at)`

Plus three columns on `hardware_components`: `vuln_match_status`, `cpe23_candidates TEXT[]`, `vuln_matched_at`.

**Not `normalize.findings`, and the reason is a silent false negative.** That table's only reader — `services/report/internal/store/bomsource.go`'s `loadFindings` — is an `INNER JOIN` against `normalize.components`. A row whose `component_id` points at a hardware component matches nothing and disappears from the report with no error anywhere, which is exactly what invariant 12 exists to prevent. Making it a `UNION` would also make an SBOM hot path (50k components, 200k findings, 16 hash partitions) pay for a hardware feature. **Not JSONB on `hardware_components` either** — that re-opens the dangling-cluster hole migration `0007` closed, because a JSONB array carries no foreign key.

**`cluster_id` is the same global cluster an SBOM finding points at** (ADR-0005). CVE-2021-1472 affecting a router and CVE-2021-1472 affecting a library are one vulnerability; a hardware-private cluster would make them look unrelated in every future query.

> ⚠ **`vuln_match_status` is what makes an empty `findings` list readable, and without it the column is dangerous.** Four values — `matched`, `no-match`, `no-cpe`, `not-attempted` — and collapsing any two loses the distinction that matters: *"we searched and found nothing"* and *"no vulnerability source is configured"* are the same empty list, and only one of them is reassuring. `not-attempted` rendered as "no known vulnerabilities" is a false negative a customer would act on.

**`match_basis` and `match_confidence` are columns, not a footnote.** An SBOM finding is keyed on a purl the ecosystem itself minted; this one is keyed on a CPE assembled from a manufacturer string somebody typed and a model number off a datasheet, matched against NVD's own vocabulary that was never reconciled with either. `match_confidence` defaults to `low` — a default that flatters a guess is how an advisory becomes a claim somebody acts on — and the matcher never emits `high` at all.

> ⚠ **Element 24 scores "a vulnerability reference is present", not "we checked", and the arithmetic is counter-intuitive because the guideline's field is.** It is a `ref_list`, and `coverage.is_substantive([])` is `False` — so a component with **no** known vulnerability scores **zero** on element 24 while a vulnerable one scores full marks. Widening `is_substantive` is *not* the fix: it is the most sensitive function in the codebase and would change what `not-provided` means for every BOM type at once. The arithmetic stays honest and **the report says so in words**, beside the number (`render.vulnerabilityNote`).

**These severities are never summed into the counts an SBOM report quotes.** One blended figure, part fact and part guess, with nothing saying which, is worse than two honest numbers.

---

## 7. Vulnerability disclosure — schema `normalize`

### `normalize.vex_statements`
`(id, tenant_id, project_id, component_key, cluster_id, status, justification, remediation, workarounds, downtime, scope, version, superseded_by NULL, author_user_id, created_at)`

`status` CHECK in (`not_affected`,`affected`,`fixed`,`under_investigation`) — CERT-In §6 (p.35).

> **Iterative and append-only.** The guideline (p.35) is explicit that VEX is an iterative process updated with each change. A new statement supersedes rather than mutates; full history is preserved. Effective status = most specific scope, then latest timestamp. **VEX never mutates a finding** — it joins to it.

### `normalize.csaf_advisories`
`(id, tenant_id, vex_statement_id, tracking_id, description, affected_versions JSONB, severity, mitigation_steps, published_at, document JSONB)`
`document` holds the full CSAF 2.0 JSON for round-trip fidelity.

---

## 8. Reports — schema `report`

### `report.reports`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id`, `scan_id` | UUID NOT NULL | |
| `bom_document_ids` | UUID[] NOT NULL | one report may span several BOM types |
| `bom_type`, `level`, `standard`, `format` | TEXT NOT NULL | |
| `visibility` | TEXT NOT NULL | CHECK in (`public`,`private`) — CERT-In §5.3.2 requires both be maintainable |
| `status` | TEXT NOT NULL | CHECK in (`queued`,`rendering`,`ready`,`failed`) — **rendering is async**; a Complete BOM can exceed 50k components |
| `storage_ref` | TEXT NULL | |
| `sha256` | TEXT NULL | |
| `size_bytes` | BIGINT NULL | |
| `signature` | TEXT NULL | detached Ed25519 |
| `signing_key_id` | TEXT NULL | |
| `truncated` | BOOLEAN NOT NULL DEFAULT false | PDF hit the page cap |
| `truncation_note` | TEXT NULL | what was omitted and where to get it |
| `created_at` | TIMESTAMPTZ | |

### `report.share_links`
`(id, tenant_id, report_id, token_hash, expires_at, max_downloads, download_count, created_by, revoked_at, created_at)`

Store only the **hash** of the token. Every access writes an `auth.audit_log` row.

### `report.comments` — schema `comment`
`(id, tenant_id, report_id, user_id, parent_id NULL, body, edited_at NULL, deleted_at NULL, created_at)`
Threaded via `parent_id`. Depth capped at 5. Edits and deletes are audited.

---

## 9. Campaigns — schema `campaign`

### `campaign.campaigns`
`(id, tenant_id, name, project_ids UUID[], cron_expr, timezone, bom_types[], report_levels[], standards[], formats[], enabled, next_run_at, last_run_at, created_by, created_at)`

`timezone` is an IANA name. DST transitions are handled by the scheduler, not by storing offsets.

### `campaign.runs`
`(id, tenant_id, campaign_id, scheduled_for, started_at, finished_at, status, scan_ids UUID[], error)`

`UNIQUE (campaign_id, scheduled_for)` — this is what makes triggers **idempotent** across restarts and leader changes. Leader election uses a **Postgres advisory lock**; no etcd, no Consul, no ZooKeeper.

### `notify.subscriptions` / `notify.deliveries`
`(id, tenant_id, kind, target, events[], secret_ref, enabled)` and `(id, subscription_id, event_type, payload, attempt, status, response_code, next_retry_at)`.

---

## 10. Scale and partitioning

A large monorepo yields 50k+ components and 200k+ findings **per scan**. Design for it from Phase 1, not after the first outage:

- Bulk-insert normalized rows via `COPY`, never row-by-row `INSERT`.
- Partition `normalize.findings` and `normalize.components` by `bom_document_id` hash (16 partitions initially).
- Hard cap ~250k components per scan, emitting a loud diagnostic rather than silently truncating.
- Every component and finding endpoint is paginated. Keyset pagination on UUIDv7 `id`, never `OFFSET`.
- `normalize.vuln_alias_edges` grows globally and monotonically: incremental union-find with a merge log, recomputing only affected clusters. Never full-recompute.

---

## 11. Entity relationships

```
tenant ─┬─ user (via membership)
        └─ project ─┬─ classification (1..5 BOM types)
                    ├─ practices          (CERT-In Table 5 cat. 3)
                    ├─ repository_connection
                    └─ scan ─┬─ engine_run ── raw_artifact  (immutable)
                             └─ bom_document ─┬─ component ─┬─ location
                                              │             ├─ provenance
                                              │             ├─ candidate_identity
                                              │             └─ finding ── vuln_cluster
                                              │                              ↑
                                              │                       vuln_alias_edge
                                              │                       (global union-find)
                                              ├─ crypto_asset      (type-discriminated)
                                              ├─ quantum_component
                                              ├─ ai_model ── ai_dataset
                                              └─ hardware_component (recursive)

project ── vex_statement ── csaf_advisory
scan ───── report ─┬─ share_link
                   └─ comment (threaded)
campaign ── run ── scan
```

---

## 12. Migration rules

1. `goose`, one directory per schema: `migrations/<schema>/NNNN_description.sql`.
2. Forward-only in production; reversible in development.
3. **A migration adding a tenant-scoped table without an RLS policy is incomplete.** `TestRLSCoverage` enumerates every table in tenant schemas and fails on any without `FORCE ROW LEVEL SECURITY` and a policy.
4. Never add a cross-schema foreign key. Cross-schema references are plain UUIDs.
5. Adding a column to `normalize.components` means adding the field to `reference/certin-v2.0.yaml` first, if it is a compliance field.
6. Data backfills go in a separate migration from schema changes, so a slow backfill never blocks a deploy.
