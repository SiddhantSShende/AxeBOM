-- +goose Up
-- ===========================================================================
-- findings.cluster_id gets the foreign key its sibling vuln_ids.cluster_id
-- has always had.
--
-- Before this, a finding could reference a cluster_id that was never
-- persisted to normalize.vuln_clusters, and nothing in the database would
-- catch it — exactly the failure mode ADR-0005's durable-surrogate design
-- exists to prevent (a finding pointing at a cluster id with no row behind
-- it is indistinguishable, at read time, from a genuine dangling reference
-- versus "the write path never actually wired real cluster ids through").
-- Now it fails loudly at INSERT time instead.
--
-- No ON DELETE CASCADE: vuln_clusters rows are never deleted (ADR-0005's
-- forwarding-table design merges clusters, it does not remove them), and
-- cascading a delete into tenant findings would be actively dangerous if
-- that ever changed.
--
-- Postgres propagates a FOREIGN KEY declared on a partitioned parent to
-- every existing partition automatically — normalize.findings is HASH
-- partitioned 16 ways (migration 0002), and this one ALTER TABLE covers all
-- sixteen without a loop.
-- ===========================================================================
ALTER TABLE normalize.findings
    ADD CONSTRAINT findings_cluster_id_fkey
    FOREIGN KEY (cluster_id) REFERENCES normalize.vuln_clusters (id);

-- +goose Down
ALTER TABLE normalize.findings DROP CONSTRAINT IF EXISTS findings_cluster_id_fkey;
