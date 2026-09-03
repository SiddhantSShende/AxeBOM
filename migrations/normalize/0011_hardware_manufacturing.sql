-- +goose Up
-- ===========================================================================
-- Manufacturing, sourcing and assembly data for hardware components.
--
-- ⚠ NONE OF THIS IS A CERT-In ELEMENT, AND NOTHING HERE MAY MOVE
-- completeness_pct OR declaration_pct.
--
-- CERT-In Table 11 describes a component's IDENTITY and PROVENANCE. It says
-- nothing about how many are fitted, where they sit on the board, what they
-- cost, or whether the part is still manufactured — all of which a real parts
-- list carries and a buyer needs. These columns let AxeBOM hold what the
-- customer's own file already says, without inventing a compliance claim out
-- of it. They are scored SEPARATELY, against
-- docs/reference/hbom-manufacturing-v1.yaml, into
-- bom_documents.supplementary_coverage — never into completeness_pct
-- (CLAUDE.md invariants 2 and 3).
--
-- Same shape as the AxeBOM analysis columns already sitting beside CERT-In
-- ones on normalize.crypto_assets (quantum_vulnerable, pqc_recommendation)
-- and normalize.ai_models (risk_score): one table, a commented block,
-- excluded from compliance scoring by the PROFILE rather than by a separate
-- table. A side table would cost a LEFT JOIN in every reader for no benefit —
-- the row is 1:1 and every read path already selects the whole row.
--
-- ⚠ NO `description` COLUMN, DELIBERATELY. An engineering description IS
-- CERT-In element 3 (`certin.hbom.03.product_details`), and
-- csv_import.CANONICAL_COLUMNS already maps the header `description` onto it.
-- A second column would split one fact in two and halve element 3's coverage.
-- ===========================================================================
ALTER TABLE normalize.hardware_components

    -- ⚠ THIS COLUMN SHOULD ALREADY HAVE EXISTED, AND ITS ABSENCE IS ACTIVELY
    -- LOSING DATA. workers/hbom/model.py, services/project/internal/hbom
    -- .Component and frontend/src/lib/hbom.ts have all carried a quantity
    -- since Phase 15, and fixtures/hbom-nested/parts.csv has a populated
    -- `Qty` header — with nowhere to store it, store/hbom.go's read path
    -- hardcodes `&hbom.Component{Quantity: 1}`. A CSV that said 100 renders
    -- as 1 today, silently.
    --
    -- DEFAULT 1, not 0: a part present in an assembly with no stated count is
    -- one of them, and defaulting to zero would make every extended-cost
    -- roll-up understate every unquantified line.
    ADD COLUMN quantity            integer NOT NULL DEFAULT 1 CHECK (quantity >= 0),

    -- R1, C4, U2. ⚠ AN ARRAY, BECAUSE ONE LINE ITEM COVERS MANY PLACEMENTS.
    -- "R1, R4, R17" is one part with quantity 3, which is how every CAD and
    -- ERP export writes it. A scalar column would force either three rows for
    -- one part — inflating the component count in a compliance document — or
    -- silently keeping only the first designator.
    ADD COLUMN designators         text[] NOT NULL DEFAULT '{}',

    ADD COLUMN package_footprint   text,
    ADD COLUMN supplier_sku        text,
    ADD COLUMN preferred_supplier  text,

    -- ⚠ numeric, NEVER float, and SIX decimal places. A price is money and
    -- binary floating point cannot represent 0.10; over a 4000-line BOM the
    -- error accumulates into a figure somebody procures against. Six places
    -- because passive parts are genuinely quoted at fractions of a cent at
    -- reel volume (0.0018/unit is an ordinary price).
    ADD COLUMN unit_price          numeric(18,6) CHECK (unit_price IS NULL OR unit_price >= 0),

    -- ISO 4217, uppercase. ⚠ SHAPE, NOT MEMBERSHIP: the list gains and retires
    -- codes, and rejecting a real currency a customer actually paid in is
    -- worse than accepting an odd one.
    --
    -- ⚠ AND NO DEFAULT. A currency default is a fabricated fact about somebody
    -- else's money — guessing USD turns an unusable number into a wrong one.
    ADD COLUMN currency            text CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),

    -- ⚠ GENERATED, NOT STORED-AND-MAINTAINED. It can never disagree with its
    -- own inputs, there is exactly one implementation of the arithmetic, and
    -- it stays SUM-able and sortable in SQL. NULL when either input is NULL,
    -- which is correct: the extended price of an unknown unit price is not
    -- zero, and rendering it as zero would understate a total.
    --
    -- Writers must NOT list this column — Postgres rejects an explicit value
    -- for GENERATED ALWAYS.
    ADD COLUMN extended_price      numeric GENERATED ALWAYS AS (quantity * unit_price) STORED,

    -- DNI / DNP / NOFIT / "do not stuff". ⚠ SPELLED OUT RATHER THAN LEFT AS AN
    -- ACRONYM: a boolean named with an initialism is exactly what a future
    -- reader gets backwards, and backwards here means shipping a board with a
    -- part that should have been omitted.
    --
    -- DNP is NOT the same as absent. The part is on the schematic and
    -- deliberately not fitted for this variant; omitting the row instead of
    -- flagging it loses the difference between "this variant does not populate
    -- C14" and "nobody considered C14", and only the first is a decision.
    ADD COLUMN do_not_populate     boolean NOT NULL DEFAULT false,

    -- ⚠ A CLOSED SET, AND AN UNRECOGNISED VALUE IS DROPPED WITH A DIAGNOSTIC
    -- RATHER THAN COERCED — exactly what `criticality` already does two
    -- columns down (workers/hbom/model.py's normalize(): mapping "urgent"
    -- onto "critical" is a guess this product does not make).
    ADD COLUMN assembly_type       text CHECK (assembly_type IS NULL OR
                                    assembly_type IN ('smt','tht','mechanical')),

    -- ⚠ 'nrnd' IS NOT A SYNONYM FOR EITHER NEIGHBOUR. Not Recommended for New
    -- Designs means buyable today, refused at the next respin. Collapsing it
    -- into 'active' or 'obsolete' destroys the one status that prompts a
    -- redesign before the part actually goes away.
    --
    -- ⚠ 'unknown' IS STORABLE AND SCORES ZERO FOR COMPLETENESS.
    -- axebom_shared.normalize.coverage.NON_SUBSTANTIVE contains "unknown", so
    -- a parts database that answered "unknown" is REPORTED and does not count
    -- as covered — invariant 3 applied to the field where a distributor most
    -- often answers exactly that way.
    ADD COLUMN lifecycle_status    text CHECK (lifecycle_status IS NULL OR
                                    lifecycle_status IN ('active','nrnd','obsolete',
                                                         'eol','preview','unknown')),

    -- providers/base.py's Enrichment has carried `datasheet_url` and
    -- `lifecycle` since Phase 15 and providers.apply() discards both, because
    -- there was nowhere to put them.
    ADD COLUMN datasheet_url       text,

    -- ⚠ ALSO MODELLED IN BOTH LANGUAGES WITH NO COLUMN. attribute name ->
    -- provider name, per providers/base.py's apply(). Without it every
    -- enrichment loses its attribution on write, and a datasheet's claim about
    -- a manufacturer becomes indistinguishable from a serial number somebody
    -- read off the device. Those are different kinds of fact and rendering
    -- them identically overstates one of them.
    ADD COLUMN enriched_fields     jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- ⚠ A SECOND field_status, NOT A NAMESPACED KEY INSIDE THE FIRST.
    -- field_status records which CERT-In elements held a substantive value
    -- (bulk._field_status's contract). Nesting a non-CERT-In block inside it
    -- would make every reader parse a discriminator to find out whether a key
    -- is a compliance fact. Two columns, zero ambiguity.
    ADD COLUMN manufacturing_field_status jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Which engine produced this node — hbom-ecad, hbom-cdxgen-host, or NULL
    -- for a row entered through the REST import or the form.
    ADD COLUMN source_engine       text;

-- Partial: the whole point of the index is finding the parts that need action.
CREATE INDEX hardware_lifecycle_idx ON normalize.hardware_components (lifecycle_status)
    WHERE lifecycle_status IN ('nrnd','obsolete','eol');

-- ---------------------------------------------------------------------------
-- ⚠ THE SELF-FK BECOMES DEFERRABLE, AND THIS IS NOT A STYLE CHANGE.
--
-- The Go store inserts one tree node at a time, parents first, so a per-row
-- check has always been satisfiable there. The Python bulk path is different:
-- writer.py chunks every batch at _CHUNK_SIZE = 500 rows per INSERT, and a
-- non-deferrable FK is validated at the end of EACH statement. A 700-node
-- assembly whose parent lands in chunk 2 while its child lands in chunk 1
-- fails — and it fails only above 500 nodes, which is exactly the input size
-- nobody writes a test for. Deferring the check to COMMIT removes the class.
--
-- bulk.py still emits parents before children, because a deferred FK buffers
-- every row's check until commit and that costs memory on a large tree.
-- Ordering is the fast path; this constraint is the correctness floor.
-- ---------------------------------------------------------------------------
ALTER TABLE normalize.hardware_components
    DROP CONSTRAINT hardware_components_parent_id_fkey;
ALTER TABLE normalize.hardware_components
    ADD CONSTRAINT hardware_components_parent_id_fkey
    FOREIGN KEY (parent_id) REFERENCES normalize.hardware_components (id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

-- ===========================================================================
-- hardware_component_alternates — approved second-source parts.
--
-- ⚠ THE SUPPLY-CHAIN RISK FIELD. A single-sourced part with no recorded
-- alternate is the line item that stops a production run, and "we know of a
-- second source" lives in an engineer's head until something records it.
--
-- ⚠ A TABLE, NOT A jsonb ARRAY, and one reason decides it: the query this
-- feature exists to answer is "which boards have a second source for this
-- obsolete part", which needs a b-tree index on the ALTERNATE's MPN. A jsonb
-- array is reachable only through a GIN containment query against a
-- hand-written path, and any rule joining alternates back to the primary
-- parts table would have to unnest it on every read. normalize.ai_datasets is
-- the standing precedent for this exact shape: a 1:N child of a normalize
-- entity, own tenant_id, own RLS policy, cascade delete.
-- ===========================================================================
CREATE TABLE normalize.hardware_component_alternates (
    id                     uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id              uuid NOT NULL,
    hardware_component_id  uuid NOT NULL
                           REFERENCES normalize.hardware_components (id) ON DELETE CASCADE,

    -- The customer's own preference order, preserved. Re-sorting somebody's
    -- approved-vendor list would change which part actually gets bought.
    ordinal                integer NOT NULL DEFAULT 0 CHECK (ordinal >= 0),

    manufacturer_name      text,
    model_number           text,
    supplier_info          text,
    supplier_sku           text,
    lifecycle_status       text CHECK (lifecycle_status IS NULL OR
                           lifecycle_status IN ('active','nrnd','obsolete',
                                                'eol','preview','unknown')),

    -- ⚠ DEFAULTS TO 'unverified', NOT 'drop-in'. Asserting that a part is a
    -- drop-in replacement is a substitution decision made about somebody's
    -- hardware; defaulting to the flattering value would make AxeBOM the
    -- author of a claim it never checked.
    equivalence            text NOT NULL DEFAULT 'unverified'
                           CHECK (equivalence IN ('drop-in','functional','unverified')),

    -- "Approved by EE 2026-03, pin-compatible, tighter tolerance." An
    -- alternate nobody signed off on is a suggestion, not an alternate.
    approval_note          text,

    created_at             timestamptz NOT NULL DEFAULT now(),

    -- An alternate that names nothing is not an alternate.
    CONSTRAINT hardware_alternate_identifiable
        CHECK (model_number IS NOT NULL OR manufacturer_name IS NOT NULL
               OR supplier_sku IS NOT NULL)
);

CREATE INDEX hardware_alt_component_idx
    ON normalize.hardware_component_alternates (hardware_component_id);
CREATE INDEX hardware_alt_tenant_idx
    ON normalize.hardware_component_alternates (tenant_id);
CREATE INDEX hardware_alt_mpn_idx
    ON normalize.hardware_component_alternates (model_number)
    WHERE model_number IS NOT NULL;

-- CLAUDE.md invariant 6: a tenant-scoped table without a policy in the SAME
-- migration is incomplete, and TestRLSCoverage enumerates the live catalog
-- and fails on any table without one.
SELECT app.enable_tenant_rls('normalize.hardware_component_alternates');

-- ⚠ EXPLICIT, EVEN THOUGH 0006's ALTER DEFAULT PRIVILEGES SHOULD COVER IT.
-- Default privileges are recorded PER GRANTOR and apply only to tables
-- created by the same role that ran 0006. That holds under goose today and is
-- invisible if it ever stops holding — the failure mode is `permission denied
-- for table` on the first live HBOM normalization, at whatever hour that is.
-- One idempotent line removes the assumption.
GRANT SELECT, INSERT ON normalize.hardware_component_alternates
    TO axebom_normalize_writer;

-- +goose Down
DROP TABLE IF EXISTS normalize.hardware_component_alternates;

ALTER TABLE normalize.hardware_components
    DROP CONSTRAINT IF EXISTS hardware_components_parent_id_fkey;
ALTER TABLE normalize.hardware_components
    ADD CONSTRAINT hardware_components_parent_id_fkey
    FOREIGN KEY (parent_id) REFERENCES normalize.hardware_components (id) ON DELETE CASCADE;

DROP INDEX IF EXISTS normalize.hardware_lifecycle_idx;

ALTER TABLE normalize.hardware_components
    DROP COLUMN IF EXISTS source_engine,
    DROP COLUMN IF EXISTS manufacturing_field_status,
    DROP COLUMN IF EXISTS enriched_fields,
    DROP COLUMN IF EXISTS datasheet_url,
    DROP COLUMN IF EXISTS lifecycle_status,
    DROP COLUMN IF EXISTS assembly_type,
    DROP COLUMN IF EXISTS do_not_populate,
    DROP COLUMN IF EXISTS extended_price,
    DROP COLUMN IF EXISTS currency,
    DROP COLUMN IF EXISTS unit_price,
    DROP COLUMN IF EXISTS preferred_supplier,
    DROP COLUMN IF EXISTS supplier_sku,
    DROP COLUMN IF EXISTS package_footprint,
    DROP COLUMN IF EXISTS designators,
    DROP COLUMN IF EXISTS quantity;
