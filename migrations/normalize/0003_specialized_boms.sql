-- +goose Up
-- ===========================================================================
-- normalize (3/4) — crypto, quantum, AI and hardware inventories.
-- Implements docs/01-DATA-MODEL.md §6.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- crypto_assets — CERT-In Table 9 (PDF p.45-48).
--
-- ⚠ THIS TABLE IS TYPE-DISCRIMINATED.
--
-- Four asset types with DIFFERENT field sets. Storage is one wide table, but
-- COVERAGE MUST BE SCORED AGAINST THE FIELD SET FOR THE ROW'S asset_type:
--   algorithm    8 fields
--   key          7 fields
--   protocol     5 fields
--   certificate 10 fields
--
-- Scoring a certificate against key_size would report every CBOM at roughly
-- 30% coverage — falsely, in a document shown to a regulator. The coverage
-- checker branches on asset_type. This is a correctness requirement, not an
-- optimization.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.crypto_assets (
    id                        uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id                 uuid NOT NULL,
    bom_document_id           uuid NOT NULL REFERENCES normalize.bom_documents (id) ON DELETE CASCADE,
    -- Optional link to the software component that implements or uses it.
    component_key             text,

    asset_type                text NOT NULL
                              CHECK (asset_type IN ('algorithm','key','protocol','certificate')),
    name                      text NOT NULL,

    -- ---- algorithm ----
    primitive                 text,
    mode                      text,
    crypto_functions          text[],
    classical_security_level  int,
    algorithm_list            text[],

    -- ---- key ----
    key_id                    text,
    key_state                 text CHECK (key_state IS NULL OR
                                          key_state IN ('active','revoked','expired','unknown')),
    key_size                  int,
    creation_date             date,
    activation_date           date,

    -- ---- protocol ----
    protocol_version          text,
    cipher_suites             text[],

    -- ---- shared by algorithm and protocol ----
    oid                       text,

    -- ---- certificate ----
    cert_subject              text,
    cert_issuer               text,
    not_valid_before          timestamptz,
    not_valid_after           timestamptz,
    signature_algo_ref        text,
    subject_public_key_ref    text,
    cert_format               text,
    cert_extension            text,

    -- ---- AxeBOM analysis: NOT CERT-In fields, EXCLUDED from coverage ----
    -- True for Shor-vulnerable primitives: RSA, ECC/ECDSA/ECDH, DH, DSA.
    -- Symmetric primitives get a Grover note on effective key strength, not a
    -- vulnerability flag — halving effective strength is a sizing concern, and
    -- flagging AES-256 as quantum-vulnerable would simply be wrong.
    quantum_vulnerable        boolean NOT NULL DEFAULT false,
    pqc_recommendation        text,
    deprecation_status        text CHECK (deprecation_status IS NULL OR
                                          deprecation_status IN ('current','deprecated','weak','broken')),

    field_status              jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at                timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX crypto_assets_doc_idx     ON normalize.crypto_assets (bom_document_id, asset_type);
CREATE INDEX crypto_assets_tenant_idx  ON normalize.crypto_assets (tenant_id);
CREATE INDEX crypto_assets_quantum_idx ON normalize.crypto_assets (bom_document_id)
    WHERE quantum_vulnerable = true;
CREATE INDEX crypto_assets_weak_idx    ON normalize.crypto_assets (bom_document_id, deprecation_status)
    WHERE deprecation_status IN ('weak','broken');

SELECT app.enable_tenant_rls('normalize.crypto_assets');

-- ---------------------------------------------------------------------------
-- quantum_components — CERT-In Table 8 (PDF p.44-45), 11 elements.
--
-- Populated by FORM/IMPORT, not discovery. No open-source tool discovers
-- quantum hardware. Crypto assets come from CBOM discovery with
-- quantum-vulnerability rules applied; only this device metadata is captured
-- separately. The UI must say so.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.quantum_components (
    id                      uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id               uuid NOT NULL,
    bom_document_id         uuid NOT NULL REFERENCES normalize.bom_documents (id) ON DELETE CASCADE,

    model_name              text NOT NULL,
    version                 text,
    vendor_origin           text,
    license_info            text,
    communication_protocol  text,
    hardware                text,
    software_dependencies   text[],
    environmental_impact    text,
    attestation_signature   text,

    field_status            jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX quantum_components_doc_idx    ON normalize.quantum_components (bom_document_id);
CREATE INDEX quantum_components_tenant_idx ON normalize.quantum_components (tenant_id);

SELECT app.enable_tenant_rls('normalize.quantum_components');

-- ---------------------------------------------------------------------------
-- ai_models — CERT-In Table 10 (PDF p.54-55), 19 elements.
--
-- Several elements (intended usage, out-of-scope usage, environmental impact,
-- security requirements) are rarely in tool output and will mostly be
-- `not-provided` or user-supplied. THAT IS THE CORRECT OUTCOME, visible in the
-- coverage number — not something to paper over with a guess.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.ai_models (
    id                     uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id              uuid NOT NULL,
    bom_document_id        uuid NOT NULL REFERENCES normalize.bom_documents (id) ON DELETE CASCADE,

    model_name             text NOT NULL,
    model_version          text,
    model_type             text,
    model_developer        text,
    licensing              text,
    ml_models_algorithms   text[],
    performance_metrics    jsonb NOT NULL DEFAULT '{}'::jsonb,
    data_source            text,
    hardware               text,
    security_requirements  text,
    input                  text,
    output                 text,
    intended_usage         text,
    out_of_scope_usage     text,
    environmental_impact   text,
    attestation_signature  text,

    -- AxeBOM extensions from Trusera ai-bom. NOT CERT-In fields; excluded
    -- from coverage scoring and labelled as extensions in reports.
    risk_score             numeric(5,2),
    owasp_llm_top10        text[],

    field_status           jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ai_models_doc_idx    ON normalize.ai_models (bom_document_id);
CREATE INDEX ai_models_tenant_idx ON normalize.ai_models (tenant_id);

SELECT app.enable_tenant_rls('normalize.ai_models');

CREATE TABLE normalize.ai_datasets (
    id           uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id    uuid NOT NULL,
    ai_model_id  uuid NOT NULL REFERENCES normalize.ai_models (id) ON DELETE CASCADE,
    name         text NOT NULL,
    version      text,
    format       text,
    limitations  text,
    license      text,
    source       text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ai_datasets_model_idx  ON normalize.ai_datasets (ai_model_id);
CREATE INDEX ai_datasets_tenant_idx ON normalize.ai_datasets (tenant_id);

SELECT app.enable_tenant_rls('normalize.ai_datasets');

-- Links an AI model to software components already in the SBOM — an AI
-- dependency is usually also a package.
CREATE TABLE normalize.ai_model_dependencies (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id      uuid NOT NULL,
    ai_model_id    uuid NOT NULL REFERENCES normalize.ai_models (id) ON DELETE CASCADE,
    component_key  text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),

    UNIQUE (ai_model_id, component_key)
);

CREATE INDEX ai_model_deps_tenant_idx ON normalize.ai_model_dependencies (tenant_id);

SELECT app.enable_tenant_rls('normalize.ai_model_dependencies');

-- ---------------------------------------------------------------------------
-- hardware_components — CERT-In Table 11 (PDF p.60-61) PLUS §10.4.1.4 (p.62).
--
-- TWO THINGS TABLE 11 ALONE WOULD GET WRONG:
--
-- 1. §10.4.1.4 mandates four fields that appear NOWHERE in Table 11:
--    firmware_version, origin, criticality, and vulnerabilities. A tool
--    implementing only Table 11 is not compliant.
--
-- 2. Table 11 lists "Supplier Information" and "Supplier Location" TWICE with
--    different descriptions — the PRODUCT's supplier, and the COMPONENT's
--    supplier to the manufacturer. Different relationships, distinct columns.
--
-- Recursive via parent_id, depth-capped by the application (default 10).
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.hardware_components (
    id                            uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id                     uuid NOT NULL,
    bom_document_id               uuid NOT NULL REFERENCES normalize.bom_documents (id) ON DELETE CASCADE,
    parent_id                     uuid REFERENCES normalize.hardware_components (id) ON DELETE CASCADE,

    product_name                  text NOT NULL,
    product_version               text,
    product_details               text,
    warranty_amc                  text,
    manufacturer_name             text,
    manufacturer_location         text,
    manufacturing_date            date,

    -- product-level supplier (Table 11, first occurrence)
    supplier_info                 text,
    supplier_location             text,

    model_number                  text,
    serial_number                 text,
    technical_specification       text,

    -- component-level supplier (Table 11, second occurrence)
    component_supplier_info       text,
    component_supplier_location   text,

    technology_node               text,
    compliance                    text[],
    power_supply                  text,
    license_info                  text,
    test_result                   text,

    -- ---- §10.4.1.4 additions, absent from Table 11 ----
    firmware_version              text,
    origin                        text,
    criticality                   text CHECK (criticality IS NULL OR
                                              criticality IN ('critical','high','medium','low')),

    field_status                  jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at                    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT hardware_not_own_parent CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE INDEX hardware_doc_idx    ON normalize.hardware_components (bom_document_id);
CREATE INDEX hardware_parent_idx ON normalize.hardware_components (parent_id);
CREATE INDEX hardware_tenant_idx ON normalize.hardware_components (tenant_id);
CREATE INDEX hardware_mpn_idx    ON normalize.hardware_components (model_number)
    WHERE model_number IS NOT NULL;

SELECT app.enable_tenant_rls('normalize.hardware_components');

-- +goose Down
DROP TABLE IF EXISTS normalize.hardware_components;
DROP TABLE IF EXISTS normalize.ai_model_dependencies;
DROP TABLE IF EXISTS normalize.ai_datasets;
DROP TABLE IF EXISTS normalize.ai_models;
DROP TABLE IF EXISTS normalize.quantum_components;
DROP TABLE IF EXISTS normalize.crypto_assets;
