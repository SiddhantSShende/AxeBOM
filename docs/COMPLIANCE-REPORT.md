# CERT-In coverage evidence

Profile `certin-v2.0` revision 1, generated from `docs/reference/certin-v2.0.yaml`.

| | |
|---|---|
| Source | docs/reference/CERT-In_BOM_Guidelines_v2.0.pdf |
| Authority | Indian Computer Emergency Response Team (CERT-In), MeitY, Government of India |
| Published | 2025-07-09 |
| Every entry verified against the PDF | true |


## How to read this

**Two coverage numbers, always.** Every generated report publishes
`completeness_pct` (substantive values only — the honest signal) and
`declaration_pct` (any value, including an explicit `not-provided`).
A value of `not-provided` is *reported* but scores zero for completeness,
because omitting a field hides a gap while declaring it states one.

**Weights are AxeBOM's judgement, not CERT-In's.** The guideline assigns no
weights. They exist so a single percentage can be produced; the per-element
table below is the unweighted evidence, and it is the part to check.

**"How obtained" is a claim about this product, not about the guideline.**
`user-supplied` means only you can answer — a judgement about your own
system that a tool guessing would get wrong while reporting a higher number for
having guessed. `imported` means structured entry; for hardware it is the
only form, because no tool discovers physical parts.

**What this document does not say.** It does not assert that any project is
compliant. AxeBOM reports violations against a configured policy; compliance
is a determination an auditor makes about an organisation.


## SBOM — 21 elements

Source: CERT-In Table 5 (data fields)

| How obtained | Elements |
|---|---|
| automated | 14 |
| derived | 4 |
| user-supplied | 3 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 1 | Component Name | p.22 | verified | automated | `component.name` |
| 2 | Component Version | p.22 | verified | automated | `component.version_raw` |
| 3 | Component Description | p.23 | verified | automated | `component.description` |
| 4 | Component Supplier | p.23 | verified | automated | `component.supplier` |
| 5 | Component License | p.23 | verified | automated | `component.license_effective` |
| 6 | Component Origin | p.23 | verified | automated | `component.origin` |
| 7 | Component Dependencies | p.23 | verified | automated | `component.dependencies[]` |
| 8 | Vulnerabilities | p.23 | verified | automated | `component.findings[]` |
| 9 | Patch Status | p.23 | verified | derived | `component.patch_status` |
| 10 | Release Date | p.23 | verified | automated | `component.release_date` |
| 11 | End-of-Life (EOL) Date | p.23 | verified | automated | `component.eol_date` |
| 12 | Criticality | p.23 | verified | user-supplied | `component.criticality` |
| 13 | Usage Restrictions | p.23 | verified | user-supplied | `component.usage_restrictions` |
| 14 | Checksums or Hashes | p.23 | verified | automated | `component.hashes[]` |
| 15 | Comments or Notes | p.23 | verified | user-supplied | `component.comments` |
| 16 | Author of SBOM Data | p.23 | verified | derived | `component.author_of_sbom_data` |
| 17 | Timestamp | p.23 | verified | derived | `bom_document.generated_at` |
| 18 | Executable Property | p.24 | verified | automated | `component.executable_property` |
| 19 | Archive Property | p.24 | verified | automated | `component.archive_property` |
| 20 | Structured Property | p.24 | verified | automated | `component.structured_property` |
| 21 | Unique Identifier | p.24 | verified | derived | `component.certin_identifier` |

## QBOM — 11 elements

Source: CERT-In Table 8

| How obtained | Elements |
|---|---|
| derived | 3 |
| user-supplied | 8 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Model Name | p.44 | verified | user-supplied | `quantum_component.model_name` |
| 0 | Version | p.44 | verified | user-supplied | `quantum_component.version` |
| 0 | Vendor & Origin Information | p.44 | verified | user-supplied | `quantum_component.vendor_origin` |
| 0 | License Information | p.44 | verified | user-supplied | `quantum_component.license_info` |
| 0 | Cryptographic Asset | p.44 | verified | derived | `quantum_component.crypto_assets[]` |
| 0 | Communication Protocol | p.45 | verified | user-supplied | `quantum_component.communication_protocol` |
| 0 | Hardware | p.45 | verified | user-supplied | `quantum_component.hardware` |
| 0 | Software Dependencies | p.45 | verified | derived | `quantum_component.software_dependencies` |
| 0 | Environmental Impact | p.45 | verified | user-supplied | `quantum_component.environmental_impact` |
| 0 | Vulnerabilities | p.45 | verified | derived | `quantum_component.findings[]` |
| 0 | Attestations | p.45 | verified | user-supplied | `quantum_component.attestation_signature` |

## AIBOM — 19 elements

Source: CERT-In Table 10

| How obtained | Elements |
|---|---|
| automated | 14 |
| user-supplied | 5 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Model Name | p.54 | verified | automated | `ai_model.model_name` |
| 0 | Model Version | p.54 | verified | automated | `ai_model.model_version` |
| 0 | Model Type | p.54 | verified | automated | `ai_model.model_type` |
| 0 | Model Developer | p.54 | verified | automated | `ai_model.model_developer` |
| 0 | Model Licensing Information | p.54 | verified | automated | `ai_model.licensing` |
| 0 | Software Dependencies | p.54 | verified | automated | `ai_model.software_dependencies[]` |
| 0 | ML Models and Algorithms | p.54 | verified | automated | `ai_model.ml_models_algorithms[]` |
| 0 | Model Performance Metrics | p.54 | verified | automated | `ai_model.performance_metrics` |
| 0 | Data Source | p.54 | verified | automated | `ai_model.data_source` |
| 0 | Data Sets | p.55 | verified | automated | `ai_model.data_sets[]` |
| 0 | Hardware | p.55 | verified | automated | `ai_model.hardware` |
| 0 | Security Requirements | p.55 | verified | user-supplied | `ai_model.security_requirements` |
| 0 | Input | p.55 | verified | automated | `ai_model.input` |
| 0 | Output | p.55 | verified | automated | `ai_model.output` |
| 0 | Intended Usage | p.55 | verified | user-supplied | `ai_model.intended_usage` |
| 0 | Out of Scope Usage | p.55 | verified | user-supplied | `ai_model.out_of_scope_usage` |
| 0 | Environmental Impact | p.55 | verified | user-supplied | `ai_model.environmental_impact` |
| 0 | Vulnerabilities | p.55 | verified | automated | `ai_model.findings[]` |
| 0 | Attestations | p.55 | verified | user-supplied | `ai_model.attestation_signature` |

## HBOM — 24 elements

Source: Table 11: Minimum Elements of HBOM plus §10.4.1.4

| How obtained | Elements |
|---|---|
| imported | 19 |
| user-supplied | 4 |
| not-implemented | 1 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Product Name | p.60 | verified | imported | `hardware_component.product_name` |
| 0 | Product Version | p.60 | verified | imported | `hardware_component.product_version` |
| 0 | Product Details | p.60 | verified | imported | `hardware_component.product_details` |
| 0 | Warranty/AMC | p.60 | verified | user-supplied | `hardware_component.warranty_amc` |
| 0 | Manufacturer Name | p.60 | verified | imported | `hardware_component.manufacturer_name` |
| 0 | Manufacturer Location | p.60 | verified | imported | `hardware_component.manufacturer_location` |
| 0 | Manufacturing Date | p.60 | verified | imported | `hardware_component.manufacturing_date` |
| 0 | Supplier Information | p.61 | verified | imported | `hardware_component.supplier_info` |
| 0 | Supplier Location | p.61 | verified | imported | `hardware_component.supplier_location` |
| 0 | Model Number | p.61 | verified | imported | `hardware_component.model_number` |
| 0 | Serial Number | p.61 | verified | imported | `hardware_component.serial_number` |
| 0 | Technical Specification | p.61 | verified | imported | `hardware_component.technical_specification` |
| 0 | Supplier Information (component) | p.61 | verified | imported | `hardware_component.component_supplier_info` |
| 0 | Supplier Location (component) | p.61 | verified | imported | `hardware_component.component_supplier_location` |
| 0 | Technology Node | p.61 | verified | imported | `hardware_component.technology_node` |
| 0 | Compliance | p.61 | verified | imported | `hardware_component.compliance[]` |
| 0 | Power supply | p.61 | verified | imported | `hardware_component.power_supply` |
| 0 | License Information | p.61 | verified | user-supplied | `hardware_component.license_info` |
| 0 | Test Result | p.61 | verified | user-supplied | `hardware_component.test_result` |
| 0 | Sub-component | p.61 | verified | imported | `hardware_component.children[]` |
| 0 | Firmware Version | p.62 | verified | imported | `hardware_component.firmware_version` |
| 0 | Origin | p.62 | verified | imported | `hardware_component.origin` |
| 0 | Criticality Rating | p.62 | verified | user-supplied | `hardware_component.criticality` |
| 0 | Vulnerabilities | p.62 | verified | not-implemented | `hardware_component.findings[]` |

## CBOM/algorithm — 8 elements

Source: Table 9: Minimum Elements pertaining to Cryptographic Asset (algorithm)

| How obtained | Elements |
|---|---|
| automated | 5 |
| derived | 3 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Name | p.45 | verified | automated | `crypto_asset.name` |
| 0 | Asset Type | p.45 | verified | automated | `crypto_asset.asset_type` |
| 0 | Primitive | p.45 | verified | derived | `crypto_asset.primitive` |
| 0 | Mode | p.45 | verified | automated | `crypto_asset.mode` |
| 0 | Crypto Functions | p.46 | verified | derived | `crypto_asset.crypto_functions[]` |
| 0 | Classical security level | p.46 | verified | derived | `crypto_asset.classical_security_level` |
| 0 | OID | p.46 | verified | automated | `crypto_asset.oid` |
| 0 | List | p.46 | verified | automated | `crypto_asset.algorithm_list[]` |

## CBOM/certificate — 10 elements

Source: Table 9: Minimum Elements pertaining to Cryptographic Asset (certificate)

| How obtained | Elements |
|---|---|
| automated | 10 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Name | p.47 | verified | automated | `crypto_asset.name` |
| 0 | Asset Type | p.47 | verified | automated | `crypto_asset.asset_type` |
| 0 | Subject Name | p.47 | verified | automated | `crypto_asset.cert_subject` |
| 0 | Issuer Name | p.47 | verified | automated | `crypto_asset.cert_issuer` |
| 0 | Not Valid Before | p.47 | verified | automated | `crypto_asset.not_valid_before` |
| 0 | Not Valid After | p.47 | verified | automated | `crypto_asset.not_valid_after` |
| 0 | Signature Algorithm Reference | p.47 | verified | automated | `crypto_asset.signature_algo_ref` |
| 0 | Subject Public Key Reference | p.47 | verified | automated | `crypto_asset.subject_public_key_ref` |
| 0 | Certificate Format | p.47 | verified | automated | `crypto_asset.cert_format` |
| 0 | Certificate Extension | p.48 | verified | automated | `crypto_asset.cert_extension` |

## CBOM/key — 7 elements

Source: Table 9: Minimum Elements pertaining to Cryptographic Asset (key)

| How obtained | Elements |
|---|---|
| automated | 4 |
| not-implemented | 3 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Name | p.46 | verified | automated | `crypto_asset.name` |
| 0 | Asset Type | p.46 | verified | automated | `crypto_asset.asset_type` |
| 0 | id | p.46 | verified | automated | `crypto_asset.key_id` |
| 0 | state | p.46 | verified | not-implemented | `crypto_asset.key_state` |
| 0 | size | p.46 | verified | automated | `crypto_asset.key_size` |
| 0 | Creation Date | p.46 | verified | not-implemented | `crypto_asset.creation_date` |
| 0 | Activation Date | p.46 | verified | not-implemented | `crypto_asset.activation_date` |

## CBOM/protocol — 5 elements

Source: Table 9: Minimum Elements pertaining to Cryptographic Asset (protocol)

| How obtained | Elements |
|---|---|
| automated | 5 |

| # | Element | Page | Status | How obtained | Canonical path |
|---|---|---|---|---|---|
| 0 | Name | p.46 | verified | automated | `crypto_asset.name` |
| 0 | Asset Type | p.47 | verified | automated | `crypto_asset.asset_type` |
| 0 | Version | p.47 | verified | automated | `crypto_asset.protocol_version` |
| 0 | Cipher Suites | p.47 | verified | automated | `crypto_asset.cipher_suites[]` |
| 0 | OID | p.47 | verified | automated | `crypto_asset.oid` |


## Engine coverage

Every generated report carries a mandatory Engine Coverage section listing each
requested engine, its terminal status, the ecosystems it covered, and any
ecosystem detected with **no available engine**.

⚠ That last line is the one to read. An SBOM that silently omits an ecosystem is
worse than no SBOM, because it converts an unknown into a false negative the
reader trusts. `partial` is a first-class status here, not an error.
