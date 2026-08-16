# 06 — Compliance Profiles

How EncoreBOM represents a compliance standard as **data** rather than code, and why that choice is load-bearing.

The profile itself is `reference/certin-v2.0.yaml`. This document explains the mechanism, not the fields.

---

## 1. The idea

A compliance standard is a list of required fields with definitions. Encoding that list in Go structs, report templates, UI copy and validator code means encoding it **four times** — and the four copies drift. When the standard revises, you hunt them down and miss one.

Instead: **one YAML file is the source of truth**, and four things generate from or validate against it.

```
                    reference/certin-v2.0.yaml
                              │
        ┌─────────────┬───────┴────────┬──────────────────┐
   Go structs    Python models    report field       coverage
   (generated)   (generated)      tables (runtime)   checker (runtime)
```

`task profile:gen` regenerates the first two. The last two **read the profile at runtime** and never hold a copy.

---

## 2. Never hardcode a count

> **Do not write `21`, or "the 21 data fields", in code, tests, UI copy, or documentation.** Render the count from the profile.

This is the rule the whole mechanism exists to enforce. A hardcoded count is how a product ships a false compliance claim: the guideline revises to 23 fields, the profile is updated, the schema is updated — and the UI still says "21 of 21 fields covered ✓" because nobody grepped for the literal.

The one place a count legitimately appears is `expected_counts` at the bottom of the profile, and those are **transcription assertions**, not application logic. If one fails, either the guideline was revised or the transcription is wrong. Both need a human decision, never a silent fix.

---

## 3. Entry shape

Every field carries enough to generate a struct, render a report row, map to both standards, score coverage, and cite its source.

```yaml
- id: certin.sbom.05.component_license      # stable forever; never renumber
  ordinal: 5
  name: Component License
  description: The license under which the software component is distributed…
  canonical_path: component.license_effective    # → 01-DATA-MODEL.md
  cyclonedx_path: components[].licenses
  spdx_path: packages[].licenseConcluded
  type: spdx_expression
  weight: 3
  required: true
  source_page: 23                                # citation into the PDF
  status: verified
  note: >
    declared / concluded / observed are stored separately…
```

| Key | Purpose |
|---|---|
| `id` | Stable identifier. Referenced by tests, diagnostics and report anchors. **Never renumber** — even if the guideline reorders its table. |
| `canonical_path` | Where the value lives in our model. The link to `01-DATA-MODEL.md`. |
| `cyclonedx_path` / `spdx_path` | Export mapping. Drives the exporters directly. |
| `weight` | Coverage weighting: 3 = minimum-element/identity, 1 = enrichment. |
| `source_page` | Page in the source PDF. This is what makes an audit conversation short. |
| `status` | `verified` or `assumed` — see below. |

---

## 4. `verified` vs `assumed`

| Status | Meaning |
|---|---|
| `verified` | Transcribed from the named page of a source document that has been read directly. |
| `assumed` | Inferred from a secondary source. **Must** carry a `note` explaining the inference. |

**Every entry in `certin-v2.0.yaml` is `verified`.** The 66-page PDF was read directly and Tables 5, 6, 8, 9, 10 and 11 extracted verbatim.

The `assumed` path exists for the case where work must start before a document is in hand. If any entry is `assumed`, `profile.all_entries_verified` becomes false and **every generated report says so**:

> Validated against profile `certin-v2.0` revision 3 — 118 of 134 fields verified against the source document.

An unverified assumption that is *visible* is a manageable risk. One that is invisible is how a compliance product lies.

---

## 5. Type-discriminated field sets

Some sections are not flat. CERT-In Table 9 defines four cryptographic asset types — Algorithms, Keys, Protocols, Certificates — with **different field sets**. The profile models this with a discriminator:

```yaml
crypto_asset:
  discriminator: crypto_asset.asset_type
  types:
    algorithms:   { asset_type_value: algorithm,   fields: [ … 8 … ] }
    keys:         { asset_type_value: key,         fields: [ … 7 … ] }
    protocols:    { asset_type_value: protocol,    fields: [ … 5 … ] }
    certificates: { asset_type_value: certificate, fields: [ … 10 … ] }
```

**The coverage checker branches on the discriminator.** Scoring a certificate against `key_size` would report every CBOM at roughly 30% coverage — falsely, in a document a customer shows a regulator. This is a correctness requirement, not an optimization.

---

## 6. Per-project settings, not just per-component fields

Not every minimum element is a component field. CERT-In Table 5 defines three categories, and only the first is per-component:

| `kind` | Category | Where it lives |
|---|---|---|
| `per_component_fields` | Data Fields | `normalize.components` |
| `enum_set` | Automation Support | `scan.standards[]` |
| `per_project_settings` | **Practices and Processes** | `project.practices` |

The third is the commonly-missed one. Its six sub-elements — Frequency, Depth, Known Unknowns, Distribution and Delivery, Access Control, Accommodation of Mistakes — are **product features captured at project registration**, not report sections. A tool that implements only the 21 data fields and claims CERT-In compliance is overstating.

---

## 7. Coverage

The profile supplies `required` and `weight`; `03-NORMALIZER-SPEC.md §5` owns the algorithm. The short version:

```
pct = 100 × Σ_c Σ_f (w_f × present(c,f)) / Σ_c Σ_f w_f
```

Two numbers, always both:

- **`completeness_pct`** — substantive values only. `not-provided`, `NOASSERTION`, `unknown`, `""`, `[]` all score 0. **The honest compliance signal.**
- **`declaration_pct`** — any value including explicit `not-provided`. A representation check, not compliance.

The formula is printed in every report, so the number is auditable rather than magic. And the report footer states that **the weights are EncoreBOM's judgement, not CERT-In's** — the guideline does not rank its fields.

---

## 8. Validation

`task profile:lint` asserts, and CI runs it as part of `task verify`:

1. YAML parses.
2. Every `expected_counts` entry matches reality.
3. Field ids are globally unique.
4. SBOM ordinals are contiguous 1..N.
5. Every `canonical_path` resolves against the generated model.
6. Every entry has `status` and, if `assumed`, a `note`.
7. Every `source_page` is within the document's page count.

Current state: **134 unique field ids, all 17 counts matching, zero `assumed` entries.**

---

## 9. Adding another standard

The mechanism is not CERT-In-specific. NTIA Minimum Elements, EU CRA, or an internal policy each become a sibling file — `reference/ntia-minimum.yaml`, `reference/eu-cra-v1.yaml` — with the same entry shape.

A scan may then be scored against several profiles at once, and a report can render a per-profile coverage table. Nothing in the normalizer or the exporters needs to know which standard it is scoring; they read whichever profile the report requests.

**Do not fork the schema per standard.** If a new standard needs a field the entry shape cannot express, extend the shape and migrate the existing profile — one shape, many profiles.

---

## 10. Revising a profile

When CERT-In publishes v2.1:

1. Place the new PDF in `reference/`.
2. Copy the profile to `certin-v2.1.yaml`, bump `revision`, and diff the tables against the new document.
3. Mark changed entries `assumed` until each is checked against a page, then `verified`.
4. Update `expected_counts`; `task profile:lint` will fail loudly until they match.
5. **Re-normalize** stored raw artifacts into a new `normalization_version`.

Step 5 is the payoff of the replayable-normalization design (ADR-0003): a standards revision is a **data change plus a re-normalization pass**, not a re-scan of every customer project. Historical reports keep their original profile revision recorded, so a report issued under v2.0 remains explainable after v2.1 ships.
