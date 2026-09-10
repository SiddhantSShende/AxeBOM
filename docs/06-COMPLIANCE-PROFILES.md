# 06 — Compliance Profiles

How AxeBOM represents a compliance standard as **data** rather than code, and why that choice is load-bearing.

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

The formula is printed in every report, so the number is auditable rather than magic. And the report footer states that **the weights are AxeBOM's judgement, not CERT-In's** — the guideline does not rank its fields.

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

---

## 11. Operational profiles — scored, but never compliance

A profile can also describe a field set **AxeBOM** defined, rather than one a standard requires. There are two:

- `reference/hbom-manufacturing-v1.yaml` — reference designators, footprints, quantities, supplier SKUs, alternates, prices, DNP flags, assembly type and lifecycle status. *How buildable and buyable is this parts list.*
- `reference/aibom-operational-v1.yaml` — resolved model identity and its confidence, which engines found it, file:line evidence, upstream verification, the AI frameworks it rests on, and the prompts / vector stores / RAG pipelines / agents / inference services around it, plus the operator's own EU AI Act, NIST AI RMF and ISO/IEC 42001 declarations and any recorded attestation result. *How much of this AI system's operational shape did we manage to see.*

> **The AIBOM one exists because CERT-In Table 10 describes a MODEL and an AI system is more than its model.** Three engines report prompts, vector stores, RAG pipelines and inference endpoints with file:line evidence, and Table 10 has no element for any of them. Before this profile the choice was between dropping those findings and inventing a CERT-In element for them; this is the third answer.
>
> ⚠ **Every element in it is something that can actually be filled today.** A field nothing can answer scores zero for every customer for ever, which does not measure the customer — it measures us, and reads on the report as the customer's gap. One element (`embeddings`) was removed after a live scan reported 0 for a repository that *has* an embedding model: `airom` correctly types it as a MODEL, so it was already scored by the identity elements and the separate element could only ever read zero. The profile's own closing comment names what else was deliberately left out, and why.

These are scored — that is the whole point of them — but into their **own number, under their own label**, never into `completeness_pct` or `declaration_pct`.

> **Why they cannot simply live in `certin-v2.0.yaml`.** That file already has `axebom_extensions:` blocks, and those are *defined* by `scored: false` — they ride alongside the standard and must never be scored at all. Manufacturing fields **are** scored. Putting scored non-CERT-In fields inside the compliance profile would make `scored` mean two different things in one document, and `certin-v2.0.yaml` is the file invariant 2 names as the single source of truth for what CERT-In requires. It stays clean.

### The three things that make the separation structural

**1. `profile.kind`.** `operational` marks it; an absent `kind` means `compliance`. The default is the safe direction — a new profile that forgets to declare itself is held to every compliance check rather than quietly escaping them.

**2. A distinct top-level key.** The fields live under `hbom_manufacturing:` / `aibom_operational:`, never a second `hbom:` or `aibom:`. Every CERT-In accessor in `libs/go-shared/compliance` reads the named sections — `FieldsForBOMType`, the guardrail's field counts, the evidence pack's HBOM section, and the code generator that produces `HBOM_FIELDS`. A different key means not one of them can return an AxeBOM field by accident. `TestOperationalFieldsNeverReachACertInAccessor` asserts that against both files, and it is mutation-verified: widening `FieldsForBOMType("HBOM")` to include the manufacturing set makes it fail by name.

**3. Inverted and added lint rules**, all gated on `Meta.IsCompliance()`:

| Rule | Compliance profile | Operational profile |
|---|---|---|
| A `status: extension` field | must set `scored: false` | **may be scored** — that is what it is for |
| `source_page` on a field | must be within the source document | **refused** — there is no document, so a page number implies a citation nobody can check |
| `all_entries_verified` | must match the `assumed` count | **refused** — a provenance claim with nothing behind it |
| Defining `sbom:`/`hbom:`/`crypto_asset:` | expected | **refused** — those blocks are read as a standard by every accessor in the package |

### Where the number goes

Both land in `normalize.bom_documents.supplementary_coverage`, keyed by profile id, each carrying its own `label` and an `is_compliance` flag — so a consumer never has to know which profile ids are standards; the flag is checkable, a naming convention is not.

> ⚠ **They were computed and stored for a whole phase with no reader.** The HBOM manufacturing score has been written to that column since migration `0011` and appeared in no report, no export and no screen. A number a customer cannot see is a number that does not exist — the same class of loss invariant 12 names for engine gaps, one layer up. Both now render on the report's Summary sheet and in the JSON export, each under its own label and beside a sentence naming AxeBOM as the authority: a percentage on a compliance document is read as a compliance percentage unless something says otherwise, so rendering the number without that sentence would be worse than omitting it.

### What deliberately does *not* change

- **`FieldsForBOMType` is untouched.** That one function feeds `HBOM_FIELDS` → `workers/hbom/normalize.py`'s `_SCORED` → `completeness_pct`. Leaving it alone *is* the separation.
- **`axebom profile gen` takes a different path for an operational profile, not no path.** It used to refuse one outright, for two reasons. The first still holds: `GenerateGo` emits package-level `ProfileID`/`ProfileRevision`/`ProfileAllVerified` and the `ProfileField` type, so a second profile through it is four duplicate declarations and a compile error — which is why `GenerateGoOperational` writes a **separate file per set** (`generated_operational_<set>.go`) carrying only the field list and its own id constants. ⚠ It writes one file **per set**, and it used to write one file full stop — correct while exactly one operational profile existed, and a silent overwrite the moment a second was generated. `axebom profile gen` likewise used to name `hbom_manufacturing` as a literal, so the second profile generated nothing and reported success; it now derives the sets from the profile (`OperationalSetNames`), because a field set that is authored, linted and scored but has no generated Go consumer is invisible in every screen and every report — exactly the failure the generator exists to prevent, and exactly what happened to `hbom_manufacturing` before it was generated. The second reason — "nothing in Go needs the list, Python reads it at runtime" — was true when written and went stale: `hbom.ComponentFormFields` builds the hardware component form from the **generated** `model.HBOMFields`, and `compliance.Load` reads from disk, which no service container has a copy of. So the manufacturing elements were authored, linted, scored and reported while being invisible in the one screen where a person could enter them.
- ⚠ **The generator emits each field's closed `values` list, and it used not to.**
  The profile has always carried `values:` — criticality's `[critical, high,
  medium, low]` is transcribed verbatim from p.23 — but `ProfileField` had no
  member for it in either language, so every consumer that needed an enum wrote
  its own copy. Four grew for criticality alone: `hbom.Criticalities` (the
  device form), `hbom.CriticalityValues` (the component validator), a sentence
  inside a validation error, and `workers/hbom/model.py`'s
  `CRITICALITY_VALUES`. **Two of them had already drifted**: the device form
  carried a fifth value, `unknown`, beneath a comment reading "⚠ IT MUST MATCH
  normalize.hardware_components.criticality" — a table whose CHECK allows four.
  A device recorded as `unknown` was storable and unrepresentable in the parts
  table its tree flows into. All four now read the profile, and
  `migrations/project/0006` brings the column with them.
- **`TestGoAndPythonEnumValuesAgree` holds the two languages together.** The
  existing agreement tests compare ids and counts, so the moment values became
  load-bearing the two could disagree about what an enum ACCEPTS with every test
  green — one language rejecting a value the other stores, on one document.
  The operational profile generates Go only, so Python's `ASSEMBLY_TYPES` and
  `LIFECYCLE_VALUES` stay literals held to the YAML by a test instead: a worker
  container has no copy of `docs/`, and a runtime file dependency would trade a
  drift risk for a harder failure.

- ⚠ **The generated operational fields must never merge into a CERT-In list.** They are emitted as `HBOMManufacturingFields`, never appended to `HBOMFields`, and every consumer opts in by naming them. The form marks each input `certin: true|false` and renders the two sets as separate groups, because a customer filling in unit prices must not watch a compliance percentage rise.
- **`docs/COMPLIANCE-REPORT.md` is unchanged.** `BuildEvidencePack` never sees an operational profile. Adding non-CERT-In rows to a document titled "CERT-In coverage evidence" is the category error this design exists to prevent.
- **`task profile:lint` runs over both files**, by the same checker. A second field set that nothing validates is a second field set that drifts.

### Storage

The score lands in `normalize.bom_documents.supplementary_coverage`, a JSONB keyed by profile id, carrying the profile's own `label` and an `is_compliance: false` flag alongside the numbers — so a renderer can never mislabel it and no consumer has to know which profile ids are standards. A keyed JSONB rather than two more `numeric` columns: the *set* of profiles is data too, which is invariant 2's reasoning one level up.
