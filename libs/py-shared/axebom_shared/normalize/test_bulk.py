"""Bulk insertion: caps that refuse rather than truncate, and NUL safety."""

from __future__ import annotations

import json

from .bulk import MAX_AI_MODELS, MAX_COMPONENTS, MAX_CRYPTO_ASSETS, _component_id, _text, plan


def model(components=None, findings=None, edges=None, crypto_assets=None, ai_models=None) -> dict:
    return {
        "components": components or [],
        "findings": findings or [],
        "graph": {"edges": edges or []},
        "crypto_assets": crypto_assets or [],
        "ai_models": ai_models or [],
    }


def component(key: str, **kwargs) -> dict:
    return {
        "component_key": key,
        "identity_rule": "purl",
        "identity_confidence": "high",
        "name": key.rsplit("/", 1)[-1],
        "version_raw": "1.0.0",
        "scope": "required",
        "observed_by": [{"engine": "syft"}],
        **kwargs,
    }


def crypto_asset(asset_type: str, **kwargs) -> dict:
    """A minimal but real canonical crypto asset — `component()`'s counterpart
    for `normalize.crypto_assets`. Shaped like what
    `workers/cbom/normalize/crypto.py`'s `normalize_crypto_asset` actually
    produces (`asset_type` and `name` always present, the three AxeBOM
    analysis fields always set by `analyse()`), so a test built from this
    exercises the real column shape rather than an idealized one.
    """
    return {
        "asset_type": asset_type,
        "name": kwargs.pop("name", f"{asset_type}-fixture"),
        "quantum_vulnerable": False,
        "deprecation_status": "current",
        "quantum_rationale": "fixture rationale",
        "deprecation_rationale": "fixture rationale",
        "deprecation_reference": "",
        **kwargs,
    }


def ai_model(identity: str, **kwargs) -> dict:
    """A minimal but real canonical AI model row — `crypto_asset()`'s
    counterpart for `normalize.ai_models`. Shaped like what `workers.aibom
    .normalize.pipeline.build_canonical_aibom` actually attaches to each row
    (`_identity`/`_datasets`/`_dependencies`, `field_status` always present),
    so a test built from this exercises the real shape rather than an
    idealized one.
    """
    return {
        "_identity": identity,
        "_datasets": kwargs.pop("datasets", []),
        "_dependencies": kwargs.pop("dependencies", []),
        "model_name": kwargs.pop("model_name", identity),
        "field_status": kwargs.pop("field_status", {}),
        **kwargs,
    }


def test_a_normal_scan_produces_batches_for_every_table() -> None:
    result = plan(
        model(
            components=[
                component("purl:pkg:npm/x@1", locations=[{"path": "a/b.js"}]),
                component("purl:pkg:npm/y@1"),
            ],
            findings=[
                {
                    "vuln_cluster_id": "c1",
                    "component_key": "purl:pkg:npm/x@1",
                    "display_id": "CVE-1",
                }
            ],
            # ⚠ REAL component_keys, not arbitrary strings. from_component_id
            # and to_component_id are foreign-key-shaped uuids resolved from
            # THIS SAME canonical model's components — an edge naming a key
            # nothing else in the scan produced is the dangling-reference case
            # covered separately below, not the ordinary path.
            edges=[{"from": "purl:pkg:npm/x@1", "to": "purl:pkg:npm/y@1"}],
            crypto_assets=[crypto_asset("algorithm", primitive="pke")],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert not result.refused
    assert len(result.batch("normalize.components")) == 2
    assert len(result.batch("normalize.component_locations")) == 1
    assert len(result.batch("normalize.findings")) == 1
    assert len(result.batch("normalize.component_dependencies")) == 1
    assert len(result.batch("normalize.crypto_assets")) == 1
    assert not result.diagnostics, "every reference in this fixture resolves; nothing to warn about"


def test_exceeding_the_component_cap_refuses_rather_than_truncating() -> None:
    """⚠ A TRUNCATED BOM IS THE WORST POSSIBLE ARTIFACT.

    It looks complete, it is smaller than the truth, and every component past
    the cut-off is a false negative the customer trusts.
    """
    too_many = [component(f"purl:pkg:npm/x{i}@1") for i in range(MAX_COMPONENTS + 1)]
    result = plan(model(components=too_many), tenant_id="t1", bom_document_id="b1")

    assert result.refused
    assert result.total_rows() == 0, "a refused plan must write nothing at all"
    assert any(d["code"] == "NORMALIZE_COMPONENT_CAP_EXCEEDED" for d in result.diagnostics)


def test_nul_bytes_never_reach_a_text_column() -> None:
    """⚠ A NUL SILENTLY TRUNCATES a Postgres text value.

    The row inserts, nothing errors, and the stored string is a prefix of the
    real one — so it must be cleaned before the write, not after.
    """
    assert "\x00" not in _text("evil\x00name")


def test_over_long_values_are_truncated_visibly() -> None:
    """A silently shortened value looks like a real, shorter value."""
    result = _text("x" * 20000)
    assert len(result) <= 8192
    assert "truncated" in result


def test_locations_are_one_to_many_against_a_single_component() -> None:
    """Identity is the package; the same jar at two paths is ONE component."""
    result = plan(
        model(
            components=[
                component(
                    "purl:pkg:maven/g/a@1",
                    locations=[{"path": "app/lib.jar"}, {"path": "vendor/lib.jar"}],
                )
            ]
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert len(result.batch("normalize.components")) == 1
    assert len(result.batch("normalize.component_locations")) == 2


def test_field_status_records_not_provided_explicitly() -> None:
    """Both coverage numbers derive from this, so it is stored rather than
    recomputed at render — a report must not disagree with itself."""
    result = plan(
        model(components=[component("purl:pkg:npm/x@1", license_effective="NOASSERTION")]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    row = result.batch("normalize.components").rows[0]
    status = json.loads(row[-1])
    assert status["name"] == "provided"
    assert status["license_effective"] == "not-provided", (
        "NOASSERTION declines to say, so it is not coverage"
    )


def test_the_pinned_display_id_is_what_gets_stored() -> None:
    result = plan(
        model(
            components=[component("k")],
            findings=[
                {"vuln_cluster_id": "c1", "component_key": "k", "display_id": "CVE-2021-44228"}
            ],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    row = result.batch("normalize.findings").rows[0]
    assert "CVE-2021-44228" in row


def test_severity_effective_is_null_not_an_empty_string_when_absent() -> None:
    """⚠ THE CHECK CONSTRAINT ONLY PERMITS NULL OR SIX ENUM VALUES.

    A finding with no resolved severity is the ORDINARY case — it is exactly
    what the NotProvided bucket on the Go side exists to count. Before this
    fix every one of them stored `""`, which satisfies neither NULL nor the
    enum, and would have failed the CHECK constraint and taken the whole
    batch down with it.
    """
    result = plan(
        model(
            components=[component("k")],
            findings=[{"vuln_cluster_id": "c1", "component_key": "k", "display_id": "CVE-1"}],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    row = result.batch("normalize.findings").rows[0]
    columns = result.batch("normalize.findings").columns
    assert row[columns.index("severity_effective")] is None


def test_a_finding_stores_the_components_surrogate_id_not_its_key() -> None:
    result = plan(
        model(
            components=[component("k")],
            findings=[{"vuln_cluster_id": "c1", "component_key": "k", "display_id": "CVE-1"}],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.findings").columns
    row = result.batch("normalize.findings").rows[0]
    assert columns[columns.index("component_id")] == "component_id"
    assert "component_key" not in columns, "the database column does not exist under that name"
    assert row[columns.index("component_id")] == _component_id("b1", "k")


def test_component_and_cluster_ids_are_deterministic() -> None:
    """Replayability (CLAUDE.md invariant 10) extends to surrogate keys.

    Re-normalizing the SAME raw artifacts into the SAME document must produce
    the SAME component and finding ids, not a fresh random set every run.
    """
    canonical = model(
        components=[component("k")],
        findings=[{"vuln_cluster_id": "c1", "component_key": "k", "display_id": "CVE-1"}],
    )
    first = plan(canonical, tenant_id="t1", bom_document_id="b1")
    second = plan(canonical, tenant_id="t1", bom_document_id="b1")

    assert first.batch("normalize.components").rows == second.batch("normalize.components").rows
    assert first.batch("normalize.findings").rows == second.batch("normalize.findings").rows

    # And a DIFFERENT document must NOT collide with this one — re-
    # normalization writes a new bom_document_id (ADR-0003), and the two
    # versions' rows must never be mistaken for each other.
    third = plan(canonical, tenant_id="t1", bom_document_id="b2")
    assert (
        first.batch("normalize.components").rows[0][0]
        != third.batch("normalize.components").rows[0][0]
    )


def test_a_finding_referencing_an_unknown_component_is_dropped_with_a_diagnostic() -> None:
    """The alternative to dropping it is a CHECK-violating NULL foreign key
    that fails the whole batch — one bad finding must not take every good one
    down with it, and dropping it silently would hide a real pipeline bug."""
    result = plan(
        model(
            components=[component("real-key")],
            findings=[
                {"vuln_cluster_id": "c1", "component_key": "real-key", "display_id": "CVE-1"},
                {"vuln_cluster_id": "c2", "component_key": "no-such-key", "display_id": "CVE-2"},
            ],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert len(result.batch("normalize.findings")) == 1, "only the resolvable finding is written"
    assert any(d["code"] == "NORMALIZE_DANGLING_COMPONENT_REFERENCE" for d in result.diagnostics), (
        "the dropped finding must be visible, not silent"
    )


def test_a_dependency_edge_referencing_an_unknown_component_is_dropped_with_a_diagnostic() -> None:
    result = plan(
        model(
            components=[component("a")],
            edges=[{"from": "a", "to": "does-not-exist"}],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert len(result.batch("normalize.component_dependencies")) == 0
    assert any(d["code"] == "NORMALIZE_DANGLING_COMPONENT_REFERENCE" for d in result.diagnostics)


def test_a_location_carries_its_tenant_id() -> None:
    """component_locations.tenant_id is NOT NULL; it was simply never in the
    column list, which is exactly the class of bug the schema-agreement test
    in test_writer.py exists to catch mechanically instead of by inspection."""
    result = plan(
        model(components=[component("k", locations=[{"path": "a.jar"}])]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.component_locations").columns
    row = result.batch("normalize.component_locations").rows[0]
    assert row[columns.index("tenant_id")] == "t1"


def test_a_batch_names_its_own_table_and_columns() -> None:
    """writer.py builds the actual INSERT statement — see test_writer.py's
    schema-agreement test — but the batch itself must at least carry enough
    to build one: its own table name and its own column list."""
    batch = plan(
        model(components=[component("purl:pkg:npm/x@1")]), tenant_id="t", bom_document_id="b"
    ).batch("normalize.components")
    assert batch.table == "normalize.components"
    assert "component_key" in batch.columns
    assert len(batch.rows) == 1


# ---------------------------------------------------------------------------
# crypto_assets — CLAUDE.md invariant 5: type-discriminated coverage
# ---------------------------------------------------------------------------


def test_a_certificate_and_a_key_populate_only_their_own_columns() -> None:
    """⚠ THE PHASE'S CORRECTNESS REQUIREMENT, AT THE WRITE-PLAN LEVEL.

    `workers/cbom/test_crypto_normalize.py` already proves `crypto.py` never
    puts a key's fields on a certificate's dict — this proves the write PLAN
    carries that through: a certificate's `key_size` column is `None`, not
    merely absent from a Python dict, and a key's `cert_subject` is `None` too.
    """
    result = plan(
        model(
            crypto_assets=[
                crypto_asset("certificate", cert_subject="CN=example.com"),
                crypto_asset("key", key_size=2048),
            ]
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.crypto_assets").columns
    rows = {
        row[columns.index("asset_type")]: row
        for row in result.batch("normalize.crypto_assets").rows
    }

    cert_row = rows["certificate"]
    assert cert_row[columns.index("cert_subject")] == "CN=example.com"
    assert cert_row[columns.index("key_size")] is None
    assert cert_row[columns.index("primitive")] is None

    key_row = rows["key"]
    assert key_row[columns.index("key_size")] == 2048
    assert key_row[columns.index("cert_subject")] is None


def test_exceeding_the_crypto_asset_cap_refuses_rather_than_truncating() -> None:
    """Same reasoning as the component cap: a truncated CBOM would look
    complete while silently missing every crypto asset past the cut-off."""
    too_many = [crypto_asset("algorithm") for _ in range(MAX_CRYPTO_ASSETS + 1)]
    result = plan(model(crypto_assets=too_many), tenant_id="t1", bom_document_id="b1")

    assert result.refused
    assert result.total_rows() == 0, "a refused plan must write nothing at all"
    assert any(d["code"] == "NORMALIZE_CRYPTO_ASSET_CAP_EXCEEDED" for d in result.diagnostics)


def test_the_crypto_assets_batch_exists_even_when_there_are_none() -> None:
    """`_locations_batch`/`_findings_batch`/`_dependencies_batch` all always
    produce a batch object regardless of emptiness — `_crypto_assets_batch`
    follows the same convention, so a caller can always find the table by
    name rather than handling a `None` for the ordinary "no crypto found"
    case (which cbomkit-theia's own adapter treats as `partial`, not an
    error)."""
    result = plan(model(), tenant_id="t1", bom_document_id="b1")
    batch = result.batch("normalize.crypto_assets")
    assert batch is not None
    assert batch.rows == []


def test_crypto_assets_have_no_component_id_dependency() -> None:
    """Unlike every other batch, crypto_assets needs no `component_ids` map at
    all — `component_key` is a plain text column, not a uuid foreign key
    (see `_crypto_assets_batch`'s own docstring). Proven by an asset that
    references a component_key absent from `components` writing successfully,
    with no `NORMALIZE_DANGLING_COMPONENT_REFERENCE` diagnostic — the
    treatment `_lookup_component_id` gives a real dangling reference
    elsewhere."""
    result = plan(
        model(crypto_assets=[crypto_asset("algorithm", component_key="no-such-component")]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert len(result.batch("normalize.crypto_assets")) == 1
    assert not any(
        d["code"] == "NORMALIZE_DANGLING_COMPONENT_REFERENCE" for d in result.diagnostics
    )


def test_crypto_field_status_marks_an_unknown_key_state_as_not_provided() -> None:
    """⚠ THE ONE CASE NULLNESS ALONE GETS WRONG.

    `key_state = 'unknown'` is a real, non-NULL value (cbomkit_theia maps a
    compromised or unrecognised state to it rather than defaulting to
    'active') but it is declared, not substantive
    (`coverage.NON_SUBSTANTIVE`) — a report inferring coverage from "is this
    column NULL" would count it as present. field_status is what makes the
    honest answer available without re-deriving it.
    """
    result = plan(
        model(crypto_assets=[crypto_asset("key", key_state="unknown", key_size=2048)]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.crypto_assets").columns
    row = result.batch("normalize.crypto_assets").rows[0]
    status = json.loads(row[columns.index("field_status")])

    assert status["key_state"] == "not-provided"
    assert status["key_size"] == "provided"


def test_crypto_field_status_only_covers_this_asset_s_own_type() -> None:
    """A certificate's field_status must not claim an opinion about
    `key_size` — that field is not in CERT-In's field set for a certificate
    at all (CLAUDE.md invariant 5), so it must not appear in the map."""
    result = plan(
        model(crypto_assets=[crypto_asset("certificate", cert_subject="CN=x")]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.crypto_assets").columns
    row = result.batch("normalize.crypto_assets").rows[0]
    status = json.loads(row[columns.index("field_status")])

    assert "key_size" not in status
    assert status["cert_subject"] == "provided"


def test_crypto_functions_travel_as_a_native_list_not_json() -> None:
    """`crypto_functions` is a Postgres `text[]` column — same "NATIVE LISTS,
    NOT json.dumps()" rule `_findings_batch`'s `detected_by` follows, and for
    the identical reason (a JSON array literal fails against an array-typed
    column)."""
    result = plan(
        model(
            crypto_assets=[
                crypto_asset("algorithm", crypto_functions=["encapsulate", "decapsulate"])
            ]
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.crypto_assets").columns
    row = result.batch("normalize.crypto_assets").rows[0]
    assert row[columns.index("crypto_functions")] == ["encapsulate", "decapsulate"]


def test_a_non_integer_key_size_becomes_null_not_a_stringified_value() -> None:
    """`_int_or_none` must reject anything that is not a real int — `_text()`
    would happily stringify a real int (satisfying no `int` column) or turn
    an absent one into `""` (satisfying no `int` column either); both fail
    the write against `key_size int`."""
    result = plan(
        model(crypto_assets=[crypto_asset("key", key_size="2048 bits")]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.crypto_assets").columns
    row = result.batch("normalize.crypto_assets").rows[0]
    assert row[columns.index("key_size")] is None


# ---------------------------------------------------------------------------
# AI models
# ---------------------------------------------------------------------------


def test_exceeding_the_ai_model_cap_refuses_rather_than_truncating() -> None:
    too_many = [ai_model(f"m/{i}") for i in range(MAX_AI_MODELS + 1)]
    result = plan(model(ai_models=too_many), tenant_id="t1", bom_document_id="b1")

    assert result.refused
    assert result.total_rows() == 0, "a refused plan must write nothing at all"
    assert any(d["code"] == "NORMALIZE_AI_MODEL_CAP_EXCEEDED" for d in result.diagnostics)


def test_the_ai_model_batches_exist_even_when_there_are_none() -> None:
    result = plan(model(), tenant_id="t1", bom_document_id="b1")
    for table in (
        "normalize.ai_models",
        "normalize.ai_datasets",
        "normalize.ai_model_dependencies",
    ):
        batch = result.batch(table)
        assert batch is not None, table
        assert batch.rows == []


def test_an_ai_model_id_is_minted_and_shared_with_its_children() -> None:
    """⚠ UNLIKE `_crypto_assets_batch`. An AI model's row IS referenced by two
    sibling tables in this same transaction, so — like a component — its id
    must be minted client-side and written explicitly, not left to the
    column's DEFAULT."""
    result = plan(
        model(
            ai_models=[
                ai_model(
                    "meta-llama/Llama-3-8B",
                    datasets=[{"name": "the-pile", "type": "text", "license": "MIT"}],
                    dependencies=["purl:pkg:pypi/langchain@0.3.7"],
                )
            ]
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )

    models_batch = result.batch("normalize.ai_models")
    assert len(models_batch) == 1
    model_id = models_batch.rows[0][models_batch.columns.index("id")]
    assert model_id, "an ai_models row must carry a real, non-empty id"

    datasets_batch = result.batch("normalize.ai_datasets")
    assert len(datasets_batch) == 1
    assert datasets_batch.rows[0][datasets_batch.columns.index("ai_model_id")] == model_id
    assert datasets_batch.rows[0][datasets_batch.columns.index("name")] == "the-pile"
    assert datasets_batch.rows[0][datasets_batch.columns.index("format")] == "text"

    deps_batch = result.batch("normalize.ai_model_dependencies")
    assert len(deps_batch) == 1
    assert deps_batch.rows[0][deps_batch.columns.index("ai_model_id")] == model_id
    assert deps_batch.rows[0][deps_batch.columns.index("component_key")] == (
        "purl:pkg:pypi/langchain@0.3.7"
    )


def test_the_same_ai_model_id_is_minted_on_replay() -> None:
    """CLAUDE.md invariant 10: re-normalizing the same raw artifacts at the
    same ruleset version must produce byte-identical output, including ids —
    a re-normalization pass over stored artifacts must not mint new
    `ai_models` ids for the same models every time it runs."""
    entities = [ai_model("meta-llama/Llama-3-8B")]

    first = plan(model(ai_models=entities), tenant_id="t1", bom_document_id="b1")
    second = plan(model(ai_models=entities), tenant_id="t1", bom_document_id="b1")

    first_id = first.batch("normalize.ai_models").rows[0][0]
    second_id = second.batch("normalize.ai_models").rows[0][0]
    assert first_id == second_id


def test_ai_model_dependencies_carry_no_foreign_key_to_components() -> None:
    """`component_key` is a plain text column — checked against the migration,
    not assumed. Proven by a dependency referencing a component_key from a
    wholly different (SBOM) bom_document_id writing successfully, with no
    dangling-reference diagnostic."""
    result = plan(
        model(ai_models=[ai_model("m/x", dependencies=["purl:pkg:pypi/no-such-package@1"])]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert len(result.batch("normalize.ai_model_dependencies")) == 1
    assert not any(
        d["code"] == "NORMALIZE_DANGLING_COMPONENT_REFERENCE" for d in result.diagnostics
    )


def test_ai_model_risk_score_and_owasp_top10_are_axebom_extensions() -> None:
    """These two columns are not CERT-In fields — `ml_models_algorithms`-style
    array handling still applies to `owasp_llm_top10` (a native list, not
    JSON), and `risk_score` reaches the column as a real number, never text."""
    result = plan(
        model(ai_models=[ai_model("m/x", risk_score=7.5, owasp_llm_top10=["LLM01", "LLM06"])]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.ai_models").columns
    row = result.batch("normalize.ai_models").rows[0]
    assert row[columns.index("risk_score")] == 7.5
    assert row[columns.index("owasp_llm_top10")] == ["LLM01", "LLM06"]


def test_an_ai_model_with_no_name_still_writes_not_null() -> None:
    """`model_name` is NOT NULL — `_text()` alone (never `_text() or None`)
    must run for it, the same convention `_crypto_assets_batch` uses for
    `name`/`asset_type`."""
    result = plan(
        model(ai_models=[ai_model("m/x", model_name=None)]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    columns = result.batch("normalize.ai_models").columns
    row = result.batch("normalize.ai_models").rows[0]
    assert row[columns.index("model_name")] == ""
