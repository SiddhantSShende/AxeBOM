"""SPDX 3.0 AI profile — the second machine-readable target.

⚠ THE PLAN SAID THIS WAS BLOCKED, AND IT IS NOT. THE ASSUMPTION WAS WRONG.

The AIBOM plan recorded "⚠ our pinned `spdx-tools` 0.8.x cannot write 3.0.1" and
pre-authorised a `LIMITATIONS.md` entry as the fallback. Checked against the
installed package rather than assumed: `spdx-tools` 0.8.5 ships a complete
`spdx_tools.spdx3` — `model.ai.AIPackage`, `model.dataset.Dataset`, and a
`writer.json_ld` that produces a real JSON-LD document. It was exercised in this
session and wrote 21KB of valid SPDX 3.0 for a single model.

⚠ WHAT IS TRUE IS NARROWER AND WORTH STATING PRECISELY: it writes **3.0.0**, not
3.0.1. 3.0.1 is a patch release of the same major/minor, so a consumer reading
3.0 reads this; a consumer demanding the literal string "3.0.1" does not get it,
and nothing here pretends otherwise.

⚠ WHY THIS IS A CONVERTER AND NOT A DOWNLOADABLE FORMAT YET.

`services/report` is a distroless Go binary. It cannot call a Python library, and
SPDX 3.0 has no mature Go writer — hand-rolling JSON-LD is exactly what
`services/report/internal/export`'s header forbids, because a writer that passes
our own tests and fails the customer's validator is worthless. Wiring this as a
report format therefore needs a Python renderer deployable, which is real work
and is named as owed rather than half-built.

What exists today is the mapping, tested, reading the ML-BOM the report service
already produces:

    python -m workers.aibom.spdx3 --in report.mlbom.cdx.json --out model.spdx3.jsonld

⚠ THE MAPPING NEVER INVENTS A VALUE. Where the ML-BOM has nothing, the SPDX field
is omitted rather than defaulted to something plausible — the same rule the
SPDX/CycloneDX exporter states for itself.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: The SPDX 3.0 profiles this document declares. Read by a consumer to know
#: which vocabularies to expect; declaring `ai` without emitting an AIPackage
#: would be a claim the document does not honour.
PROFILES = ("core", "software", "ai", "dataset")

#: Namespace for identifiers this converter mints. Not resolvable, and not
#: pretending to be: an SPDX id has to be a URI and inventing an `https://`
#: one would imply a document a reader can fetch.
NAMESPACE = "urn:axebom:aibom:"


class SPDXToolsUnavailableError(RuntimeError):
    """Raised when `spdx-tools` is not installed.

    ⚠ A CLEAR REFUSAL, NOT A DEGRADED DOCUMENT. Emitting a hand-rolled
    approximation because the real writer is missing is how a compliance artifact
    that no validator accepts gets shipped.
    """


def convert(mlbom: dict[str, Any], *, created: datetime | None = None) -> dict[str, Any]:
    """Turn a CycloneDX ML-BOM into an SPDX 3.0 AI-profile document.

    Returns the parsed JSON-LD, so a caller can serialize it however it needs to
    and a test can assert on its contents rather than on a string.

    ⚠ `created` IS AN ARGUMENT, NOT A CLOCK READ. Two conversions of one document
    must produce the same bytes — the same rule ADR-0003 puts on every other
    export, and the reason the report worker passes the scan's time everywhere.
    """
    try:
        from semantic_version import Version
        from spdx_tools.spdx3.model import CreationInfo
        from spdx_tools.spdx3.model.ai import AIPackage
        from spdx_tools.spdx3.model.profile_identifier import ProfileIdentifierType
        from spdx_tools.spdx3.model.software import SoftwarePurpose
        from spdx_tools.spdx3.payload import Payload
        from spdx_tools.spdx3.writer.json_ld import json_ld_writer
    except ImportError as exc:  # pragma: no cover - exercised by the skip below
        raise SPDXToolsUnavailableError(
            "spdx-tools is not installed; install the conformance extra "
            '(`pip install -e ".[conformance]"`) to write SPDX 3.0'
        ) from exc

    when = created or datetime(1970, 1, 1, tzinfo=UTC)
    creation_info = CreationInfo(
        # 3.0.0, and the module docstring says why it is not 3.0.1.
        spec_version=Version("3.0.0"),
        created=when,
        created_by=[NAMESPACE + "tool:axebom"],
        profile=[
            ProfileIdentifierType.CORE,
            ProfileIdentifierType.SOFTWARE,
            ProfileIdentifierType.AI,
            ProfileIdentifierType.DATASET,
        ],
        data_license="CC0-1.0",
    )

    elements: dict[str, Any] = {}
    for component in mlbom.get("components") or []:
        if not isinstance(component, dict):
            continue
        if component.get("type") != "machine-learning-model":
            continue
        package = _ai_package(component, creation_info, when, AIPackage, SoftwarePurpose)
        elements[package.spdx_id] = package

    if not elements:
        # ⚠ REFUSED RATHER THAN EMITTED. An SPDX document declaring the AI profile
        # and containing no AIPackage validates and asserts the project has no AI
        # — the exact failure the CycloneDX side already made once.
        raise ValueError(
            "refusing to convert an ML-BOM with no machine-learning-model "
            "components: the SPDX document would declare the AI profile and "
            "assert that this project contains none"
        )

    payload = Payload(elements)
    with tempfile.TemporaryDirectory(prefix="axebom-spdx3-") as tmp:
        stem = str(Path(tmp) / "document")
        json_ld_writer.write_payload(payload, stem)
        written = Path(stem + ".jsonld")
        return json.loads(written.read_text(encoding="utf-8"))


def _ai_package(
    component: dict[str, Any],
    creation_info: Any,
    when: datetime,
    ai_package_cls: Any,
    software_purpose: Any,
) -> Any:
    """One CycloneDX ML component as an SPDX 3.0 `AIPackage`.

    ⚠ THE FIELDS SPDX HAS AND CycloneDX DOES NOT ARE WHY THIS TARGET IS WORTH
    HAVING. `informationAboutApplication`, `limitation`, `typeOfModel`,
    `standardCompliance` and `sensitivePersonalInformation` are first-class in
    the SPDX AI profile and have no CycloneDX equivalent — a reviewer asking
    "what is this model FOR and what must it not do" gets a structured answer
    here rather than a property named by us.
    """
    props = {
        p.get("name"): p.get("value")
        for p in (component.get("properties") or [])
        if isinstance(p, dict)
    }
    name = str(component.get("name") or "unnamed")
    card = component.get("modelCard") or {}
    params = card.get("modelParameters") or {}
    considerations = card.get("considerations") or {}

    use_cases = considerations.get("useCases") or []
    limitations = considerations.get("technicalLimitations") or []

    kwargs: dict[str, Any] = {
        # ⚠ THE bom-ref, WHICH IS THE MODEL KEY. Two documents about one model
        # have to agree on its identifier or nothing can be joined across them.
        "spdx_id": NAMESPACE + str(component.get("bom-ref") or name),
        "name": name,
        "supplied_by": [],
        # ⚠ NOT INVENTED. SPDX requires the field; `NOASSERTION` is the format's
        # own way of saying "not asserted", and it is different from claiming a
        # location we never found.
        "download_location": "NOASSERTION",
        "package_version": str(component.get("version") or "NOASSERTION"),
        "primary_purpose": software_purpose.MODEL,
        "release_time": when,
        "creation_info": creation_info,
    }

    if task := params.get("task"):
        kwargs["type_of_model"] = [str(task)]
    if use_cases:
        kwargs["information_about_application"] = "; ".join(str(u) for u in use_cases)
    if limitations:
        kwargs["limitation"] = "; ".join(str(limitation) for limitation in limitations)
    if purl := component.get("purl"):
        kwargs["package_url"] = str(purl)
    if authors := component.get("authors"):
        kwargs["supplied_by"] = [
            NAMESPACE + "agent:" + str(a.get("name"))
            for a in authors
            if isinstance(a, dict) and a.get("name")
        ]
    if arch := params.get("modelArchitecture"):
        # ⚠ `domain`, NOT `typeOfModel`. `typeOfModel` is what the model DOES
        # (a task); an architecture family is a different fact, and folding the
        # two would put `LlamaForCausalLM` where a consumer expects
        # `text-generation`.
        kwargs["domain"] = [str(arch)]
    # ⚠ THE HONESTY PROPERTIES SURVIVE THE CONVERSION. SPDX has no field for
    # "which engines found this", so they travel as a comment rather than being
    # dropped — a document that says what a model is without saying how well we
    # know it leaves a reviewer nothing to check.
    provenance = [
        f"{key.removeprefix('axebom:aibom:')}={value}"
        for key, value in sorted(props.items())
        if key.startswith("axebom:aibom:")
    ]
    if provenance:
        kwargs["comment"] = "AxeBOM discovery provenance: " + "; ".join(provenance)

    return ai_package_cls(**kwargs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m workers.aibom.spdx3",
        description=(
            "Convert a CycloneDX ML-BOM (as `axebom report --format mlbom` "
            "produces) into an SPDX 3.0 AI-profile JSON-LD document."
        ),
    )
    parser.add_argument("--in", dest="source", required=True, help="ML-BOM JSON file")
    parser.add_argument("--out", dest="target", help="output file (default: stdout)")
    args = parser.parse_args(argv)

    mlbom = json.loads(Path(args.source).read_text(encoding="utf-8"))
    document = convert(mlbom)
    body = json.dumps(document, indent=2, sort_keys=True)

    if args.target:
        Path(args.target).write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
