"""What every AI discovery engine has in common, and what it does not.

⚠ THREE ENGINES, THREE DIALECTS OF ONE FORMAT. ai-bom, airom and cdxgen all emit
CycloneDX with `machine-learning-model` components, and all three put the things
that matter — the model's real identifier, its provider, where it was seen — in
DIFFERENT places:

    engine      model id                       provider              evidence
    ---------   ----------------------------   -------------------   ------------------------------
    ai-bom      prop `trusera:model_name`      `trusera:provider`    prop `trusera:source_location`
    airom       prop `airom:model.id`, but     `airom:model.provider` `evidence.occurrences[]`
                the TRUE CASING is only in                            with a real `line`
                `evidence.identity[].concludedValue`
    cdxgen      the purl (`pkg:huggingface/…`) `cdx:ai:provider`     `evidence.occurrences[]`,
                                                                     location as `path#Lline`

All measured against real captured output in `testdata/`, not read off a README.

So the per-engine part is a small MAPPING and the judgement is shared. This module
holds the judgement: what counts as a model reference, whether a purl is real,
whether a component the engine called a model actually is one. Getting that wrong
once put a Python library in a Table 10 inventory three times over; it is not
something to reimplement per adapter.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def looks_like_model_reference(value: str) -> bool:
    """Is this string shaped like a model identifier, rather than a display name?

    ⚠ THE `org/name` SHAPE IS THE WHOLE TEST, AND IT HAS TO BE, because a "model
    name" field is a name in some tools and an id in others.
    `meta-llama/Llama-3-8B` is a reference; `HuggingFace Transformers Model` is a
    label somebody typed. A label sent to enrichment either resolves to nothing
    or — worse — resolves to a DIFFERENT model whose licence we would then
    attribute to the customer's.
    """
    if not value or "/" not in value:
        return False
    if any(c.isspace() for c in value):
        return False
    org, _, name = value.partition("/")
    return bool(org and name)


#: Package-URL types that name a SOFTWARE PACKAGE, never a model.
#:
#: `pkg:huggingface` is deliberately absent: that one does name a model.
PACKAGE_PURL_TYPES = frozenset(
    {
        "pypi",
        "npm",
        "maven",
        "golang",
        "cargo",
        "gem",
        "nuget",
        "composer",
        "deb",
        "rpm",
        "apk",
        "conan",
        "cran",
        "hex",
        "pub",
        "swift",
        "generic",
    }
)


def package_purl_type(purl: str) -> str:
    """The package ecosystem a purl names, or empty when it names none."""
    if not purl.startswith("pkg:"):
        return ""
    ptype = purl.removeprefix("pkg:").partition("/")[0].strip().lower()
    return ptype if ptype in PACKAGE_PURL_TYPES else ""


def valid_purl(value: str) -> bool:
    """Is this a syntactically usable Package URL?

    ⚠ ai-bom EMITS PURLS CONTAINING LITERAL SPACES — `pkg:pypi/huggingface transformers`
    is verbatim from captured output. A purl is the merge key for everything
    downstream (CLAUDE.md invariant 4), so accepting one no other engine could
    produce creates a component that can never match, never dedup, and never link
    to its SBOM entry — while looking exactly like a real identifier in a report.
    """
    if not value.startswith("pkg:"):
        return False
    if any(c.isspace() for c in value):
        return False
    remainder = value.removeprefix("pkg:")
    ptype, sep, rest = remainder.partition("/")
    return bool(ptype and sep and rest.split("@", 1)[0].split("?", 1)[0])


def huggingface_ref_from_purl(purl: str) -> str:
    """The `org/name` a `pkg:huggingface/...` purl carries, or empty."""
    if not purl.startswith("pkg:huggingface/"):
        return ""
    rest = purl.removeprefix("pkg:huggingface/").split("?", 1)[0]
    return rest.split("@", 1)[0]


# ---------------------------------------------------------------------------
# Asset kinds — everything an AI scan finds that is NOT a model
# ---------------------------------------------------------------------------

ASSET_PROMPT = "prompt"
ASSET_VECTOR_STORE = "vector_store"
ASSET_RAG_PIPELINE = "rag_pipeline"
ASSET_EMBEDDING = "embedding"
ASSET_AGENT = "agent"
ASSET_TOOL = "tool"
ASSET_MCP_SERVER = "mcp_server"
ASSET_ENDPOINT = "endpoint"
ASSET_DATASET = "dataset"

#: The closed set `normalize.ai_assets.asset_type` accepts. Mirrors the CHECK in
#: migrations/normalize/0018 — a value not here is refused by the database.
ASSET_TYPES = (
    ASSET_PROMPT,
    ASSET_VECTOR_STORE,
    ASSET_RAG_PIPELINE,
    ASSET_EMBEDDING,
    ASSET_AGENT,
    ASSET_TOOL,
    ASSET_MCP_SERVER,
    ASSET_ENDPOINT,
    ASSET_DATASET,
)


def properties(raw: dict[str, Any]) -> dict[str, str]:
    """Flatten CycloneDX `properties` into a dict.

    Names are lowercased and any vendor prefix is dropped, so `trusera:provider`,
    `airom:model.provider` and `cdx:ai:provider` all reduce to a comparable tail.
    Reading one spelling would silently lose the field on the other two engines.
    """
    out: dict[str, str] = {}
    props = raw.get("properties")
    if not isinstance(props, list):
        return out
    for p in props:
        if not isinstance(p, dict):
            continue
        name = text(p.get("name")).lower()
        if not name:
            continue
        out[name.rsplit(":", 1)[-1]] = text(p.get("value"))
        # Also keep the full name minus the vendor prefix, so a dotted tail like
        # `airom:model.provider` is reachable as `model.provider` and not only as
        # the ambiguous `provider`.
        if ":" in name:
            out.setdefault(name.split(":", 1)[1], text(p.get("value")))
    return out


def counts(found: dict[str, Any]) -> dict[str, int]:
    """Per-KIND counts of what one engine discovered, for the live event feed.

    ⚠ THE FOUR SUMMARY DIMENSIONS ARE THE WRONG GRAIN FOR SOMEBODY WATCHING A
    SCAN. `summary._DIMENSION_OF` folds models, dependencies and every asset
    kind into `components`, deliberately — that is the figure a reader compares
    BETWEEN engines. "airom: 11 components" tells a person watching the progress
    bar nothing; "2 prompts, 1 vector store, 1 RAG pipeline" tells them exactly
    what was found.

    ⚠ A KIND WITH NO FINDINGS IS ABSENT, NOT ZERO. A zero would claim the engine
    looked for prompts and found none, which is a different statement from an
    engine that does not look for prompts at all — and both are true of some
    engine in this family.

    ⚠ THE KEYS ARE A CLOSED VOCABULARY, and they have to be: these reach a
    browser on the advisory event stream, so `events.SanitizeDiscoveries` drops
    anything that is not a plain lowercase identifier. A key built from a
    filename would put a path into the stream through the one field nobody
    thought to check.
    """
    out: dict[str, int] = {}
    if models := len(found.get("models") or []):
        out["ai_models"] = models
    if frameworks := len(found.get("frameworks") or []):
        out["ai_dependencies"] = frameworks
    for asset in found.get("assets") or []:
        kind = text(asset.get("asset_type"))
        if kind in ASSET_TYPES:
            out["ai_asset." + kind] = out.get("ai_asset." + kind, 0) + 1
    return out


def text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


#: Where every sandboxed engine sees the customer's source tree.
#:
#: ⚠ NOT A GUESS AND NOT PER-ENGINE. `axebom_shared.sandbox.WorkspaceLayout
#: .container_source` is `/src` for every engine, because the sandbox mounts the
#: tree there. It is a constant of OUR runner, not of any tool.
_CONTAINER_SOURCE_PREFIX = "/src/"


def repo_path(location: str) -> str:
    """One evidence path, relative to the repository root.

    ⚠ THE ENGINES DISAGREE ABOUT WHETHER TO ECHO THE MOUNT POINT, AND ONE MODEL
    ENDED UP WITH BOTH SPELLINGS. Measured on one real tree: ai-bom reports
    `/src/app.py:13` and airom reports `src/app.py:17` for the same file — so a
    model found by both carried evidence that looks like two different files and
    reads, to anyone who does not know the mount, like a path outside the
    repository.

    Stripping the mount here rather than in each adapter means one rule, applied
    once, that a fourth engine cannot forget.
    """
    location = text(location)
    if location.startswith(_CONTAINER_SOURCE_PREFIX):
        return location[len(_CONTAINER_SOURCE_PREFIX) :]
    return location


def occurrence_locations(raw: dict[str, Any]) -> list[str]:
    """`evidence.occurrences[]`, rendered as `path:line` where a line is given.

    ⚠ NORMALIZED TO ONE SHAPE, BECAUSE THE ENGINES DISAGREE. airom emits
    `{"location": "src/app.py", "line": 9}`; cdxgen emits
    `{"location": "src/app.py#L12"}`. Storing both spellings would make one
    model's evidence look like two.
    """
    evidence = raw.get("evidence")
    if not isinstance(evidence, dict):
        return []
    occurrences = evidence.get("occurrences")
    if not isinstance(occurrences, list):
        return []

    out: list[str] = []
    for o in occurrences:
        if not isinstance(o, dict):
            continue
        location = text(o.get("location"))
        if not location:
            continue
        if "#L" in location:
            path, _, line = location.partition("#L")
            location = f"{path}:{line}" if line.isdigit() else path
        elif isinstance(o.get("line"), int):
            location = f"{location}:{o['line']}"
        out.append(repo_path(location))
    return sorted(set(out))


def concluded_identity(raw: dict[str, Any], field: str = "name") -> str:
    """`evidence.identity[].concludedValue` for one field.

    ⚠ THIS IS WHERE airom KEEPS THE TRUE CASING. Its component `name` and
    `airom:model.id` are lowercased (`meta-llama/llama-3-8b`), but Hugging Face
    repository ids are case-sensitive — the real repo is `meta-llama/Llama-3-8B`,
    which is what its own identity evidence concludes. Using the lowercased form
    would key the same model differently from ai-bom and cdxgen, storing one
    model as two, and would send enrichment a reference the Hub does not resolve.
    """
    evidence = raw.get("evidence")
    if not isinstance(evidence, dict):
        return ""
    identity = evidence.get("identity")
    if isinstance(identity, dict):
        identity = [identity]
    if not isinstance(identity, list):
        return ""
    for entry in identity:
        if isinstance(entry, dict) and text(entry.get("field")) == field:
            concluded = text(entry.get("concludedValue"))
            if concluded:
                return concluded
    return ""
