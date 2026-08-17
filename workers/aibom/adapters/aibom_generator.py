"""aibom-generator (OWASP) — model enrichment.

⚠ THIS RUNS OUTSIDE THE SCAN SANDBOX, AND THAT IS THE WHOLE POINT.

It resolves a Hugging Face model id into a model card: licence, developer,
architecture, metrics, datasets. That is a NETWORK CALL, and every scan engine
runs `--network=none` by design — we execute third-party binaries over untrusted
user code, so egress is not something to grant for convenience.

The split that makes this safe:

    discovery    in the sandbox, no network, reads the customer's code
    enrichment   outside the sandbox, network, reads PUBLIC model ids only

⚠ NO USER CODE REACHES THIS STEP. The only thing that crosses the boundary is a
model identifier the discovery engine already found — `meta-llama/Llama-3-8B`,
not a line of the customer's source. That is what makes an outbound call
acceptable here and unacceptable one step earlier.

⚠ A NETWORK FAILURE DEGRADES TO `partial`, NEVER TO A FAILED SCAN. Hugging Face
being unreachable must not discard the discovery results, which are the half a
customer cannot get anywhere else.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

#: How long a cached model card stays fresh.
#:
#: ⚠ THE SAME BASE MODEL APPEARS ACROSS MANY PROJECTS, and a model card changes
#: rarely. Re-fetching `meta-llama/Llama-3-8B` for every scan in an organisation
#: is a self-inflicted rate limit — and Hugging Face rate-limits anonymously.
CACHE_TTL_SECONDS = 24 * 3600


@dataclass(frozen=True)
class ModelCard:
    """What enrichment knows about a model. Model facts only."""

    model_ref: str
    #: The revision the card describes. Part of the cache key: a model at a new
    #: revision is a different set of facts.
    revision: str = ""
    name: str = ""
    developer: str = ""
    license: str = ""
    model_type: str = ""
    architectures: list[str] = field(default_factory=list)
    datasets: list[dict[str, str]] = field(default_factory=list)
    performance_metrics: dict[str, Any] = field(default_factory=dict)
    input_modality: str = ""
    output_modality: str = ""
    #: The source's own completeness figure, kept as evidence rather than mixed
    #: into our coverage number — it scores a different thing against different
    #: rules.
    source_completeness: float | None = None


class Fetcher(Protocol):
    """Fetches one model card. Injected so tests need no network."""

    def __call__(self, model_ref: str, revision: str) -> dict[str, Any]: ...


@dataclass
class CacheEntry:
    card: ModelCard
    fetched_at: float


class ModelCache:
    """An in-process cache keyed by (model_ref, revision).

    ⚠ KEYED ON THE REVISION TOO, NOT JUST THE ID. A model id is a moving target:
    `meta-llama/Llama-3-8B` at two revisions can carry two different licences,
    and serving the older card for the newer revision would attribute the wrong
    licence in a compliance document.

    An empty revision is its own key — "whatever is current" is a legitimate
    request and a legitimately separate answer.
    """

    def __init__(
        self, *, ttl: float = CACHE_TTL_SECONDS, clock: Callable[[], float] = time.monotonic
    ):
        self._entries: dict[tuple[str, str], CacheEntry] = {}
        self._ttl = ttl
        self._clock = clock
        self.hits = 0
        self.misses = 0

    def get(self, model_ref: str, revision: str) -> ModelCard | None:
        entry = self._entries.get((model_ref, revision))
        if entry is None:
            self.misses += 1
            return None
        if self._clock() - entry.fetched_at > self._ttl:
            # Expired. Removed rather than served stale: a licence that changed
            # is exactly the fact a reviewer is reading this for.
            del self._entries[(model_ref, revision)]
            self.misses += 1
            return None
        self.hits += 1
        return entry.card

    def put(self, model_ref: str, revision: str, card: ModelCard) -> None:
        """Store under the REQUESTED key, not the one the response carries.

        ⚠ THE WRITE KEY AND THE READ KEY MUST BE THE SAME, AND THEY WERE NOT.

        This first stored under `(card.model_ref, card.revision)`. A lookup for
        `("meta-llama/Llama-3-8B", "")` — "whatever is current" — fetched a card
        whose revision resolved to `"main"`, stored it under `(..., "main")`,
        and then missed on the next identical lookup.

        The cache never hit. Nothing failed: every scan simply re-fetched every
        model, which in production is a self-inflicted rate limit against an API
        that throttles anonymously, discovered as intermittent enrichment
        failures rather than as a cache bug.
        """
        self._entries[(model_ref, revision)] = CacheEntry(card, self._clock())

    def __len__(self) -> int:
        return len(self._entries)


@dataclass
class EnrichmentResult:
    """What enrichment produced, and what it could not."""

    cards: dict[str, ModelCard] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    #: True when at least one lookup failed. The caller degrades to `partial`.
    degraded: bool = False
    cache_hits: int = 0
    cache_misses: int = 0


def enrich_models(
    model_refs: list[str],
    *,
    fetch: Fetcher,
    cache: ModelCache | None = None,
    revisions: dict[str, str] | None = None,
) -> EnrichmentResult:
    """Enrich every referenced model, surviving the ones that fail.

    ⚠ ONE FAILED LOOKUP DOES NOT FAIL THE OTHERS, AND NONE OF THEM FAILS THE
    SCAN. Discovery already produced the half of an AIBOM a customer cannot get
    elsewhere; discarding it because a public API was slow would be trading
    everything for nothing.
    """
    # ⚠ `is None`, NOT `or`. ModelCache defines __len__, so an EMPTY cache is
    # FALSY — and `cache or ModelCache()` therefore threw the caller's cache
    # away on every call and built a fresh one.
    #
    # The effect was that caching never worked at all: the caller's cache stayed
    # empty, stayed falsy, and was discarded again next time. Nothing failed and
    # no test would have noticed without counting fetches; in production it is a
    # self-inflicted rate limit against an API that throttles anonymously,
    # surfacing as intermittent enrichment failures rather than as a cache bug.
    if cache is None:
        cache = ModelCache()
    out = EnrichmentResult()
    revisions = revisions or {}

    for ref in dict.fromkeys(r for r in model_refs if r):
        revision = revisions.get(ref, "")

        cached = cache.get(ref, revision)
        if cached is not None:
            out.cards[ref] = cached
            continue

        try:
            raw = fetch(ref, revision)
        except Exception as exc:
            out.degraded = True
            out.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_PARTIAL_ECOSYSTEM",
                    "message": f"could not enrich model {ref!r}: {type(exc).__name__}",
                    "hint": (
                        "the model's CERT-In elements are recorded as `not-provided` "
                        "rather than guessed; discovery results are unaffected"
                    ),
                }
            )
            continue

        card = parse_model_card(ref, revision, raw)
        cache.put(ref, revision, card)
        out.cards[ref] = card

    out.cache_hits = cache.hits
    out.cache_misses = cache.misses
    return out


def parse_model_card(model_ref: str, revision: str, raw: dict[str, Any]) -> ModelCard:
    """Read aibom-generator's CycloneDX output into a ModelCard.

    ⚠ EVERY FIELD IS OPTIONAL AND ABSENCE IS NOT AN ERROR. Most Hugging Face
    model cards are incomplete — that is a fact about the ecosystem, and the
    honest response is `not-provided` in the report rather than a plausible
    default here.
    """
    component = _first_model_component(raw)
    props = _properties(component)
    model_card = _model_card_section(component)

    return ModelCard(
        model_ref=model_ref,
        revision=revision or _string(component.get("version")),
        name=_string(component.get("name")) or model_ref,
        developer=_developer(component, props),
        license=_license(component),
        model_type=props.get("model_type", "") or _string(model_card.get("modelType")),
        architectures=_list(props.get("architectures")),
        datasets=_datasets(model_card),
        performance_metrics=_metrics(model_card),
        input_modality=_modality(model_card, "inputs"),
        output_modality=_modality(model_card, "outputs"),
        source_completeness=_float(props.get("completeness_score")),
    )


def _first_model_component(raw: dict[str, Any]) -> dict[str, Any]:
    components = raw.get("components")
    if not isinstance(components, list):
        return {}
    for c in components:
        if isinstance(c, dict) and str(c.get("type", "")).lower() in {
            "machine-learning-model",
            "model",
        }:
            return c
    return {}


def _model_card_section(component: dict[str, Any]) -> dict[str, Any]:
    """CycloneDX 1.6 puts model metadata under `modelCard`."""
    card = component.get("modelCard")
    return card if isinstance(card, dict) else {}


def _developer(component: dict[str, Any], props: dict[str, str]) -> str:
    """Who published the model.

    ⚠ NOT DERIVED FROM THE ORG PREFIX OF THE MODEL ID. `meta-llama/Llama-3-8B`
    is published by Meta, but `someuser/Llama-3-8B-finetuned` is not published by
    someuser in any sense a compliance reviewer means — and attributing it to
    them would put a wrong name in a Table 10 element.
    """
    for key in ("author", "publisher"):
        value = _string(component.get(key))
        if value:
            return value
    return props.get("author", "")


def _license(component: dict[str, Any]) -> str:
    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return ""
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        expression = _string(entry.get("expression"))
        if expression:
            return expression
        lic = entry.get("license")
        if isinstance(lic, dict):
            value = _string(lic.get("id")) or _string(lic.get("name"))
            if value:
                return value
    return ""


def _datasets(model_card: dict[str, Any]) -> list[dict[str, str]]:
    considerations = model_card.get("modelParameters")
    if not isinstance(considerations, dict):
        return []
    datasets = considerations.get("datasets")
    if not isinstance(datasets, list):
        return []

    out: list[dict[str, str]] = []
    for d in datasets:
        if not isinstance(d, dict):
            continue
        name = _string(d.get("name")) or _string(d.get("ref"))
        if not name:
            continue
        out.append(
            {
                "name": name,
                "type": _string(d.get("type")),
                "license": _string(d.get("license")),
                "source": _string(d.get("source")),
            }
        )
    return out


def _metrics(model_card: dict[str, Any]) -> dict[str, Any]:
    analysis = model_card.get("quantitativeAnalysis")
    if not isinstance(analysis, dict):
        return {}
    measures = analysis.get("performanceMetrics")
    if not isinstance(measures, list):
        return {}

    out: dict[str, Any] = {}
    for m in measures:
        if not isinstance(m, dict):
            continue
        metric_type = _string(m.get("type"))
        value = m.get("value")
        if metric_type and value not in (None, ""):
            out[metric_type] = value
    return out


def _modality(model_card: dict[str, Any], key: str) -> str:
    params = model_card.get("modelParameters")
    if not isinstance(params, dict):
        return ""
    entries = params.get(key)
    if not isinstance(entries, list):
        return ""
    formats = [
        _string(e.get("format"))
        for e in entries
        if isinstance(e, dict) and _string(e.get("format"))
    ]
    return ", ".join(dict.fromkeys(formats))


def _properties(component: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    props = component.get("properties")
    if not isinstance(props, list):
        return out
    for p in props:
        if isinstance(p, dict):
            name = _string(p.get("name")).lower()
            if name:
                out[name.rsplit(":", 1)[-1]] = _string(p.get("value"))
    return out


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [v.strip() for v in value.split(",") if v.strip()]
    return []


def _float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
