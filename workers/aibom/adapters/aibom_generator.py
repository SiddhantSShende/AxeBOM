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

#: The two keys of the enrichment envelope — aibom-generator's own CycloneDX
#: document, and what the Hugging Face Hub itself said. Declared here, beside the
#: parser that reads them, and imported by the fetcher that writes them, so the
#: two halves of one contract cannot drift apart.
_GENERATOR_KEY = "aibom_generator"
_HUB_KEY = "huggingface"

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
    #: What could not be established, in the publisher's terms, ready to become
    #: diagnostics. A value this parser DECLINED to use belongs here rather than
    #: nowhere: a field that quietly stays `not-provided` because we distrusted
    #: the number is invisible, and invariant 12 exists to stop exactly that.
    notes: tuple[str, ...] = ()


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
        # ⚠ A VALUE THIS PARSER DECLINED TO USE IS REPORTED, NOT DROPPED. The
        # model enriched; one of its elements still came back `not-provided`
        # because the only source for it was a scrape of English prose. Saying so
        # is what stops that gap reading as "the publisher declared nothing".
        for note in card.notes:
            out.diagnostics.append(
                {
                    "severity": "info",
                    "code": "AIBOM_ENRICHMENT_VALUE_REJECTED",
                    "message": note,
                }
            )

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
    generated, hub = _split_envelope(raw)
    card_data = hub.get("card_data") if isinstance(hub.get("card_data"), dict) else {}

    component = _first_model_component(generated)
    props = _properties(component)
    model_card = _model_card_section(component)

    notes: list[str] = []
    license_value = _resolved_license(component, card_data, model_ref, notes)
    datasets = _resolved_datasets(model_card, card_data, model_ref, notes)

    return ModelCard(
        model_ref=model_ref,
        revision=revision or _string(component.get("version")),
        name=_string(component.get("name")) or model_ref,
        developer=_developer(component, props),
        license=license_value,
        model_type=_model_type(model_card, props),
        architectures=_list(props.get("architectures")),
        datasets=datasets,
        performance_metrics=_metrics(model_card),
        input_modality=_modality(model_card, "inputs"),
        output_modality=_modality(model_card, "outputs"),
        source_completeness=_float(props.get("completeness_score")),
        notes=tuple(notes),
    )


def _split_envelope(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Accept both the two-source envelope and a bare aibom-generator document.

    ⚠ THE BARE FORM IS NOT LEGACY TOLERANCE, IT IS REPLAY. Raw artifacts are
    immutable (invariant 10), so every enrichment response captured before the
    envelope existed is still on disk and still has to normalize — under the same
    rules, minus the half it does not carry.
    """
    generated = raw.get(_GENERATOR_KEY)
    hub = raw.get(_HUB_KEY)
    if isinstance(generated, dict):
        return generated, hub if isinstance(hub, dict) else {}
    return raw, {}


def _resolved_license(
    component: dict[str, Any],
    card_data: dict[str, Any],
    model_ref: str,
    notes: list[str],
) -> str:
    """CERT-In Table 10's licence element, from the source that gets it right.

    ⚠ THE HUB'S OWN FIELD, NOT AIBOM-GENERATOR'S PARSE OF THE PROSE.

    aibom-generator re-reads the rendered model card and returns the licence with
    the next word of the document glued to it. Measured against the Hub's own
    `card_data.license` for three real models in this session:

        distilbert-base-uncased   "apache-2.0 datasets"  vs  apache-2.0
        gpt2                      "mit ---"              vs  mit
        all-MiniLM-L6-v2          "apache-2.0 library"   vs  apache-2.0

    Every one of those is wrong, and a wrong licence in a compliance document is
    worse than an absent one — a reader acts on it. So the structured field wins
    outright when it is there.

    When it is not, aibom-generator's value is used only if it is a single token:
    the observed corruption is always "identifier + stray word", so whitespace is
    the signal that we are looking at the corruption rather than at a licence.
    (A genuine multi-part expression — `Apache-2.0 OR MIT` — arrives through
    CycloneDX's `expression` field, which `_license` returns before it ever looks
    at `license.name`.)
    """
    hub_license = _string(card_data.get("license"))
    if hub_license:
        return hub_license

    generated_license = _license(component)
    if not generated_license or " " not in generated_license:
        return generated_license

    notes.append(
        f"{model_ref}: aibom-generator reported the licence as "
        f"{generated_license!r}, which is its parse of the card's prose rather "
        f"than a licence identifier, and the model card declares none in its "
        f"structured metadata — so the licence is recorded as not-provided"
    )
    return ""


def _resolved_datasets(
    model_card: dict[str, Any],
    card_data: dict[str, Any],
    model_ref: str,
    notes: list[str],
) -> list[dict[str, str]]:
    """The training datasets a publisher actually DECLARED.

    ⚠ AIBOM-GENERATOR'S DATASET LIST IS SCRAPED OUT OF ENGLISH PROSE AND IS NOT
    USABLE. Real output, this session:

        distilbert-base-uncased   ["consisting"]  vs  bookcorpus, wikipedia
        gpt2                      ["one", "a"]    vs  (none declared)
        all-MiniLM-L6-v2          ["given"]       vs  21 real dataset ids

    `consisting`, `one`, `a` and `given` are words from a sentence. Writing them
    into Table 10 as a model's training data is fabrication in the precise sense
    the product forbids, and the tool tells us so itself: it sets
    `genai:aibom:trainingDataAvailable = "false"` and attaches a warning saying
    the datasets "could not be verified on Hugging Face Hub".

    The model card's `datasets:` front matter is the declaration — machine-written
    by the publisher, and a list of real Hub dataset ids. It is used when present;
    otherwise nothing is recorded and the gap is stated.
    """
    declared = card_data.get("datasets")
    if isinstance(declared, str):
        declared = [declared]
    if isinstance(declared, list):
        out = [
            {
                "name": name,
                "type": "dataset",
                "license": "",
                "source": f"https://huggingface.co/datasets/{name}",
            }
            for name in (_string(d) for d in declared)
            if name
        ]
        if out:
            return out

    scraped = _datasets(model_card)
    if not scraped:
        return []

    notes.append(
        f"{model_ref}: aibom-generator named "
        f"{', '.join(repr(d['name']) for d in scraped[:5])} as training data by "
        f"reading the card's prose, and reports it could not verify them on "
        f"Hugging Face; the model card declares no datasets in its structured "
        f"metadata, so none are recorded"
    )
    return []


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


def _model_type(model_card: dict[str, Any], props: dict[str, str]) -> str:
    """CERT-In Table 10 element 03 — the model's TYPE, in CERT-In's own sense.

    ⚠ THE TASK, NOT THE ARCHITECTURE FAMILY, AND THE ORDER USED TO BE BACKWARDS.
    Table 10's own examples for this element are `text-generation`,
    `image-processing`, `image-classifier` — all of them TASKS. Real
    aibom-generator output for `distilbert-base-uncased` carries
    `modelParameters.task = "fill-mask"` and a vendor property
    `model_type = "distilbert"`; reading the property first put the architecture
    family in the element CERT-In defines by task, and `distilbert` is not one of
    the things Table 10 is asking about.

    It was also the third copy of a fact already recorded twice: `architectures`
    (`DistilBertForMaskedLM`) feeds element 07, and `modelArchitecture` says it
    again. The vendor property stays as the last fallback — a card that gives
    nothing else is better described by it than by nothing.
    """
    parameters = model_card.get("modelParameters")
    if isinstance(parameters, dict):
        task = _string(parameters.get("task"))
        if task:
            return task

    declared = _string(model_card.get("modelType"))
    if declared:
        return declared

    return props.get("model_type", "")


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
