"""AIBOM engine adapters.

Four components that answer different questions and are merged afterwards
(see ../merge.py):

    ai-bom            CODE-LEVEL discovery — which LLM providers, agent
                      frameworks, MCP servers and model references a repository
                      actually uses. Runs sandboxed over the source tree.

    airom             CODE-LEVEL discovery, WIDER — models, prompts, vector
                      stores, RAG pipelines and frameworks, each with real
                      file:line evidence. Sandboxed. It is the only engine that
                      reports the non-model AI assets.

    cdxgen-ai         CODE-LEVEL discovery, the same digest-pinned binary the
                      SBOM family runs, invoked with `-t ai`. Sandboxed. The only
                      engine that emits a correctly-cased `pkg:huggingface/…`
                      purl and the only one that reports inference services.

    aibom-generator   MODEL-METADATA enrichment — pulls the model card, config,
                      licence and completeness score for a Hugging Face model
                      id. NOT a scanner and NOT sandboxed: it makes an outbound
                      HTTP call and touches no user code, so it is enrichment
                      logic driven by an injected Fetcher rather than a
                      ToolAdapter.

    aibom-toml        A DECLARATION the customer committed — `aibom.toml`, the
                      `0disoft/ai-bom-generator` format. Parsing a committed file
                      is a scan in the same sense parsing a lockfile is, and the
                      models it names are the customer's own claim rather than an
                      observation.

    aibom-k8s-runtime  } DOCUMENTS THE CUSTOMER PRODUCED SOMEWHERE AxeBOM CANNOT
    aibom-glaas        } REACH — a live cluster, and a training run on their own
                         machine. Uploaded, never run. See aibom_import.py for
                         why calling either a scanner would manufacture coverage
                         out of nothing.

⚠ THE THREE DISCOVERY ENGINES SPEAK THREE DIALECTS OF ONE FORMAT, and the shared
judgement about what a model reference IS lives in `../discovery.py`, not in each
adapter. Getting it wrong once put a Python library in a Table 10 inventory three
times over.
"""

from .ai_bom import AIBomAdapter, extract_discovery
from .aibom_generator import (
    EnrichmentResult,
    Fetcher,
    ModelCache,
    ModelCard,
    enrich_models,
    parse_model_card,
)
from .aibom_import import (
    GLaaSImportAdapter,
    K8sAIBOMImportAdapter,
    extract_import_discovery,
)
from .aibom_toml import AIBOMTomlAdapter, extract_toml_discovery
from .airom import AiromAdapter, extract_airom_discovery
from .cdxgen_ai import CdxgenAIAdapter, extract_cdxgen_ai_discovery

__all__ = [
    "AIBOMTomlAdapter",
    "AIBomAdapter",
    "AiromAdapter",
    "CdxgenAIAdapter",
    "EnrichmentResult",
    "Fetcher",
    "GLaaSImportAdapter",
    "K8sAIBOMImportAdapter",
    "ModelCache",
    "ModelCard",
    "enrich_models",
    "extract_airom_discovery",
    "extract_cdxgen_ai_discovery",
    "extract_discovery",
    "extract_import_discovery",
    "extract_toml_discovery",
    "parse_model_card",
]
