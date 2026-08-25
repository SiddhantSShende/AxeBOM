"""AIBOM engine adapters.

Two components that answer different questions and are merged afterwards
(see ../merge.py):

    ai-bom            CODE-LEVEL discovery — which LLM providers, agent
                      frameworks, MCP servers and model references a repository
                      actually uses. Runs sandboxed over the source tree.

    aibom-generator   MODEL-METADATA enrichment — pulls the model card, config,
                      licence and completeness score for a Hugging Face model
                      id. NOT a scanner and NOT sandboxed: it makes an outbound
                      HTTP call and touches no user code, so it is enrichment
                      logic driven by an injected Fetcher rather than a
                      ToolAdapter.

This file was empty, so neither was exported.
"""

from .ai_bom import AIBomAdapter
from .aibom_generator import (
    EnrichmentResult,
    Fetcher,
    ModelCache,
    ModelCard,
    enrich_models,
    parse_model_card,
)

__all__ = [
    "AIBomAdapter",
    "EnrichmentResult",
    "Fetcher",
    "ModelCache",
    "ModelCard",
    "enrich_models",
    "parse_model_card",
]
