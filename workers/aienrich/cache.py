"""A durable, cross-scan cache for Hugging Face model cards.

⚠ THE EXISTING CACHE DIES WITH THE JOB. `aibom_generator.ModelCache` is an
in-process dict, so every scan re-fetched every model card — and Phase 12's own
test requirement says "a second scan of the same model does not re-fetch". The
same base model appears across many projects in one tenant, let alone one estate.

⚠ ON DISK, NOT IN POSTGRES, AND THAT IS A DELIBERATE NARROWING OF THE PLAN.
The plan put this in an `aibom` schema. Building one here would mean a new schema,
a new migration and a new database credential held by **the one component in the
AI path with outbound network** — widening exactly the blast radius that splitting
this worker out was meant to contain. A model card is public data about a public
model, so it needs no tenant scoping and no RLS; a content-addressed directory on
a volume the worker already mounts is durable, survives restarts, and is trivially
inspectable. `services/aibom` (M4) can lift it into the schema if it ever needs to
be queried rather than read by key.

⚠ THE CACHE IS NOT THE PROVENANCE RECORD. Every fetched card is ALSO written as an
immutable raw artifact under the scan's own output prefix, which is what makes a
re-normalization replayable without re-fetching (ADR-0003, CLAUDE.md invariant 10).
This is the layer above that: it stops the second SCAN paying for the first scan's
lookups. Losing it costs latency and rate limit, never correctness.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: A model card is versioned metadata, not a moving target, but a publisher can
#: edit one in place. A day is long enough to make a re-scan free and short
#: enough that a licence correction reaches the next week's report.
DEFAULT_TTL_SECONDS = 24 * 3600


def _slug(model_ref: str, revision: str) -> str:
    """A filesystem-safe, collision-free key.

    ⚠ HASHED, NOT SANITIZED. A model reference is `org/name` and can carry any
    character a publisher chose; building a path out of it directly is a path
    traversal waiting to happen (`../../etc`), and "sanitizing" it invites two
    different references to sanitize to one file — which would serve one model's
    licence under another model's name.
    """
    digest = hashlib.sha256(f"{model_ref}\x00{revision}".encode()).hexdigest()
    return digest


@dataclass
class CardCache:
    """A content-addressed directory of raw model-card responses."""

    root: Path
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    def path_for(self, model_ref: str, revision: str) -> Path:
        slug = _slug(model_ref, revision)
        # Two levels of fan-out: a flat directory of tens of thousands of entries
        # is slow to list and unpleasant to operate.
        return self.root / slug[:2] / slug[2:4] / f"{slug}.json"

    def get(self, model_ref: str, revision: str) -> dict[str, Any] | None:
        """The cached response, or None. NEVER raises — a broken cache entry must
        degrade to a fetch, not fail the scan."""
        path = self.path_for(model_ref, revision)
        try:
            stat = path.stat()
        except OSError:
            return None

        if self.ttl_seconds > 0 and (time.time() - stat.st_mtime) > self.ttl_seconds:
            return None

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

        return payload if isinstance(payload, dict) else None

    def put(self, model_ref: str, revision: str, payload: dict[str, Any]) -> None:
        """Store a response. A failure here is logged by the caller and ignored —
        an uncacheable result is still a correct result."""
        path = self.path_for(model_ref, revision)
        path.parent.mkdir(parents=True, exist_ok=True)
        # ⚠ ATOMIC. Two workers may enrich the same model concurrently; a reader
        # must never see a half-written file, and a half-written file must never
        # become a permanent poisoned entry.
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
            tmp.replace(path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
