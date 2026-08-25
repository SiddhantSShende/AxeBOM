"""Tests for the shared worker library."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from axebom_shared import errors, timeutil
from axebom_shared import logging as eb_logging
from axebom_shared.config import ConfigError, load_worker_config

# --------------------------------------------------------------------------
# Redaction. Every case below is a real way a secret reaches a worker log:
# a scanner echoing a clone URL, a wrapped exception carrying a DSN, an auth
# header in an HTTP error body.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "must_not_contain", "must_contain"),
    [
        ("clone postgres://app:hunter2@db:5432/x failed", "hunter2", "db:5432"),
        ("redis://default:s3cr3t@cache:6379/0", "s3cr3t", "cache:6379"),
        ("Authorization: Bearer eyJabc123def456ghi", "eyJabc123def456ghi", "Authorization"),
        (
            "token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "token",
        ),
        ("using AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "using"),
        ("-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY", ""),
        ("found 1421 components in 6 ecosystems", "", "1421 components"),
    ],
)
def test_redact(raw: str, must_not_contain: str, must_contain: str) -> None:
    out = eb_logging.redact(raw)
    if must_not_contain:
        assert must_not_contain not in out, f"secret survived: {out}"
    if must_contain:
        assert must_contain in out, f"useful context destroyed: {out}"


def test_redact_processor_by_key_and_value() -> None:
    event = {
        "event": "clone failed for postgres://app:hunter2@db:5432/x",
        "password": "hunter2",
        "github_token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "component": "lodash",
        "count": 1421,
    }
    out = eb_logging._redact_processor(None, "info", dict(event))

    blob = json.dumps(out)
    assert "hunter2" not in blob
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in blob
    # Non-secret data must survive or the logs are useless.
    assert out["component"] == "lodash"
    assert out["count"] == 1421
    assert "db:5432" in out["event"]


# --------------------------------------------------------------------------
# Time. A naive datetime in a BOM timestamp is a compliance defect that looks
# perfectly well-formed, so it is rejected rather than assumed to be UTC.
# --------------------------------------------------------------------------


def test_utc_now_is_aware() -> None:
    assert timeutil.utc_now().tzinfo is not None


def test_rfc3339_uses_literal_z() -> None:
    dt = datetime(2026, 8, 16, 9, 14, 22, tzinfo=UTC)
    assert timeutil.to_rfc3339(dt) == "2026-08-16T09:14:22Z"


def test_rfc3339_rejects_naive() -> None:
    with pytest.raises(ValueError, match="naive datetime"):
        timeutil.to_rfc3339(datetime(2026, 8, 16, 9, 14, 22))  # noqa: DTZ001


def test_rfc3339_roundtrip() -> None:
    now = timeutil.utc_now().replace(microsecond=0)
    assert timeutil.from_rfc3339(timeutil.to_rfc3339(now)) == now


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


def test_engine_unavailable_is_not_retryable() -> None:
    err = errors.EngineUnavailableError("grype", "container image not pulled")
    assert err.code == errors.ErrorCode.ENGINE_UNAVAILABLE
    # A missing engine will still be missing on redelivery; retrying burns
    # delivery attempts and delays the scan for no benefit.
    assert err.retryable is False
    assert err.detail["engine"] == "grype"


def test_engine_timeout_is_retryable() -> None:
    err = errors.EngineTimeoutError("dependency-check", 900)
    assert err.retryable is True


def test_as_diagnostic_shape() -> None:
    diag = errors.EngineUnavailableError("syft", "binary missing").as_diagnostic()
    assert diag["severity"] == "error"
    assert diag["code"] == "ENGINE_UNAVAILABLE"
    assert "syft" in diag["message"]


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def test_config_defaults_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SANDBOX_NETWORK", "ALLOW_PACKAGE_MANAGER_RESOLUTION"):
        monkeypatch.delenv(var, raising=False)

    cfg = load_worker_config("sbom")
    # Both defaults are security-relevant and must not drift.
    assert cfg.sandbox.network == "none"
    assert cfg.allow_package_manager_resolution is False


def test_config_rejects_invalid_enum(monkeypatch: pytest.MonkeyPatch) -> None:
    # A typo'd SANDBOX_NETWORK must fail loudly, not fall back silently —
    # silently defaulting a security control is how it stops being one.
    monkeypatch.setenv("SANDBOX_NETWORK", "opne")
    with pytest.raises(ConfigError, match="SANDBOX_NETWORK"):
        load_worker_config("sbom")


def test_config_reports_all_problems_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_NETWORK", "nope")
    monkeypatch.setenv("SANDBOX_MEMORY_MB", "lots")
    with pytest.raises(ConfigError) as exc:
        load_worker_config("sbom")
    msg = str(exc.value)
    # Discovering config problems one restart at a time is miserable.
    assert "SANDBOX_NETWORK" in msg
    assert "SANDBOX_MEMORY_MB" in msg


def test_worker_config_has_no_credential_fields() -> None:
    """Workers hold no credentials — see docs/ADR/0008.

    This is a structural assertion, not a style check. If someone adds a token
    field to WorkerConfig, the sandbox's security property (compromising a
    scanner yields only the code it was scanning) quietly stops holding.
    """
    cfg = load_worker_config("sbom")
    forbidden = ("token", "password", "secret", "credential", "key")
    for attr in vars(cfg):
        assert not any(f in attr.lower() for f in forbidden), (
            f"WorkerConfig.{attr} looks credential-shaped; workers must hold "
            f"no credentials (docs/ADR/0008)"
        )
