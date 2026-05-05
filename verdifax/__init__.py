"""Verdifax — cryptographic attestation for AI inference.

Three-line integration:

    >>> import verdifax
    >>> receipt = verdifax.attest(
    ...     payload="hello verdifax",
    ...     program_id="a" * 64,
    ...     route_id="route-test",
    ...     registry_record_hash="b" * 64,
    ... )  # doctest: +SKIP
    >>> receipt.manifest_hash  # doctest: +SKIP
    '7f...'

The SDK targets the Verdifax orchestrator REST API. By default it talks
to ``http://localhost:9090``; override with ``$VERDIFAX_API_URL`` or by
passing ``base_url`` to :class:`VerdifaxClient`.
"""

from __future__ import annotations

from typing import Optional as _Optional, Union as _Union

from ._version import __version__
from .async_client import AsyncVerdifaxClient
from .client import VerdifaxClient
from .exceptions import (
    APIError,
    ConnectionError,
    StageError,
    ValidationError,
    VerdifaxError,
)
from .helpers import attest_claude_response, attest_openai_response
from .models import (
    KERNEL_NAMES,
    STAGE_NAMES,
    AttestationReceipt,
    AttestedContext,
    ExecuteRequest,
    ExecutionManifest,
    StageResult,
)


def from_env(
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
) -> VerdifaxClient:
    """Construct a :class:`VerdifaxClient` from environment variables.

    Honors ``VERDIFAX_API_URL`` and ``VERDIFAX_API_KEY``. Any explicit
    arguments override the corresponding environment variable.
    """
    kwargs: dict[str, object] = {}
    if base_url is not None:
        kwargs["base_url"] = base_url
    if api_key is not None:
        kwargs["api_key"] = api_key
    if timeout is not None:
        kwargs["timeout"] = timeout
    return VerdifaxClient(**kwargs)  # type: ignore[arg-type]


def attest(
    payload: _Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    attested_context: _Optional[AttestedContext] = None,
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
) -> AttestationReceipt:
    """Module-level shortcut: attest a payload using a one-shot client.

    Equivalent to ``VerdifaxClient(...).attest(...)`` with the client
    closed automatically afterwards. For high-throughput use, instantiate
    a :class:`VerdifaxClient` yourself and reuse its connection pool.

    Pass ``attested_context`` to record a caller-attested actor / model /
    decision block into the run's EPA artifact — see
    :class:`AttestedContext`.
    """
    with from_env(base_url=base_url, api_key=api_key, timeout=timeout) as client:
        return client.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )


def verify(
    manifest_hash: str,
    payload: _Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    attested_context: _Optional[AttestedContext] = None,
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
) -> bool:
    """Module-level shortcut: verify a previously issued manifest hash.

    ``attested_context`` must match the value used on the original
    ``attest`` call.
    """
    with from_env(base_url=base_url, api_key=api_key, timeout=timeout) as client:
        return client.verify(
            manifest_hash=manifest_hash,
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )


__all__ = [
    "APIError",
    "AsyncVerdifaxClient",
    "AttestationReceipt",
    "AttestedContext",
    "ConnectionError",
    "ExecuteRequest",
    "ExecutionManifest",
    "KERNEL_NAMES",
    "STAGE_NAMES",
    "StageError",
    "StageResult",
    "ValidationError",
    "VerdifaxClient",
    "VerdifaxError",
    "__version__",
    "attest",
    "attest_claude_response",
    "attest_openai_response",
    "from_env",
    "verify",
]
