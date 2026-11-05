"""Verdifax, cryptographic attestation for AI inference.

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
to the production API at ``https://api.verdifax.com``; override with
``$VERDIFAX_API_URL`` or by
passing ``base_url`` to :class:`VerdifaxClient`.
"""

from __future__ import annotations

from typing import NoReturn as _NoReturn, Optional as _Optional, Union as _Union

from ._signing import RequestKeyPair, generate_request_key
from ._version import __version__
from .async_client import AsyncVerdifaxClient
from .client import VERIFY_UNSUPPORTED_MESSAGE, VerdifaxClient
from .exceptions import (
    APIError,
    ConnectionError,
    StageError,
    UnsupportedOperationError,
    ValidationError,
    VerdifaxError,
)
from .helpers import attest_claude_response, attest_openai_response
from .models import (
    KERNEL_NAMES,
    STAGE_NAMES,
    AttestationReceipt,
    AttestedContext,
    DCAEEngineHint,
    ExecuteRequest,
    ExecutionManifest,
    StageResult,
    VerifyResponse,
)
from . import research  # reproducible-research toolkit (Option B Phase 3)
from . import section0  # §0 cross-language canonical hash verifier


def from_env(
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
    signing_key: _Optional[bytes] = None,
) -> VerdifaxClient:
    """Construct a :class:`VerdifaxClient` from environment variables.

    Honors ``VERDIFAX_API_URL`` and ``VERDIFAX_API_KEY``. Any explicit
    arguments override the corresponding environment variable.
    ``signing_key`` is never read from the environment.
    """
    kwargs: dict[str, object] = {}
    if base_url is not None:
        kwargs["base_url"] = base_url
    if api_key is not None:
        kwargs["api_key"] = api_key
    if timeout is not None:
        kwargs["timeout"] = timeout
    if signing_key is not None:
        kwargs["signing_key"] = signing_key
    return VerdifaxClient(**kwargs)  # type: ignore[arg-type]


def attest(
    payload: _Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    attested_context: _Optional[AttestedContext] = None,
    ai_output_text: _Optional[str] = None,
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
    signing_key: _Optional[bytes] = None,
) -> AttestationReceipt:
    """Module-level shortcut: attest a payload using a one-shot client.

    Equivalent to ``VerdifaxClient(...).attest(...)`` with the client
    closed automatically afterwards. For high-throughput use, instantiate
    a :class:`VerdifaxClient` yourself and reuse its connection pool.

    Pass ``attested_context`` to record a caller-attested actor / model /
    decision block into the run's EPA artifact, see
    :class:`AttestedContext`. Pass ``ai_output_text`` to route the run
    through AIVP governance (the live Claude adapter in production).
    Pass ``signing_key`` to sign the request; see :class:`VerdifaxClient`.
    """
    with from_env(
        base_url=base_url, api_key=api_key, timeout=timeout, signing_key=signing_key
    ) as client:
        return client.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
            ai_output_text=ai_output_text,
        )


def verify_run(
    run_id: int,
    *,
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
) -> VerifyResponse:
    """Module-level shortcut for :meth:`VerdifaxClient.verify_run`.

    Calls ``GET /runs/{run_id}/verify`` with a one-shot client. The
    server re-derives the manifest hash from the run's stored manifest
    fields and compares it with the recorded seal. For an independent
    offline check of the sealed audit bundle, use the open-source
    ``verdifax-verify`` CLI.
    """
    with from_env(base_url=base_url, api_key=api_key, timeout=timeout) as client:
        return client.verify_run(run_id)


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
) -> _NoReturn:
    """Unsupported since 0.6.0; always raises :class:`UnsupportedOperationError`.

    It re-ran the pipeline and compared manifest hashes, which cannot
    match because every run seals its own admission clock, nonce, and
    public-log entry. Use :func:`verify_run` instead, or
    :func:`verdifax.research.verify_determinism` to check that the
    pipeline replays deterministically.
    """
    raise UnsupportedOperationError(VERIFY_UNSUPPORTED_MESSAGE)


__all__ = [
    "APIError",
    "AsyncVerdifaxClient",
    "AttestationReceipt",
    "AttestedContext",
    "ConnectionError",
    "DCAEEngineHint",
    "ExecuteRequest",
    "ExecutionManifest",
    "KERNEL_NAMES",
    "RequestKeyPair",
    "STAGE_NAMES",
    "StageError",
    "StageResult",
    "UnsupportedOperationError",
    "ValidationError",
    "VerdifaxClient",
    "VerdifaxError",
    "VerifyResponse",
    "__version__",
    "attest",
    "attest_claude_response",
    "attest_openai_response",
    "from_env",
    "generate_request_key",
    "research",
    "verify",
    "verify_run",
]
