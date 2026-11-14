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
``$VERDIFAX_BASE_URL``, ``$VERDIFAX_API_URL`` or by
passing ``base_url`` to :class:`VerdifaxClient`.
"""

from __future__ import annotations

import os as _os
from typing import (
    Any as _Any,
    Mapping as _Mapping,
    NoReturn as _NoReturn,
    Optional as _Optional,
    Union as _Union,
)

from ._requests import MAX_BATCH_ROWS, DeletedJobLinks, RunDeletion, format_provider_payload
from ._retry import DEFAULT_MAX_RETRIES
from ._signals import (
    FEED_HEAD_FORM,
    SIGNAL_KINDS,
    AsyncSignalFollower,
    FeedHead,
    SignalFollower,
    pending_signoffs,
    signal_event_hash,
    verify_webhook,
    webhook_value,
)
from ._signoffs import approver_key_proof, signoff_preimage
from ._signing import (
    RequestKeyPair,
    generate_request_key,
    owner_change_preimage,
    policy_activation_approval,
    policy_activation_preimage,
    request_key_change_preimage,
    request_key_registration_body,
    request_signature_preimage,
    request_signature_preimage_v2,
    sign_request,
    sign_request_v2,
)
from ._validation import validate_hex64, validate_route_id
from ._version import __version__
from .async_client import AsyncVerdifaxClient
from .client import (
    ENV_MAX_RETRIES,
    ENV_TIMEOUT_MS,
    ENV_USER_AGENT,
    VERIFY_UNSUPPORTED_MESSAGE,
    VerdifaxClient,
)
from .exceptions import (
    APIError,
    ConnectionError,
    StageError,
    UnsupportedOperationError,
    ValidationError,
    VerdifaxError,
    WebhookVerificationError,
)
from .helpers import attest_claude_response, attest_openai_response
from .jobs import AsyncJob, Job
from .models import (
    KERNEL_NAMES,
    RUN_STATUSES,
    STAGE_NAMES,
    AccountRunsExport,
    AttestationReceipt,
    AivpFinding,
    AivpReview,
    AttestedContext,
    DCAEEngineHint,
    ExecuteBatchResponse,
    ExecuteBatchResult,
    ExecuteRequest,
    ExecutionManifest,
    ExportRow,
    Run,
    RunList,
    RunSummary,
    RunsExport,
    RunsExportCSV,
    SignOffTarget,
    StageResult,
    VerifyResponse,
)
from . import research  # reproducible-research toolkit (Option B Phase 3)
from . import section0  # §0 cross-language canonical hash verifier


def _env_int(name: str) -> _Optional[int]:
    raw = _os.environ.get(name)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValidationError(f"{name}={raw!r} is not an integer") from exc


def from_env(
    base_url: _Optional[str] = None,
    api_key: _Optional[str] = None,
    timeout: _Optional[float] = None,
    signing_key: _Optional[bytes] = None,
) -> VerdifaxClient:
    """Construct a :class:`VerdifaxClient` from environment variables.

    Honors ``VERDIFAX_BASE_URL``, then ``VERDIFAX_API_URL``, and
    ``VERDIFAX_API_KEY``, ``VERDIFAX_TIMEOUT_MS``, ``VERDIFAX_USER_AGENT``
    and ``VERDIFAX_MAX_RETRIES``. Any explicit arguments override the
    corresponding environment variable. ``signing_key`` is never read from
    the environment.

    Raises:
        ValidationError: If ``VERDIFAX_TIMEOUT_MS`` or
            ``VERDIFAX_MAX_RETRIES`` is not an integer.
    """
    kwargs: dict[str, object] = {}
    timeout_ms = _env_int(ENV_TIMEOUT_MS)
    if timeout_ms is not None:
        kwargs["timeout"] = timeout_ms / 1000
    max_retries = _env_int(ENV_MAX_RETRIES)
    if max_retries is not None:
        kwargs["max_retries"] = max_retries
    user_agent = _os.environ.get(ENV_USER_AGENT)
    if user_agent:
        kwargs["user_agent"] = user_agent
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
    job: _Optional[_Mapping[str, _Any]] = None,
    policy_context: _Optional[_Mapping[str, _Any]] = None,
    expected_policy_hash: _Optional[str] = None,
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
    Pass ``job`` to place the run in a job map, and ``policy_context`` or
    ``expected_policy_hash`` for the active policy; see
    :meth:`VerdifaxClient.attest`.
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
            job=job,
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
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
    "AccountRunsExport",
    "AsyncJob",
    "AsyncSignalFollower",
    "AsyncVerdifaxClient",
    "AttestationReceipt",
    "AivpFinding",
    "AivpReview",
    "AttestedContext",
    "ConnectionError",
    "DCAEEngineHint",
    "DEFAULT_MAX_RETRIES",
    "DeletedJobLinks",
    "ExecuteBatchResponse",
    "ExecuteBatchResult",
    "ExecuteRequest",
    "ExecutionManifest",
    "ExportRow",
    "FEED_HEAD_FORM",
    "FeedHead",
    "Job",
    "KERNEL_NAMES",
    "MAX_BATCH_ROWS",
    "RUN_STATUSES",
    "RequestKeyPair",
    "Run",
    "RunDeletion",
    "RunList",
    "RunSummary",
    "RunsExport",
    "RunsExportCSV",
    "SIGNAL_KINDS",
    "STAGE_NAMES",
    "SignOffTarget",
    "SignalFollower",
    "StageError",
    "StageResult",
    "UnsupportedOperationError",
    "ValidationError",
    "VerdifaxClient",
    "VerdifaxError",
    "VerifyResponse",
    "WebhookVerificationError",
    "__version__",
    "approver_key_proof",
    "attest",
    "attest_claude_response",
    "attest_openai_response",
    "format_provider_payload",
    "from_env",
    "generate_request_key",
    "owner_change_preimage",
    "policy_activation_approval",
    "policy_activation_preimage",
    "request_key_change_preimage",
    "request_key_registration_body",
    "request_signature_preimage",
    "request_signature_preimage_v2",
    "research",
    "section0",
    "sign_request",
    "sign_request_v2",
    "pending_signoffs",
    "signal_event_hash",
    "signoff_preimage",
    "validate_hex64",
    "validate_route_id",
    "verify",
    "verify_run",
    "verify_webhook",
    "webhook_value",
]
