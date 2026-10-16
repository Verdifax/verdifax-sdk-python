"""Synchronous Verdifax API client.

Example:
    >>> from verdifax import VerdifaxClient
    >>> client = VerdifaxClient()  # production; pass base_url for a local orchestrator
    >>> receipt = client.attest(
    ...     payload="hello verdifax",
    ...     program_id="a" * 64,
    ...     route_id="route-test",
    ...     registry_record_hash="b" * 64,
    ... )
    >>> receipt.manifest_hash  # doctest: +SKIP
    '7f...'
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any, NoReturn, Optional, Type, Union

import httpx

from ._transport import parse_response, wrap_transport_error
from ._validation import (
    normalize_payload,
    validate_hex64,
    validate_route_id,
    validate_run_id,
)
from ._version import __version__
from .exceptions import APIError, UnsupportedOperationError
from .models import (
    AttestationReceipt,
    AttestedContext,
    ExecuteRequest,
    ExecutionManifest,
    VerifyResponse,
)

# The default points at production (2026-10-15, v0.5.1): an SDK whose
# three-line quickstart silently talked to localhost produced a
# connection-refused for every new user who followed the docs, and a
# silent wrong default is worse than an explicit one. Local
# development opts in via $VERDIFAX_API_URL or the base_url argument.
DEFAULT_BASE_URL = "https://api.verdifax.com"
DEFAULT_TIMEOUT = 30.0
ENV_BASE_URL = "VERDIFAX_API_URL"
ENV_API_KEY = "VERDIFAX_API_KEY"

# Raised by every verify() variant (sync, async, module-level) as of 0.6.0.
VERIFY_UNSUPPORTED_MESSAGE = (
    "verify() is no longer supported (verdifax 0.6.0). It re-ran the pipeline "
    "and compared manifest hashes, which cannot match: every run seals its own "
    "admission clock, nonce, and public-log entry into its manifest hash. Use "
    "verify_run(run_id) to have the server re-derive a recorded run's manifest "
    "hash and compare it with the recorded seal, or "
    "verdifax.research.verify_determinism() to check that the pipeline replays "
    "deterministically."
)


class VerdifaxClient:
    """Synchronous client for the Verdifax pipeline REST API.

    Args:
        base_url: Base URL of the Verdifax API. Falls back to
            ``$VERDIFAX_API_URL`` and finally to the production API at
            ``https://api.verdifax.com``.
        api_key: Optional API key sent as the ``X-Verdifax-Key`` header.
            Falls back to ``$VERDIFAX_API_KEY``.
        timeout: Request timeout in seconds. Defaults to 30.
        transport: Optional custom ``httpx.BaseTransport`` (useful for
            tests, e.g. with the ``respx`` library).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key or os.environ.get(ENV_API_KEY)
        self.timeout = timeout

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"verdifax-python/{__version__}",
        }
        if self.api_key:
            headers["X-Verdifax-Key"] = self.api_key

        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers=headers,
            transport=transport,
        )

    # ── lifecycle ──────────────────────────────────────────────────────────
    def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> "VerdifaxClient":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # ── public API ─────────────────────────────────────────────────────────
    def health(self) -> dict[str, Any]:
        """Liveness check. Returns the JSON body of ``GET /health``."""
        try:
            response = self._http.get("/health")
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_response(response)

    def attest(
        self,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
        reproducibility_context: Optional[Any] = None,
        ai_output_text: Optional[str] = None,
    ) -> AttestationReceipt:
        """Run the nine-stage pipeline against ``payload`` and return a receipt.

        Args:
            payload: The payload to attest. Strings are sent as text; bytes
                are sent as text if UTF-8-decodable, otherwise base64.
            program_id: 64-char lowercase hex registry-authorized program ID.
            route_id: Non-empty deterministic route identifier.
            registry_record_hash: 64-char lowercase hex §0 registry record hash.
            attested_context: Optional caller-supplied actor / model /
                decision block recorded verbatim into the EPA artifact.
                See :class:`verdifax.models.AttestedContext` for the
                schema. When omitted, the run is recorded as
                ``self_attested_deterministic`` (no actor or model
                declared).
            reproducibility_context: Optional
                :class:`verdifax.research.ReproducibilityContext`
                instance carrying the caller-declared runtime
                fingerprint (container image hash, language pins,
                git SHA, etc.). Bound into the bundle's Category-6
                section. Build via
                :func:`verdifax.research.capture_environment` for
                auto-detection.
            ai_output_text: Optional AI output text to govern via the
                AIVP-T4 stage. When supplied, the orchestrator routes
                the run through the configured AIVP adapter (the live
                Claude adapter in production) and seals the adapter ID
                plus the AI-output hash into the manifest. When
                omitted, the run is attested without AI-output
                governance.

        Returns:
            An :class:`AttestationReceipt` containing the sealed manifest.

        Raises:
            ValidationError: If any input fails client-side validation.
            StageError: If a specific pipeline stage rejected the request.
            APIError: For any other non-2xx response from the API.
            ConnectionError: If the API was unreachable.
        """
        request_body = self._build_execute_body(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
            reproducibility_context=reproducibility_context,
            ai_output_text=ai_output_text,
        )
        try:
            response = self._http.post("/execute", json=request_body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        body = parse_response(response)
        if "manifest" not in body:
            raise APIError(
                message="API response missing 'manifest'",
                status_code=response.status_code,
                response_body=body,
            )
        return AttestationReceipt.from_api_response(body)

    def verify_run(self, run_id: int) -> VerifyResponse:
        """Ask the server to re-derive a recorded run's manifest hash and check its seal.

        Calls ``GET /runs/{run_id}/verify`` with this client's API key.
        The orchestrator loads the run's stored manifest fields, recomputes
        the manifest hash from them under the formula version the run was
        sealed with, and compares the result with the manifest hash it
        recorded for that run. ``verified`` is ``True`` exactly when the two
        are equal.

        What this proves: the stored manifest fields still hash to the
        recorded seal, as computed by the Verdifax server. It does not
        re-run the pipeline, it does not see the original payload (only its
        hash is stored), and it is not independent of Verdifax. For an
        independent offline check of the sealed audit bundle, use the
        open-source ``verdifax-verify`` CLI
        (https://github.com/Verdifax/verdifax-verify).

        A run recorded as a stage error has no stored manifest; the server
        then returns ``verified=False`` with a ``reason`` and no
        ``recomputed_hash``.

        Args:
            run_id: The server-side run ID, available as
                :attr:`AttestationReceipt.run_id` on the receipt returned by
                :meth:`attest`.

        Returns:
            A :class:`VerifyResponse`.

        Raises:
            ValidationError: If ``run_id`` is not a positive integer.
            APIError: For a non-2xx response, for example 401 without a
                valid API key or 404 when the run does not exist or belongs
                to another key.
            ConnectionError: If the API was unreachable.
        """
        validate_run_id(run_id)
        try:
            response = self._http.get(f"/runs/{run_id}/verify")
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return VerifyResponse.model_validate(parse_response(response))

    def verify(
        self,
        manifest_hash: str,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> NoReturn:
        """Unsupported since 0.6.0; always raises :class:`UnsupportedOperationError`.

        This method used to re-run the pipeline on the same inputs and
        compare the new manifest hash with ``manifest_hash``. Against the
        production orchestrator that comparison can never succeed, because
        every run seals its own admission clock, nonce, and public-log
        entry into its manifest hash. The signature is kept so existing
        callers get this explanation instead of a ``TypeError``.

        Use :meth:`verify_run` to have the server re-derive a recorded run's
        seal, or :func:`verdifax.research.verify_determinism` to check that
        the pipeline replays deterministically.

        Raises:
            UnsupportedOperationError: Always.
        """
        raise UnsupportedOperationError(VERIFY_UNSUPPORTED_MESSAGE)

    def execute(
        self,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> ExecutionManifest:
        """Lower-level alternative to :meth:`attest` that returns just the manifest."""
        return self.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        ).manifest

    # ── internal helpers ───────────────────────────────────────────────────
    @staticmethod
    def _build_execute_body(
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
        reproducibility_context: Optional[Any] = None,
        ai_output_text: Optional[str] = None,
    ) -> dict[str, Any]:
        validate_hex64(program_id, "program_id")
        validate_hex64(registry_record_hash, "registry_record_hash")
        validate_route_id(route_id)
        payload_text, payload_b64 = normalize_payload(payload)
        # If the caller supplied an attested_context block, auto-derive the
        # `attested` boolean from field presence (matching the orchestrator's
        # convention) so callers don't have to remember to set it.
        if attested_context is not None:
            attested_context = attested_context.with_auto_attested()
        # Reproducibility context, serialize to dict if a typed model
        # was supplied; pass dicts through unchanged so the structure
        # is also accessible from non-research call sites.
        repro_dict: Optional[dict[str, Any]] = None
        if reproducibility_context is not None:
            if hasattr(reproducibility_context, "with_auto_declared"):
                # It's a ReproducibilityContext instance, auto-derive
                # the declared flag, then dump to JSON-compatible dict.
                ctx = reproducibility_context.with_auto_declared()
                repro_dict = ctx.model_dump(mode="json", exclude_none=True)
            elif isinstance(reproducibility_context, dict):
                repro_dict = reproducibility_context
            else:
                # Best-effort: try .model_dump() on any pydantic-shaped
                # object the caller passed in; otherwise raise.
                if hasattr(reproducibility_context, "model_dump"):
                    repro_dict = reproducibility_context.model_dump(mode="json", exclude_none=True)
                else:
                    raise TypeError(
                        "reproducibility_context must be a "
                        "verdifax.research.ReproducibilityContext or a dict"
                    )
        request = ExecuteRequest(
            payload_text=payload_text or None,
            payload=payload_b64 or None,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
            reproducibility_context=repro_dict,
            ai_output_text=ai_output_text or None,
        )
        return request.model_dump_request()


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "VERIFY_UNSUPPORTED_MESSAGE",
    "VerdifaxClient",
]
