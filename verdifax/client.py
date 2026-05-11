"""Synchronous Verdifax API client.

Example:
    >>> from verdifax import VerdifaxClient
    >>> client = VerdifaxClient(base_url="http://localhost:9090")
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
from typing import Any, Optional, Type, Union

import httpx

from ._transport import parse_response, wrap_transport_error
from ._validation import normalize_payload, validate_hex64, validate_route_id
from ._version import __version__
from .exceptions import APIError
from .models import (
    AttestationReceipt,
    AttestedContext,
    ExecuteRequest,
    ExecutionManifest,
)

DEFAULT_BASE_URL = "http://localhost:9090"
DEFAULT_TIMEOUT = 30.0
ENV_BASE_URL = "VERDIFAX_API_URL"
ENV_API_KEY = "VERDIFAX_API_KEY"


class VerdifaxClient:
    """Synchronous client for the Verdifax pipeline REST API.

    Args:
        base_url: Base URL of the Verdifax API. Falls back to
            ``$VERDIFAX_API_URL`` and finally to ``http://localhost:9090``.
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

    def verify(
        self,
        manifest_hash: str,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> bool:
        """Re-derive the manifest hash from inputs and compare to ``manifest_hash``.

        This re-runs the pipeline against the same inputs and checks that
        the resulting ``manifest_hash`` matches the one provided. Equality
        means the inputs reproduce the recorded manifest deterministically.

        ``attested_context`` must match the value used on the original
        ``attest`` call, since the EPA artifact (and therefore the
        manifest hash) depends on it.

        Returns:
            ``True`` when the recomputed hash matches, ``False`` otherwise.
        """
        validate_hex64(manifest_hash, "manifest_hash")
        receipt = self.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )
        return receipt.manifest_hash == manifest_hash

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
        # Reproducibility context — serialize to dict if a typed model
        # was supplied; pass dicts through unchanged so the structure
        # is also accessible from non-research call sites.
        repro_dict: Optional[dict[str, Any]] = None
        if reproducibility_context is not None:
            if hasattr(reproducibility_context, "with_auto_declared"):
                # It's a ReproducibilityContext instance — auto-derive
                # the declared flag, then dump to JSON-compatible dict.
                ctx = reproducibility_context.with_auto_declared()
                repro_dict = ctx.model_dump(mode="json", exclude_none=True)
            elif isinstance(reproducibility_context, dict):
                repro_dict = reproducibility_context
            else:
                # Best-effort: try .model_dump() on any pydantic-shaped
                # object the caller passed in; otherwise raise.
                if hasattr(reproducibility_context, "model_dump"):
                    repro_dict = reproducibility_context.model_dump(
                        mode="json", exclude_none=True
                    )
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
        )
        return request.model_dump_request()


__all__ = ["DEFAULT_BASE_URL", "DEFAULT_TIMEOUT", "VerdifaxClient"]
