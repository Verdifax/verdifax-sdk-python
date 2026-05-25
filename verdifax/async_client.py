"""Asynchronous Verdifax API client.

Mirrors :class:`verdifax.VerdifaxClient` but uses ``httpx.AsyncClient``.

Example:
    >>> import asyncio
    >>> from verdifax import AsyncVerdifaxClient
    >>>
    >>> async def main():
    ...     async with AsyncVerdifaxClient() as client:
    ...         receipt = await client.attest(
    ...             payload="hello verdifax",
    ...             program_id="a" * 64,
    ...             route_id="route-test",
    ...             registry_record_hash="b" * 64,
    ...         )
    ...         return receipt.manifest_hash
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any, Optional, Type, Union

import httpx

from ._transport import parse_response, wrap_transport_error
from ._validation import normalize_payload, validate_hex64, validate_route_id
from ._version import __version__
from .client import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    ENV_API_KEY,
    ENV_BASE_URL,
)
from .exceptions import APIError
from .models import (
    AttestationReceipt,
    AttestedContext,
    ExecuteRequest,
    ExecutionManifest,
)


class AsyncVerdifaxClient:
    """Async client for the Verdifax pipeline REST API.

    Args:
        base_url: Base URL of the Verdifax API. Falls back to
            ``$VERDIFAX_API_URL`` and finally to ``http://localhost:9090``.
        api_key: Optional API key sent as the ``X-Verdifax-Key`` header.
            Falls back to ``$VERDIFAX_API_KEY``.
        timeout: Request timeout in seconds. Defaults to 30.
        transport: Optional custom ``httpx.AsyncBaseTransport`` for tests.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key or os.environ.get(ENV_API_KEY)
        self.timeout = timeout

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"verdifax-python/{__version__} (async)",
        }
        if self.api_key:
            headers["X-Verdifax-Key"] = self.api_key

        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers=headers,
            transport=transport,
        )

    # ── lifecycle ──────────────────────────────────────────────────────────
    async def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncVerdifaxClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.close()

    # ── public API ─────────────────────────────────────────────────────────
    async def health(self) -> dict[str, Any]:
        """Liveness check. Returns the JSON body of ``GET /health``."""
        try:
            response = await self._http.get("/health")
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_response(response)

    async def attest(
        self,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> AttestationReceipt:
        """Async version of :meth:`VerdifaxClient.attest`.

        Accepts the same optional ``attested_context`` block , 
        see :class:`verdifax.models.AttestedContext`.
        """
        request_body = self._build_execute_body(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )
        try:
            response = await self._http.post("/execute", json=request_body)
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

    async def verify(
        self,
        manifest_hash: str,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> bool:
        """Async version of :meth:`VerdifaxClient.verify`."""
        validate_hex64(manifest_hash, "manifest_hash")
        receipt = await self.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )
        return receipt.manifest_hash == manifest_hash

    async def execute(
        self,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> ExecutionManifest:
        """Async lower-level alternative returning just the manifest."""
        receipt = await self.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )
        return receipt.manifest

    # ── internal helpers ───────────────────────────────────────────────────
    @staticmethod
    def _build_execute_body(
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> dict[str, Any]:
        validate_hex64(program_id, "program_id")
        validate_hex64(registry_record_hash, "registry_record_hash")
        validate_route_id(route_id)
        payload_text, payload_b64 = normalize_payload(payload)
        # Auto-derive `attested = True` if any field carries a value, so
        # callers don't have to remember to set the boolean explicitly.
        if attested_context is not None:
            attested_context = attested_context.with_auto_attested()
        request = ExecuteRequest(
            payload_text=payload_text or None,
            payload=payload_b64 or None,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
        )
        return request.model_dump_request()


__all__ = ["AsyncVerdifaxClient"]
