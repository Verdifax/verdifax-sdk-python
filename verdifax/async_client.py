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
from typing import Any, Mapping, NoReturn, Optional, Sequence, Type, Union
from urllib.parse import quote

import httpx

from ._requests import (
    BatchRow,
    admin_erase_body,
    attest_receipt,
    batch_body,
    batch_response,
    parse_export_csv,
    provider_attest_args,
    query_params,
    run_path,
)
from ._retry import AsyncRetryingClient, DEFAULT_MAX_RETRIES, DEFAULT_RETRY_BASE_DELAY
from ._signing import (
    REQUEST_KEY_PATH,
    attach_signature,
    load_signing_key,
    request_key_body,
    request_key_clear_body,
    request_key_rotation_body,
)
from ._transport import checked_response, parse_response, wrap_transport_error
from ._validation import (
    validate_positive_id,
    validate_run_id,
)
from ._version import __version__
from .client import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    ENV_API_KEY,
    VERIFY_UNSUPPORTED_MESSAGE,
    VerdifaxClient,
    env_base_url,
)
from .exceptions import UnsupportedOperationError, ValidationError
from .jobs import AsyncJob
from .models import (
    AttestationReceipt,
    AttestedContext,
    ExecuteBatchResponse,
    ExecutionManifest,
    Run,
    RunList,
    RunsExport,
    RunsExportCSV,
    VerifyResponse,
)
from .research import (
    DeterminismResult,
    ReproducibilityContext,
    determinism_body,
    determinism_result,
)


class AsyncVerdifaxClient:
    """Async client for the Verdifax pipeline REST API.

    Args:
        base_url: Base URL of the Verdifax API. Falls back to
            ``$VERDIFAX_BASE_URL``, then ``$VERDIFAX_API_URL``, and finally
            to the production API at ``https://api.verdifax.com``.
        api_key: Optional API key sent as the ``X-Verdifax-Key`` header.
            Falls back to ``$VERDIFAX_API_KEY``.
        timeout: Request timeout in seconds. Defaults to 90.
        transport: Optional custom ``httpx.AsyncBaseTransport`` for tests.
        signing_key: Optional 32 raw bytes of an Ed25519 private key. When
            set, every call to ``POST /execute`` is sent as signed text with
            a request signature, each row of a batch carries its own, and a
            determinism check carries one. Needs ``pip install "verdifax[signing]"``. The key is never sent
            to the server.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        signing_key: Optional[bytes] = None,
        user_agent: Optional[str] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_base_delay: float = DEFAULT_RETRY_BASE_DELAY,
    ) -> None:
        self._signing_key = None if signing_key is None else load_signing_key(signing_key)
        self.base_url = (base_url or env_base_url() or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key or os.environ.get(ENV_API_KEY)
        self.timeout = timeout

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent or f"verdifax-python/{__version__} (async)",
        }
        if self.api_key:
            headers["X-Verdifax-Key"] = self.api_key

        self._http = AsyncRetryingClient(
            max_retries=max_retries,
            retry_base_delay=retry_base_delay,
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
        ai_output_text: Optional[str] = None,
        reproducibility_context: Optional[Any] = None,
        request_substance: Optional[dict[str, Any]] = None,
        authorization_chain: Optional[dict[str, Any]] = None,
        regulatory_scaffolding: Optional[dict[str, Any]] = None,
        causal_graph: Optional[dict[str, Any]] = None,
        job: Optional[Mapping[str, Any]] = None,
    ) -> AttestationReceipt:
        """Async version of :meth:`VerdifaxClient.attest`.

        Accepts the same optional ``attested_context`` block ,
        see :class:`verdifax.models.AttestedContext`, the same
        optional ``ai_output_text`` for AIVP governance, and the same
        optional ``reproducibility_context``. In this method
        ``reproducibility_context`` comes last, so that existing
        positional calls keep working.
        """
        request_body = self._build_execute_body(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
            reproducibility_context=reproducibility_context,
            ai_output_text=ai_output_text,
            request_substance=request_substance,
            authorization_chain=authorization_chain,
            regulatory_scaffolding=regulatory_scaffolding,
            causal_graph=causal_graph,
            job=job,
        )
        request_body = attach_signature(self._signing_key, request_body)
        try:
            response = await self._http.post("/execute", json=request_body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return attest_receipt(response, request_body)

    async def register_request_key(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.register_request_key`."""
        body = request_key_body(self._signing_key)
        try:
            response = await self._http.post(REQUEST_KEY_PATH, json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_response(response)

    async def rotate_request_key(self, new_signing_key: bytes) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.rotate_request_key`."""
        new_key = load_signing_key(new_signing_key)
        body = request_key_rotation_body(self._signing_key, new_key)
        result = await self._send_json("POST", REQUEST_KEY_PATH, body)
        self._signing_key = new_key
        return result

    async def clear_request_key(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.clear_request_key`."""
        result = await self._send_json(
            "DELETE", REQUEST_KEY_PATH, request_key_clear_body(self._signing_key)
        )
        self._signing_key = None
        return result

    async def verify_run(self, run_id: int) -> VerifyResponse:
        """Async version of :meth:`VerdifaxClient.verify_run`.

        Calls ``GET /runs/{run_id}/verify``. The server re-derives the
        manifest hash from the run's stored manifest fields and compares it
        with the recorded seal. For an independent offline check of the
        sealed audit bundle, use the open-source ``verdifax-verify`` CLI.
        """
        validate_run_id(run_id)
        try:
            response = await self._http.get(f"/runs/{run_id}/verify")
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return VerifyResponse.model_validate(parse_response(response))

    async def verify(
        self,
        manifest_hash: str,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
    ) -> NoReturn:
        """Unsupported since 0.6.0; always raises :class:`UnsupportedOperationError`.

        See :meth:`VerdifaxClient.verify`. Use :meth:`verify_run` instead.
        """
        raise UnsupportedOperationError(VERIFY_UNSUPPORTED_MESSAGE)

    async def execute(
        self,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        attested_context: Optional[AttestedContext] = None,
        reproducibility_context: Optional[Any] = None,
        ai_output_text: Optional[str] = None,
        request_substance: Optional[dict[str, Any]] = None,
        authorization_chain: Optional[dict[str, Any]] = None,
        regulatory_scaffolding: Optional[dict[str, Any]] = None,
        causal_graph: Optional[dict[str, Any]] = None,
        job: Optional[Mapping[str, Any]] = None,
    ) -> ExecutionManifest:
        """Async lower-level alternative returning just the manifest."""
        receipt = await self.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
            reproducibility_context=reproducibility_context,
            ai_output_text=ai_output_text,
            request_substance=request_substance,
            authorization_chain=authorization_chain,
            regulatory_scaffolding=regulatory_scaffolding,
            causal_graph=causal_graph,
            job=job,
        )
        return receipt.manifest

    async def get_run(self, run_id: int) -> Run:
        """Async version of :meth:`VerdifaxClient.get_run`."""
        validate_run_id(run_id)
        try:
            response = await self._http.get(f"/runs/{run_id}")
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return Run.model_validate(parse_response(response))

    async def list_runs(self, limit: Optional[int] = None, offset: Optional[int] = None) -> RunList:
        """Async version of :meth:`VerdifaxClient.list_runs`."""
        params = query_params(limit=limit, offset=offset)
        try:
            response = await self._http.get("/runs", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return RunList.model_validate(parse_response(response))

    async def search_runs(
        self,
        manifest_hash: Optional[str] = None,
        program_id: Optional[str] = None,
        route_id: Optional[str] = None,
        status: Optional[str] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> RunList:
        """Async version of :meth:`VerdifaxClient.search_runs`."""
        params = query_params(
            manifest_hash=manifest_hash,
            program_id=program_id,
            route_id=route_id,
            status=status,
            limit=limit,
            offset=offset,
            **{"from": from_, "to": to},
        )
        try:
            response = await self._http.get("/runs/search", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return RunList.model_validate(parse_response(response))

    async def export_runs(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> RunsExport:
        """Async version of :meth:`VerdifaxClient.export_runs`."""
        params = query_params(format="json", job_id=job_id, **{"from": from_, "to": to})
        try:
            response = await self._http.get("/runs/export", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return RunsExport.model_validate(parse_response(response))

    async def export_runs_csv(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> RunsExportCSV:
        """Async version of :meth:`VerdifaxClient.export_runs_csv`."""
        params = query_params(format="csv", job_id=job_id, **{"from": from_, "to": to})
        try:
            response = await self._http.get("/runs/export", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_export_csv(response)

    async def execute_batch(self, runs: Sequence[BatchRow]) -> ExecuteBatchResponse:
        """Async version of :meth:`VerdifaxClient.execute_batch`."""
        body = batch_body(runs, self._signing_key)
        try:
            response = await self._http.post("/execute/batch", json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return batch_response(parse_response(response), body)

    def job(self, job_id: str) -> AsyncJob:
        """Async version of :meth:`VerdifaxClient.job`: each step is a coroutine."""
        return AsyncJob(self, job_id)

    async def verify_determinism(
        self,
        payload: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        *,
        reproducibility_context: Optional[ReproducibilityContext] = None,
        ai_output_text: Optional[str] = None,
        attested_context: Optional[AttestedContext] = None,
        request_substance: Optional[dict[str, Any]] = None,
        authorization_chain: Optional[dict[str, Any]] = None,
        regulatory_scaffolding: Optional[dict[str, Any]] = None,
        causal_graph: Optional[dict[str, Any]] = None,
    ) -> DeterminismResult:
        """Async version of :func:`verdifax.research.verify_determinism`.

        One signature covers the request, and the server claims its nonce
        once. Both runs are recorded.
        """
        body = determinism_body(
            payload,
            program_id,
            route_id,
            registry_record_hash,
            reproducibility_context=reproducibility_context,
            ai_output_text=ai_output_text,
            attested_context=attested_context,
            request_substance=request_substance,
            authorization_chain=authorization_chain,
            regulatory_scaffolding=regulatory_scaffolding,
            causal_graph=causal_graph,
        )
        body = attach_signature(self._signing_key, body)
        try:
            response = await self._http.post("/execute/verify-determinism", json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return determinism_result(response, body)

    async def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> httpx.Response:
        try:
            return await self._http.get(path, params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc

    async def _get_json(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return parse_response(await self._get(path, params))

    async def _send_json(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        try:
            response = await self._http.request(method, path, json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_response(response)

    async def version(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.version`."""
        return await self._get_json("/version")

    async def get_openapi(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_openapi`."""
        return await self._get_json("/openapi.json")

    async def get_stats(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_stats`."""
        return await self._get_json("/stats")

    async def list_attestations(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_attestations`."""
        return await self._get_json("/attestations", query_params(limit=limit, offset=offset))

    async def get_attestation(self, attestation_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_attestation`."""
        validate_positive_id(attestation_id, "attestation_id")
        return await self._get_json(f"/attestations/{attestation_id}")

    async def get_allow_token(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_allow_token`."""
        return await self._get_json(run_path(run_id, "/allow-token"))

    async def get_deny_receipt(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_deny_receipt`."""
        return await self._get_json(run_path(run_id, "/deny-receipt"))

    async def get_ccv_halt_receipt(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_ccv_halt_receipt`."""
        return await self._get_json(run_path(run_id, "/ccv-halt-receipt"))

    async def get_macc_halt_receipt(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_macc_halt_receipt`."""
        return await self._get_json(run_path(run_id, "/macc-halt-receipt"))

    async def get_aivp_t4_halt_receipt(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_aivp_t4_halt_receipt`."""
        return await self._get_json(run_path(run_id, "/aivp-t4-halt-receipt"))

    async def get_attestation_gap_receipt(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_attestation_gap_receipt`."""
        return await self._get_json(run_path(run_id, "/attestation-gap-receipt"))

    async def get_ces_audit_record(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_ces_audit_record`."""
        return await self._get_json(run_path(run_id, "/ces-audit-record"))

    async def get_run_report(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_run_report`."""
        body = await self._get_json(run_path(run_id, "/report"))
        report: dict[str, Any] = body["report"]
        return report

    async def download_audit_pdf(self, run_id: int, format: str = "comprehensive") -> bytes:
        """Async version of :meth:`VerdifaxClient.download_audit_pdf`."""
        path = run_path(run_id, "/report.pdf")
        return checked_response(await self._get(path, {"format": format})).content

    async def get_run_artifacts(self, run_id: int) -> str:
        """Async version of :meth:`VerdifaxClient.get_run_artifacts`."""
        return checked_response(await self._get(run_path(run_id, "/artifacts"))).text

    async def get_public_bundle(self, run_id: int) -> str:
        """Async version of :meth:`VerdifaxClient.get_public_bundle`."""
        return checked_response(await self._get(run_path(run_id, "/bundle.json"))).text

    async def get_public_bundle_by_token(self, token: str) -> str:
        """Async version of :meth:`VerdifaxClient.get_public_bundle_by_token`."""
        if not token:
            raise ValidationError("token is required")
        path = f"/public/runs/{quote(token, safe='')}/bundle.json"
        return checked_response(await self._get(path)).text

    async def list_deletion_receipts(self, run_id: int) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.list_deletion_receipts`."""
        body = await self._get_json(run_path(run_id, "/deletion-receipts"))
        receipts: list[dict[str, Any]] = body.get("receipts") or []
        return receipts

    async def dcae_verify(self, bundle: Mapping[str, Any]) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.dcae_verify`."""
        return await self._send_json("POST", "/dcae/verify", dict(bundle))

    async def admin_create_key(self, name: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.admin_create_key`."""
        if not name:
            raise ValidationError("name is required")
        return await self._send_json("POST", "/admin/keys", {"name": name})

    async def admin_list_keys(self) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.admin_list_keys`."""
        body = await self._get_json("/admin/keys")
        keys: list[dict[str, Any]] = body.get("keys") or []
        return keys

    async def admin_revoke_key(self, key_id: int) -> None:
        """Async version of :meth:`VerdifaxClient.admin_revoke_key`."""
        validate_positive_id(key_id, "key_id")
        await self._send_json("DELETE", f"/admin/keys/{key_id}")

    async def admin_clear_request_key(self, key_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.admin_clear_request_key`."""
        validate_positive_id(key_id, "key_id")
        return await self._send_json("DELETE", f"/admin/keys/{key_id}/request-key")

    async def admin_erase(
        self,
        run_id: int,
        field_path: str,
        ciphertext_hash: str,
        dsar_reference: Optional[str] = None,
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.admin_erase`."""
        body = admin_erase_body(run_id, field_path, ciphertext_hash, dsar_reference)
        out = await self._send_json("POST", "/admin/erase", body)
        receipt: dict[str, Any] = out["deletion_receipt"]
        return receipt

    async def attest_claude_response(
        self,
        prompt: str,
        response: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        *,
        govern: bool = False,
        job: Optional[Mapping[str, Any]] = None,
    ) -> AttestationReceipt:
        """Async version of :meth:`VerdifaxClient.attest_claude_response`."""
        return await self.attest(
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            job=job,
            **provider_attest_args("anthropic", prompt, response, govern),
        )

    async def attest_openai_response(
        self,
        prompt: str,
        response: Union[str, bytes],
        program_id: str,
        route_id: str,
        registry_record_hash: str,
        *,
        govern: bool = False,
        job: Optional[Mapping[str, Any]] = None,
    ) -> AttestationReceipt:
        """Async version of :meth:`VerdifaxClient.attest_openai_response`."""
        return await self.attest(
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            job=job,
            **provider_attest_args("openai", prompt, response, govern),
        )

    # ── internal helpers ───────────────────────────────────────────────────
    @staticmethod
    def _build_execute_body(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return VerdifaxClient._build_execute_body(*args, **kwargs)


__all__ = ["AsyncVerdifaxClient"]
