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
from typing import Any, AsyncGenerator, Mapping, NoReturn, Optional, Sequence, Type, Union
from urllib.parse import quote

import httpx

from ._requests import (
    ACCOUNT_PATH,
    ACCOUNT_POLICIES_PATH,
    POLICIES_PATH,
    BatchRow,
    account_key_body,
    account_key_path,
    activation_record,
    admin_account_body,
    admin_accounts,
    admin_erase_body,
    admin_key_body,
    attest_receipt,
    batch_body,
    batch_response,
    parse_export_csv,
    policy_activation_body,
    policy_history,
    policy_path,
    policy_test_body,
    policy_upload_body,
    provider_attest_args,
    query_params,
    refuse_unsigned_account_change,
    run_path,
)
from ._retry import AsyncRetryingClient, DEFAULT_MAX_RETRIES, DEFAULT_RETRY_BASE_DELAY
from ._signals import (
    FEED_KEYS_PATH,
    FOLLOW_WAIT_DEFAULT,
    WEBHOOKS_PATH,
    SignalsRequest,
    deliveries_request,
    failure_receipt_path,
    feed_key_body,
    feed_key_path,
    follow_async,
    follow_request,
    signal_page,
    signals_path,
    signals_request,
    webhook_body,
    webhook_path,
)
from ._signoffs import (
    APPROVERS_PATH,
    SIGNOFF_HISTORY_PATH,
    SignOffTargetLike,
    ApproverKeyLike,
    approver_body,
    approver_path,
    newest_signoff_path,
    prepare_signoff,
    run_signoffs_path,
    signoff_body,
    signoff_list,
    signoff_record,
    submit_signoff_path,
)
from ._signing import (
    ACCOUNT_REQUEST_KEY_PATH,
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
    AccountRunsExport,
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
            determinism check carries one. ``activate_policy`` and
            ``activate_account_policy`` send the key's approval of the
            change. Needs
            ``pip install "verdifax[signing]"``. The key is never sent to the
            server.
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
        policy_context: Optional[Mapping[str, Any]] = None,
        expected_policy_hash: Optional[str] = None,
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
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
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
        policy_context: Optional[Mapping[str, Any]] = None,
        expected_policy_hash: Optional[str] = None,
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
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
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
        policy_context: Optional[Mapping[str, Any]] = None,
        expected_policy_hash: Optional[str] = None,
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
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
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

    # ── policies ───────────────────────────────────────────────────────────
    async def upload_policy(self, document: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.upload_policy`."""
        return await self._send_json("POST", POLICIES_PATH, policy_upload_body(document))

    async def list_policies(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_policies`."""
        return await self._get_json(POLICIES_PATH)

    async def get_policy(self, document_hash: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_policy`."""
        return await self._get_json(policy_path(document_hash))

    async def test_policy(
        self,
        inputs: Mapping[str, Any],
        document: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.test_policy`. It seals nothing."""
        body = policy_test_body(inputs, document, document_hash)
        return await self._send_json("POST", f"{POLICIES_PATH}/test", body)

    async def get_policy_history(self) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.get_policy_history`.

        Save the list with ``json.dump`` to a file and check it with
        ``verdifax-verify --policy-history FILE``.
        """
        return policy_history(parse_response(await self._get(f"{POLICIES_PATH}/history")))

    async def activate_policy(self, document_hash: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.activate_policy`.

        Rolling back is activating an earlier document. A 409 raises
        :class:`APIError` and is not retried.
        """
        path = policy_path(document_hash, "/activate")
        listing = await self.list_policies()
        body = policy_activation_body(self._signing_key, listing, document_hash)
        return activation_record(await self._send_json("POST", path, body))

    # ── account (owner key) ────────────────────────────────────────────────
    async def get_account(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_account`."""
        return await self._get_json(ACCOUNT_PATH)

    async def create_account_key(
        self, name: str, expires_at: Optional[str] = None
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.create_account_key`."""
        body = account_key_body(name, expires_at)
        return await self._send_json("POST", f"{ACCOUNT_PATH}/keys", body)

    async def list_account_keys(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_account_keys`."""
        return await self._get_json(f"{ACCOUNT_PATH}/keys")

    async def revoke_account_key(self, key_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.revoke_account_key`."""
        return await self._send_json("DELETE", account_key_path(key_id))

    async def register_account_request_key(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.register_account_request_key`."""
        body = request_key_body(self._signing_key, "register_account_request_key")
        return await self._send_json("POST", ACCOUNT_REQUEST_KEY_PATH, body)

    async def clear_account_request_key(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.clear_account_request_key`."""
        result = await self._send_json(
            "DELETE", ACCOUNT_REQUEST_KEY_PATH, request_key_clear_body(self._signing_key)
        )
        self._signing_key = None
        return result

    async def list_account_runs(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> RunList:
        """Async version of :meth:`VerdifaxClient.list_account_runs`."""
        params = query_params(limit=limit, offset=offset)
        return RunList.model_validate(await self._get_json(f"{ACCOUNT_PATH}/runs", params))

    async def export_account_runs(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> AccountRunsExport:
        """Async version of :meth:`VerdifaxClient.export_account_runs`."""
        params = query_params(format="json", job_id=job_id, **{"from": from_, "to": to})
        body = await self._get_json(f"{ACCOUNT_PATH}/runs/export", params)
        return AccountRunsExport.model_validate(body)

    async def export_account_runs_csv(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> RunsExportCSV:
        """Async version of :meth:`VerdifaxClient.export_account_runs_csv`."""
        params = query_params(format="csv", job_id=job_id, **{"from": from_, "to": to})
        return parse_export_csv(
            await self._get(f"{ACCOUNT_PATH}/runs/export", params), "export_account_runs"
        )

    async def upload_account_policy(self, document: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.upload_account_policy`."""
        return await self._send_json("POST", ACCOUNT_POLICIES_PATH, policy_upload_body(document))

    async def list_account_policies(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_account_policies`."""
        return await self._get_json(ACCOUNT_POLICIES_PATH)

    async def test_account_policy(
        self,
        inputs: Mapping[str, Any],
        document: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.test_account_policy`. It seals nothing."""
        body = policy_test_body(inputs, document, document_hash)
        return await self._send_json("POST", f"{ACCOUNT_POLICIES_PATH}/test", body)

    async def get_account_policy_history(self) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.get_account_policy_history`."""
        response = await self._get(f"{ACCOUNT_POLICIES_PATH}/history")
        return policy_history(parse_response(response))

    async def get_account_policy(self, document_hash: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_account_policy`."""
        return await self._get_json(policy_path(document_hash, base=ACCOUNT_POLICIES_PATH))

    async def activate_account_policy(self, document_hash: str) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.activate_account_policy`.

        The owner key's request key signs the change. A 409 raises
        :class:`APIError` and is not retried.
        """
        path = policy_path(document_hash, "/activate", ACCOUNT_POLICIES_PATH)
        refuse_unsigned_account_change(self._signing_key)
        listing = await self.list_account_policies()
        body = policy_activation_body(
            self._signing_key, listing, document_hash, f"GET {ACCOUNT_POLICIES_PATH}"
        )
        return activation_record(await self._send_json("POST", path, body))

    # ── sign-off ───────────────────────────────────────────────────────────
    async def register_approver(self, name: str, approver_key: ApproverKeyLike) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.register_approver`.

        The proof is computed on this machine, or a ready-made proof is
        verified here and refused before sending if it does not verify. Only
        the public key, the name and the proof are sent.
        """
        body = approver_body(name, approver_key, self._signing_key)
        return await self._send_json("POST", APPROVERS_PATH, body)

    async def list_approvers(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_approvers`."""
        return await self._get_json(APPROVERS_PATH)

    async def revoke_approver(self, approver_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.revoke_approver`."""
        return await self._send_json("DELETE", approver_path(approver_id))

    async def sign_off(
        self,
        target: SignOffTargetLike,
        decision: str,
        approver_key: bytes,
        note: Optional[str] = None,
        as_owner: bool = False,
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.sign_off`.

        Every input is checked before anything is sent. The note's text is
        never sent, only its SHA-256. A 409 raises :class:`APIError` and is
        not retried.
        """
        newest_path, submit_path = newest_signoff_path(as_owner), submit_signoff_path(as_owner)
        prepared = prepare_signoff(target, decision, approver_key, note, self._signing_key)
        newest = await self._get_json(newest_path)
        body = signoff_body(prepared, newest, f"GET {newest_path}")
        answer = await self._send_json("POST", submit_path, body)
        return signoff_record(answer, body)

    async def get_signoffs(self, run_id: int, as_owner: bool = False) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.get_signoffs`."""
        path = run_signoffs_path(run_id, as_owner)
        return signoff_list(parse_response(await self._get(path)), "sign-off list")

    async def get_newest_signoff(self, as_owner: bool = False) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_newest_signoff`."""
        return await self._get_json(newest_signoff_path(as_owner))

    async def get_signoff_history(self) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.get_signoff_history`."""
        body = parse_response(await self._get(SIGNOFF_HISTORY_PATH))
        return signoff_list(body, "sign-off history")

    # ── signal feed ────────────────────────────────────────────────────────
    async def _read_signals(self, request: SignalsRequest) -> dict[str, Any]:
        try:
            response = await self._http.get(
                request.path, params=request.params, timeout=request.timeout
            )
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return signal_page(parse_response(response), f"GET {request.path}")

    async def get_signals(
        self,
        after: int = 0,
        limit: Optional[int] = None,
        wait: int = 0,
        as_owner: bool = False,
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_signals`.

        The HTTP timeout of this call is at least ``wait`` plus 30 seconds.
        """
        request = signals_request(after, limit, wait, as_owner, self.timeout)
        return await self._read_signals(request)

    def follow_signals(
        self, after: int = 0, wait: int = FOLLOW_WAIT_DEFAULT, as_owner: bool = False
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Async version of :meth:`VerdifaxClient.follow_signals`: an async generator.

        Use it with ``async for``. The arguments are checked when this is
        called, before anything is sent. An error carries ``last_sequence``,
        the last sequence read.
        """
        follow_request(after, wait, as_owner)

        async def read_page(place: int) -> dict[str, Any]:
            request = signals_request(place, None, wait, as_owner, self.timeout)
            return await self._read_signals(request)

        return follow_async(read_page, after, wait, f"GET {signals_path(as_owner)}")

    async def create_feed_key(self, name: str, expires_at: Optional[str] = None) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.create_feed_key`.

        A feed key reads the account's feed and nothing else.
        """
        return await self._send_json("POST", FEED_KEYS_PATH, feed_key_body(name, expires_at))

    async def revoke_feed_key(self, id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.revoke_feed_key`."""
        return await self._send_json("DELETE", feed_key_path(id))

    async def create_webhook(
        self, url: str, types: Optional[Sequence[str]] = None
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.create_webhook`."""
        return await self._send_json("POST", WEBHOOKS_PATH, webhook_body(url, types))

    async def list_webhooks(self) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_webhooks`."""
        return await self._get_json(WEBHOOKS_PATH)

    async def delete_webhook(self, id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.delete_webhook`."""
        return await self._send_json("DELETE", webhook_path(id))

    async def list_webhook_deliveries(self, id: int, limit: Optional[int] = None) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.list_webhook_deliveries`."""
        path, params = deliveries_request(id, limit)
        return await self._get_json(path, params or None)

    async def get_failure_receipt(self, run_id: int) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.get_failure_receipt`."""
        return await self._get_json(failure_receipt_path(run_id))

    async def admin_create_account(
        self, name: str, tier: Optional[str] = None, expires_at: Optional[str] = None
    ) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.admin_create_account`."""
        body = admin_account_body(name, tier, expires_at)
        return await self._send_json("POST", "/admin/accounts", body)

    async def admin_list_accounts(self) -> list[dict[str, Any]]:
        """Async version of :meth:`VerdifaxClient.admin_list_accounts`."""
        return admin_accounts(await self._get_json("/admin/accounts"))

    async def admin_create_key(self, name: str, account_id: Optional[int] = None) -> dict[str, Any]:
        """Async version of :meth:`VerdifaxClient.admin_create_key`."""
        return await self._send_json("POST", "/admin/keys", admin_key_body(name, account_id))

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
        policy_context: Optional[Mapping[str, Any]] = None,
        expected_policy_hash: Optional[str] = None,
    ) -> AttestationReceipt:
        """Async version of :meth:`VerdifaxClient.attest_claude_response`."""
        return await self.attest(
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            job=job,
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
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
        policy_context: Optional[Mapping[str, Any]] = None,
        expected_policy_hash: Optional[str] = None,
    ) -> AttestationReceipt:
        """Async version of :meth:`VerdifaxClient.attest_openai_response`."""
        return await self.attest(
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            job=job,
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
            **provider_attest_args("openai", prompt, response, govern),
        )

    # ── internal helpers ───────────────────────────────────────────────────
    @staticmethod
    def _build_execute_body(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return VerdifaxClient._build_execute_body(*args, **kwargs)


__all__ = ["AsyncVerdifaxClient"]
