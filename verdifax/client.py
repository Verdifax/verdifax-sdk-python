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
from typing import Any, Mapping, NoReturn, Optional, Sequence, Type, Union
from urllib.parse import quote

import httpx

from ._requests import (
    POLICIES_PATH,
    BatchRow,
    activation_record,
    admin_erase_body,
    apply_policy_fields,
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
    refuse_origin_hashes,
    reproducibility_block,
    run_path,
)
from ._retry import DEFAULT_MAX_RETRIES, DEFAULT_RETRY_BASE_DELAY, RetryingClient
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
    job_block,
    normalize_payload,
    validate_hex64,
    validate_positive_id,
    validate_route_id,
    validate_run_id,
)
from ._version import __version__
from .exceptions import UnsupportedOperationError, ValidationError
from .jobs import Job
from .models import (
    AttestationReceipt,
    AttestedContext,
    ExecuteBatchResponse,
    ExecuteRequest,
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
    verify_determinism,
)

# The default points at production (2026-10-15, v0.5.1): an SDK whose
# three-line quickstart silently talked to localhost produced a
# connection-refused for every new user who followed the docs, and a
# silent wrong default is worse than an explicit one. Local
# development opts in via $VERDIFAX_BASE_URL or the base_url argument.
DEFAULT_BASE_URL = "https://api.verdifax.com"
# A sealed run makes two public-log entries and, with govern=True, an AI
# review; on a slow day that takes longer than 30 seconds, and a client
# that gave up then reported an error for a run the server went on to
# seal. 90 seconds keeps the SDK from being the limit.
DEFAULT_TIMEOUT = 90.0
ENV_BASE_URL = "VERDIFAX_BASE_URL"
ENV_BASE_URL_FALLBACK = "VERDIFAX_API_URL"
ENV_API_KEY = "VERDIFAX_API_KEY"
ENV_TIMEOUT_MS = "VERDIFAX_TIMEOUT_MS"
ENV_USER_AGENT = "VERDIFAX_USER_AGENT"
ENV_MAX_RETRIES = "VERDIFAX_MAX_RETRIES"

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


def env_base_url() -> Optional[str]:
    """``$VERDIFAX_BASE_URL``, then ``$VERDIFAX_API_URL``."""
    return os.environ.get(ENV_BASE_URL) or os.environ.get(ENV_BASE_URL_FALLBACK)


class VerdifaxClient:
    """Synchronous client for the Verdifax pipeline REST API.

    Args:
        base_url: Base URL of the Verdifax API. Falls back to
            ``$VERDIFAX_BASE_URL``, then ``$VERDIFAX_API_URL``, and finally
            to the production API at ``https://api.verdifax.com``.
        api_key: Optional API key sent as the ``X-Verdifax-Key`` header.
            Falls back to ``$VERDIFAX_API_KEY``.
        timeout: Request timeout in seconds. Defaults to 90.
        transport: Optional custom ``httpx.BaseTransport`` (useful for
            tests, e.g. with the ``respx`` library).
        signing_key: Optional 32 raw bytes of an Ed25519 private key. When
            set, every call to ``POST /execute`` is sent as signed text with
            a request signature, each row of a batch carries its own, and a
            determinism check carries one. ``activate_policy`` sends the
            key's approval of the change. Needs
            ``pip install "verdifax[signing]"``. The key is never sent to the
            server.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
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
            "User-Agent": user_agent or f"verdifax-python/{__version__}",
        }
        if self.api_key:
            headers["X-Verdifax-Key"] = self.api_key

        self._http = RetryingClient(
            max_retries=max_retries,
            retry_base_delay=retry_base_delay,
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
        request_substance: Optional[dict[str, Any]] = None,
        authorization_chain: Optional[dict[str, Any]] = None,
        regulatory_scaffolding: Optional[dict[str, Any]] = None,
        causal_graph: Optional[dict[str, Any]] = None,
        job: Optional[Mapping[str, Any]] = None,
        policy_context: Optional[Mapping[str, Any]] = None,
        expected_policy_hash: Optional[str] = None,
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
                AIVP stage. When supplied, the orchestrator routes
                the run through the configured AIVP adapter (the live
                Claude adapter in production) and seals the adapter ID
                plus the AI-output hash into the manifest. When
                omitted, the run is attested without AI-output
                governance.
            request_substance: Optional prompt, output, cost, latency and
                origin metadata. Leave out ``origin.source_ip_hash`` and
                ``origin.user_agent_hash``: the server computes those, and
                they are refused here.
            authorization_chain: Optional approval chain.
            regulatory_scaffolding: Optional regulatory metadata.
            causal_graph: Optional record of what led to this run.
            job: Optional place of this run in a job map:
                ``{"job_id", "step_id", "previous_record_hashes",
                "external_previous", "final"}``. The two lists are sorted
                and repeats removed for you. :meth:`job` builds this block.
            policy_context: Optional facts for the active policy's rules:
                ``actor_type``, ``mfa_satisfied``, ``session_age_seconds``,
                ``object_type``, ``object_id`` and ``classification``. An
                unknown key or a value the server refuses raises here.
                ``actor_type``, ``mfa_satisfied`` and ``session_age_seconds``
                describe the attested actor, so they need an
                ``attested_context`` that names one. A rule on these judges
                what was declared. It cannot show the declared facts are true.
            expected_policy_hash: Optional ``policy_hash`` of the policy this
                run must be decided under. When another policy is active the
                server refuses the run with 409.

        ``request_substance``, ``authorization_chain``,
        ``regulatory_scaffolding`` and ``causal_graph`` are recorded as
        supplied, and Verdifax does not check them.

        Returns:
            An :class:`AttestationReceipt` containing the sealed manifest,
            with ``record_hash`` and, when the call was signed,
            ``signed_request``.

        Raises:
            ValidationError: If any input fails client-side validation.
            StageError: If a specific pipeline stage rejected the request.
                ``record_hash`` on the error holds the hash of a refused or
                halted run, and ``signed_request`` the exact text of a signed
                one.
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
            response = self._http.post("/execute", json=request_body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return attest_receipt(response, request_body)

    def register_request_key(self) -> dict[str, Any]:
        """Register this client's public key on its API key.

        Sends the public key with a proof that this client holds the private
        key. From then on the server refuses a run on this API key without a
        request signature.

        Raises:
            ValidationError: If this client has no ``signing_key``.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        body = request_key_body(self._signing_key)
        try:
            response = self._http.post(REQUEST_KEY_PATH, json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_response(response)

    def rotate_request_key(self, new_signing_key: bytes) -> dict[str, Any]:
        """Replace the registered public key, approved by the current key.

        Sends the new public key with its proof, and an approval signed by
        this client's current key. After success this client signs with the
        new key. After a failure it keeps the current one.

        Args:
            new_signing_key: 32 raw bytes of the new Ed25519 private key.

        Raises:
            ValidationError: If this client has no ``signing_key``, or the
                new key is not 32 raw bytes.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        new_key = load_signing_key(new_signing_key)
        body = request_key_rotation_body(self._signing_key, new_key)
        result = self._send_json("POST", REQUEST_KEY_PATH, body)
        self._signing_key = new_key
        return result

    def clear_request_key(self) -> dict[str, Any]:
        """Clear the registered public key, so signatures stop being required.

        With a ``signing_key`` the current key approves the clear, which the
        server requires. After success this client drops its signing key and
        sends unsigned requests, because the server refuses a signature on an
        API key with no registered key. After a failure it keeps the key.
        """
        result = self._send_json(
            "DELETE", REQUEST_KEY_PATH, request_key_clear_body(self._signing_key)
        )
        self._signing_key = None
        return result

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
        """Lower-level alternative to :meth:`attest` that returns just the manifest.

        Use :meth:`attest` to keep ``signed_request`` from a sealed run. An
        error from this method carries it as :meth:`attest`'s does.
        """
        return self.attest(
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
        ).manifest

    def get_run(self, run_id: int) -> Run:
        """Fetch one run from ``GET /runs/{run_id}``.

        Raises:
            ValidationError: If ``run_id`` is not a positive integer.
            APIError: For a non-2xx response, for example 404 when the run
                does not exist or belongs to another key.
            ConnectionError: If the API was unreachable.
        """
        validate_run_id(run_id)
        try:
            response = self._http.get(f"/runs/{run_id}")
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return Run.model_validate(parse_response(response))

    def list_runs(self, limit: Optional[int] = None, offset: Optional[int] = None) -> RunList:
        """List this key's runs from ``GET /runs``. The server caps ``limit`` at 500."""
        params = query_params(limit=limit, offset=offset)
        try:
            response = self._http.get("/runs", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return RunList.model_validate(parse_response(response))

    def search_runs(
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
        """Search this key's runs with ``GET /runs/search``.

        ``manifest_hash`` matches a prefix. ``from_`` and ``to`` are RFC 3339
        times; the server ignores one it cannot parse here, unlike
        :meth:`export_runs`, which refuses it.
        """
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
            response = self._http.get("/runs/search", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return RunList.model_validate(parse_response(response))

    def export_runs(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> RunsExport:
        """List what the server holds for this key in a period, as parsed JSON.

        Calls ``GET /runs/export``. Failures are included, up to 10,000 rows;
        ``truncated`` is ``True`` when the period holds more. The list states
        what was stored, not a verdict, and a call that never reached
        Verdifax cannot appear in it.

        Args:
            from_: RFC 3339 time, inclusive.
            to: RFC 3339 time, exclusive. Defaults to the time of the request.
            job_id: Limit the export to the runs of one job.

        Raises:
            APIError: For a non-2xx response, for example 400 for a time the
                server cannot parse.
            ConnectionError: If the API was unreachable.
        """
        params = query_params(format="json", job_id=job_id, **{"from": from_, "to": to})
        try:
            response = self._http.get("/runs/export", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return RunsExport.model_validate(parse_response(response))

    def export_runs_csv(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> RunsExportCSV:
        """The same rows as :meth:`export_runs`: raw CSV text with its counts.

        ``total`` and ``truncated`` come from the response headers. Check
        ``truncated``: when ``True``, the CSV is missing rows for the period.

        Raises:
            VerdifaxError: If the server does not send those headers, so that
                a cut-off export cannot pass for a complete one.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        params = query_params(format="csv", job_id=job_id, **{"from": from_, "to": to})
        try:
            response = self._http.get("/runs/export", params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_export_csv(response)

    def execute_batch(self, runs: Sequence[BatchRow]) -> ExecuteBatchResponse:
        """Send up to 1,000 runs in one ``POST /execute/batch``.

        Each row is an :class:`ExecuteRequest`, or a mapping with the same
        names as :meth:`attest`. With a ``signing_key`` each row carries its
        own signature and nonce. Only a row's field names, its
        ``attested_context`` names, ``job`` block, ``policy_context`` and
        ``expected_policy_hash`` are checked here: the server reports any
        other bad value in that row's result, and a failed row does not
        raise.

        This is one POST and it is never retried. After a timeout the server
        may have run some or all of the rows.

        Raises:
            ValidationError: If there are no rows, more than 1,000, a field
                the server does not read, or an invalid ``attested_context``,
                ``job`` block, ``policy_context`` or ``expected_policy_hash``.
                Nothing is sent.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        body = batch_body(runs, self._signing_key)
        try:
            response = self._http.post("/execute/batch", json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return batch_response(parse_response(response), body)

    def job(self, job_id: str) -> Job:
        """Start a helper that runs the steps of one job and links them.

        Raises:
            ValidationError: If ``job_id`` is not a valid job name.
        """
        return Job(self, job_id)

    def verify_determinism(
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
        """Same as :func:`verdifax.research.verify_determinism` with this client."""
        return verify_determinism(
            self,
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

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> httpx.Response:
        try:
            return self._http.get(path, params=params)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc

    def _get_json(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return parse_response(self._get(path, params))

    def _send_json(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        try:
            response = self._http.request(method, path, json=body)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return parse_response(response)

    def version(self) -> dict[str, Any]:
        """Deploy details from ``GET /version``."""
        return self._get_json("/version")

    def get_openapi(self) -> dict[str, Any]:
        """The server's own API description, from ``GET /openapi.json``."""
        return self._get_json("/openapi.json")

    def get_stats(self) -> dict[str, Any]:
        """Run counts for this API key, from ``GET /stats``."""
        return self._get_json("/stats")

    def list_attestations(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> dict[str, Any]:
        """List attestation receipts from ``GET /attestations``, newest first."""
        return self._get_json("/attestations", query_params(limit=limit, offset=offset))

    def get_attestation(self, attestation_id: int) -> dict[str, Any]:
        """Fetch one attestation receipt from ``GET /attestations/{id}``."""
        validate_positive_id(attestation_id, "attestation_id")
        return self._get_json(f"/attestations/{attestation_id}")

    def get_allow_token(self, run_id: int) -> dict[str, Any]:
        """The sealed AllowToken of an admitted run."""
        return self._get_json(run_path(run_id, "/allow-token"))

    def get_deny_receipt(self, run_id: int) -> dict[str, Any]:
        """The sealed DenyReceipt of a ``pepg_deny`` run."""
        return self._get_json(run_path(run_id, "/deny-receipt"))

    def get_ccv_halt_receipt(self, run_id: int) -> dict[str, Any]:
        """The sealed CCVHaltReceipt of a ``ccv_halt`` run."""
        return self._get_json(run_path(run_id, "/ccv-halt-receipt"))

    def get_macc_halt_receipt(self, run_id: int) -> dict[str, Any]:
        """The sealed MACCHaltReceipt of a ``macc_halt`` run."""
        return self._get_json(run_path(run_id, "/macc-halt-receipt"))

    def get_aivp_t4_halt_receipt(self, run_id: int) -> dict[str, Any]:
        """The sealed halt receipt of a run the AIVP stage stopped."""
        return self._get_json(run_path(run_id, "/aivp-t4-halt-receipt"))

    def get_attestation_gap_receipt(self, run_id: int) -> dict[str, Any]:
        """The sealed AttestationGapReceipt of an ``attestation_gap`` run."""
        return self._get_json(run_path(run_id, "/attestation-gap-receipt"))

    def get_ces_audit_record(self, run_id: int) -> dict[str, Any]:
        """The CES audit record of a run."""
        return self._get_json(run_path(run_id, "/ces-audit-record"))

    def get_run_report(self, run_id: int) -> dict[str, Any]:
        """The audit report for a run, as JSON."""
        body = self._get_json(run_path(run_id, "/report"))
        report: dict[str, Any] = body["report"]
        return report

    def download_audit_pdf(self, run_id: int, format: str = "comprehensive") -> bytes:
        """The audit PDF bytes. ``format`` is brief, auditor, legal or comprehensive."""
        path = run_path(run_id, "/report.pdf")
        return checked_response(self._get(path, {"format": format})).content

    def get_run_artifacts(self, run_id: int) -> str:
        """The sealed audit bundle as the exact JSON text the server sent."""
        return checked_response(self._get(run_path(run_id, "/artifacts"))).text

    def get_public_bundle(self, run_id: int) -> str:
        """The public bundle of a record published by run id, as sent."""
        return checked_response(self._get(run_path(run_id, "/bundle.json"))).text

    def get_public_bundle_by_token(self, token: str) -> str:
        """The public bundle a share token points to, as sent."""
        if not token:
            raise ValidationError("token is required")
        path = f"/public/runs/{quote(token, safe='')}/bundle.json"
        return checked_response(self._get(path)).text

    def list_deletion_receipts(self, run_id: int) -> list[dict[str, Any]]:
        """The CRES deletion receipts bound to a run."""
        body = self._get_json(run_path(run_id, "/deletion-receipts"))
        receipts: list[dict[str, Any]] = body.get("receipts") or []
        return receipts

    def dcae_verify(self, bundle: Mapping[str, Any]) -> dict[str, Any]:
        """Submit a proof bundle to ``POST /dcae/verify``. No API key needed."""
        return self._send_json("POST", "/dcae/verify", dict(bundle))

    # ── policies ───────────────────────────────────────────────────────────
    def upload_policy(self, document: str) -> dict[str, Any]:
        """Store a policy document with ``POST /policies``. It changes nothing yet.

        Args:
            document: The policy's exact text. The server hashes these exact
                bytes as ``document_hash``, so the text is sent unchanged.

        Returns:
            The server's object: ``policy_id``, ``policy_version``,
            ``policy_hash``, ``document_hash`` and ``created_at``.

        Raises:
            ValidationError: If ``document`` is not a ``str``. A dict or list
                is refused, because serializing it would change the hash.
            APIError: For a non-2xx response, for example 400 for a field the
                server refuses.
            ConnectionError: If the API was unreachable.
        """
        return self._send_json("POST", POLICIES_PATH, policy_upload_body(document))

    def list_policies(self) -> dict[str, Any]:
        """List this key's policy documents with ``GET /policies``.

        Returns:
            The server's object: ``ok``, ``chain_id``,
            ``newest_activation_hash`` (64 zeros before the first change),
            ``active_document_hash`` (empty under the built-in policy) and
            ``policies``.
        """
        return self._get_json(POLICIES_PATH)

    def get_policy(self, document_hash: str) -> dict[str, Any]:
        """Read one stored document with ``GET /policies/{document_hash}``.

        Returns:
            The upload object plus ``document``, the exact text.

        Raises:
            ValidationError: If ``document_hash`` is not 64 lowercase hex
                characters.
            APIError: For a non-2xx response, for example 404.
            ConnectionError: If the API was unreachable.
        """
        return self._get_json(policy_path(document_hash))

    def test_policy(
        self,
        inputs: Mapping[str, Any],
        document: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> dict[str, Any]:
        """Show which rule would fire on sample inputs, with ``POST /policies/test``.

        Pass exactly one of ``document`` (exact text) and ``document_hash``
        (a stored document). It seals nothing.

        Returns:
            The server's object: ``ok``, ``sealed`` (always ``False``),
            ``outcome``, ``fired_rule_id`` and ``reason_code``.

        Raises:
            ValidationError: If both or neither of ``document`` and
                ``document_hash`` are given, or one of them is malformed.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        body = policy_test_body(inputs, document, document_hash)
        return self._send_json("POST", f"{POLICIES_PATH}/test", body)

    def get_policy_history(self) -> list[dict[str, Any]]:
        """The chain of this key's policy changes, oldest first.

        Calls ``GET /policies/history`` and returns the list as the server
        sent it. Save it with ``json.dump`` to a file and check it with
        ``verdifax-verify --policy-history FILE``.

        Raises:
            VerdifaxError: If the server did not send a list.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        return policy_history(parse_response(self._get(f"{POLICIES_PATH}/history")))

    def activate_policy(self, document_hash: str) -> dict[str, Any]:
        """Make a stored document the policy in force.

        Reads ``GET /policies`` for the chain and its newest change, then
        sends ``POST /policies/{document_hash}/activate`` naming that change.
        With a ``signing_key`` the request key approves the change, which the
        server requires once a request key is registered.

        Rolling back is activating an earlier document. It is one more change
        in the chain, so the change it undoes stays on the record.

        Returns:
            The ``activation`` object: the change record.

        Raises:
            ValidationError: If ``document_hash`` is not 64 lowercase hex
                characters.
            APIError: For a non-2xx response. A 409 means the chain moved
                (someone else changed it first), the document is not yet
                effective, or similar. It is not retried: read the policies
                again before deciding to repeat the change.
            VerdifaxError: If ``GET /policies`` gave no newest change, or no
                ``chain_id`` for a signing client.
            ConnectionError: If the API was unreachable.
        """
        path = policy_path(document_hash, "/activate")
        body = policy_activation_body(self._signing_key, self.list_policies(), document_hash)
        return activation_record(self._send_json("POST", path, body))

    def admin_create_key(self, name: str) -> dict[str, Any]:
        """Create an API key. The response holds its secret once."""
        if not name:
            raise ValidationError("name is required")
        return self._send_json("POST", "/admin/keys", {"name": name})

    def admin_list_keys(self) -> list[dict[str, Any]]:
        """List the API keys in the deployment, without their secrets."""
        body = self._get_json("/admin/keys")
        keys: list[dict[str, Any]] = body.get("keys") or []
        return keys

    def admin_revoke_key(self, key_id: int) -> None:
        """Revoke an API key by id."""
        validate_positive_id(key_id, "key_id")
        self._send_json("DELETE", f"/admin/keys/{key_id}")

    def admin_clear_request_key(self, key_id: int) -> dict[str, Any]:
        """Clear the request key of an API key whose holder lost it."""
        validate_positive_id(key_id, "key_id")
        return self._send_json("DELETE", f"/admin/keys/{key_id}/request-key")

    def admin_erase(
        self,
        run_id: int,
        field_path: str,
        ciphertext_hash: str,
        dsar_reference: Optional[str] = None,
    ) -> dict[str, Any]:
        """Shred one field and return its sealed deletion receipt."""
        body = admin_erase_body(run_id, field_path, ciphertext_hash, dsar_reference)
        out = self._send_json("POST", "/admin/erase", body)
        receipt: dict[str, Any] = out["deletion_receipt"]
        return receipt

    def attest_claude_response(
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
        """Same as :func:`verdifax.attest_claude_response` with this client."""
        return self.attest(
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            job=job,
            policy_context=policy_context,
            expected_policy_hash=expected_policy_hash,
            **provider_attest_args("anthropic", prompt, response, govern),
        )

    def attest_openai_response(
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
        """Same as :func:`verdifax.attest_openai_response` with this client."""
        return self.attest(
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
    def _build_execute_body(
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
    ) -> dict[str, Any]:
        validate_hex64(program_id, "program_id")
        validate_hex64(registry_record_hash, "registry_record_hash")
        validate_route_id(route_id)
        refuse_origin_hashes(request_substance)
        payload_text, payload_b64 = normalize_payload(payload)
        # If the caller supplied an attested_context block, auto-derive the
        # `attested` boolean from field presence (matching the orchestrator's
        # convention) so callers don't have to remember to set it.
        if attested_context is not None:
            attested_context = attested_context.with_auto_attested()
        request = ExecuteRequest(
            payload_text=payload_text or None,
            payload=payload_b64 or None,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
            attested_context=attested_context,
            reproducibility_context=(
                None
                if reproducibility_context is None
                else reproducibility_block(reproducibility_context)
            ),
            ai_output_text=ai_output_text or None,
            request_substance=request_substance,
            authorization_chain=authorization_chain,
            regulatory_scaffolding=regulatory_scaffolding,
            causal_graph=causal_graph,
            job=job_block(job),
        )
        body = request.model_dump_request()
        body["policy_context"] = policy_context
        body["expected_policy_hash"] = expected_policy_hash
        return apply_policy_fields(body)


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "VERIFY_UNSUPPORTED_MESSAGE",
    "VerdifaxClient",
    "env_base_url",
]
