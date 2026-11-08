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
from typing import Any, Generator, Mapping, NoReturn, Optional, Sequence, Type, Union
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
    refuse_unsigned_account_change,
    reproducibility_block,
    run_path,
)
from ._retry import DEFAULT_MAX_RETRIES, DEFAULT_RETRY_BASE_DELAY, RetryingClient
from ._signals import (
    FEED_KEYS_PATH,
    FOLLOW_WAIT_DEFAULT,
    WEBHOOKS_PATH,
    SignalsRequest,
    deliveries_request,
    failure_receipt_path,
    feed_key_body,
    feed_key_path,
    follow,
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
    publication_path,
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
    AccountRunsExport,
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

    # ── account (owner key) ────────────────────────────────────────────────
    # An account is a company. Every API key belongs to one account for life.
    # These methods need the account's owner key, which manages the account
    # and cannot run anything: the server refuses it (403) on every other
    # route that needs an API key. The account number is a label Verdifax
    # assigned, not a verified company identity.
    def get_account(self) -> dict[str, Any]:
        """The owner key's account, from ``GET /account``.

        Returns:
            The server's object: ``ok``, ``account_id`` (such as
            ``account-7``), ``id``, ``name``, ``tier``, ``created_at``,
            ``member_keys``, ``owner_keys`` and ``chain_id``, the chain of
            the account's policy changes.
        """
        return self._get_json(ACCOUNT_PATH)

    def create_account_key(self, name: str, expires_at: Optional[str] = None) -> dict[str, Any]:
        """Create a member key in the account with ``POST /account/keys``.

        The key takes the account's tier and stays in this account for life.
        On a trial account it needs a request key before it can run, as
        every trial key does.

        Args:
            name: The key's name.
            expires_at: Optional cutoff, RFC 3339 or ``YYYY-MM-DD``.

        Returns:
            The key with ``secret``, which is shown this once, and
            ``request_key_required``.

        Raises:
            ValidationError: If ``name`` is empty, or ``expires_at`` is not a
                ``str``.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        return self._send_json("POST", f"{ACCOUNT_PATH}/keys", account_key_body(name, expires_at))

    def list_account_keys(self) -> dict[str, Any]:
        """The account's keys, without their secrets, from ``GET /account/keys``.

        Returns:
            The server's object: ``ok``, ``account_id`` and ``keys``. Each key
            has ``owner``, ``run_count``, ``revoked`` and, when it has one,
            ``expires_at``.
        """
        return self._get_json(f"{ACCOUNT_PATH}/keys")

    def revoke_account_key(self, key_id: int) -> dict[str, Any]:
        """Revoke one of the account's member keys with ``DELETE /account/keys/{id}``.

        Raises:
            ValidationError: If ``key_id`` is not a positive integer.
            APIError: For a non-2xx response, for example 404 for a key
                outside the account or an owner key.
            ConnectionError: If the API was unreachable.
        """
        return self._send_json("DELETE", account_key_path(key_id))

    def register_account_request_key(self) -> dict[str, Any]:
        """Register this client's public key on the owner key.

        Sends ``POST /account/request-key`` with the same body as
        :meth:`register_request_key`. The owner key's request key signs every
        change to the account's policy.

        Raises:
            ValidationError: If this client has no ``signing_key``.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        body = request_key_body(self._signing_key, "register_account_request_key")
        return self._send_json("POST", ACCOUNT_REQUEST_KEY_PATH, body)

    def clear_account_request_key(self) -> dict[str, Any]:
        """Clear the owner key's request key with ``DELETE /account/request-key``.

        Works as :meth:`clear_request_key`: with a ``signing_key`` the current
        key approves the clear, and after success this client drops its
        signing key. Until another request key is registered, the account's
        policy cannot be changed.
        """
        result = self._send_json(
            "DELETE", ACCOUNT_REQUEST_KEY_PATH, request_key_clear_body(self._signing_key)
        )
        self._signing_key = None
        return result

    def list_account_runs(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> RunList:
        """List the runs of every key in the account from ``GET /account/runs``.

        The server caps ``limit`` at 500. The list covers the runs the
        account's keys made through Verdifax, not runs made elsewhere.
        """
        params = query_params(limit=limit, offset=offset)
        return RunList.model_validate(self._get_json(f"{ACCOUNT_PATH}/runs", params))

    def export_account_runs(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> AccountRunsExport:
        """Export the account's runs in a period with ``GET /account/runs/export``.

        Takes the same arguments as :meth:`export_runs` and covers every key
        in the account. The answer adds ``account_id``,
        ``account_policy_documents``, ``account_policy_history`` and
        ``signoffs``, the account's chain of sign-offs. It
        states what was stored, not a verdict, and covers the runs the
        account's keys made through Verdifax, not runs made elsewhere.

        Raises:
            APIError: For a non-2xx response, for example 400 for a time the
                server cannot parse.
            ConnectionError: If the API was unreachable.
        """
        params = query_params(format="json", job_id=job_id, **{"from": from_, "to": to})
        body = self._get_json(f"{ACCOUNT_PATH}/runs/export", params)
        return AccountRunsExport.model_validate(body)

    def export_account_runs_csv(
        self,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> RunsExportCSV:
        """The same rows as :meth:`export_account_runs`, as raw CSV text with its counts.

        Raises:
            VerdifaxError: If the server does not send the count headers, so
                that a cut-off export cannot pass for a complete one.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        params = query_params(format="csv", job_id=job_id, **{"from": from_, "to": to})
        return parse_export_csv(
            self._get(f"{ACCOUNT_PATH}/runs/export", params), "export_account_runs"
        )

    def upload_account_policy(self, document: str) -> dict[str, Any]:
        """Store an account policy document with ``POST /account/policies``.

        Works as :meth:`upload_policy`. It changes nothing until it is
        activated. An account policy is the customer's own: Verdifax did not
        write, review or approve it.
        """
        return self._send_json("POST", ACCOUNT_POLICIES_PATH, policy_upload_body(document))

    def list_account_policies(self) -> dict[str, Any]:
        """List the account's policy documents with ``GET /account/policies``.

        Returns:
            The same object as :meth:`list_policies`, with ``chain_id`` the
            account's chain, such as ``account-7``.
        """
        return self._get_json(ACCOUNT_POLICIES_PATH)

    def test_account_policy(
        self,
        inputs: Mapping[str, Any],
        document: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> dict[str, Any]:
        """Show which rule would fire on sample inputs, with ``POST /account/policies/test``.

        Works as :meth:`test_policy`, on the account's documents. It seals
        nothing.
        """
        body = policy_test_body(inputs, document, document_hash)
        return self._send_json("POST", f"{ACCOUNT_POLICIES_PATH}/test", body)

    def get_account_policy_history(self) -> list[dict[str, Any]]:
        """The chain of the account's policy changes, oldest first.

        Calls ``GET /account/policies/history`` and returns the list as the
        server sent it.

        Raises:
            VerdifaxError: If the server did not send a list.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        return policy_history(parse_response(self._get(f"{ACCOUNT_POLICIES_PATH}/history")))

    def get_account_policy(self, document_hash: str) -> dict[str, Any]:
        """Read one of the account's documents with ``GET /account/policies/{document_hash}``.

        Raises:
            ValidationError: If ``document_hash`` is not 64 lowercase hex
                characters.
            APIError: For a non-2xx response, for example 404.
            ConnectionError: If the API was unreachable.
        """
        return self._get_json(policy_path(document_hash, base=ACCOUNT_POLICIES_PATH))

    def activate_account_policy(self, document_hash: str) -> dict[str, Any]:
        """Make a stored account document the account's policy in force.

        Reads ``GET /account/policies`` for the account's chain and its
        newest change, then sends ``POST /account/policies/{document_hash}/activate``
        signed by this client's ``signing_key``, the owner key's request key,
        exactly as :meth:`activate_policy` signs. Every key in the account
        must then pass this policy on top of its own, and a run is admitted
        only when both allow it.

        Returns:
            The ``activation`` object: the change record.

        Raises:
            ValidationError: If ``document_hash`` is not 64 lowercase hex
                characters, or this client has no ``signing_key``: the server
                refuses an unsigned account policy change.
            APIError: For a non-2xx response. A 409 is not retried.
            VerdifaxError: If ``GET /account/policies`` gave no newest change
                or no ``chain_id``.
            ConnectionError: If the API was unreachable.
        """
        path = policy_path(document_hash, "/activate", ACCOUNT_POLICIES_PATH)
        refuse_unsigned_account_change(self._signing_key)
        listing = self.list_account_policies()
        body = policy_activation_body(
            self._signing_key, listing, document_hash, f"GET {ACCOUNT_POLICIES_PATH}"
        )
        return activation_record(self._send_json("POST", path, body))

    # ── sign-off ───────────────────────────────────────────────────────────
    # An approver signs approve or reject on one exact result with a key the
    # account's owner registered. A sign-off shows the holder of a registered
    # approver key signed that decision on that exact result, and Verdifax
    # logged it on the public log. It does not show the review was careful,
    # the result right, or who the person is, and it gates nothing on its
    # own. Methods that serve both a member route and an /account route take
    # as_owner=True for the owner key's route.
    def register_approver(self, name: str, approver_key: ApproverKeyLike) -> dict[str, Any]:
        """Register an approver key to the account with ``POST /account/approvers``.

        Needs the account's owner key. The proof that the key's holder has
        its private key is computed on this machine: pass the approver's 32
        raw private key bytes, or, so the private key never leaves the
        approver's machine, the answer of :func:`verdifax.approver_key_proof`
        that the approver built there. A ready-made proof is verified here,
        and one that does not verify is refused before anything is sent.
        Only the public key, the name and the proof are sent.

        An approver key is never a request key in the same account, so the
        key that requested a run can never sign it off; the server answers
        409 for such a key.

        Args:
            name: The approver's name, as the account lists it. At most 200
                bytes. It is a label, not a verified identity.
            approver_key: The approver's private key, or
                ``{"public_key": ..., "proof": ...}``.

        Returns:
            The approver: ``id``, ``public_key``, ``name``, ``account_id``,
            ``registered_at`` and ``revoked``.

        Raises:
            ValidationError: If ``name`` is empty or too long, the key is not
                valid, a ready-made proof does not verify, or the key is this
                client's own ``signing_key``, before anything is sent.
            APIError: For a non-2xx response, for example 409.
            ConnectionError: If the API was unreachable.
        """
        body = approver_body(name, approver_key, self._signing_key)
        return self._send_json("POST", APPROVERS_PATH, body)

    def list_approvers(self) -> dict[str, Any]:
        """The account's approver keys, revoked ones included, from ``GET /account/approvers``.

        Needs the account's owner key.

        Returns:
            The server's object: ``ok``, ``account_id`` and ``approvers``.
        """
        return self._get_json(APPROVERS_PATH)

    def revoke_approver(self, approver_id: int) -> dict[str, Any]:
        """Revoke an approver key with ``DELETE /account/approvers/{id}``.

        Needs the account's owner key. The key's earlier sign-offs stay on
        the record.

        Raises:
            ValidationError: If ``approver_id`` is not a positive integer.
            APIError: For a non-2xx response, for example 404 for no such
                active approver in the account.
            ConnectionError: If the API was unreachable.
        """
        return self._send_json("DELETE", approver_path(approver_id))

    def sign_off(
        self,
        target: SignOffTargetLike,
        decision: str,
        approver_key: bytes,
        note: Optional[str] = None,
        as_owner: bool = False,
    ) -> dict[str, Any]:
        """Sign a decision on one exact result with an approver key, and submit it.

        Checks every input first, then reads the account's chain and its
        newest sign-off from ``GET /signoffs/newest``, signs on this machine,
        and sends ``POST /signoffs``. With ``as_owner=True`` it uses the owner
        key's routes, ``GET /account/signoffs/newest`` and
        ``POST /account/signoffs``. Any key in the account can submit; the
        approver's signature, not the calling key, decides who signed.

        The approver's private key never leaves this machine. The note's
        text is never sent: the client sends only its SHA-256 as
        ``note_hash``, so keep the text yourself to show it matches.

        A later sign-off on the same result supersedes the earlier one, and
        nothing is deleted.

        Args:
            target: A :class:`SignOffTarget`, or a mapping with ``kind``
                (``record``, ``receipt`` or ``job``), ``run_id``, ``digest``
                and, for a job only, ``job_id``. ``digest`` is what the
                result's public-log entry covers. A record's digest is its
                ``bundle_anchor`` ``anchored_digest``, in the JSON
                :meth:`get_run_artifacts` returns. A receipt's digest is its
                ``hash``, from :meth:`get_deny_receipt` or the other receipt
                methods. A job's digest is its final step's record digest.
            decision: ``approve`` or ``reject``.
            approver_key: The 32 raw bytes of a registered approver's Ed25519
                private key. It must not be this client's ``signing_key``.
            note: Optional text of the approver's note. Only its hash is sent.
                An empty string is refused; leave ``note`` out for no note,
                and the body then carries no ``note_hash``.
            as_owner: Use the owner key's routes.

        Returns:
            The sign-off record, in the form ``verdifax-verify --signoff``
            reads, with its ``signoff_hash``, ``sequence`` and ``anchor``.

        Raises:
            ValidationError: For a bad target, decision, note (an empty one
                included), approver key or ``as_owner``, before anything is
                sent.
            VerdifaxError: If the newest route gave no account chain or no
                usable newest sign-off, or the record sent back is not the
                sign-off sent.
            APIError: For a non-2xx response. A 409 means the chain moved,
                or the target is not a result of the account or its digest
                is not the one its public-log entry covers. It is not retried.
            ConnectionError: If the API was unreachable.
        """
        newest_path, submit_path = newest_signoff_path(as_owner), submit_signoff_path(as_owner)
        prepared = prepare_signoff(target, decision, approver_key, note, self._signing_key)
        newest = self._get_json(newest_path)
        body = signoff_body(prepared, newest, f"GET {newest_path}")
        return signoff_record(self._send_json("POST", submit_path, body), body)

    def publish_run(self, run_id: int) -> dict[str, Any]:
        """Make one of the account's records public with ``POST /account/runs/{id}/publish``.

        Needs the account's owner key; the record may have been made by any
        key of the account. The record is served on a random link, the same
        link a later publish restores. The decision is sealed as a run
        publication (``verdifax.run-publication.v1``), anchored on the public
        log and placed in the account's signal feed as a ``run.published``
        event. Idempotent: a record already public is answered as it is, with
        ``publication`` ``None``. The service's admin key cannot publish
        another key's record.

        Returns:
            The server's object: ``ok``, ``run_id``, ``public``,
            ``public_bundle_url`` while public, ``verify_url`` and
            ``publication``, the sealed record or ``None``. Save
            ``publication`` as sent; ``verdifax-verify --signals`` reads it
            since v0.24.0.

        Raises:
            ValidationError: If ``run_id`` is not a positive integer.
            APIError: For a non-2xx response, for example 404 for a run of
                another account.
            ConnectionError: If the API was unreachable.
        """
        return self._send_json("POST", publication_path(run_id, "publish"))

    def unpublish_run(self, run_id: int) -> dict[str, Any]:
        """Withdraw one of the account's records from its public link with ``POST /account/runs/{id}/unpublish``.

        Both public routes answer 404 for it afterwards; its link is kept,
        so a later :meth:`publish_run` restores it. Sealed and placed in the
        feed as a ``run.unpublished`` event. Needs the account's owner key.
        Idempotent for a run that is not public.

        Returns:
            The same object as :meth:`publish_run`, with ``public`` false.
        """
        return self._send_json("POST", publication_path(run_id, "unpublish"))

    def get_signoffs(self, run_id: int, as_owner: bool = False) -> list[dict[str, Any]]:
        """The sign-offs on one run, oldest first, from ``GET /runs/{id}/signoffs``.

        A member key reads the runs it made. With ``as_owner=True`` the
        owner key reads any run of the account from
        ``GET /account/runs/{id}/signoffs``. Save the list with ``json.dump``
        and check it with ``verdifax-verify --signoff FILE``; the latest
        sign-off is the decision in force.

        Raises:
            ValidationError: If ``run_id`` is not a positive integer.
            VerdifaxError: If the server did not send a list.
            APIError: For a non-2xx response, for example 404.
            ConnectionError: If the API was unreachable.
        """
        path = run_signoffs_path(run_id, as_owner)
        return signoff_list(parse_response(self._get(path)), "sign-off list")

    def get_newest_signoff(self, as_owner: bool = False) -> dict[str, Any]:
        """What an approver signs against, from ``GET /signoffs/newest``.

        With ``as_owner=True`` it reads ``GET /account/signoffs/newest``.

        Returns:
            The server's object: ``ok``, ``chain_id`` (such as
            ``account-7``), ``newest_signoff_hash`` (64 zeros before the
            first sign-off) and ``sequence``.
        """
        return self._get_json(newest_signoff_path(as_owner))

    def get_signoff_history(self) -> list[dict[str, Any]]:
        """The account's whole chain of sign-offs, oldest first.

        Calls ``GET /account/signoffs/history``, which needs the owner key,
        and returns the list as the server sent it. Save it with
        ``json.dump`` and check it with ``verdifax-verify --signoff-history FILE``.

        Raises:
            VerdifaxError: If the server did not send a list.
            APIError: For a non-2xx response.
            ConnectionError: If the API was unreachable.
        """
        body = parse_response(self._get(SIGNOFF_HISTORY_PATH))
        return signoff_list(body, "sign-off history")

    # ── signal feed ────────────────────────────────────────────────────────
    # The feed lists every control signal Verdifax recorded for the account,
    # in order, each with its sealed entry. It cannot show a signal Verdifax
    # never recorded. A feed key reads GET /signals and nothing else; the
    # owner key reads the same feed with as_owner=True. A webhook delivery is
    # a copy: the pull feed and the public log are the record. The checks and
    # the paging live in verdifax/_signals.py.
    def _read_signals(self, request: SignalsRequest) -> dict[str, Any]:
        try:
            response = self._http.get(request.path, params=request.params, timeout=request.timeout)
        except httpx.HTTPError as exc:
            raise wrap_transport_error(exc) from exc
        return signal_page(parse_response(response), f"GET {request.path}")

    def get_signals(
        self,
        after: int = 0,
        limit: Optional[int] = None,
        wait: int = 0,
        as_owner: bool = False,
    ) -> dict[str, Any]:
        """Read one page of the account's feed from ``GET /signals``.

        A feed key reads ``GET /signals``. With ``as_owner=True`` the owner
        key reads the same feed from ``GET /account/signals``. Events come
        oldest first, each a CloudEvent whose ``data`` carries ``kind``,
        ``sequence``, ``previous_signal_hash``, ``event_hash`` and the sealed
        ``entry``. When there is no event after ``after`` the server holds
        the request open up to ``wait`` seconds for the next. The HTTP
        timeout of this call is at least ``wait`` plus 30 seconds, whatever
        the client's own.

        Args:
            after: The last sequence read; 0 reads from the start.
            limit: At most this many events, 1 to 500. The server's default
                is 100.
            wait: Seconds to wait for an event, 0 to 25.
            as_owner: Use the owner key's route.

        Returns:
            The page: ``events``, ``next_after`` (pass it as ``after`` next)
            and ``newest``, the account's newest sequence.

        Raises:
            ValidationError: For a bad ``after``, ``limit``, ``wait`` or
                ``as_owner``, before anything is sent.
            VerdifaxError: If the answer is not a feed page.
            APIError: For a non-2xx response, for example 429 for a key
                that already holds two waits open.
            ConnectionError: If the API was unreachable.
        """
        return self._read_signals(signals_request(after, limit, wait, as_owner, self.timeout))

    def follow_signals(
        self, after: int = 0, wait: int = FOLLOW_WAIT_DEFAULT, as_owner: bool = False
    ) -> Generator[dict[str, Any], None, None]:
        """Follow the account's feed from ``after``, yielding each event in order.

        Reads page after page with :meth:`get_signals`, going on from each
        page's ``next_after``, so no event is skipped or repeated, and waits
        up to ``wait`` seconds on the server when there is nothing new. A
        failed read is retried with the client's normal retry policy. Stop by
        leaving the loop. The arguments are checked when this is called,
        before anything is sent.

        Raises:
            ValidationError: For a bad ``after``, ``wait`` or ``as_owner``.
            VerdifaxError: Any error a read raises, or a page that would
                skip or repeat an event, with ``last_sequence`` set to the
                last sequence read: pass it as ``after`` to go on.
        """
        follow_request(after, wait, as_owner)

        def read_page(place: int) -> dict[str, Any]:
            return self._read_signals(signals_request(place, None, wait, as_owner, self.timeout))

        return follow(read_page, after, wait, f"GET {signals_path(as_owner)}")

    def create_feed_key(self, name: str, expires_at: Optional[str] = None) -> dict[str, Any]:
        """Create a feed key in the account with ``POST /account/feed-keys``.

        Needs the account's owner key. A feed key reads the account's feed
        with :meth:`get_signals` and :meth:`follow_signals`, and nothing else.

        Args:
            name: The key's name. At most 200 bytes.
            expires_at: Optional cutoff, RFC 3339.

        Returns:
            The key with ``secret``, which is shown this once, ``id``,
            ``name``, ``hint``, ``tier`` and ``account_id``.

        Raises:
            ValidationError: If ``name`` is empty, or ``expires_at`` is not a
                ``str``, before anything is sent.
        """
        return self._send_json("POST", FEED_KEYS_PATH, feed_key_body(name, expires_at))

    def revoke_feed_key(self, id: int) -> dict[str, Any]:
        """Revoke a feed key with ``DELETE /account/feed-keys/{id}``.

        Needs the account's owner key.

        Raises:
            ValidationError: If ``id`` is not a positive integer.
            APIError: For a non-2xx response, for example 404 if ``id`` is not
                a feed key of the account.
        """
        return self._send_json("DELETE", feed_key_path(id))

    def create_webhook(self, url: str, types: Optional[Sequence[str]] = None) -> dict[str, Any]:
        """Subscribe a webhook with ``POST /account/webhooks``.

        Needs the account's owner key. Each event of the named kinds is sent
        to ``url``, signed under the Standard Webhooks scheme; check each
        delivery with :func:`verdifax.verify_webhook`. A delivery is a copy:
        the pull feed and the public log are the record.

        Args:
            url: An ``https://`` address. The server checks it too.
            types: Signal kinds, each at most once. ``None`` or an empty list
                takes every kind.

        Returns:
            The subscription with ``secret`` (``whsec_`` and base64), which is
            shown this once, ``id``, ``url``, ``types``, ``created_at`` and
            ``hint``.

        Raises:
            ValidationError: If ``url`` does not start ``https://`` or
                ``types`` is not a list of distinct signal kinds, before
                anything is sent.
            APIError: For a non-2xx response: 400 for an address or type the
                server refuses, 409 when the account holds ten already, 503
                when the deployment has no KMS key.
        """
        return self._send_json("POST", WEBHOOKS_PATH, webhook_body(url, types))

    def list_webhooks(self) -> dict[str, Any]:
        """The account's webhooks, without their secrets, from ``GET /account/webhooks``."""
        return self._get_json(WEBHOOKS_PATH)

    def delete_webhook(self, id: int) -> dict[str, Any]:
        """Delete a webhook with ``DELETE /account/webhooks/{id}``.

        Raises:
            ValidationError: If ``id`` is not a positive integer.
        """
        return self._send_json("DELETE", webhook_path(id))

    def list_webhook_deliveries(self, id: int, limit: Optional[int] = None) -> dict[str, Any]:
        """A webhook's delivery log from ``GET /account/webhooks/{id}/deliveries``.

        Args:
            id: The webhook's id.
            limit: At most this many deliveries, 1 to 500. The server's
                default is 50.

        Returns:
            The server's object: ``ok``, ``webhook_id`` and ``deliveries``,
            each with ``sequence``, ``status``, ``attempts``,
            ``last_status_code``, ``last_error`` and ``created_at``.

        Raises:
            ValidationError: If ``id`` is not a positive integer or ``limit``
                is not 1 to 500, before anything is sent.
        """
        path, params = deliveries_request(id, limit)
        return self._get_json(path, params or None)

    def get_failure_receipt(self, run_id: int) -> dict[str, Any]:
        """The sealed failure receipt of a run that failed with a server error.

        Calls ``GET /runs/{run_id}/failure-receipt`` with a member key.

        Returns:
            The receipt document: ``ok``, ``run_id``, ``failure_receipt`` and,
            when present, ``receipt_anchor`` and ``receipt_context``.

        Raises:
            ValidationError: If ``run_id`` is not a positive integer.
            APIError: For a non-2xx response, for example 404 for a failed run
                from before failure receipts.
        """
        return self._get_json(failure_receipt_path(run_id))

    def admin_create_account(
        self, name: str, tier: Optional[str] = None, expires_at: Optional[str] = None
    ) -> dict[str, Any]:
        """Create an account and its first owner key with ``POST /admin/accounts``.

        Args:
            name: The account's name.
            tier: ``trial`` (the server's default) or ``production``.
            expires_at: Optional cutoff for the owner key, RFC 3339 or
                ``YYYY-MM-DD``.

        Returns:
            The server's object: ``ok``, ``account`` (as :meth:`get_account`)
            and ``owner_key`` (as :meth:`create_account_key`, with its
            ``secret`` shown this once).
        """
        body = admin_account_body(name, tier, expires_at)
        return self._send_json("POST", "/admin/accounts", body)

    def admin_list_accounts(self) -> list[dict[str, Any]]:
        """List every account with its key counts, from ``GET /admin/accounts``."""
        return admin_accounts(self._get_json("/admin/accounts"))

    def admin_create_key(self, name: str, account_id: Optional[int] = None) -> dict[str, Any]:
        """Create an API key. The response holds its secret once.

        Args:
            name: The key's name.
            account_id: Optional number of an existing account (``7`` for
                ``account-7``) to put this customer key in. Without it the
                key gets an account of its own. A key never changes account.

        Raises:
            ValidationError: If ``name`` is empty or ``account_id`` is not a
                positive integer.
        """
        return self._send_json("POST", "/admin/keys", admin_key_body(name, account_id))

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
