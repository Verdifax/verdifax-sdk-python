"""Request building shared by the sync and async clients."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Mapping, Optional, Sequence, Union

import httpx

from ._signing import attach_signature
from ._transport import checked_response, parse_signed_response
from ._validation import job_block, normalize_payload, validate_hex64, validate_positive_id
from .exceptions import APIError, ValidationError, VerdifaxError
from .models import (
    AttestationReceipt,
    AttestedContext,
    ExecuteBatchResponse,
    ExecuteRequest,
    RunsExportCSV,
    is_provided,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAX_BATCH_ROWS = 1000

_HEADER_EXPORT_TOTAL = "X-Verdifax-Total"
_HEADER_EXPORT_TRUNCATED = "X-Verdifax-Truncated"

BatchRow = Union[ExecuteRequest, Mapping[str, Any]]


def query_params(**values: Any) -> dict[str, Any]:
    """Drop the unset values, so the server applies its defaults."""
    return {name: value for name, value in values.items() if value not in (None, "")}


def with_attested_flag(context: Mapping[str, Any]) -> dict[str, Any]:
    """Copy an ``attested_context`` mapping with ``attested`` derived from its fields."""
    provided = any(is_provided(value) for name, value in context.items() if name != "attested")
    return {**context, "attested": provided}


def attested_block(context: Any) -> dict[str, Any]:
    """Serialize an :class:`AttestedContext` or a mapping, with ``attested`` derived."""
    if isinstance(context, AttestedContext):
        return context.with_auto_attested().model_dump(exclude_none=True)
    return with_attested_flag(context)


def reproducibility_block(context: Any) -> dict[str, Any]:
    """Serialize a reproducibility context, with ``declared`` derived."""
    if hasattr(context, "with_auto_declared"):
        block: dict[str, Any] = context.with_auto_declared().model_dump(
            mode="json", exclude_none=True
        )
        return block
    if hasattr(context, "model_dump"):
        context = context.model_dump(mode="json", exclude_none=True)
    if not isinstance(context, Mapping):
        raise TypeError(
            "reproducibility_context must be a "
            "verdifax.research.ReproducibilityContext or a dict"
        )
    declared = any(
        is_provided(value) and value != [] for name, value in context.items() if name != "declared"
    )
    return {**context, "declared": declared}


def refuse_origin_hashes(substance: Optional[Mapping[str, Any]]) -> None:
    """Refuse the two ``request_substance`` fields the server computes.

    The server refuses them on ``POST /execute`` and in each row of a batch.
    """
    origin = (substance or {}).get("origin") or {}
    if origin.get("source_ip_hash") or origin.get("user_agent_hash"):
        raise ValidationError(
            "request_substance.origin.source_ip_hash and user_agent_hash are "
            "computed by the server and cannot be supplied"
        )


def attest_receipt(response: httpx.Response, request_body: Mapping[str, Any]) -> AttestationReceipt:
    """Read a ``POST /execute`` response.

    An error carries the signed text too, so a refused run can be checked
    the same way as a sealed one.
    """
    signed_request = request_body.get("signed_request")
    body = parse_signed_response(response, request_body)
    if "manifest" not in body:
        error = APIError(
            message="API response missing 'manifest'",
            status_code=response.status_code,
            response_body=body,
        )
        error.signed_request = signed_request
        raise error
    return AttestationReceipt.from_api_response(body, signed_request)


def batch_row(row: BatchRow) -> dict[str, Any]:
    """Turn one batch row into its JSON body.

    Only a ``job`` block is checked here. The server reports any other bad
    value in that row's result. A mapping takes the same names as
    ``attest()``, so a ``payload`` of ``str`` or ``bytes`` is sent the way
    ``attest()`` sends it.

    Raises:
        ValidationError: If the row's ``job`` block is invalid.
    """
    if isinstance(row, ExecuteRequest):
        body = row.model_dump_request()
    elif isinstance(row, Mapping):
        body = dict(row)
    else:
        raise ValidationError(
            f"each run must be a mapping or an ExecuteRequest, got {type(row).__name__}"
        )
    if isinstance(row, Mapping):
        payload = body.pop("payload", None)
        if payload is not None:
            payload_text, payload_b64 = normalize_payload(payload)
            if payload_text:
                body["payload_text"] = payload_text
            elif payload_b64:
                body["payload"] = payload_b64
    if body.get("attested_context") is not None:
        body["attested_context"] = attested_block(body["attested_context"])
    if body.get("reproducibility_context") is not None:
        body["reproducibility_context"] = reproducibility_block(body["reproducibility_context"])
    job = job_block(body.pop("job", None))
    if job is not None:
        body["job"] = job
    return body


def batch_body(
    runs: Sequence[BatchRow], key: "Optional[Ed25519PrivateKey]" = None
) -> dict[str, list[dict[str, Any]]]:
    """Build ``{"runs": [...]}``, each row signed on its own when there is a key.

    Raises:
        ValidationError: If there are no rows, more than ``MAX_BATCH_ROWS``,
            or an invalid ``job`` block.
    """
    if len(runs) == 0:
        raise ValidationError("execute_batch needs at least one run")
    if len(runs) > MAX_BATCH_ROWS:
        raise ValidationError(
            f"execute_batch accepts at most {MAX_BATCH_ROWS} runs, got {len(runs)}"
        )
    return {"runs": [attach_signature(key, batch_row(row)) for row in runs]}


def batch_response(
    parsed: Mapping[str, Any], request_body: Mapping[str, Any]
) -> ExecuteBatchResponse:
    """Read a batch response, giving each signed row its exact text.

    ``results`` holds one row for each row sent, in the same order.
    """
    results = [
        {**result, "signed_request": sent.get("signed_request")}
        for result, sent in zip(parsed.get("results") or [], request_body["runs"])
    ]
    return ExecuteBatchResponse.model_validate({**parsed, "results": results})


def run_path(run_id: int, suffix: str = "") -> str:
    """Validate ``run_id`` and build ``/runs/{run_id}`` with an optional suffix."""
    validate_positive_id(run_id, "run_id")
    return f"/runs/{run_id}{suffix}"


def parse_export_csv(response: httpx.Response) -> RunsExportCSV:
    """Read a CSV export with its counts.

    Raises:
        VerdifaxError: If the server does not report the counts, so that a
            cut-off export cannot pass for a complete one.
    """
    checked_response(response)
    total = response.headers.get(_HEADER_EXPORT_TOTAL, "")
    truncated = response.headers.get(_HEADER_EXPORT_TRUNCATED, "")
    if not total.isdecimal() or truncated not in ("true", "false"):
        raise VerdifaxError(
            f"the server did not report {_HEADER_EXPORT_TOTAL} and "
            f"{_HEADER_EXPORT_TRUNCATED}, so this CSV may be cut off; use export_runs instead"
        )
    return RunsExportCSV(csv=response.text, total=int(total), truncated=truncated == "true")


def admin_erase_body(
    run_id: int, field_path: str, ciphertext_hash: str, dsar_reference: Optional[str] = None
) -> dict[str, Any]:
    """Validate the inputs and build the body of ``POST /admin/erase``."""
    validate_positive_id(run_id, "run_id")
    if not field_path:
        raise ValidationError("field_path is required")
    validate_hex64(ciphertext_hash, "ciphertext_hash")
    body: dict[str, Any] = {
        "run_id": run_id,
        "field_path": field_path,
        "ciphertext_hash": ciphertext_hash,
    }
    if dsar_reference:
        body["dsar_reference"] = dsar_reference
    return body


def format_provider_payload(provider: str, prompt: str, response: Union[str, bytes]) -> str:
    """The payload the provider helpers attest.

    Canonical JSON with sorted keys, no extra whitespace and UTF-8 text,
    exactly ``{"prompt":...,"provider":...,"response":...}``. All four SDKs
    produce the same bytes, and a shared test vector holds them to it. A
    bytes ``response`` that is not UTF-8 is carried as ``base64:`` text.

    Raises:
        ValidationError: If the text has no UTF-8 form.
    """
    if isinstance(response, bytes):
        # Keep the bytes value typed as bytes for the except branch so
        # mypy can resolve b64encode's argument type. Reassigning
        # ``response`` to str inside the try-block narrows the union but
        # also widens the binding back to ``Union[str, bytes]`` in the
        # except branch, capturing the raw bytes separately keeps the
        # type discriminator clean.
        raw_bytes = response
        try:
            response = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            import base64

            response = "base64:" + base64.b64encode(raw_bytes).decode("ascii")
    payload = json.dumps(
        {"prompt": prompt, "provider": provider, "response": response},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        payload.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError("provider payload text cannot be encoded as UTF-8") from exc
    return payload


def provider_attest_args(
    provider: str, prompt: str, response: Union[str, bytes], govern: bool
) -> dict[str, Any]:
    """The ``attest()`` arguments of a provider helper.

    ``ai_output_text`` is set only with ``govern``, so AI output goes for
    review only when the caller asks.
    """
    if not response:
        raise ValidationError("response is required for attestation")
    return {
        "payload": format_provider_payload(provider, prompt, response),
        "attested_context": AttestedContext(actor_role="ai_assistant", model_provider=provider),
        "ai_output_text": governed_text(response) if govern else None,
    }


def governed_text(response: Union[str, bytes]) -> str:
    """Decode the response for AIVP governance.

    Governance reviews TEXT: a bytes response is decoded as UTF-8 and
    refused if it is not text, because silently governing a lossy
    decode would seal a review of something other than the output.
    """
    if isinstance(response, bytes):
        return response.decode("utf-8")
    return response


__all__ = [
    "BatchRow",
    "MAX_BATCH_ROWS",
    "admin_erase_body",
    "attest_receipt",
    "attested_block",
    "batch_body",
    "batch_response",
    "batch_row",
    "format_provider_payload",
    "governed_text",
    "parse_export_csv",
    "provider_attest_args",
    "query_params",
    "refuse_origin_hashes",
    "reproducibility_block",
    "run_path",
    "with_attested_flag",
]
