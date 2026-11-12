"""Request building shared by the sync and async clients."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote
from typing import TYPE_CHECKING, Any, Mapping, Optional, Sequence, Union

import httpx

from ._signing import attach_signature, owner_change_signature, policy_activation_signature
from ._transport import checked_response, parse_signed_response
from ._validation import (
    ATTESTED_CONTEXT_FIELDS,
    EXECUTE_FIELDS,
    check_policy_actor,
    job_block,
    normalize_payload,
    policy_context_block,
    refuse_unknown_keys,
    validate_hex64,
    validate_positive_id,
)
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
    """Copy an ``attested_context`` mapping with ``attested`` derived from its fields.

    Raises:
        ValidationError: If the mapping has a key the server does not read.
    """
    refuse_unknown_keys(context, ATTESTED_CONTEXT_FIELDS, "attested_context")
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


def apply_policy_fields(body: dict[str, Any]) -> dict[str, Any]:
    """Check ``policy_context`` and ``expected_policy_hash`` in a built body.

    ``body`` is changed in place and returned. Each is left out when it is
    ``None``. They go into the body before it is serialized, so a signed
    request covers them.

    Raises:
        ValidationError: If ``policy_context`` has an unknown key or a value
            the server refuses, sets an actor value with no attested actor,
            or ``expected_policy_hash`` is not 64 lowercase hex characters.
    """
    context = policy_context_block(body.pop("policy_context", None))
    if context is not None:
        check_policy_actor(context, body.get("attested_context"))
        body["policy_context"] = context
    expected = body.pop("expected_policy_hash", None)
    if expected is not None:
        validate_hex64(expected, "expected_policy_hash")
        body["expected_policy_hash"] = expected
    return body


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

    Only the names of a row's fields and of its ``attested_context``, the
    ``job`` block, ``policy_context`` and ``expected_policy_hash`` are
    checked here. The server reports any other bad value in that row's
    result. A mapping takes the same names as ``attest()``, so a ``payload``
    of ``str`` or ``bytes`` is sent the way ``attest()`` sends it.

    Raises:
        ValidationError: If the row has a field the server does not read, or
            its ``attested_context`` keys, ``job`` block, ``policy_context`` or
            ``expected_policy_hash`` are invalid. A misspelt field must never
            be dropped.
    """
    if isinstance(row, ExecuteRequest):
        body = row.model_dump_request()
    elif isinstance(row, Mapping):
        refuse_unknown_keys(row, EXECUTE_FIELDS, "run")
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
    return apply_policy_fields(body)


def batch_body(
    runs: Sequence[BatchRow], key: "Optional[Ed25519PrivateKey]" = None
) -> dict[str, list[dict[str, Any]]]:
    """Build ``{"runs": [...]}``, each row signed on its own when there is a key.

    Raises:
        ValidationError: If there are no rows, more than ``MAX_BATCH_ROWS``,
            a row with a field the server does not read, or an invalid
            ``attested_context``, ``job`` block, ``policy_context`` or
            ``expected_policy_hash``.
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


def report_request(
    format: str, ai_output_text: Optional[str], fallback: Optional[str] = None
) -> tuple[str, Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """The method, query and body of an audit PDF request.

    Without ``ai_output_text`` it is a GET with the format. With it, a POST
    carrying the format and the AI's exact answer, which the server prints
    on the report's first page, marked as supplied by the caller, only when
    its SHA-256 is the hash the record seals; any other text is refused
    with a 422 and nothing is printed. Verdifax stores only the hash.

    A format the server does not know is refused with a 400 that lists the
    four names, unless ``fallback="comprehensive"`` asks for the
    comprehensive report instead.
    """
    if ai_output_text is None:
        params: dict[str, Any] = {"format": format}
        if fallback is not None:
            params["fallback"] = fallback
        return "GET", params, None
    if not isinstance(ai_output_text, str) or ai_output_text == "":
        raise ValidationError("ai_output_text must be the AI's exact answer, a non-empty string")
    body: dict[str, Any] = {"format": format}
    if fallback is not None:
        body["fallback"] = fallback
    body["ai_output_text"] = ai_output_text
    return "POST", None, body


def public_report_path(token: str) -> str:
    """``/public/runs/{token}/report.pdf`` for a share token."""
    if not token:
        raise ValidationError("token is required")
    return f"/public/runs/{quote(token, safe='')}/report.pdf"


def run_path(run_id: int, suffix: str = "") -> str:
    """Validate ``run_id`` and build ``/runs/{run_id}`` with an optional suffix."""
    validate_positive_id(run_id, "run_id")
    return f"/runs/{run_id}{suffix}"


def parse_export_csv(response: httpx.Response, json_method: str = "export_runs") -> RunsExportCSV:
    """Read a CSV export with its counts.

    ``json_method`` names the JSON form to use instead, in the error.

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
            f"{_HEADER_EXPORT_TRUNCATED}, so this CSV may be cut off; use {json_method} instead"
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


POLICIES_PATH = "/policies"
# The account's policies: the same bodies and answers as the key's, under
# the owner key.
ACCOUNT_POLICIES_PATH = "/account/policies"


def policy_path(document_hash: str, suffix: str = "", base: str = POLICIES_PATH) -> str:
    """Validate ``document_hash`` and build ``{base}/{document_hash}``.

    ``base`` is ``/policies`` for the key's own policies, or
    ``/account/policies`` for the account's.
    """
    validate_hex64(document_hash, "document_hash")
    return f"{base}/{document_hash}{suffix}"


def _policy_document(document: Any) -> str:
    """Refuse a document that is not exact text.

    The server hashes the exact bytes, so a dict or list cannot be sent:
    serializing it here would decide the text, and so the hash.
    """
    if not isinstance(document, str):
        raise ValidationError(
            "document must be the policy's exact text as a str, got "
            f"{type(document).__name__}; serializing an object would change its hash"
        )
    try:
        document.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError("document is not valid Unicode, so it has no exact bytes") from exc
    return document


def policy_upload_body(document: Any) -> dict[str, str]:
    """The body of ``POST /policies``: the document exactly as given."""
    return {"document": _policy_document(document)}


def policy_test_body(
    inputs: Mapping[str, Any],
    document: Optional[str] = None,
    document_hash: Optional[str] = None,
    ai_output_declared: bool = False,
) -> dict[str, Any]:
    """The body of ``POST /policies/test``, with exactly one of the two documents.

    ``ai_output_declared`` says whether the request being tried declares an
    AI output, as ``ai_output_text`` does on a run: a policy that requires an
    AI review refuses a step without one. It is sent only when true.

    Raises:
        ValidationError: If both or neither of ``document`` and
            ``document_hash`` are given, ``document`` is not a ``str``,
            ``document_hash`` is not 64 lowercase hex characters, or
            ``inputs`` is not a mapping.
    """
    if (document is None) == (document_hash is None):
        raise ValidationError("test_policy needs exactly one of document and document_hash")
    if not isinstance(inputs, Mapping):
        raise ValidationError(f"inputs must be a mapping, got {type(inputs).__name__}")
    body: dict[str, Any] = {"inputs": dict(inputs)}
    if document_hash is not None:
        validate_hex64(document_hash, "document_hash")
        body["document_hash"] = document_hash
    else:
        body["document"] = _policy_document(document)
    if not isinstance(ai_output_declared, bool):
        raise ValidationError("ai_output_declared must be a bool")
    if ai_output_declared:
        body["ai_output_declared"] = True
    return body


def policy_history(body: Any) -> list[dict[str, Any]]:
    """Read ``GET /policies/history``: the list of changes, oldest first.

    Raises:
        VerdifaxError: If the server did not send a list.
    """
    if not isinstance(body, list):
        raise VerdifaxError("the server's policy history is not a list")
    return body


def policy_activation_body(
    key: "Optional[Ed25519PrivateKey]",
    listing: Mapping[str, Any],
    document_hash: str,
    source: str = f"GET {POLICIES_PATH}",
) -> dict[str, Any]:
    """The body of ``POST /policies/{document_hash}/activate``.

    ``listing`` is the answer of ``GET /policies``. With a key, the body
    carries its approval of the change. An account's change takes the same
    body, built from ``GET /account/policies``; ``source`` names the route
    the listing came from in the error.

    Raises:
        VerdifaxError: If the listing has no usable newest change, or, with a
            key, no ``chain_id`` to sign.
    """
    previous: Any = listing.get("newest_activation_hash")
    try:
        validate_hex64(previous, "newest_activation_hash")
    except ValidationError as exc:
        raise VerdifaxError(f"{source} did not return a usable newest change: {exc}") from exc
    body: dict[str, Any] = {"previous_activation_hash": previous}
    if key is None:
        return body
    chain_id = listing.get("chain_id")
    if not isinstance(chain_id, str) or not chain_id:
        raise VerdifaxError(f"{source} returned no chain_id, so the change cannot be signed")
    body["signature"] = policy_activation_signature(key, chain_id, document_hash, previous)
    return body


def activation_record(response_body: Mapping[str, Any]) -> dict[str, Any]:
    """The change record from an activation answer.

    Raises:
        VerdifaxError: If the answer has no ``activation`` object.
    """
    record = response_body.get("activation")
    if not isinstance(record, dict):
        raise VerdifaxError("the server's answer has no activation record")
    return record


ACCOUNT_PATH = "/account"
ACCOUNT_TIME_ZONE_PATH = "/account/time-zone"


def _account_name(name: Any) -> str:
    """Refuse an empty name. The server checks its length, at most 200 bytes."""
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("name is required")
    return name


def _optional_text(value: Any, field_name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a str, got {type(value).__name__}")


def account_key_body(name: str, expires_at: Optional[str] = None) -> dict[str, str]:
    """The body of ``POST /account/keys``.

    ``expires_at`` is RFC 3339 or ``YYYY-MM-DD``, and the server checks it.

    Raises:
        ValidationError: If ``name`` is empty, or ``expires_at`` is not a
            ``str``.
    """
    body = {"name": _account_name(name)}
    _optional_text(expires_at, "expires_at")
    if expires_at:
        body["expires_at"] = expires_at
    return body


def admin_account_body(
    name: str, tier: Optional[str] = None, expires_at: Optional[str] = None
) -> dict[str, str]:
    """The body of ``POST /admin/accounts``.

    ``tier`` is ``trial`` (the server's default) or ``production``, and the
    server checks it, as it does ``expires_at``.

    Raises:
        ValidationError: If ``name`` is empty, or ``tier`` or ``expires_at``
            is not a ``str``.
    """
    body = {"name": _account_name(name)}
    _optional_text(tier, "tier")
    _optional_text(expires_at, "expires_at")
    if tier:
        body["tier"] = tier
    if expires_at:
        body["expires_at"] = expires_at
    return body


def admin_key_body(name: str, account_id: Optional[int] = None) -> dict[str, Any]:
    """The body of ``POST /admin/keys``.

    ``account_id`` is the number of an existing account, the ``id`` of
    ``POST /admin/accounts`` (``7`` for ``account-7``). Without it the server
    gives the key an account of its own. A key never changes account.

    Raises:
        ValidationError: If ``name`` is empty, or ``account_id`` is not a
            positive ``int``.
    """
    if not name:
        raise ValidationError("name is required")
    body: dict[str, Any] = {"name": name}
    if account_id is not None:
        validate_positive_id(account_id, "account_id")
        body["account_id"] = account_id
    return body


def account_key_path(key_id: int) -> str:
    """Validate ``key_id`` and build ``/account/keys/{key_id}``."""
    validate_positive_id(key_id, "key_id")
    return f"{ACCOUNT_PATH}/keys/{key_id}"


def refuse_unsigned_account_change(key: "Optional[Ed25519PrivateKey]") -> None:
    """Refuse an account policy change from a client with no signing key.

    The server refuses every unsigned change to an account's policy (403),
    because that policy binds every key in the account.

    Raises:
        ValidationError: If ``key`` is ``None``.
    """
    if key is None:
        raise ValidationError(
            "activate_account_policy needs a client with a signing_key: the owner key's "
            "request key must sign every change to the account's policy"
        )


# The owner's two settings, as their routes name them, and the change each
# signature names (the orchestrator's settingRoutes).
ACCOUNT_SETTINGS_PATH = "/account/settings"
ACCOUNT_SETTING_CHANGES = {
    "owner-replacement": "setting.owner_replacement",
    "verdifax-deletion": "setting.verdifax_deletion",
}
ACCOUNT_SETTING_VALUES = ("allowed", "blocked")
# The change an owner's deletion signature names: the feed kind of its tombstone.
RUN_DELETED_CHANGE = "run.deleted"
# An account's label as records seal it (the orchestrator's AccountLabel).
_ACCOUNT_LABEL = re.compile(r"account-[1-9][0-9]*")


def refuse_unsigned_owner_change(
    key: "Optional[Ed25519PrivateKey]", method: str
) -> "Ed25519PrivateKey":
    """Refuse an owner's setting or deletion from a client with no signing key.

    The server refuses an owner's change that its request key did not sign
    (400), so that Verdifax, which never holds that key, cannot make one.
    Returns the key.

    Raises:
        ValidationError: If ``key`` is ``None``.
    """
    if key is None:
        raise ValidationError(
            f"{method} needs a client with a signing_key: the owner key's request key "
            "must sign every setting and deletion the owner decides"
        )
    return key


def account_setting_change(setting: Any, value: Any) -> str:
    """Check a setting and its value, and return the change the owner signs.

    Raises:
        ValidationError: If ``setting`` is not ``owner-replacement`` or
            ``verdifax-deletion``, or ``value`` is not ``allowed`` or
            ``blocked``.
    """
    if not isinstance(setting, str) or setting not in ACCOUNT_SETTING_CHANGES:
        raise ValidationError(
            "setting must be one of " f"{', '.join(ACCOUNT_SETTING_CHANGES)}, got {setting!r}"
        )
    if not isinstance(value, str) or value not in ACCOUNT_SETTING_VALUES:
        raise ValidationError(
            f"value must be one of {', '.join(ACCOUNT_SETTING_VALUES)}, got {value!r}"
        )
    return ACCOUNT_SETTING_CHANGES[setting]


def account_setting_path(setting: str) -> str:
    """``/account/settings/{setting}`` for a checked setting."""
    return f"{ACCOUNT_SETTINGS_PATH}/{setting}"


def check_account_label(account_id: Any) -> str:
    """Check an account label the caller passed, such as ``account-7``.

    Raises:
        ValidationError: If it is not ``account-`` and a positive number.
    """
    if not isinstance(account_id, str) or not _ACCOUNT_LABEL.fullmatch(account_id):
        raise ValidationError(
            "account_id must be the account's label, such as account-7, as GET /account "
            f"returns it, got {account_id!r}"
        )
    return account_id


def account_label(account: Mapping[str, Any]) -> str:
    """The account's label from the answer of ``GET /account``.

    Raises:
        VerdifaxError: If the answer has no usable ``account_id``, so no
            change can be signed for it.
    """
    label = account.get("account_id")
    if not isinstance(label, str) or not _ACCOUNT_LABEL.fullmatch(label):
        raise VerdifaxError(
            f"GET {ACCOUNT_PATH} returned no usable account_id, so the change cannot be signed"
        )
    return label


def account_setting_body(
    key: "Ed25519PrivateKey", account: str, change: str, value: str
) -> dict[str, Any]:
    """The body of ``PUT /account/settings/{setting}``: the value and the owner's signature."""
    return {"value": value, "owner_signature": owner_change_signature(key, account, change, value)}


def check_run_deletion(run_id: Any, record_hash: Any) -> None:
    """Check the run and the record hash an owner's deletion signs.

    Raises:
        ValidationError: If ``run_id`` is not a positive integer, or
            ``record_hash`` is not 64 lowercase hex characters.
    """
    validate_positive_id(run_id, "run_id")
    validate_hex64(record_hash, "record_hash")


def run_deletion_path(run_id: int) -> str:
    """``/account/runs/{run_id}/delete`` for a checked run id."""
    return f"{ACCOUNT_PATH}/runs/{run_id}/delete"


def run_deletion_body(
    key: "Ed25519PrivateKey", account: str, run_id: int, record_hash: str
) -> dict[str, Any]:
    """The body of ``POST /account/runs/{run_id}/delete``.

    The owner signs ``run.deleted`` over ``RUN_ID:RECORD_HASH``, the run in
    decimal and the record's hash, so the tombstone names the exact record.
    """
    subject = f"{run_id}:{record_hash}"
    return {
        "record_hash": record_hash,
        "owner_signature": owner_change_signature(key, account, RUN_DELETED_CHANGE, subject),
    }


def _check_owner_record(
    record: Mapping[str, Any],
    sent: Mapping[str, Any],
    key: "Ed25519PrivateKey",
    what: str,
    expected: Mapping[str, Any],
) -> None:
    """Check that a sealed owner's change carries what was sent, signed by ``key``.

    Raises:
        VerdifaxError: If a field in ``expected``, ``decided_by``, or the
            owner's signature, its time, nonce or public key, differs.
    """
    for name, value in {**expected, "decided_by": "owner"}.items():
        if record.get(name) != value:
            raise VerdifaxError(f"the server's {what} has another {name} than was sent")
    sealed = record.get("owner_signature")
    signed = sent["owner_signature"]
    if not isinstance(sealed, Mapping):
        raise VerdifaxError(f"the server's {what} carries no owner_signature")
    for name in ("signature", "signed_at", "nonce"):
        if sealed.get(name) != signed[name]:
            raise VerdifaxError(
                f"the server's {what} has another owner_signature {name} than was sent"
            )
    public_key = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    if sealed.get("public_key") != public_key:
        raise VerdifaxError(
            f"the server's {what} names another owner_signature public_key than this "
            "client's signing_key"
        )


def account_setting_answer(
    response_body: Any, sent: Mapping[str, Any], change: str, key: "Ed25519PrivateKey"
) -> dict[str, Any]:
    """The answer of ``PUT /account/settings/{setting}``, checked against what was sent.

    ``account_change`` is ``None`` when the value was already set. Otherwise
    the sealed record must carry the change, the value, ``decided_by``
    ``owner`` and the owner's signature that was sent.

    Raises:
        VerdifaxError: If the answer has no ``account_change``, or the record
            does not carry what was sent.
    """
    if not isinstance(response_body, dict) or "account_change" not in response_body:
        raise VerdifaxError("the server's answer has no account_change")
    record = response_body["account_change"]
    if record is None:
        return response_body
    if not isinstance(record, Mapping):
        raise VerdifaxError("the server's account_change is not a record")
    expected = {"action": change, "value": sent["value"]}
    _check_owner_record(record, sent, key, "account change record", expected)
    return response_body


def run_deletion_answer(
    response_body: Any, sent: Mapping[str, Any], run_id: int, key: "Ed25519PrivateKey"
) -> dict[str, Any]:
    """The answer of ``POST /account/runs/{run_id}/delete``, checked against what was sent.

    The tombstone must carry the run, the record hash, ``decided_by``
    ``owner`` and the owner's signature that was sent.

    Raises:
        VerdifaxError: If the answer has no ``run_deletion`` record, or the
            record does not carry what was sent.
    """
    record = response_body.get("run_deletion") if isinstance(response_body, dict) else None
    if not isinstance(record, Mapping):
        raise VerdifaxError("the server's answer has no run_deletion record")
    expected = {"run_id": run_id, "record_hash": sent["record_hash"]}
    _check_owner_record(record, sent, key, "run deletion record", expected)
    result: dict[str, Any] = response_body
    return result


def admin_run_deletion_path(run_id: int) -> str:
    """Validate ``run_id`` and build ``/admin/runs/{run_id}/delete``."""
    validate_positive_id(run_id, "run_id")
    return f"/admin/runs/{run_id}/delete"


def admin_owner_key_replacement_path(account_id: int) -> str:
    """Validate ``account_id`` and build ``/admin/accounts/{account_id}/owner-key/replace``.

    ``account_id`` is the account's number (``7`` for ``account-7``), as
    ``GET /admin/accounts`` lists it.
    """
    validate_positive_id(account_id, "account_id")
    return f"/admin/accounts/{account_id}/owner-key/replace"


def admin_accounts(body: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The list of ``GET /admin/accounts``.

    Raises:
        VerdifaxError: If the server did not send a list.
    """
    accounts = body.get("accounts")
    if accounts is None:
        return []
    if not isinstance(accounts, list):
        raise VerdifaxError("the server's account list is not a list")
    return accounts


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
    "ACCOUNT_PATH",
    "ACCOUNT_SETTING_CHANGES",
    "ACCOUNT_SETTING_VALUES",
    "ACCOUNT_SETTINGS_PATH",
    "RUN_DELETED_CHANGE",
    "ACCOUNT_TIME_ZONE_PATH",
    "ACCOUNT_POLICIES_PATH",
    "BatchRow",
    "MAX_BATCH_ROWS",
    "POLICIES_PATH",
    "account_key_body",
    "account_key_path",
    "account_label",
    "account_setting_answer",
    "account_setting_body",
    "account_setting_change",
    "account_setting_path",
    "activation_record",
    "admin_account_body",
    "admin_accounts",
    "admin_erase_body",
    "admin_key_body",
    "admin_owner_key_replacement_path",
    "admin_run_deletion_path",
    "apply_policy_fields",
    "attest_receipt",
    "attested_block",
    "batch_body",
    "batch_response",
    "batch_row",
    "check_account_label",
    "check_run_deletion",
    "format_provider_payload",
    "governed_text",
    "parse_export_csv",
    "policy_activation_body",
    "policy_history",
    "policy_path",
    "policy_test_body",
    "policy_upload_body",
    "provider_attest_args",
    "query_params",
    "refuse_origin_hashes",
    "refuse_unsigned_account_change",
    "refuse_unsigned_owner_change",
    "reproducibility_block",
    "run_deletion_answer",
    "run_deletion_body",
    "run_deletion_path",
    "run_path",
    "with_attested_flag",
    "account_time_zone_body",
]


def account_time_zone_body(time_zone: str) -> dict[str, Any]:
    """The body of ``PUT /account/time-zone``: an IANA zone such as
    ``Europe/London``, ``"none"`` for UTC alone, or ``""`` for the zone of the
    server's region. The server checks the zone loads.

    Raises:
        ValidationError: If ``time_zone`` is not a ``str`` or is longer than
            64 characters.
    """
    if not isinstance(time_zone, str):
        raise ValidationError(f"time_zone must be a str, got {type(time_zone).__name__}")
    if len(time_zone) > 64:
        raise ValidationError("time_zone is longer than 64 characters")
    return {"time_zone": time_zone}
