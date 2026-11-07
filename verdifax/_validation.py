"""Client-side validation helpers shared by the sync and async clients.

These mirror the validation the Verdifax API performs server-side (see
``cmd/api/main.go``). Performing the check client-side gives callers an
immediate :class:`~verdifax.exceptions.ValidationError` instead of an
HTTP 400 round-trip.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Union

from .exceptions import ValidationError

_HEX_CHARS = frozenset("0123456789abcdef")
_ROUTE_ID_MAX_LENGTH = 256
_ROUTE_ID_PATTERN = re.compile(r"[\x20-\x7E]+")
_JOB_NAME_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_JOB_FIELDS = frozenset(
    {"job_id", "step_id", "previous_record_hashes", "external_previous", "final"}
)
# Every top-level key of a run request. The server ignores a key it does not
# know, so a misspelt one would be dropped with no error: the client refuses
# it instead. A test holds this list equal to execute_fields in the shared
# sdk-parity.json.
EXECUTE_FIELDS = (
    "payload",
    "payload_text",
    "program_id",
    "route_id",
    "registry_record_hash",
    "ai_output_text",
    "attested_context",
    "reproducibility_context",
    "request_substance",
    "authorization_chain",
    "regulatory_scaffolding",
    "causal_graph",
    "request_signature",
    "signed_request",
    "job",
    "policy_context",
    "expected_policy_hash",
)
# Every key of attested_context, as the orchestrator reads it.
ATTESTED_CONTEXT_FIELDS = (
    "attested",
    "actor_id",
    "actor_role",
    "authorization_policy",
    "actor_signature",
    "model_provider",
    "model_name",
    "model_version",
    "model_temperature",
    "prompt_hash",
    "decision_kind",
    "decision_result",
    "decision_note",
)
# The values the orchestrator's policy_context accepts (policy_gate.go).
POLICY_ACTOR_TYPES = ("agent", "user", "service", "system")
POLICY_OBJECT_TYPES = ("text", "transaction", "code", "data", "model", "file")
POLICY_CLASSIFICATIONS = (
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "RESTRICTED",
    "TOP_SECRET",
    "TS_SCI",
)
_POLICY_OBJECT_ID_MAX_BYTES = 256
# The server reads session_age_seconds into a 64-bit integer.
_POLICY_SESSION_AGE_MAX = 2**63 - 1
_POLICY_ENUMS: dict[str, tuple[str, ...]] = {
    "actor_type": POLICY_ACTOR_TYPES,
    "object_type": POLICY_OBJECT_TYPES,
    "classification": POLICY_CLASSIFICATIONS,
}
_POLICY_CONTEXT_FIELDS = frozenset(
    {
        "actor_type",
        "mfa_satisfied",
        "session_age_seconds",
        "object_type",
        "object_id",
        "classification",
    }
)


def validate_hex64(value: str, field_name: str) -> None:
    """Raise ``ValidationError`` unless ``value`` is 64 lowercase hex chars."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string, got {type(value).__name__}")
    if len(value) != 64:
        raise ValidationError(f"{field_name} must be 64-char hex, got {len(value)} chars")
    lowered = value.lower()
    if lowered != value:
        raise ValidationError(f"{field_name} must be lowercase hex")
    for c in lowered:
        if c not in _HEX_CHARS:
            raise ValidationError(f"{field_name} must be lowercase hex (offending char: {c!r})")


def validate_route_id(value: str) -> None:
    """Raise ``ValidationError`` unless ``value`` is 1 to 256 printable ASCII characters."""
    if not isinstance(value, str) or not value:
        raise ValidationError("route_id must be a non-empty string")
    if len(value) > _ROUTE_ID_MAX_LENGTH:
        raise ValidationError(f"route_id is too long ({len(value)} > {_ROUTE_ID_MAX_LENGTH})")
    if not _ROUTE_ID_PATTERN.fullmatch(value):
        raise ValidationError("route_id contains non-printable-ASCII character")


def validate_job_name(value: Any, field_name: str) -> None:
    """Raise ``ValidationError`` unless ``value`` is a valid job or step id.

    That is 1 to 128 letters, digits, dots, underscores, colons or dashes.
    """
    if not isinstance(value, str) or not _JOB_NAME_PATTERN.fullmatch(value):
        raise ValidationError(
            f"{field_name} must be 1 to 128 letters, digits, dots, underscores, " "colons or dashes"
        )


def _job_hash_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"job {field_name} must be a list of strings")
    return sorted(set(value))


def job_block(job: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    """Check a job block and return the form the server requires.

    The two hash lists are sorted with repeats removed, an empty list is
    left out, and ``final`` is left out when false, so one job block has
    exactly one form. ``None`` means no job.

    Raises:
        ValidationError: If a name is invalid, ``final`` is not a ``bool``,
            a hash list is not a ``list`` of strings, or a field is unknown.
            A typo must never silently drop a link.
    """
    if job is None:
        return None
    if not isinstance(job, Mapping):
        raise ValidationError(f"job must be a mapping, got {type(job).__name__}")
    unknown = sorted(str(name) for name in job if name not in _JOB_FIELDS)
    if unknown:
        raise ValidationError(f"job has unknown fields: {', '.join(unknown)}")
    validate_job_name(job.get("job_id"), "job_id")
    validate_job_name(job.get("step_id"), "step_id")
    final = job.get("final", False)
    if not isinstance(final, bool):
        raise ValidationError(f"job final must be a bool, got {type(final).__name__}")
    block: dict[str, Any] = {"job_id": job["job_id"], "step_id": job["step_id"]}
    for name in ("previous_record_hashes", "external_previous"):
        hashes = _job_hash_list(job[name], name) if name in job else []
        if hashes:
            block[name] = hashes
    if final:
        block["final"] = True
    return block


def _policy_value(name: str, value: Any) -> None:
    if name in _POLICY_ENUMS:
        allowed = _POLICY_ENUMS[name]
        if not isinstance(value, str) or value not in allowed:
            raise ValidationError(
                f"policy_context {name} must be one of {', '.join(allowed)}, got {value!r}"
            )
    elif name == "mfa_satisfied":
        if not isinstance(value, bool):
            raise ValidationError(
                f"policy_context mfa_satisfied must be a bool, got {type(value).__name__}"
            )
    elif name == "session_age_seconds":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(
                "policy_context session_age_seconds must be an int, " f"got {type(value).__name__}"
            )
        if value < 0:
            raise ValidationError(
                f"policy_context session_age_seconds cannot be negative, got {value}"
            )
        if value > _POLICY_SESSION_AGE_MAX:
            raise ValidationError("policy_context session_age_seconds is too large")
    else:  # object_id
        if not isinstance(value, str):
            raise ValidationError(
                f"policy_context object_id must be a string, got {type(value).__name__}"
            )
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValidationError("policy_context object_id is not valid Unicode") from exc
        if size > _POLICY_OBJECT_ID_MAX_BYTES:
            raise ValidationError(
                f"policy_context object_id is longer than {_POLICY_OBJECT_ID_MAX_BYTES} "
                f"bytes ({size})"
            )


def policy_context_block(context: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    """Check a ``policy_context`` block and return a copy to send.

    The keys are ``actor_type``, ``mfa_satisfied``, ``session_age_seconds``,
    ``object_type``, ``object_id`` and ``classification``, all optional.
    ``None`` means no block.

    Raises:
        ValidationError: If a key is unknown or a value is outside what the
            server accepts. A misspelt field must never be dropped, because a
            rule on it would read its zero value.
    """
    if context is None:
        return None
    if not isinstance(context, Mapping):
        raise ValidationError(f"policy_context must be a mapping, got {type(context).__name__}")
    unknown = sorted(str(name) for name in context if name not in _POLICY_CONTEXT_FIELDS)
    if unknown:
        raise ValidationError(f"policy_context has unknown fields: {', '.join(unknown)}")
    for name, value in context.items():
        _policy_value(name, value)
    return dict(context)


def check_policy_actor(
    context: Optional[Mapping[str, Any]], attested_context: Optional[Mapping[str, Any]]
) -> None:
    """Refuse actor values in ``policy_context`` with no attested actor to describe.

    ``actor_type``, ``mfa_satisfied`` and ``session_age_seconds`` describe the
    attested actor, so the server refuses them unless ``attested_context``
    declares one. ``attested_context`` is the block as it is sent, with
    ``attested`` derived.

    Raises:
        ValidationError: If one of the three is set and no actor is attested.
    """
    if not context:
        return
    declares_actor = (
        bool(context.get("actor_type"))
        or context.get("mfa_satisfied") is True
        or bool(context.get("session_age_seconds"))
    )
    if declares_actor and not (attested_context or {}).get("attested"):
        raise ValidationError(
            "policy_context actor_type, mfa_satisfied and session_age_seconds describe "
            "the attested actor; send attested_context with the actor, such as its actor_id"
        )


def refuse_unknown_keys(block: Mapping[str, Any], known: Any, what: str) -> None:
    """Raise ``ValidationError`` naming each key of ``block`` not in ``known``.

    The server ignores a key it does not know, so a misspelt one would
    otherwise be dropped with no error.
    """
    unknown = sorted(str(name) for name in block if name not in known)
    if unknown:
        raise ValidationError(f"{what} has unknown fields: {', '.join(unknown)}")


def validate_positive_id(value: int, field_name: str) -> None:
    """Raise ``ValidationError`` unless ``value`` is a positive integer ID.

    ``bool`` is rejected even though it subclasses ``int``, so a stray
    ``True`` is not silently sent as ID 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValidationError(f"{field_name} must be > 0, got {value}")


def validate_run_id(value: int) -> None:
    """Raise ``ValidationError`` unless ``value`` is a positive integer run ID."""
    validate_positive_id(value, "run_id")


def normalize_payload(payload: Union[str, bytes]) -> tuple[str, str]:
    """Return ``(payload_text, payload_b64)`` exactly one of which is non-empty.

    Strings are sent as ``payload_text``. Bytes are decoded as UTF-8 if
    possible so the API can hash them deterministically; otherwise they are
    base64-encoded into the ``payload`` field.
    """
    if isinstance(payload, str):
        return payload, ""
    if isinstance(payload, bytes):
        try:
            return payload.decode("utf-8"), ""
        except UnicodeDecodeError:
            import base64

            return "", base64.b64encode(payload).decode("ascii")
    raise ValidationError(f"payload must be str or bytes, got {type(payload).__name__}")


__all__ = [
    "ATTESTED_CONTEXT_FIELDS",
    "EXECUTE_FIELDS",
    "POLICY_ACTOR_TYPES",
    "POLICY_CLASSIFICATIONS",
    "POLICY_OBJECT_TYPES",
    "check_policy_actor",
    "job_block",
    "normalize_payload",
    "policy_context_block",
    "refuse_unknown_keys",
    "validate_hex64",
    "validate_job_name",
    "validate_positive_id",
    "validate_route_id",
    "validate_run_id",
]
