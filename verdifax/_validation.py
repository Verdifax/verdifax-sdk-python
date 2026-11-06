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
    "job_block",
    "normalize_payload",
    "validate_hex64",
    "validate_job_name",
    "validate_positive_id",
    "validate_route_id",
    "validate_run_id",
]
