"""Client-side validation helpers shared by the sync and async clients.

These mirror the validation the Verdifax API performs server-side (see
``cmd/api/main.go``). Performing the check client-side gives callers an
immediate :class:`~verdifax.exceptions.ValidationError` instead of an
HTTP 400 round-trip.
"""

from __future__ import annotations

from typing import Union

from .exceptions import ValidationError

_HEX_CHARS = frozenset("0123456789abcdef")


def validate_hex64(value: str, field_name: str) -> None:
    """Raise ``ValidationError`` unless ``value`` is 64 lowercase hex chars."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string, got {type(value).__name__}")
    if len(value) != 64:
        raise ValidationError(
            f"{field_name} must be 64-char hex, got {len(value)} chars"
        )
    lowered = value.lower()
    if lowered != value:
        raise ValidationError(f"{field_name} must be lowercase hex")
    for c in lowered:
        if c not in _HEX_CHARS:
            raise ValidationError(f"{field_name} must be lowercase hex (offending char: {c!r})")


def validate_route_id(value: str) -> None:
    """Raise ``ValidationError`` unless ``value`` is a non-empty string."""
    if not isinstance(value, str) or not value:
        raise ValidationError("route_id must be a non-empty string")


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
    raise ValidationError(
        f"payload must be str or bytes, got {type(payload).__name__}"
    )


__all__ = ["normalize_payload", "validate_hex64", "validate_route_id"]
