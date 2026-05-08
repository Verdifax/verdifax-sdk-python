"""Tests for client-side input validation."""

from __future__ import annotations

import base64

import pytest

from verdifax._validation import normalize_payload, validate_hex64, validate_route_id
from verdifax.exceptions import ValidationError


# ── validate_hex64 ─────────────────────────────────────────────────────────────


def test_validate_hex64_accepts_canonical_value():
    validate_hex64("a" * 64, "field")
    validate_hex64("0123456789abcdef" * 4, "field")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 63,
        "a" * 65,
        "A" * 64,  # uppercase
        "g" * 64,  # non-hex char
        "0" * 63 + "Z",  # invalid char at end
    ],
)
def test_validate_hex64_rejects_invalid_values(value):
    with pytest.raises(ValidationError):
        validate_hex64(value, "program_id")


def test_validate_hex64_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_hex64(123, "field")  # type: ignore[arg-type]


# ── validate_route_id ──────────────────────────────────────────────────────────


def test_validate_route_id_accepts_non_empty_string():
    validate_route_id("route-test")
    validate_route_id("any string at all")


@pytest.mark.parametrize("value", ["", None, 0])
def test_validate_route_id_rejects_invalid_values(value):
    with pytest.raises(ValidationError):
        validate_route_id(value)  # type: ignore[arg-type]


# ── normalize_payload ──────────────────────────────────────────────────────────


def test_normalize_payload_accepts_string_unchanged():
    text, b64 = normalize_payload("hello")
    assert text == "hello"
    assert b64 == ""


def test_normalize_payload_decodes_utf8_bytes():
    text, b64 = normalize_payload(b"hello")
    assert text == "hello"
    assert b64 == ""


def test_normalize_payload_base64_encodes_non_utf8_bytes():
    raw = b"\xff\xfe\xfd"
    text, b64 = normalize_payload(raw)
    assert text == ""
    assert base64.b64decode(b64) == raw


def test_normalize_payload_rejects_unsupported_type():
    with pytest.raises(ValidationError):
        normalize_payload(123)  # type: ignore[arg-type]
