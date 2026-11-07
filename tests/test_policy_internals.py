"""Direct tests of the helpers behind the policy fields and the request
field checks. The public calls are tested elsewhere; these name each helper
so a change to one fails here first."""

from __future__ import annotations

import pytest

from verdifax._requests import _policy_document, apply_policy_fields, policy_path
from verdifax._validation import _policy_value, refuse_unknown_keys
from verdifax.exceptions import ValidationError
from verdifax.models import ExecuteRequest, refuse_unknown_fields

HASH = "a" * 64


def test_apply_policy_fields_checks_and_leaves_out_none() -> None:
    body = {"policy_context": {"classification": "INTERNAL"}, "expected_policy_hash": HASH}
    out = apply_policy_fields(body)
    assert out["policy_context"] == {"classification": "INTERNAL"}
    assert out["expected_policy_hash"] == HASH
    assert apply_policy_fields({"policy_context": None, "expected_policy_hash": None}) == {}
    with pytest.raises(ValidationError):
        apply_policy_fields({"policy_context": {"mfa": True}})
    with pytest.raises(ValidationError):
        apply_policy_fields({"expected_policy_hash": "A" * 64})


def test_policy_path_validates_the_hash() -> None:
    assert policy_path(HASH) == "/policies/" + HASH
    assert policy_path(HASH, "/activate") == "/policies/" + HASH + "/activate"
    with pytest.raises(ValidationError):
        policy_path("not-a-hash")


def test_policy_document_takes_exact_text_only() -> None:
    assert _policy_document('{"a": 1}') == '{"a": 1}'
    for not_text in ({"a": 1}, ["a"], b"{}", 7):
        with pytest.raises(ValidationError):
            _policy_document(not_text)


def test_policy_value_refuses_values_no_rule_reads() -> None:
    _policy_value("classification", "RESTRICTED")
    _policy_value("mfa_satisfied", True)
    _policy_value("session_age_seconds", 0)
    for name, bad in (
        ("classification", "SORT-OF"),
        ("actor_type", "robot"),
        ("mfa_satisfied", "yes"),
        ("session_age_seconds", -1),
        ("object_id", "x" * 257),
    ):
        with pytest.raises(ValidationError):
            _policy_value(name, bad)


def test_refuse_unknown_keys_names_each_one() -> None:
    refuse_unknown_keys({"a": 1}, {"a", "b"}, "block")
    with pytest.raises(ValidationError, match="polcy_context, zz"):
        refuse_unknown_keys({"zz": 1, "polcy_context": 2, "a": 3}, {"a"}, "block")


def test_refuse_unknown_fields_names_the_field() -> None:
    assert refuse_unknown_fields(ExecuteRequest, {"route_id": "r"}) == {"route_id": "r"}
    with pytest.raises(ValidationError, match="polcy_context"):
        refuse_unknown_fields(ExecuteRequest, {"route_id": "r", "polcy_context": {}})
