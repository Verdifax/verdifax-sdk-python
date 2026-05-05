"""Tests for the exception hierarchy."""

from __future__ import annotations

from verdifax.exceptions import (
    APIError,
    ConnectionError as VerdifaxConnectionError,
    StageError,
    ValidationError,
    VerdifaxError,
)


def test_all_errors_inherit_from_base():
    assert issubclass(APIError, VerdifaxError)
    assert issubclass(StageError, APIError)
    assert issubclass(ValidationError, VerdifaxError)
    assert issubclass(VerdifaxConnectionError, VerdifaxError)


def test_api_error_carries_status_and_body():
    err = APIError(message="bad things", status_code=500, response_body={"error": "bad things"})
    assert err.status_code == 500
    assert err.message == "bad things"
    assert err.response_body == {"error": "bad things"}
    assert str(err) == "bad things"


def test_stage_error_carries_stage_name():
    err = StageError(message="DOG rejected envelope", status_code=422, stage="DOG")
    assert err.stage == "DOG"
    assert err.status_code == 422
    assert isinstance(err, APIError)


def test_connection_error_is_verdifax_error_not_builtin_oserror():
    err = VerdifaxConnectionError("offline")
    assert isinstance(err, VerdifaxError)
    # Important: do NOT subclass the builtin OSError.ConnectionError so a
    # caller's ``except OSError`` does not silently swallow our errors.
    assert not isinstance(err, OSError)
