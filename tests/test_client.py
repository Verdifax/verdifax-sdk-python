"""Mock-HTTP tests for the synchronous client."""

from __future__ import annotations

import json

import httpx
import pytest

from verdifax import AttestedContext, VerdifaxClient
from verdifax.exceptions import (
    APIError,
    ConnectionError as VerdifaxConnectionError,
    StageError,
    ValidationError,
)
from tests.conftest import (
    PROGRAM_ID,
    REGISTRY_RECORD_HASH,
    ROUTE_ID,
    make_execute_response,
)

# ── helpers ────────────────────────────────────────────────────────────────────


def _client_with(handler):
    """Build a VerdifaxClient whose HTTP layer is replaced by ``handler``."""
    transport = httpx.MockTransport(handler)
    return VerdifaxClient(base_url="http://test.invalid", transport=transport)


def _success_handler(captured: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured["request"] = request
            captured["body"] = json.loads(request.content) if request.content else None
        return httpx.Response(200, json=make_execute_response())

    return handler


# ── happy path ────────────────────────────────────────────────────────────────


def test_attest_success_returns_receipt():
    client = _client_with(_success_handler())
    receipt = client.attest(
        payload="hello",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert receipt.ok is True
    assert receipt.duration_ms == 42
    assert receipt.manifest_hash == "9" * 64


def test_attest_sends_payload_text_and_validated_fields():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload="hello",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    body = captured["body"]
    assert body["payload_text"] == "hello"
    assert "payload" not in body  # bytes path not used
    assert body["program_id"] == PROGRAM_ID
    assert body["route_id"] == ROUTE_ID
    assert body["registry_record_hash"] == REGISTRY_RECORD_HASH


def test_attest_sends_ai_output_text_when_supplied():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload="hello",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        ai_output_text="Loan denied: DTI 52% exceeds 43% policy threshold.",
    )
    body = captured["body"]
    assert body["ai_output_text"] == ("Loan denied: DTI 52% exceeds 43% policy threshold.")


def test_attest_omits_ai_output_text_by_default():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload="hello",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert "ai_output_text" not in captured["body"]


def test_attest_with_bytes_payload_decodes_when_utf8():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload=b"hello",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert captured["body"]["payload_text"] == "hello"


def test_attest_with_non_utf8_bytes_uses_base64_payload():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload=b"\xff\xfe\xfd",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    body = captured["body"]
    assert "payload_text" not in body
    assert body["payload"]


def test_health_returns_dict():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/health"
        return httpx.Response(200, json={"ok": True, "service": "verdifax-orchestrator-api"})

    client = _client_with(handler)
    assert client.health() == {"ok": True, "service": "verdifax-orchestrator-api"}


def test_user_agent_header_includes_sdk_version():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    ua = captured["request"].headers.get("user-agent")
    assert ua and ua.startswith("verdifax-python/")


def test_api_key_set_as_x_verdifax_key_header():
    captured: dict = {}
    transport = httpx.MockTransport(_success_handler(captured))
    client = VerdifaxClient(
        base_url="http://test.invalid",
        api_key="secret",
        transport=transport,
    )
    client.attest(
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert captured["request"].headers["x-verdifax-key"] == "secret"


def test_context_manager_closes_underlying_client():
    transport = httpx.MockTransport(_success_handler())
    with VerdifaxClient(base_url="http://test.invalid", transport=transport) as client:
        assert client.health.__self__ is client  # sanity


# ── client-side validation ─────────────────────────────────────────────────────


def test_attest_validates_program_id_before_request():
    client = _client_with(_success_handler())
    with pytest.raises(ValidationError):
        client.attest(
            payload="hi",
            program_id="not-hex",
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )


def test_attest_validates_route_id_before_request():
    client = _client_with(_success_handler())
    with pytest.raises(ValidationError):
        client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id="",
            registry_record_hash=REGISTRY_RECORD_HASH,
        )


def test_attest_validates_registry_record_hash_before_request():
    client = _client_with(_success_handler())
    with pytest.raises(ValidationError):
        client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash="too-short",
        )


# ── error paths ────────────────────────────────────────────────────────────────


def test_stage_failure_raises_stage_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={"ok": False, "error": "DOG rejected", "error_stage": "DOG"},
        )

    client = _client_with(handler)
    with pytest.raises(StageError) as exc_info:
        client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert exc_info.value.stage == "DOG"
    assert exc_info.value.status_code == 422


def test_non_stage_5xx_raises_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "server boom"})

    client = _client_with(handler)
    with pytest.raises(APIError) as exc_info:
        client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert not isinstance(exc_info.value, StageError)
    assert exc_info.value.status_code == 500


def test_response_missing_manifest_raises_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "duration_ms": 1})

    client = _client_with(handler)
    with pytest.raises(APIError):
        client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )


def test_transport_error_translated_to_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated DNS failure")

    client = _client_with(handler)
    with pytest.raises(VerdifaxConnectionError):
        client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )


# ── verify ─────────────────────────────────────────────────────────────────────


def test_verify_returns_true_when_hashes_match():
    client = _client_with(_success_handler())
    ok = client.verify(
        manifest_hash="9" * 64,
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert ok is True


def test_verify_returns_false_when_hashes_differ():
    client = _client_with(_success_handler())
    ok = client.verify(
        manifest_hash="0" * 64,
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert ok is False


def test_verify_validates_manifest_hash_format():
    client = _client_with(_success_handler())
    with pytest.raises(ValidationError):
        client.verify(
            manifest_hash="not-hex",
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )


# ── env-var configuration ──────────────────────────────────────────────────────


def test_env_var_overrides_default_base_url(monkeypatch):
    monkeypatch.setenv("VERDIFAX_API_URL", "http://from-env.invalid")
    client = VerdifaxClient()
    assert client.base_url == "http://from-env.invalid"


def test_explicit_argument_overrides_env_var(monkeypatch):
    monkeypatch.setenv("VERDIFAX_API_URL", "http://from-env.invalid")
    client = VerdifaxClient(base_url="http://explicit.invalid")
    assert client.base_url == "http://explicit.invalid"


def test_trailing_slash_stripped_from_base_url():
    client = VerdifaxClient(base_url="http://test.invalid/")
    assert client.base_url == "http://test.invalid"


# ── attested_context (Day 27 / closes pending #19) ────────────────────────────


def test_attest_omits_attested_context_block_when_unused():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert "attested_context" not in captured["body"]


def test_attest_serializes_attested_context_block_into_request():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    ctx = AttestedContext(
        actor_id="user-42",
        actor_role="compliance_officer",
        model_provider="anthropic",
        model_name="claude-sonnet-4-6",
        model_temperature=0.2,
        decision_kind="approve",
        decision_result="approved",
    )
    client.attest(
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        attested_context=ctx,
    )
    block = captured["body"]["attested_context"]
    # attested flag auto-derived because at least one field is set.
    assert block["attested"] is True
    assert block["actor_id"] == "user-42"
    assert block["actor_role"] == "compliance_officer"
    assert block["model_provider"] == "anthropic"
    assert block["model_name"] == "claude-sonnet-4-6"
    assert block["model_temperature"] == 0.2
    assert block["decision_kind"] == "approve"
    assert block["decision_result"] == "approved"
    # Unset optionals are omitted (matches Go's omitempty).
    assert "actor_signature" not in block
    assert "prompt_hash" not in block
    assert "decision_note" not in block


def test_attest_keeps_explicit_attested_false_when_no_other_fields_set():
    """Empty AttestedContext stays attested=False even after auto-derive.

    Useful for the rare integration case where the caller wants to send
    a deliberate "no, this run was not attested" signal.
    """
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.attest(
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        attested_context=AttestedContext(),
    )
    block = captured["body"]["attested_context"]
    assert block == {"attested": False}


def test_verify_passes_attested_context_through():
    captured: dict = {}
    client = _client_with(_success_handler(captured))
    client.verify(
        manifest_hash="9" * 64,
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        attested_context=AttestedContext(actor_id="user-1"),
    )
    assert captured["body"]["attested_context"]["actor_id"] == "user-1"
