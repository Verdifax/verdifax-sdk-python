"""Tests for the convenience helpers and module-level shortcuts."""

from __future__ import annotations

import json

import httpx
import pytest

import verdifax
from verdifax import VerdifaxClient
from verdifax.helpers import attest_claude_response, attest_openai_response
from tests.conftest import (
    MANIFEST_HASH,
    PROGRAM_ID,
    REGISTRY_RECORD_HASH,
    ROUTE_ID,
    make_execute_response,
    make_verify_ok_response,
)


def _success_transport(captured: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured["request"] = request
            captured["body"] = json.loads(request.content) if request.content else None
        return httpx.Response(200, json=make_execute_response())

    return httpx.MockTransport(handler)


def test_module_level_attest_uses_env_var(monkeypatch):
    captured: dict = {}
    transport = _success_transport(captured)

    # Patch VerdifaxClient instantiation inside verdifax.from_env to inject the transport.
    real_init = VerdifaxClient.__init__

    def patched_init(self, base_url=None, api_key=None, timeout=30.0, transport=None):
        real_init(self, base_url=base_url, api_key=api_key, timeout=timeout, transport=transport)

    # Use a transport-aware client by monkeypatching the from_env factory.
    def fake_from_env(**kwargs):
        kwargs["transport"] = transport
        return VerdifaxClient(**kwargs)

    monkeypatch.setattr("verdifax.from_env", fake_from_env)

    receipt = verdifax.attest(
        payload="hi",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert receipt.manifest_hash == "9" * 64


def test_module_level_verify_run_calls_runs_verify(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json=make_verify_ok_response())

    transport = httpx.MockTransport(handler)

    def fake_from_env(**kwargs):
        kwargs["transport"] = transport
        return VerdifaxClient(**kwargs)

    monkeypatch.setattr("verdifax.from_env", fake_from_env)

    result = verdifax.verify_run(42, base_url="http://test.invalid", api_key="sk-test")
    assert captured["request"].method == "GET"
    assert captured["request"].url.path == "/runs/42/verify"
    assert captured["request"].headers["X-Verdifax-Key"] == "sk-test"
    assert isinstance(result, verdifax.VerifyResponse)
    assert result.verified is True


def test_module_level_verify_raises_with_explanation():
    with pytest.raises(verdifax.UnsupportedOperationError) as exc_info:
        verdifax.verify(
            manifest_hash=MANIFEST_HASH,
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert str(exc_info.value) == verdifax.client.VERIFY_UNSUPPORTED_MESSAGE
    assert "verify_run(run_id)" in str(exc_info.value)


def test_attest_claude_response_calls_attest_with_combined_payload():
    captured: dict = {}
    transport = _success_transport(captured)
    client = VerdifaxClient(base_url="http://test.invalid", transport=transport)
    receipt = attest_claude_response(
        prompt="What is the boiling point of water?",
        response="100 °C at sea level.",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        client=client,
    )
    assert receipt.manifest_hash == "9" * 64
    payload = captured["body"]["payload_text"]
    assert "claude" in payload
    assert "What is the boiling point of water?" in payload
    assert "100 °C at sea level." in payload


def test_claude_and_openai_helpers_produce_distinct_payloads():
    cap_claude: dict = {}
    cap_openai: dict = {}
    claude_client = VerdifaxClient(
        base_url="http://test.invalid", transport=_success_transport(cap_claude)
    )
    openai_client = VerdifaxClient(
        base_url="http://test.invalid", transport=_success_transport(cap_openai)
    )
    attest_claude_response(
        prompt="P",
        response="R",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        client=claude_client,
    )
    attest_openai_response(
        prompt="P",
        response="R",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        client=openai_client,
    )
    assert cap_claude["body"]["payload_text"] != cap_openai["body"]["payload_text"]


def test_helpers_decode_utf8_bytes_response():
    captured: dict = {}
    client = VerdifaxClient(base_url="http://test.invalid", transport=_success_transport(captured))
    attest_openai_response(
        prompt="P",
        response=b"hello",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
        client=client,
    )
    assert "hello" in captured["body"]["payload_text"]


def test_from_env_factory_returns_client():
    client = verdifax.from_env(base_url="http://factory.invalid")
    assert isinstance(client, VerdifaxClient)
    assert client.base_url == "http://factory.invalid"
    client.close()
