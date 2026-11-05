"""The provider payload, settings, retries, validators, flags and execute blocks.

Requests go to ``httpx.MockTransport``, so nothing reaches the network.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx
import pytest

import verdifax
import verdifax._retry
from tests.conftest import make_execute_response
from tests.test_parity import ROW, async_client, responder, sent, sync_client
from tests.test_signing import INPUTS
from verdifax import (
    APIError,
    AsyncVerdifaxClient,
    AttestedContext,
    ConnectionError,
    ExecuteRequest,
    ValidationError,
    VerdifaxClient,
    _env_int,
    format_provider_payload,
)
from verdifax._requests import (
    attested_block,
    batch_row,
    provider_attest_args,
    refuse_origin_hashes,
    reproducibility_block,
    with_attested_flag,
)
from verdifax._retry import attempts_for, backoff_delay
from verdifax._validation import validate_hex64, validate_route_id
from verdifax.client import env_base_url
from verdifax.models import is_provided
from verdifax.research import ReproducibilityContext

# The vector shared by the four SDKs, so they cannot disagree.
VECTOR_PROMPT = 'Say "hi" to <b>&\n'
VECTOR_RESPONSE = "café\t\\ /   \x01 \U0001f600"
VECTOR_PAYLOAD = (
    '{"prompt":"Say \\"hi\\" to <b>&\\n","provider":"anthropic",'
    '"response":"café\\t\\\\ /   \\u0001 \U0001f600"}'
)
VECTOR_SHA256 = "3adc179eb067ac68d290b78eaf48442bab6f580fbf4198ce7a7a56cc9c632425"

BLOCKS: dict[str, dict[str, Any]] = {
    "request_substance": {"prompt": {"template_id": "t"}},
    "authorization_chain": {"approvers": [{"actor_id": "a"}]},
    "regulatory_scaffolding": {"right_to_explanation": "yes"},
    "causal_graph": {"parent_run_id": 3},
}
BAD_SUBSTANCE = {"origin": {"source_ip_hash": "x"}}
DETERMINISM_BODY = {
    "ok": True,
    "deterministic": True,
    "first": {"run_id": 1, "duration_ms": 1, "status": "ok"},
    "second": {"run_id": 2, "duration_ms": 1, "status": "ok"},
    "diff": {"differs": False, "manifest_hash_differs": False, "bundle_hash_differs": False},
}


def test_shared_provider_payload_vector():
    payload = format_provider_payload("anthropic", VECTOR_PROMPT, VECTOR_RESPONSE)
    assert payload == VECTOR_PAYLOAD
    assert hashlib.sha256(payload.encode("utf-8")).hexdigest() == VECTOR_SHA256
    plain = format_provider_payload("openai", "p", "r")
    assert plain == '{"prompt":"p","provider":"openai","response":"r"}'
    assert (
        hashlib.sha256(plain.encode("utf-8")).hexdigest()
        == "f642f9972df7037832635f8bcf43675d1d1da9fb6e1af2667e53ca38717ce301"
    )


def test_format_provider_payload_refuses_text_with_no_utf8_form():
    with pytest.raises(ValidationError, match="UTF-8"):
        format_provider_payload("openai", "\ud800", "r")


def test_format_provider_payload_carries_non_utf8_bytes_as_base64_text():
    assert "base64://4=" in format_provider_payload("openai", "p", b"\xff\xfe")


def test_provider_attest_args_govern_only_when_asked():
    assert provider_attest_args("openai", "p", "r", False)["ai_output_text"] is None
    assert provider_attest_args("openai", "p", "r", True)["ai_output_text"] == "r"
    with pytest.raises(ValidationError, match="response is required"):
        provider_attest_args("openai", "p", "", False)


def test_module_helpers_send_the_shared_payload():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=make_execute_response()))
    verdifax.attest_openai_response("p", "r", **INPUTS, client=client)
    body = sent(seen[0])
    assert body["payload_text"] == format_provider_payload("openai", "p", "r")
    assert "ai_output_text" not in body
    assert body["attested_context"]["model_provider"] == "openai"


def test_retry_tests_run_without_the_backoff(_no_retry_delay):
    assert verdifax._retry.backoff_delay(1.0, 1) == 0.0


def test_env_int_reads_a_set_integer(monkeypatch):
    monkeypatch.delenv("VERDIFAX_TIMEOUT_MS", raising=False)
    assert _env_int("VERDIFAX_TIMEOUT_MS") is None
    monkeypatch.setenv("VERDIFAX_TIMEOUT_MS", "7")
    assert _env_int("VERDIFAX_TIMEOUT_MS") == 7


def test_async_client_builds_the_same_body_as_the_sync_client():
    assert AsyncVerdifaxClient._build_execute_body(
        "x", **INPUTS
    ) == VerdifaxClient._build_execute_body("x", **INPUTS)


def test_env_base_url_prefers_the_new_name(monkeypatch):
    monkeypatch.delenv("VERDIFAX_BASE_URL", raising=False)
    monkeypatch.delenv("VERDIFAX_API_URL", raising=False)
    assert env_base_url() is None
    monkeypatch.setenv("VERDIFAX_API_URL", "http://fallback.invalid/")
    assert env_base_url() == "http://fallback.invalid/"
    assert VerdifaxClient().base_url == "http://fallback.invalid"
    monkeypatch.setenv("VERDIFAX_BASE_URL", "http://first.invalid")
    assert env_base_url() == "http://first.invalid"
    assert VerdifaxClient().base_url == "http://first.invalid"


def test_from_env_reads_timeout_user_agent_and_retries(monkeypatch):
    monkeypatch.setenv("VERDIFAX_TIMEOUT_MS", "5000")
    monkeypatch.setenv("VERDIFAX_USER_AGENT", "agent/1")
    monkeypatch.setenv("VERDIFAX_MAX_RETRIES", "0")
    client = verdifax.from_env()
    assert client.timeout == 5.0
    assert client._http.headers["User-Agent"] == "agent/1"
    assert client._http._max_retries == 0


def test_explicit_timeout_overrides_the_environment(monkeypatch):
    monkeypatch.setenv("VERDIFAX_TIMEOUT_MS", "5000")
    assert verdifax.from_env(timeout=1.0).timeout == 1.0


@pytest.mark.parametrize("name", ["VERDIFAX_TIMEOUT_MS", "VERDIFAX_MAX_RETRIES"])
def test_from_env_refuses_a_setting_that_is_not_an_integer(monkeypatch, name):
    monkeypatch.setenv(name, "not-a-number")
    with pytest.raises(ValidationError, match=name):
        verdifax.from_env()


def test_client_settings_reach_the_requests():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen), user_agent="agent/2")
    client.health()
    assert seen[0].headers["user-agent"] == "agent/2"


def test_attempts_for_counts_only_idempotent_methods():
    url = "http://test.invalid/"
    for method in ("GET", "HEAD", "OPTIONS"):
        assert attempts_for(httpx.Request(method, url), 3) == 4
        assert attempts_for(httpx.Request(method, url), 0) == 1
    for method in ("POST", "PUT", "DELETE"):
        assert attempts_for(httpx.Request(method, url), 3) == 1


def test_backoff_delay_stays_within_the_jitter_window():
    for attempt in (1, 2, 3):
        for _ in range(50):
            assert 0 <= backoff_delay(0.2, attempt) <= 0.2 * 2 ** (attempt - 1)


def flaky(calls: list[httpx.Request], failures: int, failure: Any) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) <= failures:
            if isinstance(failure, int):
                return httpx.Response(failure, json={"error": "busy"})
            raise failure("down", request=request)
        return httpx.Response(200, json={"ok": True})

    return handler


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_get_is_retried_on_transient_statuses(status):
    calls: list[httpx.Request] = []
    assert sync_client(flaky(calls, 3, status)).health() == {"ok": True}
    assert len(calls) == 4


def test_get_is_retried_after_a_transport_failure():
    calls: list[httpx.Request] = []
    assert sync_client(flaky(calls, 2, httpx.ConnectError)).get_stats() == {"ok": True}
    assert len(calls) == 3


def test_retries_stop_at_the_budget():
    calls: list[httpx.Request] = []
    with pytest.raises(APIError) as caught:
        sync_client(flaky(calls, 99, 503)).health()
    assert caught.value.status_code == 503
    assert len(calls) == 4
    calls.clear()
    with pytest.raises(ConnectionError):
        sync_client(flaky(calls, 99, httpx.ConnectError)).health()
    assert len(calls) == 4


def test_a_refusal_is_not_retried():
    calls: list[httpx.Request] = []
    with pytest.raises(APIError):
        sync_client(flaky(calls, 99, 404)).health()
    assert len(calls) == 1


def test_max_retries_zero_turns_retries_off():
    calls: list[httpx.Request] = []
    with pytest.raises(APIError):
        sync_client(flaky(calls, 99, 503), max_retries=0).health()
    assert len(calls) == 1


def test_post_is_never_retried():
    calls: list[httpx.Request] = []
    client = sync_client(flaky(calls, 99, 503))
    with pytest.raises(APIError):
        client.attest("x", **INPUTS)
    with pytest.raises(APIError):
        client.admin_create_key("n")
    assert len(calls) == 2
    calls.clear()
    with pytest.raises(ConnectionError):
        sync_client(flaky(calls, 99, httpx.ConnectError)).dcae_verify({"a": 1})
    assert len(calls) == 1


async def test_async_get_is_retried_and_post_is_not():
    calls: list[httpx.Request] = []
    async with async_client(flaky(calls, 3, 503)) as client:
        assert await client.health() == {"ok": True}
    assert len(calls) == 4
    calls.clear()
    async with async_client(flaky(calls, 2, httpx.ReadTimeout)) as client:
        assert await client.get_stats() == {"ok": True}
    assert len(calls) == 3
    calls.clear()
    async with async_client(flaky(calls, 99, 503)) as client:
        with pytest.raises(APIError):
            await client.execute_batch([ROW])
    assert len(calls) == 1


async def test_async_retries_stop_at_the_budget():
    calls: list[httpx.Request] = []
    async with async_client(flaky(calls, 99, httpx.ConnectError), max_retries=1) as client:
        with pytest.raises(ConnectionError):
            await client.health()
    assert len(calls) == 2


@pytest.mark.parametrize("value", ["é", "line\nbreak", "tab\t", "\x7f", "a" * 257, "x\n"], ids=repr)
def test_validate_route_id_applies_the_strict_rule(value):
    with pytest.raises(ValidationError):
        validate_route_id(value)


def test_validate_route_id_accepts_the_printable_range():
    validate_route_id(" ~")
    validate_route_id("a" * 256)


def test_validate_hex64_is_lowercase_only():
    validate_hex64("a" * 64, "f")
    with pytest.raises(ValidationError):
        validate_hex64("A" * 64, "f")


def test_attest_applies_the_strict_route_rule_without_a_request():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError):
        client.attest("x", "a" * 64, "café", "b" * 64)
    assert seen == []


def test_is_provided_counts_zero_and_not_empty_values():
    assert is_provided(0.0) and is_provided("x") and is_provided(True)
    assert not is_provided(None) and not is_provided("") and not is_provided(False)


def test_attested_context_counts_a_temperature_of_zero():
    assert AttestedContext(model_temperature=0.0).with_auto_attested().attested is True
    assert AttestedContext().with_auto_attested().attested is False


def test_with_attested_flag_derives_from_the_fields():
    assert with_attested_flag({"attested": False, "actor_role": "r"})["attested"] is True
    assert with_attested_flag({"attested": True, "decision_note": ""})["attested"] is False


def test_attested_block_accepts_a_model_or_a_mapping():
    assert attested_block(AttestedContext(actor_role="r"))["attested"] is True
    assert attested_block({"actor_role": "r"})["attested"] is True


def test_reproducibility_block_derives_declared():
    assert reproducibility_block(ReproducibilityContext(runtime_name="p"))["declared"] is True
    assert reproducibility_block({"declared": False, "runtime_name": "p"})["declared"] is True
    assert reproducibility_block({"declared": True, "random_seeds": []})["declared"] is False
    with pytest.raises(TypeError):
        reproducibility_block("nope")


def test_batch_rows_derive_the_flags():
    row = batch_row(
        {
            **ROW,
            "attested_context": {"actor_role": "r"},
            "reproducibility_context": {"platform": "x"},
        }
    )
    assert row["attested_context"]["attested"] is True
    assert row["reproducibility_context"]["declared"] is True


def test_refuse_origin_hashes_only_refuses_a_set_value():
    refuse_origin_hashes(None)
    refuse_origin_hashes({"origin": {"client_app": "a", "source_ip_hash": ""}})
    for name in ("source_ip_hash", "user_agent_hash"):
        with pytest.raises(ValidationError, match="computed by the server"):
            refuse_origin_hashes({"origin": {name: "x"}})


def test_the_four_blocks_reach_every_sync_path():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=make_execute_response()))
    client.attest("x", **INPUTS, **BLOCKS)
    client.execute("x", **INPUTS, **BLOCKS)
    client.execute_batch([{**ROW, **BLOCKS}, ExecuteRequest(payload_text="x", **INPUTS, **BLOCKS)])
    determinism = sync_client(responder(seen, body=DETERMINISM_BODY))
    determinism.verify_determinism("x", **INPUTS, **BLOCKS)
    bodies = [sent(seen[0]), sent(seen[1]), *sent(seen[2])["runs"], sent(seen[3])]
    assert len(bodies) == 5
    for body in bodies:
        for name, block in BLOCKS.items():
            assert body[name] == block


async def test_the_four_blocks_reach_every_async_path():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=make_execute_response())) as client:
        await client.attest("x", **INPUTS, **BLOCKS)
        await client.execute("x", **INPUTS, **BLOCKS)
        await client.execute_batch([{**ROW, **BLOCKS}])
    async with async_client(responder(seen, body=DETERMINISM_BODY)) as client:
        await client.verify_determinism("x", **INPUTS, **BLOCKS)
    for body in (sent(seen[0]), sent(seen[1]), sent(seen[2])["runs"][0], sent(seen[3])):
        for name, block in BLOCKS.items():
            assert body[name] == block


def test_origin_hashes_are_refused_without_a_request():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError):
        client.attest("x", **INPUTS, request_substance=BAD_SUBSTANCE)
    with pytest.raises(ValidationError):
        client.execute("x", **INPUTS, request_substance=BAD_SUBSTANCE)
    with pytest.raises(ValidationError):
        client.verify_determinism("x", **INPUTS, request_substance=BAD_SUBSTANCE)
    assert seen == []


async def test_async_origin_hashes_are_refused_without_a_request():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen)) as client:
        with pytest.raises(ValidationError):
            await client.attest("x", **INPUTS, request_substance=BAD_SUBSTANCE)
        with pytest.raises(ValidationError):
            await client.verify_determinism("x", **INPUTS, request_substance=BAD_SUBSTANCE)
    assert seen == []
