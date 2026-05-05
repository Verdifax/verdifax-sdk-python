"""Mock-HTTP tests for the asynchronous client (mirrors test_client.py)."""

from __future__ import annotations

import json

import httpx
import pytest

from verdifax import AsyncVerdifaxClient, AttestedContext
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


def _async_client_with(handler):
    transport = httpx.MockTransport(handler)
    return AsyncVerdifaxClient(base_url="http://test.invalid", transport=transport)


def _success_handler(captured: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured["request"] = request
            captured["body"] = json.loads(request.content) if request.content else None
        return httpx.Response(200, json=make_execute_response())
    return handler


# ── happy path ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_attest_success_returns_receipt():
    async with _async_client_with(_success_handler()) as client:
        receipt = await client.attest(
            payload="hello",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert receipt.manifest_hash == "9" * 64


@pytest.mark.asyncio
async def test_async_health_returns_dict():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})
    async with _async_client_with(handler) as client:
        result = await client.health()
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_async_context_manager_closes_pool():
    transport = httpx.MockTransport(_success_handler())
    async with AsyncVerdifaxClient(base_url="http://test.invalid", transport=transport) as client:
        await client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    # After exit, client._http should be closed.
    assert client._http.is_closed


@pytest.mark.asyncio
async def test_async_user_agent_marks_async():
    captured: dict = {}
    async with _async_client_with(_success_handler(captured)) as client:
        await client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    ua = captured["request"].headers["user-agent"]
    assert "async" in ua


# ── client-side validation ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_attest_validates_program_id():
    async with _async_client_with(_success_handler()) as client:
        with pytest.raises(ValidationError):
            await client.attest(
                payload="hi",
                program_id="bad",
                route_id=ROUTE_ID,
                registry_record_hash=REGISTRY_RECORD_HASH,
            )


@pytest.mark.asyncio
async def test_async_verify_validates_manifest_hash():
    async with _async_client_with(_success_handler()) as client:
        with pytest.raises(ValidationError):
            await client.verify(
                manifest_hash="bad",
                payload="hi",
                program_id=PROGRAM_ID,
                route_id=ROUTE_ID,
                registry_record_hash=REGISTRY_RECORD_HASH,
            )


# ── error paths ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_stage_failure_raises_stage_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={"ok": False, "error": "ZKSP rejected", "error_stage": "ZKSP"},
        )
    async with _async_client_with(handler) as client:
        with pytest.raises(StageError) as exc_info:
            await client.attest(
                payload="hi",
                program_id=PROGRAM_ID,
                route_id=ROUTE_ID,
                registry_record_hash=REGISTRY_RECORD_HASH,
            )
    assert exc_info.value.stage == "ZKSP"


@pytest.mark.asyncio
async def test_async_500_raises_api_error_not_stage_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})
    async with _async_client_with(handler) as client:
        with pytest.raises(APIError) as exc_info:
            await client.attest(
                payload="hi",
                program_id=PROGRAM_ID,
                route_id=ROUTE_ID,
                registry_record_hash=REGISTRY_RECORD_HASH,
            )
    assert not isinstance(exc_info.value, StageError)


@pytest.mark.asyncio
async def test_async_transport_error_translated_to_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated DNS failure")
    async with _async_client_with(handler) as client:
        with pytest.raises(VerdifaxConnectionError):
            await client.attest(
                payload="hi",
                program_id=PROGRAM_ID,
                route_id=ROUTE_ID,
                registry_record_hash=REGISTRY_RECORD_HASH,
            )


# ── verify ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_verify_returns_true_when_hashes_match():
    async with _async_client_with(_success_handler()) as client:
        ok = await client.verify(
            manifest_hash="9" * 64,
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert ok is True


@pytest.mark.asyncio
async def test_async_verify_returns_false_when_hashes_differ():
    async with _async_client_with(_success_handler()) as client:
        ok = await client.verify(
            manifest_hash="0" * 64,
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert ok is False


# ── attested_context (Day 27 / closes pending #19) ────────────────────────────


@pytest.mark.asyncio
async def test_async_attest_serializes_attested_context_block():
    captured: dict = {}
    async with _async_client_with(_success_handler(captured)) as client:
        await client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
            attested_context=AttestedContext(
                actor_id="user-7",
                decision_kind="approve",
            ),
        )
    block = captured["body"]["attested_context"]
    assert block["attested"] is True
    assert block["actor_id"] == "user-7"
    assert block["decision_kind"] == "approve"


@pytest.mark.asyncio
async def test_async_attest_omits_attested_context_when_unused():
    captured: dict = {}
    async with _async_client_with(_success_handler(captured)) as client:
        await client.attest(
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    assert "attested_context" not in captured["body"]


@pytest.mark.asyncio
async def test_async_verify_threads_attested_context_to_attest():
    captured: dict = {}
    async with _async_client_with(_success_handler(captured)) as client:
        await client.verify(
            manifest_hash="9" * 64,
            payload="hi",
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
            attested_context=AttestedContext(actor_role="admin"),
        )
    assert captured["body"]["attested_context"]["actor_role"] == "admin"
