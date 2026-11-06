"""Run listing, evidence export, batch runs and the determinism check.

Requests go to ``httpx.MockTransport``, so nothing reaches the network.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Callable, Optional

import httpx
import pytest

from tests.test_signing import INPUTS, SEED, assert_verifies, inner
from verdifax import (
    APIError,
    AsyncVerdifaxClient,
    AttestedContext,
    ConnectionError,
    ExecuteRequest,
    MAX_BATCH_ROWS,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
)
from verdifax._requests import batch_body, batch_row, query_params
from verdifax._signing import attach_signature, load_signing_key
from verdifax._transport import checked_response
from verdifax.research import ReproducibilityContext, determinism_body

ROW = {"payload": "hello", **INPUTS}
CSV_TEXT = "run_id,created_at,status\n1,2026-11-05T00:00:00Z,ok\n"
RUN = {
    "ok": True,
    "id": 7,
    "created_at": "2026-11-05T00:00:00Z",
    "payload_hash": "p",
    "program_id": "1" * 64,
    "route_id": "r",
    "manifest_hash": "m",
    "duration_ms": 4,
    "status": "pepg_deny",
    "error_stage": "PEPG",
    "error_message": "policy denied",
    "manifest": {"manifest": {"ManifestHash": "m"}, "deny_receipt": {}},
}
SUMMARY = {"id": 7, "status": "ok", "error_stage": "", "duration_ms": 4, "execution_region": "us"}
RUN_LIST = {"ok": True, "total": 9, "limit": 2, "offset": 4, "runs": [SUMMARY]}
EXPORT = {
    "ok": True,
    "to": "2026-11-05T00:00:00Z",
    "total": 3,
    "returned": 1,
    "truncated": True,
    "by_status": {"ok": 1},
    "runs": [{"run_id": 1, "status": "ok", "complete_record_leaf_hash": "l"}],
}
BATCH = {
    "ok": True,
    "total": 2,
    "successful": 1,
    "failed": 1,
    "duration_ms": 3,
    "results": [
        {"index": 0, "ok": True, "run_id": 1, "manifest": {"ManifestHash": "a"}, "duration_ms": 1},
        {
            "index": 1,
            "ok": False,
            "run_id": 2,
            "error": "policy denied",
            "error_stage": "PEPG",
            "deny_receipt": {"fired_rule_id": "r1"},
            "partial_manifest": {"ManifestHash": "b"},
            "duration_ms": 1,
        },
    ],
}
_RUN_RESULT = {
    "run_id": 1,
    "manifest_hash": "a",
    "bundle_hash": "b",
    "duration_ms": 1,
    "status": "ok",
}
DETERMINISM = {
    "ok": True,
    "deterministic": True,
    "first": _RUN_RESULT,
    "second": {**_RUN_RESULT, "run_id": 2},
    "diff": {"differs": False, "manifest_hash_differs": False, "bundle_hash_differs": False},
}


def responder(
    seen: list[httpx.Request],
    *,
    body: Any = None,
    text: Optional[str] = None,
    status: int = 200,
    headers: Optional[dict[str, str]] = None,
) -> Callable[[httpx.Request], httpx.Response]:
    if text is not None and headers is None:
        headers = {"X-Verdifax-Total": "1", "X-Verdifax-Truncated": "false"}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if text is not None:
            return httpx.Response(
                status, text=text, headers={"Content-Type": "text/csv", **(headers or {})}
            )
        return httpx.Response(status, json={"ok": True} if body is None else body)

    return handler


def sync_client(handler: Any, **kwargs: Any) -> VerdifaxClient:
    transport = httpx.MockTransport(handler)
    return VerdifaxClient(
        base_url="http://test.invalid", api_key="k", transport=transport, **kwargs
    )


def async_client(handler: Any, **kwargs: Any) -> AsyncVerdifaxClient:
    transport = httpx.MockTransport(handler)
    return AsyncVerdifaxClient(
        base_url="http://test.invalid", api_key="k", transport=transport, **kwargs
    )


def query(request: httpx.Request) -> dict[str, str]:
    return dict(request.url.params)


def sent(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)


# ── Shared request building ──────────────────────────────────────────────


def test_query_params_drops_unset_values_and_keeps_zero():
    assert query_params(a=None, b="", c=0, d="x") == {"c": 0, "d": "x"}


def test_batch_row_treats_a_mapping_like_attest():
    assert batch_row(ROW) == {"payload_text": "hello", **INPUTS}
    binary = batch_row({"payload": b"\xff\xfe", **INPUTS})
    assert binary["payload"] == base64.b64encode(b"\xff\xfe").decode()
    assert "payload_text" not in binary


def test_batch_row_accepts_an_execute_request():
    row = ExecuteRequest(payload_text="hello", **INPUTS)
    assert batch_row(row) == {"payload_text": "hello", **INPUTS}


def test_batch_row_serializes_context_models():
    row = batch_row(
        {
            **ROW,
            "attested_context": AttestedContext(actor_role="reviewer"),
            "reproducibility_context": ReproducibilityContext(runtime_name="python"),
        }
    )
    assert row["attested_context"]["attested"] is True
    assert row["attested_context"]["actor_role"] == "reviewer"
    assert row["reproducibility_context"]["declared"] is True
    json.dumps(row)


def test_batch_row_leaves_bad_values_for_the_server():
    row = batch_row({"payload": "x", "program_id": "not-hex"})
    assert row == {"payload_text": "x", "program_id": "not-hex"}


def test_batch_row_refuses_a_row_of_the_wrong_kind():
    with pytest.raises(ValidationError, match="mapping or an ExecuteRequest"):
        batch_row("hello")  # type: ignore[arg-type]


def test_signed_row_signs_a_row_with_missing_fields_as_empty():
    row = attach_signature(load_signing_key(SEED), {"payload_text": "x"})
    assert set(row) == {"signed_request", "request_signature"}
    assert "program_id" not in inner(row)


def test_signed_row_without_a_key_returns_the_row():
    row = {"payload_text": "x"}
    assert attach_signature(None, row) is row


def test_batch_body_limits():
    assert MAX_BATCH_ROWS == 1000
    assert len(batch_body([ROW] * 1000)["runs"]) == 1000
    with pytest.raises(ValidationError, match="at most 1000 runs, got 1001"):
        batch_body([ROW] * 1001)
    with pytest.raises(ValidationError, match="at least one run"):
        batch_body([])


def test_determinism_body_validates_and_builds():
    assert determinism_body("hello", **INPUTS) == {"payload_text": "hello", **INPUTS}
    with pytest.raises(ValidationError):
        determinism_body("hello", "bad", INPUTS["route_id"], INPUTS["registry_record_hash"])


def test_checked_response_returns_the_response_and_raises_on_failure():
    assert checked_response(httpx.Response(200, text=CSV_TEXT)).text == CSV_TEXT
    with pytest.raises(APIError) as caught:
        checked_response(httpx.Response(400, json={"error": "bad time"}))
    assert caught.value.status_code == 400
    assert caught.value.message == "bad time"


# ── Sync client ──────────────────────────────────────────────────────────


def test_get_run_keeps_a_halted_manifest_as_stored():
    seen: list[httpx.Request] = []
    run = sync_client(responder(seen, body=RUN)).get_run(7)
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/runs/7"
    assert run.status == "pepg_deny"
    assert run.error_message == "policy denied"
    assert run.manifest == RUN["manifest"]


def test_get_run_refuses_a_bad_id_without_a_request():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError):
        sync_client(responder(seen)).get_run(0)
    assert seen == []


def test_get_run_404_raises_api_error():
    seen: list[httpx.Request] = []
    with pytest.raises(APIError) as caught:
        sync_client(responder(seen, body={"error": "run not found"}, status=404)).get_run(7)
    assert caught.value.status_code == 404


def test_list_runs_sends_limit_and_offset():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, body=RUN_LIST)).list_runs(limit=2, offset=4)
    assert seen[0].url.path == "/runs"
    assert query(seen[0]) == {"limit": "2", "offset": "4"}
    assert (out.total, out.limit, out.offset) == (9, 2, 4)
    assert out.runs[0].id == 7
    assert out.runs[0].execution_region == "us"


def test_list_runs_without_arguments_sends_no_query():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=RUN_LIST)).list_runs()
    assert query(seen[0]) == {}


def test_search_runs_sends_every_filter():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, body=RUN_LIST)).search_runs(
        manifest_hash="ab",
        program_id="1" * 64,
        route_id="r 1",
        status="ok",
        from_="2026-11-01T00:00:00+02:00",
        to="2026-11-05T00:00:00Z",
        limit=2,
        offset=4,
    )
    assert seen[0].url.path == "/runs/search"
    assert query(seen[0]) == {
        "manifest_hash": "ab",
        "program_id": "1" * 64,
        "route_id": "r 1",
        "status": "ok",
        "from": "2026-11-01T00:00:00+02:00",
        "to": "2026-11-05T00:00:00Z",
        "limit": "2",
        "offset": "4",
    }
    assert out.total == 9


def test_export_runs_sends_the_period_and_parses_the_body():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, body=EXPORT)).export_runs(
        from_="2026-11-01T00:00:00+02:00", to="2026-11-05T00:00:00Z"
    )
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/runs/export"
    assert query(seen[0]) == {
        "from": "2026-11-01T00:00:00+02:00",
        "to": "2026-11-05T00:00:00Z",
        "format": "json",
    }
    assert out.truncated is True
    assert out.by_status == {"ok": 1}
    assert out.runs[0].complete_record_leaf_hash == "l"


def test_export_runs_csv_returns_raw_text_and_counts():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, text=CSV_TEXT)).export_runs_csv(from_="2026-11-01T00:00:00Z")
    assert (out.csv, out.total, out.truncated) == (CSV_TEXT, 1, False)
    assert query(seen[0]) == {"from": "2026-11-01T00:00:00Z", "format": "csv"}


def test_export_runs_csv_reports_a_truncated_export():
    seen: list[httpx.Request] = []
    headers = {"X-Verdifax-Total": "12000", "X-Verdifax-Truncated": "true"}
    out = sync_client(responder(seen, text=CSV_TEXT, headers=headers)).export_runs_csv()
    assert (out.total, out.truncated) == (12000, True)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Verdifax-Total": "1"},
        {"X-Verdifax-Truncated": "false"},
        {"X-Verdifax-Total": "x", "X-Verdifax-Truncated": "false"},
        {"X-Verdifax-Total": "1", "X-Verdifax-Truncated": "maybe"},
    ],
)
def test_export_runs_csv_refuses_a_response_without_its_counts(headers):
    seen: list[httpx.Request] = []
    with pytest.raises(VerdifaxError, match="may be cut off"):
        sync_client(responder(seen, text=CSV_TEXT, headers=headers)).export_runs_csv()


def test_export_runs_csv_raises_on_a_refused_time():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"error": "from must be"}, status=400))
    with pytest.raises(APIError) as caught:
        client.export_runs_csv(from_="yesterday")
    assert caught.value.status_code == 400


def test_execute_batch_posts_runs_and_returns_failed_rows():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, body=BATCH)).execute_batch(
        [ROW, ExecuteRequest(payload_text="other", **INPUTS)]
    )
    assert len(seen) == 1
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/execute/batch"
    assert sent(seen[0]) == {
        "runs": [{"payload_text": "hello", **INPUTS}, {"payload_text": "other", **INPUTS}]
    }
    assert (out.total, out.successful, out.failed) == (2, 1, 1)
    good, bad = out.results
    assert good.ok and good.manifest == {"ManifestHash": "a"}
    assert not bad.ok
    assert bad.error == "policy denied"
    assert bad.error_stage == "PEPG"
    assert bad.deny_receipt == {"fired_rule_id": "r1"}
    assert bad.partial_manifest == {"ManifestHash": "b"}


def test_a_signed_batch_gives_each_row_its_own_signature_and_nonce():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH), signing_key=SEED)
    client.execute_batch([ROW, ROW, {**ROW, "payload": "other"}])
    rows = sent(seen[0])["runs"]
    assert len(rows) == 3
    for row in rows:
        assert_verifies(row, inner(row)["payload_text"].encode())
    assert len({row["request_signature"]["nonce"] for row in rows}) == 3
    assert len({row["request_signature"]["signature"] for row in rows}) == 3


def test_a_signed_batch_sends_an_incomplete_row_for_the_server_to_report():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH), signing_key=SEED)
    client.execute_batch([{"payload": "x"}])
    assert "request_signature" in sent(seen[0])["runs"][0]


def test_execute_batch_refuses_1001_rows_without_a_request():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH))
    with pytest.raises(ValidationError, match="at most 1000 runs"):
        client.execute_batch([ROW] * 1001)
    assert seen == []
    client.execute_batch([ROW] * 1000)
    assert len(seen) == 1


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.execute_batch([ROW]),
        lambda c: c.verify_determinism("hello", **INPUTS),
    ],
    ids=["batch", "determinism"],
)
def test_posts_are_not_retried(call):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"error": "busy"}, status=503), signing_key=SEED)
    with pytest.raises(APIError) as caught:
        call(client)
    assert caught.value.status_code == 503
    assert len(seen) == 1


def test_a_dropped_connection_on_a_batch_is_not_retried():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        raise httpx.RemoteProtocolError("server disconnected", request=request)

    with pytest.raises(ConnectionError):
        sync_client(handler).execute_batch([ROW])
    assert len(seen) == 1


def test_verify_determinism_posts_and_parses():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, body=DETERMINISM)).verify_determinism("hello", **INPUTS)
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/execute/verify-determinism"
    assert sent(seen[0]) == {"payload_text": "hello", **INPUTS}
    assert out.deterministic is True
    assert out.second.run_id == 2


def test_a_signed_verify_determinism_carries_one_signature():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=DETERMINISM), signing_key=SEED).verify_determinism(
        "hello", **INPUTS
    )
    assert len(seen) == 1
    assert_verifies(sent(seen[0]), b"hello")


# ── Async client ─────────────────────────────────────────────────────────


async def test_async_run_methods():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=RUN if request.url.path == "/runs/7" else RUN_LIST)

    async with async_client(handler) as client:
        run = await client.get_run(7)
        listed = await client.list_runs(limit=2, offset=4)
        found = await client.search_runs(status="ok", from_="2026-11-01T00:00:00Z")
    assert run.id == 7
    assert listed.total == 9
    assert found.runs[0].id == 7
    assert [request.url.path for request in seen] == ["/runs/7", "/runs", "/runs/search"]
    assert query(seen[1]) == {"limit": "2", "offset": "4"}
    assert query(seen[2]) == {"status": "ok", "from": "2026-11-01T00:00:00Z"}


async def test_async_export_runs():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=EXPORT)) as client:
        out = await client.export_runs(from_="2026-11-01T00:00:00Z", to="2026-11-05T00:00:00Z")
    assert out.total == 3
    assert query(seen[0]) == {
        "from": "2026-11-01T00:00:00Z",
        "to": "2026-11-05T00:00:00Z",
        "format": "json",
    }


async def test_async_export_runs_csv():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, text=CSV_TEXT)) as client:
        out = await client.export_runs_csv()
    assert (out.csv, out.total, out.truncated) == (CSV_TEXT, 1, False)
    assert query(seen[0]) == {"format": "csv"}


async def test_async_execute_batch_signs_each_row():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=BATCH), signing_key=SEED) as client:
        out = await client.execute_batch([ROW, ROW])
    assert out.failed == 1
    rows = sent(seen[0])["runs"]
    for row in rows:
        assert_verifies(row, b"hello")
    assert rows[0]["request_signature"]["nonce"] != rows[1]["request_signature"]["nonce"]


async def test_async_execute_batch_refuses_1001_rows_without_a_request():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=BATCH)) as client:
        with pytest.raises(ValidationError, match="at most 1000 runs"):
            await client.execute_batch([ROW] * 1001)
    assert seen == []


async def test_async_posts_are_not_retried():
    seen: list[httpx.Request] = []
    handler = responder(seen, body={"error": "busy"}, status=503)
    async with async_client(handler, signing_key=SEED) as client:
        with pytest.raises(APIError):
            await client.execute_batch([ROW])
        with pytest.raises(APIError):
            await client.verify_determinism("hello", **INPUTS)
    assert len(seen) == 2


async def test_async_transport_failures_are_wrapped():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    async with async_client(handler) as client:
        with pytest.raises(ConnectionError):
            await client.export_runs()


async def test_async_verify_determinism_posts_and_parses():
    seen: list[httpx.Request] = []
    context = ReproducibilityContext(runtime_name="python")
    async with async_client(responder(seen, body=DETERMINISM)) as client:
        out = await client.verify_determinism(
            "hello", **INPUTS, reproducibility_context=context, ai_output_text="out"
        )
    assert seen[0].url.path == "/execute/verify-determinism"
    body = sent(seen[0])
    assert body["ai_output_text"] == "out"
    assert body["reproducibility_context"]["declared"] is True
    assert "request_signature" not in body
    assert out.deterministic is True


async def test_async_verify_determinism_carries_one_signature():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=DETERMINISM), signing_key=SEED) as client:
        await client.verify_determinism("hello", **INPUTS)
    assert len(seen) == 1
    assert_verifies(sent(seen[0]), b"hello")
