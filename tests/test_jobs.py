"""SDK 1.1: signature version 2, job maps, key changes and the job export.

Requests go to ``httpx.MockTransport``, so nothing reaches the network. The
bytes come from ``sdk-signature-vector.json``, shared by the four SDKs.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import verdifax
from tests.conftest import make_execute_response
from tests.test_parity import BATCH, CSV_TEXT, DETERMINISM, EXPORT, responder
from tests.test_signing import INPUTS, inner, preimage_for
from pydantic import ValidationError as PydanticValidationError

from verdifax import (
    APIError,
    AsyncJob,
    AsyncVerdifaxClient,
    ExecuteRequest,
    ExportRow,
    Job,
    StageError,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    __version__,
    request_key_change_preimage,
    request_signature_preimage_v2,
    sign_request_v2,
)
from verdifax._requests import attest_receipt, batch_body, batch_response, batch_row
from verdifax._signing import (
    load_signing_key,
    payload_hash,
    request_key_body,
    request_key_change,
    request_key_clear_body,
    request_key_rotation_body,
    serialize_request,
    sign_envelope,
)
from verdifax._transport import parse_signed_response
from verdifax._validation import job_block, validate_job_name
from verdifax.jobs import _STEP_ATTEST_OPTIONS
from verdifax.research import determinism_result, verify_determinism

VECTOR = json.loads(
    (Path(__file__).parent / "sdk-signature-vector.json").read_text(encoding="utf-8")
)
SEED = bytes.fromhex(VECTOR["seed_hex"])
NEW_SEED = bytes(range(32, 64))
SIGNED_AT = VECTOR["signed_at"]
NONCE = VECTOR["nonce"]
VECTOR_BODY = json.loads(VECTOR["signed_request"])

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
ARGS = {"payload": "hello", **INPUTS}
SIGNED_REFUSAL = {"ok": False, "error": "policy denied", "error_stage": "PEPG"}


def vector_public_key() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(VECTOR["public_key"]))


def assert_verifies(body: dict[str, Any], payload_bytes: bytes) -> None:
    signature = base64.b64decode(body["request_signature"]["signature"])
    vector_public_key().verify(signature, preimage_for(body, payload_bytes))


def sent_body(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)


def sent_job(request: httpx.Request) -> dict[str, Any]:
    body = sent_body(request)
    return (inner(body) if "signed_request" in body else body)["job"]


def success(record_hash: str) -> httpx.Response:
    body = {**make_execute_response(manifest_hash=record_hash), "record_hash": record_hash}
    return httpx.Response(200, json=body)


def refusal(record_hash: Optional[str]) -> httpx.Response:
    body = dict(SIGNED_REFUSAL)
    if record_hash:
        body["record_hash"] = record_hash
    return httpx.Response(422, json=body)


def scripted(seen: list[httpx.Request], answers: list[httpx.Response]) -> Any:
    remaining = iter(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return next(remaining)

    return handler


def sync_client(handler: Any, signing_key: Optional[bytes] = SEED) -> VerdifaxClient:
    return VerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        transport=httpx.MockTransport(handler),
        signing_key=signing_key,
    )


def async_client(handler: Any, signing_key: Optional[bytes] = SEED) -> AsyncVerdifaxClient:
    return AsyncVerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        transport=httpx.MockTransport(handler),
        signing_key=signing_key,
    )


# ── the vector, byte for byte ─────────────────────────────────────────────────


def test_vector_body_hash():
    text = VECTOR["signed_request"].encode("utf-8")
    assert hashlib.sha256(text).hexdigest() == VECTOR["body_hash"]


def test_vector_payload_and_ai_output_hashes():
    assert payload_hash(VECTOR_BODY) == VECTOR["payload_hash"]
    digest = hashlib.sha256(VECTOR_BODY["ai_output_text"].encode("utf-8")).hexdigest()
    assert digest == VECTOR["ai_output_hash"]


def test_vector_seed_gives_the_public_key():
    assert request_key_body(load_signing_key(SEED))["public_key"] == VECTOR["public_key"]


def test_vector_preimage():
    preimage = request_signature_preimage_v2(
        VECTOR["body_hash"],
        VECTOR["payload_hash"],
        VECTOR_BODY["program_id"],
        VECTOR_BODY["route_id"],
        VECTOR_BODY["registry_record_hash"],
        VECTOR["ai_output_hash"],
        VECTOR_BODY["job"],
        SIGNED_AT,
        NONCE,
    )
    assert preimage.hex() == VECTOR["preimage_hex"]


def test_vector_no_job_preimage_hashes_the_literal_body():
    preimage = request_signature_preimage_v2(
        hashlib.sha256(b'{"payload_text":"hello"}').hexdigest(),
        hashlib.sha256(b"hello").hexdigest(),
        VECTOR_BODY["program_id"],
        VECTOR_BODY["route_id"],
        VECTOR_BODY["registry_record_hash"],
        "",
        None,
        SIGNED_AT,
        NONCE,
    )
    assert preimage.hex() == VECTOR["no_job_preimage_hex"]


def test_vector_key_change_preimage():
    preimage = request_key_change_preimage(VECTOR["public_key"], SIGNED_AT, NONCE)
    assert preimage.hex() == VECTOR["key_change_preimage_hex"]


def test_vector_signature_through_the_public_function():
    assert sign_request_v2(SEED, VECTOR_BODY, SIGNED_AT, NONCE) == {
        "signed_request": VECTOR["signed_request"],
        "request_signature": {
            "version": "2",
            "signature": VECTOR["signature"],
            "signed_at": SIGNED_AT,
            "nonce": NONCE,
        },
    }


def test_vector_signature_through_the_internal_function():
    envelope = sign_envelope(load_signing_key(SEED), VECTOR_BODY, SIGNED_AT, NONCE)
    assert envelope["request_signature"]["signature"] == VECTOR["signature"]
    vector_public_key().verify(
        base64.b64decode(VECTOR["signature"]), bytes.fromhex(VECTOR["preimage_hex"])
    )


def test_vector_key_change_signature():
    change = request_key_change(load_signing_key(SEED), VECTOR["public_key"], SIGNED_AT, NONCE)
    assert change == {
        "signature": VECTOR["key_change_signature"],
        "signed_at": SIGNED_AT,
        "nonce": NONCE,
    }


def test_serialize_request_keeps_the_vector_text():
    assert serialize_request(VECTOR_BODY) == VECTOR["signed_request"]


def test_serialize_request_keeps_non_ascii_as_utf8_text():
    assert serialize_request({"payload_text": "café"}) == '{"payload_text":"café"}'


@pytest.mark.parametrize(
    "body", [{"x": float("nan")}, {"x": object()}, {"x": "bad \ud800"}], ids=["nan", "type", "utf8"]
)
def test_serialize_request_refuses_what_has_no_json_text(body):
    with pytest.raises(ValidationError, match="cannot be signed"):
        serialize_request(body)


def test_sign_request_v2_puts_a_job_in_its_sorted_form():
    body = {
        **VECTOR_BODY,
        "job": {
            **VECTOR_BODY["job"],
            "previous_record_hashes": [HASH_B, HASH_A, HASH_B],
        },
    }
    assert sign_request_v2(SEED, body, SIGNED_AT, NONCE)["signed_request"] == (
        VECTOR["signed_request"]
    )


def test_sign_request_v2_refuses_a_bad_job():
    with pytest.raises(ValidationError, match="job_id"):
        sign_request_v2(SEED, {**INPUTS, "job": {"job_id": "a b", "step_id": "s"}})


def test_a_non_text_field_cannot_be_signed():
    with pytest.raises(ValidationError, match="route_id cannot be signed"):
        sign_envelope(load_signing_key(SEED), {"payload_text": "x", "route_id": 7})


# ── what a signed call sends ──────────────────────────────────────────────────


def test_a_signed_call_sends_exactly_the_two_fields():
    seen: list[httpx.Request] = []
    sync_client(scripted(seen, [success(HASH_A)])).attest(ai_output_text="the answer", **ARGS)
    body = sent_body(seen[0])
    assert set(body) == {"signed_request", "request_signature"}
    assert_verifies(body, b"hello")
    assert inner(body) == {"payload_text": "hello", "ai_output_text": "the answer", **INPUTS}


def test_a_signed_job_step_binds_the_job_into_the_signature():
    seen: list[httpx.Request] = []
    job = {
        "job_id": "loan-1",
        "step_id": "decide",
        "previous_record_hashes": [HASH_B, HASH_A],
        "external_previous": [HASH_C],
        "final": True,
    }
    sync_client(scripted(seen, [success(HASH_D)])).attest(job=job, **ARGS)
    body = sent_body(seen[0])
    assert_verifies(body, b"hello")
    assert inner(body)["job"]["previous_record_hashes"] == [HASH_A, HASH_B]


def test_the_result_carries_the_exact_text_and_the_record_hash():
    seen: list[httpx.Request] = []
    receipt = sync_client(scripted(seen, [success(HASH_A)])).attest(**ARGS)
    assert receipt.signed_request == sent_body(seen[0])["signed_request"]
    assert receipt.record_hash == HASH_A


def test_execute_takes_a_job():
    seen: list[httpx.Request] = []
    job = {"job_id": "j", "step_id": "s"}
    sync_client(scripted(seen, [success(HASH_A)])).execute(job=job, **ARGS)
    assert sent_job(seen[0]) == job


def test_an_unsigned_call_stays_plain_json_with_an_optional_job():
    seen: list[httpx.Request] = []
    receipt = sync_client(scripted(seen, [success(HASH_A)]), signing_key=None).attest(
        job={"job_id": "j", "step_id": "s"}, **ARGS
    )
    assert sent_body(seen[0]) == {
        "payload_text": "hello",
        **INPUTS,
        "job": {"job_id": "j", "step_id": "s"},
    }
    assert receipt.signed_request is None
    assert receipt.record_hash == HASH_A


def test_an_unsigned_call_with_no_job_is_unchanged():
    seen: list[httpx.Request] = []
    sync_client(scripted(seen, [success(HASH_A)]), signing_key=None).attest(**ARGS)
    assert sent_body(seen[0]) == {"payload_text": "hello", **INPUTS}


def test_module_level_attest_takes_a_job(monkeypatch):
    seen: list[httpx.Request] = []
    real_init = VerdifaxClient.__init__

    def init(self: VerdifaxClient, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = httpx.MockTransport(scripted(seen, [success(HASH_A)]))
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(VerdifaxClient, "__init__", init)
    verdifax.attest(
        "hello",
        **INPUTS,
        base_url="http://test.invalid",
        api_key="k",
        job={"job_id": "j", "step_id": "s"},
    )
    assert sent_job(seen[0]) == {"job_id": "j", "step_id": "s"}


def test_the_determinism_check_is_signed_and_keeps_the_text():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=DETERMINISM))
    result = verify_determinism(client, "hello", **INPUTS)
    assert_verifies(sent_body(seen[0]), b"hello")
    assert result.signed_request == sent_body(seen[0])["signed_request"]


async def test_async_determinism_keeps_the_text():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=DETERMINISM)) as client:
        result = await client.verify_determinism("hello", **INPUTS)
    assert_verifies(sent_body(seen[0]), b"hello")
    assert result.signed_request == sent_body(seen[0])["signed_request"]


def test_determinism_result_without_a_signature_has_no_text():
    response = httpx.Response(200, json=DETERMINISM)
    assert determinism_result(response, {"payload_text": "x"}).signed_request is None


async def test_async_attest_signs_the_same_way():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A)])) as client:
        receipt = await client.attest(ai_output_text="o", **ARGS)
    body = sent_body(seen[0])
    assert_verifies(body, b"hello")
    assert receipt.signed_request == body["signed_request"]
    assert receipt.record_hash == HASH_A


async def test_async_execute_takes_a_job():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A)])) as client:
        await client.execute(job={"job_id": "j", "step_id": "s"}, **ARGS)
    assert sent_job(seen[0]) == {"job_id": "j", "step_id": "s"}


# ── a refused or halted signed run ────────────────────────────────────────────


def test_a_refused_signed_run_error_carries_the_text_and_the_hash():
    seen: list[httpx.Request] = []
    with pytest.raises(StageError) as excinfo:
        sync_client(scripted(seen, [refusal(HASH_A)])).attest(**ARGS)
    assert excinfo.value.signed_request == sent_body(seen[0])["signed_request"]
    assert excinfo.value.record_hash == HASH_A


@pytest.mark.parametrize("status", [401, 403, 409, 500])
def test_every_api_error_on_a_signed_call_carries_the_text(status):
    seen: list[httpx.Request] = []
    answer = httpx.Response(status, json={"ok": False, "error": "no"})
    with pytest.raises(APIError) as excinfo:
        sync_client(scripted(seen, [answer])).attest(**ARGS)
    assert excinfo.value.signed_request == sent_body(seen[0])["signed_request"]
    assert excinfo.value.record_hash is None


def test_a_response_with_no_manifest_carries_the_text():
    seen: list[httpx.Request] = []
    answer = httpx.Response(200, json={"ok": True})
    with pytest.raises(APIError, match="missing 'manifest'") as excinfo:
        sync_client(scripted(seen, [answer])).attest(**ARGS)
    assert excinfo.value.signed_request == sent_body(seen[0])["signed_request"]


def test_execute_error_carries_the_text():
    seen: list[httpx.Request] = []
    with pytest.raises(StageError) as excinfo:
        sync_client(scripted(seen, [refusal(HASH_A)])).execute(**ARGS)
    assert excinfo.value.signed_request == sent_body(seen[0])["signed_request"]


def test_an_unsigned_refusal_has_no_text_but_keeps_the_hash():
    seen: list[httpx.Request] = []
    with pytest.raises(StageError) as excinfo:
        sync_client(scripted(seen, [refusal(HASH_A)]), signing_key=None).attest(**ARGS)
    assert excinfo.value.signed_request is None
    assert excinfo.value.record_hash == HASH_A


def test_a_halted_determinism_check_error_carries_the_text():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [refusal(None)]))
    with pytest.raises(StageError) as excinfo:
        verify_determinism(client, "hello", **INPUTS)
    assert excinfo.value.signed_request == sent_body(seen[0])["signed_request"]


async def test_async_refused_run_and_determinism_errors_carry_the_text():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [refusal(HASH_A), refusal(None)])) as client:
        with pytest.raises(StageError) as attest_error:
            await client.attest(**ARGS)
        with pytest.raises(StageError) as determinism_error:
            await client.verify_determinism("hello", **INPUTS)
    assert attest_error.value.signed_request == sent_body(seen[0])["signed_request"]
    assert attest_error.value.record_hash == HASH_A
    assert determinism_error.value.signed_request == sent_body(seen[1])["signed_request"]


@pytest.mark.parametrize("status", [422, 403])
def test_the_signed_text_stays_out_of_the_error_message(status):
    seen: list[httpx.Request] = []
    answer = httpx.Response(status, json=SIGNED_REFUSAL)
    with pytest.raises(APIError) as excinfo:
        sync_client(scripted(seen, [answer])).attest(**ARGS)
    error = excinfo.value
    assert error.signed_request
    for text in (str(error), repr(error), error.message, repr(error.args)):
        assert error.signed_request not in text
        assert "signed_request" not in text
        assert "payload_text" not in text


def test_parse_signed_response_returns_the_body_on_success():
    response = httpx.Response(200, json={"ok": True})
    assert parse_signed_response(response, {"signed_request": "t"}) == {"ok": True}


def test_parse_signed_response_puts_the_text_on_an_error():
    response = httpx.Response(500, json={"error": "no"})
    with pytest.raises(APIError) as excinfo:
        parse_signed_response(response, {"signed_request": "t"})
    assert excinfo.value.signed_request == "t"


def test_record_hash_on_an_error_ignores_a_body_without_a_usable_hash():
    assert APIError("no", 500).record_hash is None
    assert APIError("no", 500, {"record_hash": ""}).record_hash is None
    assert APIError("no", 500, {"record_hash": 7}).record_hash is None


# ── batch ─────────────────────────────────────────────────────────────────────


def test_a_batch_signs_each_row_with_exactly_the_two_fields():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH))
    client.execute_batch([ARGS, {**ARGS, "payload": "other"}])
    first, second = sent_body(seen[0])["runs"]
    assert_verifies(first, b"hello")
    assert_verifies(second, b"other")
    assert first["request_signature"]["nonce"] != second["request_signature"]["nonce"]


def test_a_batch_result_row_keeps_its_own_text_and_hash():
    seen: list[httpx.Request] = []
    results = [
        {"index": 0, "ok": True, "record_hash": HASH_A},
        {"index": 1, "ok": False, "record_hash": HASH_B, "error": "policy denied"},
    ]
    client = sync_client(responder(seen, body={**BATCH, "results": results}))
    batch = client.execute_batch([ARGS, {**ARGS, "payload": "other"}])
    rows = sent_body(seen[0])["runs"]
    assert [row.record_hash for row in batch.results] == [HASH_A, HASH_B]
    assert [row.signed_request for row in batch.results] == [r["signed_request"] for r in rows]


def test_a_row_refused_with_index_zero_still_gets_its_own_text():
    seen: list[httpx.Request] = []
    results = [{"index": 0, "ok": True}, {"index": 0, "ok": False, "error": "refused"}]
    client = sync_client(responder(seen, body={**BATCH, "results": results}))
    batch = client.execute_batch([ARGS, {**ARGS, "payload": "other"}])
    rows = sent_body(seen[0])["runs"]
    assert batch.results[1].signed_request == rows[1]["signed_request"]


def test_a_signed_batch_row_carries_a_job():
    seen: list[httpx.Request] = []
    row = {
        **ARGS,
        "job": {"job_id": "j", "step_id": "s", "previous_record_hashes": [HASH_B, HASH_A]},
    }
    sync_client(responder(seen, body=BATCH)).execute_batch([row])
    sent = sent_body(seen[0])["runs"][0]
    assert_verifies(sent, b"hello")
    assert inner(sent)["job"]["previous_record_hashes"] == [HASH_A, HASH_B]


def test_an_unsigned_batch_row_carries_a_plain_job():
    body = batch_body([{**ARGS, "job": {"job_id": "j", "step_id": "s", "final": False}}])
    assert body["runs"][0]["job"] == {"job_id": "j", "step_id": "s"}


def test_a_batch_row_model_carries_a_job():
    row = ExecuteRequest(
        payload_text="x", **INPUTS, job={"job_id": "j", "step_id": "s", "final": True}
    )
    assert batch_row(row)["job"] == {"job_id": "j", "step_id": "s", "final": True}


def test_a_batch_row_with_no_job_sends_no_job_field():
    assert "job" not in batch_row({**ARGS, "job": None})


def test_a_bad_job_in_a_batch_row_is_refused_before_sending():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH))
    with pytest.raises(ValidationError, match="step_id"):
        client.execute_batch([{**ARGS, "job": {"job_id": "j", "step_id": "bad step"}}])
    assert seen == []


async def test_async_batch_keeps_each_rows_text():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=BATCH)) as client:
        batch = await client.execute_batch([ARGS, {**ARGS, "payload": "other"}])
    rows = sent_body(seen[0])["runs"]
    assert_verifies(rows[0], b"hello")
    assert [row.signed_request for row in batch.results] == [r["signed_request"] for r in rows]


def test_an_unsigned_batch_has_no_text():
    seen: list[httpx.Request] = []
    batch = sync_client(responder(seen, body=BATCH), signing_key=None).execute_batch([ARGS, ARGS])
    assert [row.signed_request for row in batch.results] == [None, None]


def test_batch_response_matches_rows_by_position():
    parsed = {**BATCH, "results": [{"index": 0, "ok": True}, {"index": 0, "ok": False}]}
    sent = {"runs": [{"signed_request": "first"}, {"signed_request": "second"}]}
    rows = batch_response(parsed, sent).results
    assert [row.signed_request for row in rows] == ["first", "second"]


def test_batch_response_reads_a_response_with_no_results():
    assert batch_response({"ok": True}, {"runs": []}).results == []


def test_attest_receipt_reads_the_hash_and_the_text():
    receipt = attest_receipt(success(HASH_A), {"signed_request": "t"})
    assert (receipt.record_hash, receipt.signed_request) == (HASH_A, "t")


# ── the job block ─────────────────────────────────────────────────────────────


def test_job_block_sorts_removes_repeats_and_omits_the_empty():
    block = job_block(
        {
            "job_id": "j",
            "step_id": "s",
            "previous_record_hashes": [HASH_B, HASH_A, HASH_B],
            "external_previous": [],
            "final": False,
        }
    )
    assert block == {
        "job_id": "j",
        "step_id": "s",
        "previous_record_hashes": [HASH_A, HASH_B],
    }


def test_job_block_keeps_final_when_true_and_none_is_no_job():
    assert job_block({"job_id": "j", "step_id": "s", "final": True})["final"] is True
    assert job_block(None) is None


def test_job_block_is_stable_when_applied_twice():
    once = job_block({"job_id": "j", "step_id": "s", "external_previous": [HASH_B, HASH_A]})
    assert job_block(once) == once


@pytest.mark.parametrize(
    "job, message",
    [
        ("job", "must be a mapping"),
        ({"job_id": "j", "step_id": "s", "typo": 1}, "unknown fields: typo"),
        ({"job_id": "j", "step_id": "s", "final": "false"}, "final must be a bool"),
        ({"job_id": "j", "step_id": "s", "previous_record_hashes": HASH_A}, "list of strings"),
        ({"job_id": "j", "step_id": "s", "external_previous": [1]}, "list of strings"),
        ({"step_id": "s"}, "job_id"),
        ({"job_id": "j"}, "step_id"),
    ],
)
def test_job_block_refuses_a_bad_block(job, message):
    with pytest.raises(ValidationError, match=message):
        job_block(job)


@pytest.mark.parametrize("name", ["a", "A-z_0.9:x", "x" * 128])
def test_valid_job_names_pass(name):
    validate_job_name(name, "job_id")


@pytest.mark.parametrize(
    "name",
    ["", "x" * 129, "has space", "new\nline", "trailing\n", "café", "a/b", "a,b", None, 7],
)
def test_invalid_job_names_are_refused(name):
    with pytest.raises(ValidationError, match="job_id"):
        validate_job_name(name, "job_id")


@pytest.mark.parametrize("field", ["job_id", "step_id"])
@pytest.mark.parametrize("name", ["", "x" * 129, "bad name", "bad\n"])
def test_attest_refuses_invalid_job_names_before_sending(field, name):
    seen: list[httpx.Request] = []
    job = {"job_id": "j", "step_id": "s", field: name}
    with pytest.raises(ValidationError, match=field):
        sync_client(scripted(seen, [])).attest(job=job, **ARGS)
    assert seen == []


async def test_async_attest_refuses_invalid_job_names_before_sending():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [])) as client:
        with pytest.raises(ValidationError, match="job_id"):
            await client.attest(job={"job_id": "bad name", "step_id": "s"}, **ARGS)
    assert seen == []


# ── the job helper ────────────────────────────────────────────────────────────


def test_client_job_returns_a_job():
    job = sync_client(scripted([], [])).job("loan-1")
    assert isinstance(job, Job)
    assert job.job_id == "loan-1"
    assert job.record_hashes == {}
    assert job.signed_requests == {}


@pytest.mark.parametrize("name", ["", "bad name", "x" * 129])
def test_client_job_refuses_an_invalid_name(name):
    with pytest.raises(ValidationError, match="job_id"):
        sync_client(scripted([], [])).job(name)


def test_the_first_step_follows_nothing():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    receipt = job.step("first", **ARGS)
    assert sent_job(seen[0]) == {"job_id": "j", "step_id": "first"}
    assert_verifies(sent_body(seen[0]), b"hello")
    assert job.record_hashes == {"first": HASH_A}
    assert job.signed_requests == {"first": receipt.signed_request}


def test_the_default_after_is_the_step_run_just_before():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A), success(HASH_B)])).job("j")
    job.step("first", **ARGS)
    job.step("second", **ARGS)
    assert sent_job(seen[1])["previous_record_hashes"] == [HASH_A]


def test_a_branch_and_a_join_send_sorted_hashes():
    seen: list[httpx.Request] = []
    answers = [success(HASH_B), success(HASH_D), success(HASH_A), success(HASH_C)]
    job = sync_client(scripted(seen, answers)).job("j")
    job.step("start", **ARGS)
    job.step("left", after=["start"], **ARGS)
    job.step("right", after=["start"], **ARGS)
    job.step("join", after=["left", "right"], final=True, **ARGS)
    assert sent_job(seen[1])["previous_record_hashes"] == [HASH_B]
    assert sent_job(seen[2])["previous_record_hashes"] == [HASH_B]
    assert sent_job(seen[3]) == {
        "job_id": "j",
        "step_id": "join",
        "previous_record_hashes": [HASH_A, HASH_D],
        "final": True,
    }
    assert job.record_hashes == {
        "start": HASH_B,
        "left": HASH_D,
        "right": HASH_A,
        "join": HASH_C,
    }


def test_an_empty_after_starts_a_new_branch_from_nothing():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A), success(HASH_B)])).job("j")
    job.step("first", **ARGS)
    job.step("other", after=[], **ARGS)
    assert "previous_record_hashes" not in sent_job(seen[1])


def test_external_previous_is_sorted_and_sent():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    job.step("first", external_previous=[HASH_C, HASH_B, HASH_C], **ARGS)
    assert sent_job(seen[0])["external_previous"] == [HASH_B, HASH_C]


def test_a_refused_step_is_recorded_kept_and_re_raised():
    seen: list[httpx.Request] = []
    answers = [refusal(HASH_A), success(HASH_B), success(HASH_C)]
    job = sync_client(scripted(seen, answers)).job("j")
    with pytest.raises(StageError) as excinfo:
        job.step("refused", **ARGS)
    assert excinfo.value.stage == "PEPG"
    assert excinfo.value.record_hash == HASH_A
    text = sent_body(seen[0])["signed_request"]
    assert excinfo.value.signed_request == text
    assert job.record_hashes == {"refused": HASH_A}
    assert job.signed_requests == {"refused": text}

    job.step("after-default", **ARGS)
    assert sent_job(seen[1])["previous_record_hashes"] == [HASH_A]
    job.step("after-named", after=["refused"], **ARGS)
    assert sent_job(seen[2])["previous_record_hashes"] == [HASH_A]


def test_the_helper_raises_the_same_error_as_attest():
    errors = []
    for call in ("attest", "step"):
        client = sync_client(scripted([], [refusal(HASH_A)]))
        with pytest.raises(StageError) as excinfo:
            if call == "attest":
                client.attest(**ARGS)
            else:
                client.job("j").step("s", **ARGS)
        errors.append(excinfo.value)
    first, second = errors
    assert type(first) is type(second)
    assert (first.stage, first.status_code, first.message) == (
        second.stage,
        second.status_code,
        second.message,
    )


def test_a_refusal_with_no_record_leaves_the_map_alone():
    seen: list[httpx.Request] = []
    answer = httpx.Response(409, json={"ok": False, "error": "step already taken"})
    job = sync_client(scripted(seen, [success(HASH_A), answer, success(HASH_B)])).job("j")
    job.step("first", **ARGS)
    with pytest.raises(APIError) as excinfo:
        job.step("second", **ARGS)
    assert excinfo.value.status_code == 409
    assert job.record_hashes == {"first": HASH_A}
    assert set(job.signed_requests) == {"first"}
    job.step("third", **ARGS)
    assert sent_job(seen[2])["previous_record_hashes"] == [HASH_A]


def test_a_transport_failure_leaves_the_map_alone():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    job = sync_client(handler).job("j")
    with pytest.raises(verdifax.ConnectionError):
        job.step("first", **ARGS)
    assert job.record_hashes == {}
    assert job.signed_requests == {}


def test_a_success_with_no_record_hash_uses_the_manifest_hash():
    seen: list[httpx.Request] = []
    answer = httpx.Response(200, json=make_execute_response(manifest_hash=HASH_A))
    job = sync_client(scripted(seen, [answer])).job("j")
    job.step("first", **ARGS)
    assert job.record_hashes == {"first": HASH_A}


def test_an_unknown_after_is_refused_before_sending():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    job.step("first", **ARGS)
    with pytest.raises(ValidationError, match="nope"):
        job.step("second", after=["first", "nope"], **ARGS)
    assert len(seen) == 1


def test_after_as_a_bare_string_is_refused():
    job = sync_client(scripted([], [])).job("j")
    with pytest.raises(ValidationError, match="list of step ids"):
        job.step("second", after="first", **ARGS)


def test_an_invalid_step_id_is_refused_before_sending():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [])).job("j")
    with pytest.raises(ValidationError, match="step_id"):
        job.step("bad step", **ARGS)
    assert seen == []


def test_the_exposed_maps_are_copies():
    job = sync_client(scripted([], [success(HASH_A)])).job("j")
    job.step("first", **ARGS)
    job.record_hashes["first"] = "changed"
    job.signed_requests["first"] = "changed"
    assert job.record_hashes == {"first": HASH_A}
    assert job.signed_requests["first"] != "changed"


def test_an_unsigned_job_keeps_hashes_and_no_text():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)]), signing_key=None).job("j")
    job.step("first", **ARGS)
    assert sent_body(seen[0])["job"] == {"job_id": "j", "step_id": "first"}
    assert job.record_hashes == {"first": HASH_A}
    assert job.signed_requests == {}


def test_a_step_takes_what_attest_takes():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    job.step("first", ai_output_text="o", causal_graph={"x": 1}, **ARGS)
    request = inner(sent_body(seen[0]))
    assert request["ai_output_text"] == "o"
    assert request["causal_graph"] == {"x": 1}


async def test_async_job_runs_the_same_map():
    seen: list[httpx.Request] = []
    answers = [success(HASH_B), refusal(HASH_D), success(HASH_A), success(HASH_C)]
    async with async_client(scripted(seen, answers)) as client:
        job = client.job("j")
        assert isinstance(job, AsyncJob)
        await job.step("start", **ARGS)
        with pytest.raises(StageError) as excinfo:
            await job.step("left", after=["start"], **ARGS)
        await job.step("right", after=["start"], **ARGS)
        await job.step("join", after=["left", "right"], final=True, **ARGS)
        with pytest.raises(ValidationError, match="nope"):
            await job.step("more", after=["nope"], **ARGS)
    assert len(seen) == 4
    assert sent_job(seen[0]) == {"job_id": "j", "step_id": "start"}
    assert sent_job(seen[3])["previous_record_hashes"] == [HASH_A, HASH_D]
    assert sent_job(seen[3])["final"] is True
    assert job.record_hashes == {
        "start": HASH_B,
        "left": HASH_D,
        "right": HASH_A,
        "join": HASH_C,
    }
    assert job.signed_requests["left"] == excinfo.value.signed_request
    assert job.signed_requests["left"] == sent_body(seen[1])["signed_request"]
    assert set(job.signed_requests) == set(job.record_hashes)


def test_async_client_job_refuses_an_invalid_name():
    with pytest.raises(ValidationError, match="job_id"):
        async_client(scripted([], [])).job("bad name")


# ── key changes ───────────────────────────────────────────────────────────────


def verify_change(change: dict[str, str], new_public_key: str) -> None:
    assert set(change) == {"signature", "signed_at", "nonce"}
    preimage = "\x00".join(
        ["verdifax.request-key-change.v1", new_public_key, change["signed_at"], change["nonce"]]
    )
    vector_public_key().verify(base64.b64decode(change["signature"]), preimage.encode("utf-8"))


def verify_rotation(body: dict[str, Any]) -> None:
    assert set(body) == {"public_key", "proof", "change"}
    new_public = request_key_body(load_signing_key(NEW_SEED))
    assert body["public_key"] == new_public["public_key"]
    assert body["proof"] == new_public["proof"]
    verify_change(body["change"], body["public_key"])


def test_rotate_sends_the_change_approval_and_signs_with_the_new_key():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True}), success(HASH_A)]
    client = sync_client(scripted(seen, answers))
    assert client.rotate_request_key(NEW_SEED) == {"ok": True}
    assert (seen[0].method, seen[0].url.path) == ("POST", "/keys/request-key")
    verify_rotation(sent_body(seen[0]))

    client.attest(**ARGS)
    body = sent_body(seen[1])
    signature = base64.b64decode(body["request_signature"]["signature"])
    new_public = load_signing_key(NEW_SEED).public_key()
    new_public.verify(signature, preimage_for(body, b"hello"))
    with pytest.raises(InvalidSignature):
        vector_public_key().verify(signature, preimage_for(body, b"hello"))


def test_a_refused_rotation_keeps_the_current_key():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(403, json={"error": "no"})]))
    with pytest.raises(APIError):
        client.rotate_request_key(NEW_SEED)
    assert client._signing_key.private_bytes_raw() == SEED


def test_rotate_needs_a_current_key():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="signing_key"):
        sync_client(scripted(seen, []), signing_key=None).rotate_request_key(NEW_SEED)
    assert seen == []


def test_rotate_refuses_a_bad_new_key_without_echoing_it():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError) as excinfo:
        sync_client(scripted(seen, [])).rotate_request_key(b"short")
    assert "short" not in str(excinfo.value)
    assert seen == []


def test_rotate_sends_no_private_key():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(200, json={"ok": True})]))
    client.rotate_request_key(NEW_SEED)
    for secret in (SEED, NEW_SEED):
        assert secret.hex().encode() not in seen[0].content
        assert base64.b64encode(secret) not in seen[0].content


def test_clear_sends_the_change_approval():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(200, json={"ok": True})]))
    assert client.clear_request_key() == {"ok": True}
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/keys/request-key")
    body = sent_body(seen[0])
    assert set(body) == {"change"}
    verify_change(body["change"], "")


def test_clear_without_a_signing_key_sends_no_body():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(200, json={"ok": True})]), signing_key=None)
    client.clear_request_key()
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/keys/request-key")
    assert seen[0].content == b""


async def test_async_rotate_and_clear_send_the_change_approval():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True}), httpx.Response(200, json={"ok": True})]
    async with async_client(scripted(seen, answers)) as client:
        await client.rotate_request_key(NEW_SEED)
        verify_rotation(sent_body(seen[0]))
        assert client._signing_key.private_bytes_raw() == NEW_SEED
        await client.clear_request_key()
    assert (seen[1].method, seen[1].url.path) == ("DELETE", "/keys/request-key")
    assert set(sent_body(seen[1])) == {"change"}


async def test_async_rotate_needs_a_current_key_and_clear_can_be_empty():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True})]
    async with async_client(scripted(seen, answers), signing_key=None) as client:
        with pytest.raises(ValidationError, match="signing_key"):
            await client.rotate_request_key(NEW_SEED)
        await client.clear_request_key()
    assert seen[0].content == b""


def test_rotation_and_clear_bodies_directly():
    current = load_signing_key(SEED)
    verify_rotation(request_key_rotation_body(current, load_signing_key(NEW_SEED)))
    verify_change(request_key_clear_body(current)["change"], "")
    assert request_key_clear_body(None) is None


def test_admin_clear_route():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(200, json={"ok": True})]), signing_key=None)
    assert client.admin_clear_request_key(7) == {"ok": True}
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/admin/keys/7/request-key")
    assert seen[0].content == b""


async def test_async_admin_clear_route():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True})]
    async with async_client(scripted(seen, answers), signing_key=None) as client:
        assert await client.admin_clear_request_key(7) == {"ok": True}
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/admin/keys/7/request-key")


@pytest.mark.parametrize("key_id", [0, -1, True, "7"])
def test_admin_clear_refuses_a_bad_id(key_id):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="key_id"):
        sync_client(scripted(seen, []), signing_key=None).admin_clear_request_key(key_id)
    assert seen == []


# ── export and version ────────────────────────────────────────────────────────


EXPORT_ROW = {
    "run_id": 1,
    "status": "ok",
    "anchor_source": "ledger",
    "job_id": "j",
    "step_id": "s",
}


def test_export_sends_job_id_and_passes_the_new_columns_through():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={**EXPORT, "runs": [EXPORT_ROW]}), signing_key=None)
    export = client.export_runs(job_id="j")
    assert seen[0].url.params["job_id"] == "j"
    assert seen[0].url.params["format"] == "json"
    row = export.runs[0]
    assert isinstance(row, ExportRow)
    assert (row.anchor_source, row.job_id, row.step_id) == ("ledger", "j", "s")


def test_export_csv_sends_job_id():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, text=CSV_TEXT), signing_key=None)
    client.export_runs_csv(job_id="j")
    assert seen[0].url.params["job_id"] == "j"
    assert seen[0].url.params["format"] == "csv"


def test_export_without_a_job_sends_no_job_id():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=EXPORT), signing_key=None).export_runs()
    assert "job_id" not in seen[0].url.params


async def test_async_exports_send_job_id():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=EXPORT), signing_key=None) as client:
        await client.export_runs(job_id="j")
    async with async_client(responder(seen, text=CSV_TEXT), signing_key=None) as client:
        await client.export_runs_csv(job_id="j")
    assert [request.url.params["job_id"] for request in seen] == ["j", "j"]


def test_version_is_1_1_0_in_the_package_and_the_user_agent():
    assert __version__ == "1.1.0"
    pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "1.1.0"' in pyproject
    seen: list[httpx.Request] = []
    sync_client(responder(seen), signing_key=None).health()
    assert seen[0].headers["User-Agent"] == "verdifax-python/1.1.0"


async def test_async_user_agent_names_the_version():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen), signing_key=None) as client:
        await client.health()
    assert seen[0].headers["User-Agent"] == "verdifax-python/1.1.0 (async)"


def test_new_names_are_exported():
    for name in (
        "AsyncJob",
        "Job",
        "request_key_change_preimage",
        "request_signature_preimage_v2",
        "sign_request_v2",
    ):
        assert name in verdifax.__all__
        assert hasattr(verdifax, name)


# ── section 8: the shared follow-up ───────────────────────────────────────────


JOB = {"job_id": "j", "step_id": "s"}
PROVIDER_METHODS = ["attest_claude_response", "attest_openai_response"]
PROVIDER_FUNCTIONS = [verdifax.attest_claude_response, verdifax.attest_openai_response]


def no_hashes() -> httpx.Response:
    return httpx.Response(200, json=make_execute_response(manifest_hash=""))


def no_manifest_hash() -> httpx.Response:
    body = make_execute_response()
    del body["manifest"]["ManifestHash"]
    return httpx.Response(200, json=body)


def timing_out(seen: list[httpx.Request], answers: list[Optional[httpx.Response]]) -> Any:
    """Answer in turn, and time out wherever an answer is ``None``."""
    remaining = iter(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = next(remaining)
        if answer is None:
            raise httpx.ReadTimeout("timed out", request=request)
        return answer

    return handler


# provider helpers


@pytest.mark.parametrize("method", PROVIDER_METHODS)
def test_a_provider_method_takes_a_job_and_returns_the_hash_and_text(method):
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [success(HASH_A)]))
    receipt = getattr(client, method)("p", "r", **INPUTS, job=JOB)
    body = sent_body(seen[0])
    assert inner(body)["job"] == JOB
    assert_verifies(body, inner(body)["payload_text"].encode("utf-8"))
    assert receipt.record_hash == HASH_A
    assert receipt.signed_request == body["signed_request"]


@pytest.mark.parametrize("method", PROVIDER_METHODS)
async def test_an_async_provider_method_takes_a_job_and_returns_the_hash_and_text(method):
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A)])) as client:
        receipt = await getattr(client, method)("p", "r", **INPUTS, job=JOB)
    body = sent_body(seen[0])
    assert inner(body)["job"] == JOB
    assert receipt.record_hash == HASH_A
    assert receipt.signed_request == body["signed_request"]


@pytest.mark.parametrize("helper", PROVIDER_FUNCTIONS)
def test_a_module_provider_helper_takes_a_job_with_a_client(helper):
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [success(HASH_A)]))
    receipt = helper("p", "r", **INPUTS, client=client, job=JOB)
    assert sent_job(seen[0]) == JOB
    assert receipt.signed_request == sent_body(seen[0])["signed_request"]


@pytest.mark.parametrize("helper", PROVIDER_FUNCTIONS)
def test_a_module_provider_helper_takes_a_job_with_a_temporary_client(helper, monkeypatch):
    seen: list[httpx.Request] = []
    real_init = VerdifaxClient.__init__

    def init(self: VerdifaxClient, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = httpx.MockTransport(scripted(seen, [success(HASH_A)]))
        kwargs["base_url"] = "http://test.invalid"
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(VerdifaxClient, "__init__", init)
    receipt = helper("p", "r", **INPUTS, signing_key=SEED, job=JOB)
    assert sent_job(seen[0]) == JOB
    assert receipt.record_hash == HASH_A


@pytest.mark.parametrize("method", PROVIDER_METHODS)
def test_a_provider_method_with_no_job_sends_no_job(method):
    seen: list[httpx.Request] = []
    getattr(sync_client(scripted(seen, [success(HASH_A)])), method)("p", "r", **INPUTS)
    assert "job" not in inner(sent_body(seen[0]))


@pytest.mark.parametrize("method", PROVIDER_METHODS)
def test_a_provider_method_refuses_a_bad_job_before_sending(method):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="unknown fields"):
        getattr(sync_client(scripted(seen, [])), method)(
            "p", "r", **INPUTS, job={**JOB, "after": []}
        )
    assert seen == []


@pytest.mark.parametrize("method", PROVIDER_METHODS)
def test_a_refused_provider_call_error_carries_the_hash_and_text(method):
    seen: list[httpx.Request] = []
    with pytest.raises(StageError) as excinfo:
        getattr(sync_client(scripted(seen, [refusal(HASH_A)])), method)("p", "r", **INPUTS, job=JOB)
    assert excinfo.value.record_hash == HASH_A
    assert excinfo.value.signed_request == sent_body(seen[0])["signed_request"]


# clear drops the signing key


def test_a_clear_drops_the_key_and_later_calls_are_unsigned():
    seen: list[httpx.Request] = []
    answers = [
        httpx.Response(200, json={"ok": True}),
        success(HASH_A),
        httpx.Response(200, json=BATCH),
        httpx.Response(200, json=DETERMINISM),
    ]
    client = sync_client(scripted(seen, answers))
    client.clear_request_key()
    assert client._signing_key is None

    receipt = client.attest(**ARGS)
    assert sent_body(seen[1]) == {"payload_text": "hello", **INPUTS}
    assert receipt.signed_request is None
    client.execute_batch([ARGS])
    assert sent_body(seen[2]) == {"runs": [{"payload_text": "hello", **INPUTS}]}
    verify_determinism(client, "hello", **INPUTS)
    assert sent_body(seen[3]) == {"payload_text": "hello", **INPUTS}


def test_a_refused_clear_keeps_the_key_and_keeps_signing():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(403, json={"error": "no"}), success(HASH_A)]
    client = sync_client(scripted(seen, answers))
    with pytest.raises(APIError):
        client.clear_request_key()
    assert client._signing_key.private_bytes_raw() == SEED
    client.attest(**ARGS)
    assert_verifies(sent_body(seen[1]), b"hello")


def test_a_clear_that_never_reached_the_server_keeps_the_key():
    client = sync_client(timing_out([], [None]))
    with pytest.raises(verdifax.ConnectionError):
        client.clear_request_key()
    assert client._signing_key.private_bytes_raw() == SEED


def test_a_second_clear_sends_no_body():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True}), httpx.Response(200, json={"ok": True})]
    client = sync_client(scripted(seen, answers))
    client.clear_request_key()
    client.clear_request_key()
    assert set(sent_body(seen[0])) == {"change"}
    assert seen[1].content == b""


def test_rotate_after_a_clear_needs_a_key_again():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(200, json={"ok": True})]))
    client.clear_request_key()
    with pytest.raises(ValidationError, match="signing_key"):
        client.rotate_request_key(NEW_SEED)
    assert len(seen) == 1


def test_an_admin_clear_keeps_the_clients_own_key():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(200, json={"ok": True})]))
    client.admin_clear_request_key(7)
    assert client._signing_key.private_bytes_raw() == SEED


def test_a_job_after_a_clear_runs_unsigned():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True}), success(HASH_A)]
    client = sync_client(scripted(seen, answers))
    job = client.job("j")
    client.clear_request_key()
    job.step("first", **ARGS)
    assert sent_body(seen[1])["job"] == {"job_id": "j", "step_id": "first"}
    assert job.signed_requests == {}


async def test_async_clear_drops_the_key_and_later_calls_are_unsigned():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True}), success(HASH_A)]
    async with async_client(scripted(seen, answers)) as client:
        await client.clear_request_key()
        assert client._signing_key is None
        receipt = await client.attest(**ARGS)
    assert set(sent_body(seen[0])) == {"change"}
    assert sent_body(seen[1]) == {"payload_text": "hello", **INPUTS}
    assert receipt.signed_request is None


async def test_async_refused_clear_keeps_the_key_and_keeps_signing():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(403, json={"error": "no"}), success(HASH_A)]
    async with async_client(scripted(seen, answers)) as client:
        with pytest.raises(APIError):
            await client.clear_request_key()
        assert client._signing_key.private_bytes_raw() == SEED
        await client.attest(**ARGS)
    assert_verifies(sent_body(seen[1]), b"hello")


async def test_async_admin_clear_keeps_the_clients_own_key():
    answers = [httpx.Response(200, json={"ok": True})]
    async with async_client(scripted([], answers)) as client:
        await client.admin_clear_request_key(7)
        assert client._signing_key.private_bytes_raw() == SEED


# the job block


@pytest.mark.parametrize(
    "value",
    [(HASH_A,), {HASH_A}, frozenset({HASH_A}), HASH_A, None, {HASH_A: 1}, 7, [HASH_A, 7]],
    ids=["tuple", "set", "frozenset", "string", "none", "mapping", "number", "mixed"],
)
@pytest.mark.parametrize("field", ["previous_record_hashes", "external_previous"])
def test_a_hash_list_that_is_not_a_list_of_strings_is_refused(field, value):
    with pytest.raises(ValidationError, match=f"{field} must be a list of strings"):
        job_block({**JOB, field: value})


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None])
def test_a_final_that_is_not_a_bool_is_refused(value):
    with pytest.raises(ValidationError, match="final must be a bool"):
        job_block({**JOB, "final": value})


@pytest.mark.parametrize("typo", ["previous_hashes", "previous", "external", "Final", "after"])
def test_an_unknown_job_field_is_refused(typo):
    with pytest.raises(ValidationError, match=f"unknown fields: {typo}"):
        job_block({**JOB, typo: [HASH_A]})


def test_every_way_in_refuses_a_bad_job_block_before_sending():
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, []))
    bad = {**JOB, "previous_hashes": [HASH_A]}
    with pytest.raises(ValidationError, match="unknown fields"):
        client.attest(job=bad, **ARGS)
    with pytest.raises(ValidationError, match="unknown fields"):
        client.execute(job=bad, **ARGS)
    with pytest.raises(ValidationError, match="unknown fields"):
        client.execute_batch([{**ARGS, "job": bad}])
    with pytest.raises(ValidationError, match="unknown fields"):
        sign_request_v2(SEED, {**INPUTS, "job": bad})
    assert seen == []


async def test_async_refuses_a_bad_job_block_before_sending():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [])) as client:
        with pytest.raises(ValidationError, match="unknown fields"):
            await client.attest(job={**JOB, "previous_hashes": [HASH_A]}, **ARGS)
        with pytest.raises(ValidationError, match="must be a list"):
            await client.attest(job={**JOB, "external_previous": (HASH_A,)}, **ARGS)
        with pytest.raises(ValidationError, match="final must be a bool"):
            await client.execute_batch([{**ARGS, "job": {**JOB, "final": "true"}}])
    assert seen == []


@pytest.mark.parametrize("after", [("first",), {"first"}, "first"], ids=["tuple", "set", "string"])
def test_the_helper_refuses_an_after_that_is_not_a_list(after):
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    job.step("first", **ARGS)
    with pytest.raises(ValidationError, match="list of step ids"):
        job.step("second", after=after, **ARGS)
    assert len(seen) == 1


def test_the_helper_refuses_external_previous_that_is_not_a_list():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [])).job("j")
    with pytest.raises(ValidationError, match="external_previous must be a list"):
        job.step("first", external_previous=(HASH_A,), **ARGS)
    assert seen == []


# a step that sealed nothing


def test_a_timeout_is_not_recorded_and_does_not_advance_the_default_after():
    seen: list[httpx.Request] = []
    job = sync_client(timing_out(seen, [success(HASH_A), None, success(HASH_B)])).job("j")
    job.step("first", **ARGS)
    with pytest.raises(verdifax.ConnectionError):
        job.step("second", **ARGS)
    assert job.record_hashes == {"first": HASH_A}
    assert set(job.signed_requests) == {"first"}
    job.step("third", **ARGS)
    assert sent_job(seen[2])["previous_record_hashes"] == [HASH_A]


def test_a_step_named_after_one_that_sealed_nothing_is_refused():
    seen: list[httpx.Request] = []
    job = sync_client(timing_out(seen, [None])).job("j")
    with pytest.raises(verdifax.ConnectionError):
        job.step("first", **ARGS)
    with pytest.raises(ValidationError, match="first"):
        job.step("second", after=["first"], **ARGS)
    assert len(seen) == 1


async def test_async_timeout_and_409_are_not_recorded_or_followed():
    seen: list[httpx.Request] = []
    taken = httpx.Response(409, json={"ok": False, "error": "step already taken"})
    answers = [success(HASH_A), None, taken, success(HASH_B)]
    async with async_client(timing_out(seen, answers)) as client:
        job = client.job("j")
        await job.step("first", **ARGS)
        with pytest.raises(verdifax.ConnectionError):
            await job.step("timed-out", **ARGS)
        with pytest.raises(APIError) as excinfo:
            await job.step("taken", **ARGS)
        await job.step("last", **ARGS)
    assert excinfo.value.status_code == 409
    assert set(job.record_hashes) == {"first", "last"}
    assert sent_job(seen[3])["previous_record_hashes"] == [HASH_A]


# a success with no hash


async def test_async_success_with_no_record_hash_uses_the_manifest_hash():
    answers = [httpx.Response(200, json=make_execute_response(manifest_hash=HASH_A))]
    async with async_client(scripted([], answers)) as client:
        job = client.job("j")
        await job.step("first", **ARGS)
    assert job.record_hashes == {"first": HASH_A}


def test_an_empty_record_hash_falls_back_to_the_manifest_hash():
    body = {**make_execute_response(manifest_hash=HASH_A), "record_hash": ""}
    job = sync_client(scripted([], [httpx.Response(200, json=body)])).job("j")
    job.step("first", **ARGS)
    assert job.record_hashes == {"first": HASH_A}


def test_a_success_with_neither_hash_raises_and_leaves_no_gap():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A), no_hashes(), success(HASH_B)])).job("j")
    job.step("first", **ARGS)
    with pytest.raises(VerdifaxError, match="no record_hash and no manifest_hash"):
        job.step("second", **ARGS)
    assert job.record_hashes == {"first": HASH_A}
    assert set(job.signed_requests) == {"first"}
    job.step("third", **ARGS)
    assert sent_job(seen[2])["previous_record_hashes"] == [HASH_A]


def test_a_manifest_with_no_hash_field_raises_and_leaves_no_gap():
    job = sync_client(scripted([], [no_manifest_hash()])).job("j")
    with pytest.raises(PydanticValidationError):
        job.step("first", **ARGS)
    assert job.record_hashes == {}


def test_the_no_hash_error_keeps_the_signed_text_out_of_its_message():
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [no_hashes()])).job("j")
    with pytest.raises(VerdifaxError) as excinfo:
        job.step("first", **ARGS)
    assert sent_body(seen[0])["signed_request"] not in str(excinfo.value)


async def test_async_success_with_neither_hash_raises_and_leaves_no_gap():
    answers = [no_hashes(), no_manifest_hash()]
    async with async_client(scripted([], answers)) as client:
        job = client.job("j")
        with pytest.raises(VerdifaxError, match="no record_hash and no manifest_hash"):
            await job.step("first", **ARGS)
        with pytest.raises(PydanticValidationError):
            await job.step("second", **ARGS)
    assert job.record_hashes == {}
    assert job.signed_requests == {}


# an empty after


def test_an_empty_after_is_another_root_and_the_default_then_follows_it():
    seen: list[httpx.Request] = []
    answers = [success(HASH_A), success(HASH_B), success(HASH_C)]
    job = sync_client(scripted(seen, answers)).job("j")
    job.step("first-root", **ARGS)
    job.step("second-root", after=[], **ARGS)
    job.step("next", **ARGS)
    assert sent_job(seen[1]) == {"job_id": "j", "step_id": "second-root"}
    assert sent_job(seen[2])["previous_record_hashes"] == [HASH_B]


async def test_async_empty_after_is_another_root():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A), success(HASH_B)])) as client:
        job = client.job("j")
        await job.step("first-root", **ARGS)
        await job.step("second-root", after=[], **ARGS)
    assert sent_job(seen[1]) == {"job_id": "j", "step_id": "second-root"}
    assert job.record_hashes == {"first-root": HASH_A, "second-root": HASH_B}


# the fallback order


def body_with(**top_level: Any) -> dict[str, Any]:
    return {**make_execute_response(manifest_hash=HASH_C), **top_level}


@pytest.mark.parametrize(
    "top_level, expected",
    [
        ({"record_hash": HASH_A, "manifest_hash": HASH_B}, HASH_A),
        ({"record_hash": "", "manifest_hash": HASH_B}, HASH_B),
        ({"manifest_hash": HASH_B}, HASH_B),
        ({"manifest_hash": ""}, HASH_C),
        ({}, HASH_C),
    ],
    ids=["record", "empty-record", "top-level", "empty-top-level", "manifest"],
)
def test_the_fallback_order_for_a_step(top_level, expected):
    answer = httpx.Response(200, json=body_with(**top_level))
    job = sync_client(scripted([], [answer])).job("j")
    job.step("first", **ARGS)
    assert job.record_hashes == {"first": expected}


async def test_async_fallback_prefers_the_top_level_hash_over_the_manifest():
    answers = [
        httpx.Response(200, json=body_with(manifest_hash=HASH_B)),
        httpx.Response(200, json=body_with()),
    ]
    async with async_client(scripted([], answers)) as client:
        job = client.job("j")
        await job.step("first", **ARGS)
        await job.step("second", **ARGS)
    assert job.record_hashes == {"first": HASH_B, "second": HASH_C}


def test_a_real_response_shape_has_no_top_level_hash_and_uses_the_manifest():
    body = make_execute_response(manifest_hash=HASH_C)
    assert "manifest_hash" not in body
    job = sync_client(scripted([], [httpx.Response(200, json=body)])).job("j")
    receipt = job.step("first", **ARGS)
    assert job.record_hashes == {"first": HASH_C}
    assert receipt.manifest_hash == HASH_C


def test_a_top_level_hash_does_not_change_the_sealed_manifest_hash():
    answer = httpx.Response(200, json=body_with(manifest_hash=HASH_B))
    receipt = sync_client(scripted([], [answer])).attest(**ARGS)
    assert receipt.manifest_hash == HASH_C
    assert receipt.record_hash == HASH_B


def test_a_top_level_hash_alone_is_enough_when_the_manifest_hash_is_empty():
    body = make_execute_response(manifest_hash="")
    body["manifest_hash"] = HASH_B
    job = sync_client(scripted([], [httpx.Response(200, json=body)])).job("j")
    job.step("first", **ARGS)
    assert job.record_hashes == {"first": HASH_B}


# unknown options


@pytest.mark.parametrize("option", ["afer", "job", "external_prev", "Final", "signing_key"])
def test_a_step_refuses_an_unknown_option_before_sending(option):
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    job.step("first", **ARGS)
    with pytest.raises(ValidationError, match=f"unknown options: {option}"):
        job.step("second", **{option: ["first"]}, **ARGS)
    assert len(seen) == 1
    assert job.record_hashes == {"first": HASH_A}


@pytest.mark.parametrize("option", ["afer", "job"])
async def test_async_step_refuses_an_unknown_option_before_sending(option):
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [])) as client:
        with pytest.raises(ValidationError, match=f"unknown options: {option}"):
            await client.job("j").step("first", **{option: []}, **ARGS)
    assert seen == []


@pytest.mark.parametrize("client_class", [VerdifaxClient, AsyncVerdifaxClient])
def test_a_step_accepts_every_option_attest_takes(client_class):
    names = set(inspect.signature(client_class.attest).parameters) - {"self", "job"}
    assert names == set(_STEP_ATTEST_OPTIONS)
