"""SDK 1.2: customer policies, the activation approval and the policy fields.

Requests go to ``httpx.MockTransport``, so nothing reaches the network. The
activation bytes come from ``sdk-signature-vector.json``, shared by the four
SDKs.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable

import httpx
import pytest

import verdifax
from tests.test_jobs import (
    ARGS,
    HASH_A,
    SEED,
    VECTOR,
    assert_verifies,
    async_client,
    scripted,
    sent_body,
    success,
    sync_client,
    vector_public_key,
)
from tests.test_parity import BATCH, DETERMINISM, responder
from tests.test_signing import INPUTS, inner
from verdifax import (
    APIError,
    AttestedContext,
    ExecuteRequest,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    policy_activation_approval,
    policy_activation_preimage,
)
from verdifax._requests import (
    activation_record,
    batch_body,
    policy_activation_body,
    policy_history,
    policy_test_body,
    policy_upload_body,
)
from verdifax._signing import load_signing_key, policy_activation_signature
from verdifax._validation import check_policy_actor, policy_context_block
from verdifax.jobs import _STEP_ATTEST_OPTIONS
from verdifax.research import determinism_body, verify_determinism

CHAIN_ID = VECTOR["activation_chain_id"]
DOCUMENT_HASH = VECTOR["activation_document_hash"]
PREVIOUS = VECTOR["activation_previous_hash"]
SIGNED_AT = VECTOR["signed_at"]
NONCE = VECTOR["nonce"]
NEWEST = "e" * 64
POLICY_HASH = "f" * 64
DOCUMENT = '{\n  "policy_id": "acme",\n  "policy_version": "1",\n  "rules": []\n}\n'

UPLOADED = {
    "policy_id": "acme",
    "policy_version": "1",
    "policy_hash": POLICY_HASH,
    "document_hash": DOCUMENT_HASH,
    "created_at": "2026-11-07T12:00:00Z",
}
LISTING = {
    "ok": True,
    "chain_id": CHAIN_ID,
    "newest_activation_hash": NEWEST,
    "active_document_hash": "",
    "policies": [UPLOADED],
}
TESTED = {
    "ok": True,
    "sealed": False,
    "outcome": "deny",
    "fired_rule_id": "r1",
    "reason_code": "MFA_REQUIRED",
}
ACTIVATION = {
    "format": "verdifax.policy-activation.v1",
    "chain_id": CHAIN_ID,
    "sequence": 2,
    "previous_activation_hash": NEWEST,
    "document_hash": DOCUMENT_HASH,
    "activation_hash": "1" * 64,
}
HISTORY = [ACTIVATION, {**ACTIVATION, "sequence": 3}]

ACTOR = AttestedContext(actor_id="agent-7", actor_role="ai_assistant")
FULL_CONTEXT = {
    "actor_type": "agent",
    "mfa_satisfied": True,
    "session_age_seconds": 30,
    "object_type": "transaction",
    "object_id": "txn-1",
    "classification": "CONFIDENTIAL",
}
OBJECT_CONTEXT = {"object_type": "transaction", "classification": "RESTRICTED"}


def routed(seen: list[httpx.Request], answers: dict[tuple[str, str], Any]) -> Callable:
    """Answer by method and path; an answer is a body or an ``httpx.Response``."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = answers[(request.method, request.url.path)]
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)

    return handler


def activation_answers(
    overrides: "dict[tuple[str, str], Any] | None" = None,
) -> dict[tuple[str, str], Any]:
    answers: dict[tuple[str, str], Any] = {
        ("GET", "/policies"): LISTING,
        ("POST", f"/policies/{DOCUMENT_HASH}/activate"): {"ok": True, "activation": ACTIVATION},
    }
    answers.update(overrides or {})
    return answers


def expected_preimage(chain_id: str, document_hash: str, previous: str, sig: dict) -> bytes:
    """The bytes the server rebuilds, written out independently of the SDK."""
    fields = [
        b"verdifax.policy-activation.v1",
        chain_id.encode(),
        document_hash.encode(),
        previous.encode(),
        sig["signed_at"].encode(),
        sig["nonce"].encode(),
    ]
    return b"\x00".join(fields)


def plain_or_inner(request: httpx.Request) -> dict[str, Any]:
    body = sent_body(request)
    return inner(body) if "signed_request" in body else body


# ── the vector, byte for byte ─────────────────────────────────────────────────


def test_vector_activation_preimage():
    preimage = policy_activation_preimage(CHAIN_ID, DOCUMENT_HASH, PREVIOUS, SIGNED_AT, NONCE)
    assert preimage.hex() == VECTOR["activation_preimage_hex"]


def test_vector_activation_preimage_matches_an_independent_build():
    sig = {"signed_at": SIGNED_AT, "nonce": NONCE}
    preimage = expected_preimage(CHAIN_ID, DOCUMENT_HASH, PREVIOUS, sig)
    assert preimage.hex() == VECTOR["activation_preimage_hex"]


def test_vector_activation_signature_through_the_public_function():
    approval = policy_activation_approval(
        SEED, CHAIN_ID, DOCUMENT_HASH, PREVIOUS, signed_at=SIGNED_AT, nonce=NONCE
    )
    assert approval == {
        "signature": VECTOR["activation_signature"],
        "signed_at": SIGNED_AT,
        "nonce": NONCE,
    }


def test_vector_activation_signature_through_the_internal_function():
    approval = policy_activation_signature(
        load_signing_key(SEED), CHAIN_ID, DOCUMENT_HASH, PREVIOUS, SIGNED_AT, NONCE
    )
    assert approval["signature"] == VECTOR["activation_signature"]
    signature = base64.b64decode(approval["signature"])
    vector_public_key().verify(signature, bytes.fromhex(VECTOR["activation_preimage_hex"]))


def test_approval_defaults_to_the_current_time_and_a_fresh_nonce():
    first = policy_activation_approval(SEED, CHAIN_ID, DOCUMENT_HASH, PREVIOUS)
    second = policy_activation_approval(SEED, CHAIN_ID, DOCUMENT_HASH, PREVIOUS)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", first["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", first["nonce"])
    assert first["nonce"] != second["nonce"]
    vector_public_key().verify(
        base64.b64decode(first["signature"]),
        expected_preimage(CHAIN_ID, DOCUMENT_HASH, PREVIOUS, first),
    )


@pytest.mark.parametrize("position", range(5))
def test_preimage_refuses_a_zero_byte_or_non_text(position):
    values = [CHAIN_ID, DOCUMENT_HASH, PREVIOUS, SIGNED_AT, NONCE]
    with_zero = list(values)
    with_zero[position] = values[position] + "\x00x"
    with pytest.raises(ValidationError, match="zero byte"):
        policy_activation_preimage(*with_zero)
    not_text: list[Any] = list(values)
    not_text[position] = 7
    with pytest.raises(ValidationError, match="not text"):
        policy_activation_preimage(*not_text)


@pytest.mark.parametrize("bad", ["A" * 64, "a" * 63, "", 7])
def test_approval_refuses_a_bad_hash(bad):
    with pytest.raises(ValidationError):
        policy_activation_approval(SEED, CHAIN_ID, bad, PREVIOUS)
    with pytest.raises(ValidationError):
        policy_activation_approval(SEED, CHAIN_ID, DOCUMENT_HASH, bad)


def test_approval_refuses_a_bad_key_without_echoing_it():
    with pytest.raises(ValidationError) as caught:
        policy_activation_approval(b"\x07" * 31, CHAIN_ID, DOCUMENT_HASH, PREVIOUS)
    assert "\\x07" not in str(caught.value)


def test_the_helpers_are_exported():
    for name in ("policy_activation_preimage", "policy_activation_approval"):
        assert name in verdifax.__all__
        assert hasattr(verdifax, name)


# ── the six methods ───────────────────────────────────────────────────────────


def test_upload_sends_the_exact_text_and_returns_the_server_object():
    seen: list[httpx.Request] = []
    document = DOCUMENT.replace("acme", "caf\u00e9") + "\r\n  "
    client = sync_client(responder(seen, body=UPLOADED, status=201), signing_key=None)
    assert client.upload_policy(document) == UPLOADED
    assert (seen[0].method, seen[0].url.path) == ("POST", "/policies")
    assert sent_body(seen[0]) == {"document": document}


def test_list_returns_the_server_object():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=LISTING), signing_key=None)
    assert client.list_policies() == LISTING
    assert (seen[0].method, seen[0].url.path, seen[0].content) == ("GET", "/policies", b"")


def test_get_reads_one_document():
    seen: list[httpx.Request] = []
    answer = {**UPLOADED, "document": DOCUMENT}
    client = sync_client(responder(seen, body=answer), signing_key=None)
    assert client.get_policy(DOCUMENT_HASH) == answer
    assert (seen[0].method, seen[0].url.path) == ("GET", f"/policies/{DOCUMENT_HASH}")


def test_test_policy_sends_inputs_with_a_document():
    seen: list[httpx.Request] = []
    inputs = {"subject_type": "agent", "verb": "wire-transfer", "mfa_satisfied": False}
    client = sync_client(responder(seen, body=TESTED), signing_key=None)
    assert client.test_policy(inputs, document=DOCUMENT) == TESTED
    assert (seen[0].method, seen[0].url.path) == ("POST", "/policies/test")
    assert sent_body(seen[0]) == {"inputs": inputs, "document": DOCUMENT}


def test_test_policy_sends_inputs_with_a_document_hash():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=TESTED), signing_key=None)
    client.test_policy({"route_id": "r"}, document_hash=DOCUMENT_HASH)
    assert sent_body(seen[0]) == {"inputs": {"route_id": "r"}, "document_hash": DOCUMENT_HASH}


def test_history_returns_the_list_as_sent():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=HISTORY), signing_key=None)
    assert client.get_policy_history() == HISTORY
    assert (seen[0].method, seen[0].url.path) == ("GET", "/policies/history")


def test_an_empty_history_is_an_empty_list():
    client = sync_client(responder([], body=[]), signing_key=None)
    assert client.get_policy_history() == []


@pytest.mark.parametrize("answer", [{"ok": True}, None, "x"])
def test_a_history_that_is_not_a_list_is_refused(answer):
    with pytest.raises(VerdifaxError, match="not a list"):
        policy_history(answer)


def test_a_saved_history_is_the_list_the_server_sent(tmp_path):
    client = sync_client(responder([], body=HISTORY), signing_key=None)
    path = tmp_path / "history.json"
    path.write_text(json.dumps(client.get_policy_history()), encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8")) == HISTORY


async def test_async_methods_send_the_same_requests():
    seen: list[httpx.Request] = []
    answers = {
        ("POST", "/policies"): httpx.Response(201, json=UPLOADED),
        ("GET", "/policies"): LISTING,
        ("GET", f"/policies/{DOCUMENT_HASH}"): {**UPLOADED, "document": DOCUMENT},
        ("POST", "/policies/test"): TESTED,
        ("GET", "/policies/history"): HISTORY,
        ("POST", f"/policies/{DOCUMENT_HASH}/activate"): {"ok": True, "activation": ACTIVATION},
    }
    async with async_client(routed(seen, answers), signing_key=None) as client:
        assert await client.upload_policy(DOCUMENT) == UPLOADED
        assert await client.list_policies() == LISTING
        assert (await client.get_policy(DOCUMENT_HASH))["document"] == DOCUMENT
        assert await client.test_policy({"route_id": "r"}, document=DOCUMENT) == TESTED
        assert await client.get_policy_history() == HISTORY
        assert await client.activate_policy(DOCUMENT_HASH) == ACTIVATION
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/policies"),
        ("GET", "/policies"),
        ("GET", f"/policies/{DOCUMENT_HASH}"),
        ("POST", "/policies/test"),
        ("GET", "/policies/history"),
        ("GET", "/policies"),
        ("POST", f"/policies/{DOCUMENT_HASH}/activate"),
    ]
    assert sent_body(seen[0]) == {"document": DOCUMENT}
    assert sent_body(seen[3]) == {"inputs": {"route_id": "r"}, "document": DOCUMENT}
    assert sent_body(seen[6]) == {"previous_activation_hash": NEWEST}


# ── what the methods refuse before sending ────────────────────────────────────


@pytest.mark.parametrize("document", [{"rules": []}, ["rules"], b"rules: []", None, 7])
def test_upload_refuses_a_document_that_is_not_text(document):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="exact text"):
        sync_client(responder(seen), signing_key=None).upload_policy(document)
    assert seen == []


def test_upload_refuses_text_with_no_exact_bytes():
    with pytest.raises(ValidationError, match="Unicode"):
        policy_upload_body("rules: \udc80")


async def test_async_upload_refuses_a_document_that_is_not_text():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen), signing_key=None) as client:
        with pytest.raises(ValidationError):
            await client.upload_policy({"rules": []})  # type: ignore[arg-type]
    assert seen == []


BAD_HASHES = ["A" * 64, "a" * 63, "a" * 65, "g" * 64, "", 7, None]


@pytest.mark.parametrize("bad", BAD_HASHES)
def test_get_refuses_a_bad_hash(bad):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="document_hash"):
        sync_client(responder(seen), signing_key=None).get_policy(bad)
    assert seen == []


@pytest.mark.parametrize("bad", BAD_HASHES)
def test_activate_refuses_a_bad_hash_before_reading_the_policies(bad):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="document_hash"):
        sync_client(responder(seen)).activate_policy(bad)
    assert seen == []


async def test_async_get_and_activate_refuse_a_bad_hash():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen)) as client:
        with pytest.raises(ValidationError):
            await client.get_policy("A" * 64)
        with pytest.raises(ValidationError):
            await client.activate_policy("A" * 64)
    assert seen == []


@pytest.mark.parametrize(
    "documents",
    [{}, {"document": DOCUMENT, "document_hash": DOCUMENT_HASH}],
    ids=["neither", "both"],
)
def test_test_policy_refuses_both_or_neither(documents):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="exactly one"):
        sync_client(responder(seen), signing_key=None).test_policy({}, **documents)
    assert seen == []


async def test_async_test_policy_refuses_both_or_neither():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen), signing_key=None) as client:
        with pytest.raises(ValidationError):
            await client.test_policy({})
        with pytest.raises(ValidationError):
            await client.test_policy({}, document=DOCUMENT, document_hash=DOCUMENT_HASH)
    assert seen == []


def test_test_policy_refuses_a_bad_document_hash_or_document_or_inputs():
    with pytest.raises(ValidationError, match="document_hash"):
        policy_test_body({}, document_hash="A" * 64)
    with pytest.raises(ValidationError, match="exact text"):
        policy_test_body({}, document={"rules": []})  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="inputs"):
        policy_test_body([], document=DOCUMENT)  # type: ignore[arg-type]


def test_test_policy_passes_the_inputs_through_as_given():
    inputs = {"evaluated_at": "2026-11-07T12:00:00Z", "rates": {"1h": 3}, "x": [1, None]}
    assert policy_test_body(inputs, document="")["inputs"] == inputs


# ── activation ────────────────────────────────────────────────────────────────


def test_activate_reads_the_chain_then_sends_a_signed_change():
    seen: list[httpx.Request] = []
    record = sync_client(routed(seen, activation_answers())).activate_policy(DOCUMENT_HASH)
    assert record == ACTIVATION
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/policies"),
        ("POST", f"/policies/{DOCUMENT_HASH}/activate"),
    ]
    body = sent_body(seen[1])
    assert set(body) == {"previous_activation_hash", "signature"}
    assert body["previous_activation_hash"] == NEWEST
    sig = body["signature"]
    assert set(sig) == {"signature", "signed_at", "nonce"}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", sig["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", sig["nonce"])
    vector_public_key().verify(
        base64.b64decode(sig["signature"]),
        expected_preimage(CHAIN_ID, DOCUMENT_HASH, NEWEST, sig),
    )


def test_a_first_activation_names_no_previous_change():
    seen: list[httpx.Request] = []
    listing = {**LISTING, "newest_activation_hash": PREVIOUS}
    sync_client(routed(seen, activation_answers({("GET", "/policies"): listing}))).activate_policy(
        DOCUMENT_HASH
    )
    body = sent_body(seen[1])
    assert body["previous_activation_hash"] == "0" * 64
    vector_public_key().verify(
        base64.b64decode(body["signature"]["signature"]),
        expected_preimage(CHAIN_ID, DOCUMENT_HASH, PREVIOUS, body["signature"]),
    )


def test_the_signature_covers_the_chain_so_another_chain_does_not_verify():
    seen: list[httpx.Request] = []
    sync_client(routed(seen, activation_answers())).activate_policy(DOCUMENT_HASH)
    sig = sent_body(seen[1])["signature"]
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        vector_public_key().verify(
            base64.b64decode(sig["signature"]),
            expected_preimage("api-key-8", DOCUMENT_HASH, NEWEST, sig),
        )


def test_activate_without_a_signing_key_sends_no_signature():
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, activation_answers()), signing_key=None)
    assert client.activate_policy(DOCUMENT_HASH) == ACTIVATION
    assert sent_body(seen[1]) == {"previous_activation_hash": NEWEST}


def test_rolling_back_is_activating_an_earlier_document():
    seen: list[httpx.Request] = []
    earlier = "3" * 64
    listing = {**LISTING, "active_document_hash": DOCUMENT_HASH}
    answers = {
        ("GET", "/policies"): listing,
        ("POST", f"/policies/{earlier}/activate"): {"ok": True, "activation": ACTIVATION},
    }
    sync_client(routed(seen, answers)).activate_policy(earlier)
    sig = sent_body(seen[1])["signature"]
    vector_public_key().verify(
        base64.b64decode(sig["signature"]), expected_preimage(CHAIN_ID, earlier, NEWEST, sig)
    )


async def test_async_activate_signs_the_same_way():
    seen: list[httpx.Request] = []
    async with async_client(routed(seen, activation_answers())) as client:
        assert await client.activate_policy(DOCUMENT_HASH) == ACTIVATION
    assert [r.method for r in seen] == ["GET", "POST"]
    sig = sent_body(seen[1])["signature"]
    vector_public_key().verify(
        base64.b64decode(sig["signature"]),
        expected_preimage(CHAIN_ID, DOCUMENT_HASH, NEWEST, sig),
    )


async def test_async_activate_without_a_signing_key_sends_no_signature():
    seen: list[httpx.Request] = []
    async with async_client(routed(seen, activation_answers()), signing_key=None) as client:
        await client.activate_policy(DOCUMENT_HASH)
    assert sent_body(seen[1]) == {"previous_activation_hash": NEWEST}


def test_a_409_raises_the_usual_error_with_the_servers_message_and_is_not_retried():
    seen: list[httpx.Request] = []
    moved = httpx.Response(409, json={"error": "previous_activation_hash is not the newest change"})
    answers = activation_answers({("POST", f"/policies/{DOCUMENT_HASH}/activate"): moved})
    with pytest.raises(APIError) as caught:
        sync_client(routed(seen, answers)).activate_policy(DOCUMENT_HASH)
    assert caught.value.status_code == 409
    assert caught.value.message == "previous_activation_hash is not the newest change"
    assert [r.method for r in seen] == ["GET", "POST"]


async def test_async_409_raises_and_is_not_retried():
    seen: list[httpx.Request] = []
    early = httpx.Response(409, json={"error": "the policy is not yet effective"})
    answers = activation_answers({("POST", f"/policies/{DOCUMENT_HASH}/activate"): early})
    async with async_client(routed(seen, answers)) as client:
        with pytest.raises(APIError) as caught:
            await client.activate_policy(DOCUMENT_HASH)
    assert caught.value.status_code == 409
    assert [r.method for r in seen] == ["GET", "POST"]


@pytest.mark.parametrize("status", [403, 404, 503])
def test_other_refusals_raise_the_usual_error(status):
    refused = httpx.Response(status, json={"error": "refused"})
    answers = activation_answers({("POST", f"/policies/{DOCUMENT_HASH}/activate"): refused})
    with pytest.raises(APIError) as caught:
        sync_client(routed([], answers)).activate_policy(DOCUMENT_HASH)
    assert caught.value.status_code == status


def test_a_failed_listing_sends_no_change():
    seen: list[httpx.Request] = []
    answers = activation_answers({("GET", "/policies"): httpx.Response(401, json={})})
    client = VerdifaxClient(
        base_url="http://test.invalid",
        transport=httpx.MockTransport(routed(seen, answers)),
        signing_key=SEED,
    )
    with pytest.raises(APIError):
        client.activate_policy(DOCUMENT_HASH)
    assert [r.method for r in seen] == ["GET"]


@pytest.mark.parametrize("chain_id", [None, "", 7])
def test_a_signing_client_needs_a_chain_id(chain_id):
    seen: list[httpx.Request] = []
    listing = {**LISTING, "chain_id": chain_id}
    if chain_id is None:
        del listing["chain_id"]
    answers = activation_answers({("GET", "/policies"): listing})
    with pytest.raises(VerdifaxError, match="chain_id"):
        sync_client(routed(seen, answers)).activate_policy(DOCUMENT_HASH)
    assert [r.method for r in seen] == ["GET"]


@pytest.mark.parametrize("newest", [None, "", "E" * 64, "e" * 63])
def test_a_listing_with_no_usable_newest_change_sends_nothing(newest):
    seen: list[httpx.Request] = []
    listing = {**LISTING, "newest_activation_hash": newest}
    answers = activation_answers({("GET", "/policies"): listing})
    with pytest.raises(VerdifaxError, match="newest change"):
        sync_client(routed(seen, answers), signing_key=None).activate_policy(DOCUMENT_HASH)
    assert [r.method for r in seen] == ["GET"]


def test_an_answer_with_no_activation_record_raises():
    with pytest.raises(VerdifaxError, match="activation record"):
        activation_record({"ok": True})
    answers = activation_answers({("POST", f"/policies/{DOCUMENT_HASH}/activate"): {"ok": True}})
    with pytest.raises(VerdifaxError):
        sync_client(routed([], answers)).activate_policy(DOCUMENT_HASH)


def test_activation_body_directly():
    unsigned = policy_activation_body(None, LISTING, DOCUMENT_HASH)
    assert unsigned == {"previous_activation_hash": NEWEST}
    signed = policy_activation_body(load_signing_key(SEED), LISTING, DOCUMENT_HASH)
    assert signed["previous_activation_hash"] == NEWEST
    assert set(signed["signature"]) == {"signature", "signed_at", "nonce"}


def test_activation_sends_no_private_key():
    seen: list[httpx.Request] = []
    sync_client(routed(seen, activation_answers())).activate_policy(DOCUMENT_HASH)
    sent = b"".join(r.content for r in seen)
    assert SEED.hex().encode() not in sent
    assert base64.b64encode(SEED) not in sent


# ── policy_context and expected_policy_hash on every run ──────────────────────

POLICY_FIELDS = {
    "policy_context": FULL_CONTEXT,
    "expected_policy_hash": POLICY_HASH,
}
ACTOR_ARGS = {**ARGS, "attested_context": ACTOR}


def assert_policy_fields(request_body: dict[str, Any]) -> None:
    assert request_body["policy_context"] == FULL_CONTEXT
    assert request_body["expected_policy_hash"] == POLICY_HASH


@pytest.mark.parametrize("method", ["attest", "execute"])
def test_attest_and_execute_sign_the_policy_fields(method):
    seen: list[httpx.Request] = []
    getattr(sync_client(scripted(seen, [success(HASH_A)])), method)(**ACTOR_ARGS, **POLICY_FIELDS)
    body = sent_body(seen[0])
    assert set(body) == {"signed_request", "request_signature"}
    assert_policy_fields(inner(body))
    assert_verifies(body, b"hello")


@pytest.mark.parametrize("method", ["attest", "execute"])
def test_an_unsigned_call_sends_the_policy_fields_as_plain_json(method):
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [success(HASH_A)]), signing_key=None)
    getattr(client, method)(**ARGS, policy_context=OBJECT_CONTEXT, expected_policy_hash=POLICY_HASH)
    assert sent_body(seen[0]) == {
        "payload_text": "hello",
        **INPUTS,
        "policy_context": OBJECT_CONTEXT,
        "expected_policy_hash": POLICY_HASH,
    }


def test_a_call_without_them_sends_neither():
    seen: list[httpx.Request] = []
    sync_client(scripted(seen, [success(HASH_A)])).attest(**ARGS)
    request_body = inner(sent_body(seen[0]))
    assert "policy_context" not in request_body
    assert "expected_policy_hash" not in request_body


def test_the_receipt_keeps_the_signed_text_with_the_policy_fields():
    seen: list[httpx.Request] = []
    receipt = sync_client(scripted(seen, [success(HASH_A)])).attest(
        **ARGS, policy_context=OBJECT_CONTEXT
    )
    assert json.loads(receipt.signed_request or "")["policy_context"] == OBJECT_CONTEXT


async def test_async_attest_and_execute_sign_the_policy_fields():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A), success(HASH_A)])) as client:
        await client.attest(**ACTOR_ARGS, **POLICY_FIELDS)
        await client.execute(**ACTOR_ARGS, **POLICY_FIELDS)
    for request in seen:
        assert_policy_fields(inner(sent_body(request)))
        assert_verifies(sent_body(request), b"hello")


def test_a_signed_batch_row_carries_the_policy_fields():
    seen: list[httpx.Request] = []
    rows = [{**ACTOR_ARGS, **POLICY_FIELDS}, {**ARGS, "payload": "other"}]
    sync_client(responder(seen, body=BATCH)).execute_batch(rows)
    first, second = sent_body(seen[0])["runs"]
    assert_policy_fields(inner(first))
    assert_verifies(first, b"hello")
    assert "policy_context" not in inner(second)
    assert "expected_policy_hash" not in inner(second)


def test_a_batch_row_with_a_mapping_attested_context_passes_the_actor_rule():
    row = {**ARGS, "attested_context": {"actor_id": "agent-7"}, **POLICY_FIELDS}
    sent = batch_body([row])["runs"][0]
    assert sent["attested_context"]["attested"] is True
    assert_policy_fields(sent)


def test_a_batch_row_model_carries_the_policy_fields():
    row = ExecuteRequest(
        payload_text="hello",
        **INPUTS,
        attested_context=ACTOR,
        **POLICY_FIELDS,
    )
    assert_policy_fields(batch_body([row])["runs"][0])


async def test_async_batch_row_carries_the_policy_fields():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=BATCH)) as client:
        await client.execute_batch([{**ACTOR_ARGS, **POLICY_FIELDS}])
    assert_policy_fields(inner(sent_body(seen[0])["runs"][0]))


def test_the_determinism_check_signs_the_policy_fields():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=DETERMINISM))
    result = client.verify_determinism("hello", **INPUTS, attested_context=ACTOR, **POLICY_FIELDS)
    body = sent_body(seen[0])
    assert_policy_fields(inner(body))
    assert_verifies(body, b"hello")
    assert result.signed_request == body["signed_request"]


def test_the_module_determinism_check_sends_the_policy_fields_unsigned():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=DETERMINISM), signing_key=None)
    verify_determinism(client, "hello", **INPUTS, policy_context=OBJECT_CONTEXT)
    assert sent_body(seen[0])["policy_context"] == OBJECT_CONTEXT
    assert "expected_policy_hash" not in sent_body(seen[0])


async def test_async_determinism_check_signs_the_policy_fields():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=DETERMINISM)) as client:
        await client.verify_determinism("hello", **INPUTS, attested_context=ACTOR, **POLICY_FIELDS)
    assert_policy_fields(inner(sent_body(seen[0])))


PROVIDER_METHODS = ["attest_claude_response", "attest_openai_response"]
PROVIDER_FUNCTIONS = [verdifax.attest_claude_response, verdifax.attest_openai_response]


@pytest.mark.parametrize("method", PROVIDER_METHODS)
def test_a_provider_method_signs_the_policy_fields(method):
    seen: list[httpx.Request] = []
    # A provider helper attests an AI assistant, so actor values are allowed.
    getattr(sync_client(scripted(seen, [success(HASH_A)])), method)(
        "p", "r", **INPUTS, **POLICY_FIELDS
    )
    body = sent_body(seen[0])
    assert_policy_fields(inner(body))
    assert_verifies(body, inner(body)["payload_text"].encode("utf-8"))


@pytest.mark.parametrize("method", PROVIDER_METHODS)
async def test_an_async_provider_method_signs_the_policy_fields(method):
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A)])) as client:
        await getattr(client, method)("p", "r", **INPUTS, **POLICY_FIELDS)
    assert_policy_fields(inner(sent_body(seen[0])))


@pytest.mark.parametrize("helper", PROVIDER_FUNCTIONS)
def test_a_module_provider_helper_sends_the_policy_fields(helper):
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [success(HASH_A)]))
    helper("p", "r", **INPUTS, client=client, **POLICY_FIELDS)
    assert_policy_fields(inner(sent_body(seen[0])))


def test_module_level_attest_sends_the_policy_fields(monkeypatch):
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
        attested_context=ACTOR,
        **POLICY_FIELDS,
    )
    assert_policy_fields(sent_body(seen[0]))


def test_a_job_step_takes_the_policy_fields():
    assert {"policy_context", "expected_policy_hash"} <= _STEP_ATTEST_OPTIONS
    seen: list[httpx.Request] = []
    job = sync_client(scripted(seen, [success(HASH_A)])).job("j")
    job.step("s", **ACTOR_ARGS, **POLICY_FIELDS)
    request_body = inner(sent_body(seen[0]))
    assert_policy_fields(request_body)
    assert request_body["job"] == {"job_id": "j", "step_id": "s"}


async def test_an_async_job_step_takes_the_policy_fields():
    seen: list[httpx.Request] = []
    async with async_client(scripted(seen, [success(HASH_A)])) as client:
        await client.job("j").step("s", **ACTOR_ARGS, **POLICY_FIELDS)
    assert_policy_fields(inner(sent_body(seen[0])))


def test_a_pinned_run_refused_with_409_raises_the_usual_error_with_the_text():
    seen: list[httpx.Request] = []
    pinned = httpx.Response(
        409, json={"error": "a different policy is active than the one this request names"}
    )
    with pytest.raises(APIError) as caught:
        sync_client(scripted(seen, [pinned])).attest(**ARGS, expected_policy_hash=POLICY_HASH)
    assert caught.value.status_code == 409
    assert caught.value.signed_request == sent_body(seen[0])["signed_request"]
    assert len(seen) == 1


# ── what the policy fields refuse before sending ──────────────────────────────

BAD_CONTEXTS = [
    ({"actor": "agent"}, "unknown fields: actor"),
    ({"mfa": True}, "unknown fields: mfa"),
    ({"Classification": "PUBLIC"}, "unknown fields"),
    ({"actor_type": "robot"}, "actor_type"),
    ({"actor_type": "Agent"}, "actor_type"),
    ({"actor_type": None}, "actor_type"),
    ({"object_type": "image"}, "object_type"),
    ({"object_type": 3}, "object_type"),
    ({"classification": "SECRET"}, "classification"),
    ({"classification": "public"}, "classification"),
    ({"mfa_satisfied": "true"}, "mfa_satisfied"),
    ({"mfa_satisfied": 1}, "mfa_satisfied"),
    ({"mfa_satisfied": None}, "mfa_satisfied"),
    ({"session_age_seconds": -1}, "cannot be negative"),
    ({"session_age_seconds": 1.5}, "session_age_seconds"),
    ({"session_age_seconds": True}, "session_age_seconds"),
    ({"session_age_seconds": "30"}, "session_age_seconds"),
    ({"session_age_seconds": 2**63}, "too large"),
    ({"object_id": "x" * 257}, "longer than 256 bytes"),
    ({"object_id": "\u00e9" * 129}, "longer than 256 bytes"),
    ({"object_id": 7}, "object_id"),
    ({"object_id": "\udc80"}, "Unicode"),
]


@pytest.mark.parametrize("context, message", BAD_CONTEXTS)
def test_a_bad_policy_context_is_refused(context, message):
    with pytest.raises(ValidationError, match=message):
        policy_context_block(context)


@pytest.mark.parametrize("context", [["actor_type"], "agent", 7])
def test_a_policy_context_that_is_not_a_mapping_is_refused(context):
    with pytest.raises(ValidationError, match="mapping"):
        policy_context_block(context)


def test_the_edges_of_a_good_policy_context_pass():
    good = {
        "actor_type": "system",
        "mfa_satisfied": False,
        "session_age_seconds": 0,
        "object_type": "file",
        "object_id": "x" * 256,
        "classification": "TS_SCI",
    }
    assert policy_context_block(good) == good
    assert policy_context_block({"object_id": "\u00e9" * 128}) == {"object_id": "\u00e9" * 128}
    assert policy_context_block({}) == {}
    assert policy_context_block(None) is None


@pytest.mark.parametrize("value", ["agent", "user", "service", "system"])
def test_every_actor_type_passes(value):
    policy_context_block({"actor_type": value})


@pytest.mark.parametrize("value", ["text", "transaction", "code", "data", "model", "file"])
def test_every_object_type_passes(value):
    policy_context_block({"object_type": value})


@pytest.mark.parametrize(
    "value", ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET", "TS_SCI"]
)
def test_every_classification_passes(value):
    policy_context_block({"classification": value})


BAD_EXPECTED = ["F" * 64, "f" * 63, "f" * 65, "z" * 64, "", 7]

REFUSALS = [(context, {"policy_context": context}) for context, _ in BAD_CONTEXTS] + [
    (bad, {"expected_policy_hash": bad}) for bad in BAD_EXPECTED
]


def every_way_in(client: VerdifaxClient, fields: dict[str, Any]) -> list[Callable[[], Any]]:
    return [
        lambda: client.attest(**ACTOR_ARGS, **fields),
        lambda: client.execute(**ACTOR_ARGS, **fields),
        lambda: client.execute_batch([{**ACTOR_ARGS, **fields}]),
        lambda: client.verify_determinism("hello", **INPUTS, attested_context=ACTOR, **fields),
        lambda: client.attest_claude_response("p", "r", **INPUTS, **fields),
        lambda: client.attest_openai_response("p", "r", **INPUTS, **fields),
        lambda: client.job("j").step("s", **ACTOR_ARGS, **fields),
    ]


@pytest.mark.parametrize("value, fields", REFUSALS)
@pytest.mark.parametrize("signing_key", [SEED, None], ids=["signed", "unsigned"])
def test_every_way_in_refuses_a_bad_policy_field_before_sending(value, fields, signing_key):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen), signing_key=signing_key)
    for call in every_way_in(client, fields):
        with pytest.raises(ValidationError):
            call()
    assert seen == []


@pytest.mark.parametrize("bad", BAD_EXPECTED)
def test_a_bad_expected_policy_hash_names_the_field(bad):
    with pytest.raises(ValidationError, match="expected_policy_hash"):
        sync_client(responder([])).attest(**ARGS, expected_policy_hash=bad)


async def test_async_refuses_a_bad_policy_field_before_sending():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen)) as client:
        calls = [
            client.attest(**ACTOR_ARGS, policy_context={"mfa": True}),
            client.execute(**ACTOR_ARGS, policy_context={"session_age_seconds": -1}),
            client.execute_batch([{**ACTOR_ARGS, "policy_context": {"object_id": "x" * 257}}]),
            client.verify_determinism("hello", **INPUTS, expected_policy_hash="F" * 64),
            client.attest_claude_response("p", "r", **INPUTS, policy_context={"actor_type": "x"}),
            client.job("j").step("s", **ARGS, expected_policy_hash="short"),
        ]
        for call in calls:
            with pytest.raises(ValidationError):
                await call
    assert seen == []


def test_determinism_body_refuses_a_bad_policy_field():
    with pytest.raises(ValidationError):
        determinism_body("hello", **INPUTS, policy_context={"classification": "SECRET"})


# ── the actor values need an attested actor ───────────────────────────────────


@pytest.mark.parametrize(
    "context",
    [{"actor_type": "user"}, {"mfa_satisfied": True}, {"session_age_seconds": 30}],
)
def test_an_actor_value_with_no_attested_actor_is_refused_before_sending(context):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    calls: list[Callable[[], Any]] = [
        lambda: client.attest(**ARGS, policy_context=context),
        lambda: client.execute_batch([{**ARGS, "policy_context": context}]),
        lambda: client.verify_determinism("hello", **INPUTS, policy_context=context),
        lambda: client.attest(**ARGS, attested_context=AttestedContext(), policy_context=context),
    ]
    for call in calls:
        with pytest.raises(ValidationError, match="attested_context"):
            call()
    assert seen == []


async def test_async_actor_value_with_no_attested_actor_is_refused():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen)) as client:
        with pytest.raises(ValidationError, match="attested_context"):
            await client.attest(**ARGS, policy_context={"mfa_satisfied": True})
    assert seen == []


@pytest.mark.parametrize(
    "context",
    [
        {"object_type": "code", "object_id": "repo-1", "classification": "PUBLIC"},
        {"mfa_satisfied": False},
        {"session_age_seconds": 0},
        {},
    ],
)
def test_values_that_describe_no_actor_need_no_attested_context(context):
    seen: list[httpx.Request] = []
    sync_client(scripted(seen, [success(HASH_A)])).attest(**ARGS, policy_context=context)
    assert inner(sent_body(seen[0]))["policy_context"] == context


def test_the_actor_rule_reads_the_attested_flag_as_sent():
    check_policy_actor({"actor_type": "agent"}, {"attested": True, "actor_id": "a"})
    check_policy_actor({"object_type": "text"}, None)
    check_policy_actor(None, None)
    with pytest.raises(ValidationError):
        check_policy_actor({"actor_type": "agent"}, {"attested": False})
    with pytest.raises(ValidationError):
        check_policy_actor({"session_age_seconds": 5}, None)


# ── version ───────────────────────────────────────────────────────────────────


def test_the_readme_states_the_three_sentences():
    from pathlib import Path

    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    for sentence in (
        "Verdifax did not write, review or approve your policy. "
        "A pass means the rules ran, not that they are good rules.",
        "A policy judges what you declared. It cannot show the declared facts are true.",
        "A refusal stops the action only if your system waits for the answer.",
    ):
        assert sentence in readme
    lowered = readme.lower()
    for word in ("aligned", "compliant", "certified"):
        assert word not in lowered
    assert "\u2014" not in readme and "\u2013" not in readme


def test_no_source_file_has_a_long_dash():
    from pathlib import Path

    root = Path(__file__).parent.parent
    files = [root / "README.md", *root.glob("verdifax/*.py"), *root.glob("tests/*.py")]
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text and "\u2013" not in text, path
