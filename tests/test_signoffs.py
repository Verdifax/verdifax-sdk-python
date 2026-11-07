"""SDK 1.4: customer sign-off on results, on both clients.

Requests go to ``httpx.MockTransport``, so nothing reaches the network. The
sign-off and approver proof bytes come from ``sdk-signature-vector.json``,
shared by the four SDKs: the vector's seed signs as an approver, approving
run 42's record in account-7.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import verdifax
from tests.test_accounts import parity_names
from tests.test_jobs import (
    NEW_SEED,
    NONCE,
    SEED,
    SIGNED_AT,
    VECTOR,
    async_client,
    scripted,
    sent_body,
    sync_client,
    vector_public_key,
)
from tests.test_parity import EXPORT, responder
from tests.test_policies import routed
from verdifax import (
    AccountRunsExport,
    APIError,
    AsyncVerdifaxClient,
    RunsExport,
    SignOffTarget,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    approver_key_proof,
    signoff_preimage,
)
from verdifax._signoffs import (
    approver_body,
    approver_proof_preimage,
    load_approver_key,
    note_hash,
    prepare_signoff,
    signoff_body,
    signoff_record,
    signoff_target,
)
from verdifax._signing import load_signing_key

CHAIN = VECTOR["signoff_chain_id"]
ZERO = VECTOR["signoff_previous_hash"]
DIGEST = VECTOR["signoff_target_digest"]
RUN_ID = VECTOR["signoff_target_run_id"]
TARGET = {"kind": VECTOR["signoff_target_kind"], "run_id": RUN_ID, "digest": DIGEST}
NOTE = "checked against the loan file"
NOTE_HASH = VECTOR["signoff_note_hash"]
NEWEST_HASH = "e" * 64
APPROVER_SEED = NEW_SEED
JOB_TARGET = {"kind": "job", "run_id": 43, "digest": "b" * 64, "job_id": "loan-1"}

NEWEST = {"ok": True, "chain_id": CHAIN, "newest_signoff_hash": NEWEST_HASH, "sequence": 3}
FIRST = {"ok": True, "chain_id": CHAIN, "newest_signoff_hash": ZERO, "sequence": 0}
APPROVER = {
    "ok": True,
    "id": 5,
    "public_key": VECTOR["public_key"],
    "name": "Dana, credit review",
    "account_id": CHAIN,
    "registered_at": "2026-11-07T12:00:00Z",
    "revoked": False,
}
APPROVERS = {"ok": True, "account_id": CHAIN, "approvers": [APPROVER]}
REVOKED = {"ok": True, "id": 5, "revoked": True}
RECORD = {
    "format": "verdifax.signoff.v1",
    "chain_id": CHAIN,
    "sequence": 1,
    "previous_signoff_hash": ZERO,
    "target": TARGET,
    "decision": "approve",
    "note_hash": NOTE_HASH,
    "approver_key": VECTOR["public_key"],
    "signature": VECTOR["signoff_signature"],
    "signed_at": SIGNED_AT,
    "nonce": NONCE,
    "recorded_at": "2026-11-06T12:00:01Z",
    "signoff_hash": "f" * 64,
    "anchor": {"kind": "signoff", "log_index": 9},
}
HISTORY = [RECORD, {**RECORD, "sequence": 2, "decision": "reject"}]

SIGNOFF_METHODS = [
    "register_approver",
    "list_approvers",
    "revoke_approver",
    "sign_off",
    "get_signoffs",
    "get_newest_signoff",
    "get_signoff_history",
]


def public_key_of(seed: bytes) -> str:
    return base64.b64encode(load_signing_key(seed).public_key().public_bytes_raw()).decode()


def verifier_of(seed: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_of(seed)))


def expected_preimage(chain: str, previous: str, target: dict, body: dict) -> bytes:
    """The bytes the server rebuilds, written out independently of the SDK."""
    fields = [
        "verdifax.signoff.v1",
        chain,
        previous,
        target["kind"],
        str(target["run_id"]),
        target["digest"],
        target.get("job_id", ""),
        body["decision"],
        body.get("note_hash", ""),
        body["signed_at"],
        body["nonce"],
    ]
    return "\x00".join(fields).encode()


def echo_record(answers: dict, submit_path: str) -> Any:
    """Answer a submit with the record the server would build from the body."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST" and request.url.path == submit_path:
            body = sent_body(request)
            return httpx.Response(201, json={"ok": True, "signoff": {**RECORD, **body}})
        return routed([], answers)(request)

    return seen, handler


def all_request_text(seen: list[httpx.Request]) -> str:
    return "\n".join(str(r.url) + r.content.decode("utf-8") for r in seen)


# ── the vector, byte for byte ─────────────────────────────────────────────────


def test_the_vector_note_hash_is_the_sha256_of_the_note():
    assert hashlib.sha256(NOTE.encode()).hexdigest() == NOTE_HASH
    assert note_hash(NOTE) == NOTE_HASH
    assert note_hash(None) == ""
    with pytest.raises(ValidationError, match="note is empty"):
        note_hash("")


def test_vector_signoff_preimage():
    preimage = signoff_preimage(CHAIN, ZERO, TARGET, "approve", NOTE_HASH, SIGNED_AT, NONCE)
    assert preimage.hex() == VECTOR["signoff_preimage_hex"]


def test_vector_signoff_preimage_from_a_target_model():
    preimage = signoff_preimage(
        CHAIN, ZERO, SignOffTarget(**TARGET), "approve", NOTE_HASH, SIGNED_AT, NONCE
    )
    assert preimage.hex() == VECTOR["signoff_preimage_hex"]


def test_vector_signoff_preimage_matches_an_independent_build():
    body = {"decision": "approve", "note_hash": NOTE_HASH, "signed_at": SIGNED_AT, "nonce": NONCE}
    assert expected_preimage(CHAIN, ZERO, TARGET, body).hex() == VECTOR["signoff_preimage_hex"]


def test_vector_signoff_signature():
    prepared = prepare_signoff(TARGET, "approve", SEED, NOTE)
    body = signoff_body(prepared, FIRST, "GET /signoffs/newest", SIGNED_AT, NONCE)
    assert body == {
        "previous_signoff_hash": ZERO,
        "target": TARGET,
        "decision": "approve",
        "note_hash": NOTE_HASH,
        "approver_key": VECTOR["public_key"],
        "signature": VECTOR["signoff_signature"],
        "signed_at": SIGNED_AT,
        "nonce": NONCE,
    }
    vector_public_key().verify(
        base64.b64decode(body["signature"]), bytes.fromhex(VECTOR["signoff_preimage_hex"])
    )


def test_vector_approver_proof():
    assert approver_proof_preimage(VECTOR["public_key"]).hex() == (
        VECTOR["approver_proof_preimage_hex"]
    )
    assert approver_key_proof(SEED) == {
        "public_key": VECTOR["public_key"],
        "proof": VECTOR["approver_proof"],
    }
    independent = b"verdifax.approver-key.v1\x00" + VECTOR["public_key"].encode()
    vector_public_key().verify(base64.b64decode(VECTOR["approver_proof"]), independent)


def test_the_approver_proof_is_not_a_request_key_proof():
    request_key_preimage = b"verdifax.request-key.v1\x00" + VECTOR["public_key"].encode()
    with pytest.raises(InvalidSignature):
        vector_public_key().verify(base64.b64decode(VECTOR["approver_proof"]), request_key_preimage)


def test_a_signoff_signature_does_not_verify_for_another_result():
    moved = {**TARGET, "run_id": 43}
    body = {"decision": "approve", "note_hash": NOTE_HASH, "signed_at": SIGNED_AT, "nonce": NONCE}
    with pytest.raises(InvalidSignature):
        vector_public_key().verify(
            base64.b64decode(VECTOR["signoff_signature"]),
            expected_preimage(CHAIN, ZERO, moved, body),
        )


def test_the_preimage_refuses_ambiguous_values():
    with pytest.raises(ValidationError, match="zero byte"):
        signoff_preimage(CHAIN, ZERO, TARGET, "approve", "", SIGNED_AT, "a\x00b")
    with pytest.raises(ValidationError, match="not text"):
        signoff_preimage(CHAIN, ZERO, TARGET, "approve", None, SIGNED_AT, NONCE)  # type: ignore
    with pytest.raises(ValidationError, match="run_id must be an int"):
        signoff_preimage(CHAIN, ZERO, {**TARGET, "run_id": "42"}, "approve", "", SIGNED_AT, NONCE)


def test_the_helpers_are_exported():
    for name in ("approver_key_proof", "signoff_preimage", "SignOffTarget"):
        assert name in verdifax.__all__
        assert hasattr(verdifax, name)


# ── the shared parity map ─────────────────────────────────────────────────────


def test_the_parity_map_names_every_signoff_method_for_both_clients():
    for column in ("python", "python_async"):
        assert set(SIGNOFF_METHODS) <= set(parity_names(column))


def test_the_parity_map_names_the_signoff_helpers():
    parity = json.loads((Path(__file__).parent / "sdk-parity.json").read_text(encoding="utf-8"))
    assert parity["helpers"]["signoff_preimage"]["python"] == "signoff_preimage"
    assert parity["helpers"]["approver_key_proof"]["python"] == "approver_key_proof"
    assert "Python as_owner" in parity["notes"]["account_routes"]


@pytest.mark.parametrize("name", SIGNOFF_METHODS)
def test_the_async_signature_matches_the_sync_one(name):
    sync = inspect.signature(getattr(VerdifaxClient, name))
    async_ = inspect.signature(getattr(AsyncVerdifaxClient, name))
    assert list(sync.parameters) == list(async_.parameters)
    for param in sync.parameters:
        assert sync.parameters[param].default == async_.parameters[param].default
    assert inspect.iscoroutinefunction(getattr(AsyncVerdifaxClient, name))


@pytest.mark.parametrize("name", ["sign_off", "get_signoffs", "get_newest_signoff"])
def test_the_methods_with_two_routes_take_as_owner(name):
    param = inspect.signature(getattr(VerdifaxClient, name)).parameters["as_owner"]
    assert param.default is False


def test_sign_off_takes_the_documented_arguments():
    params = list(inspect.signature(VerdifaxClient.sign_off).parameters)
    assert params == ["self", "target", "decision", "approver_key", "note", "as_owner"]


# ── approvers ────────────────────────────────────────────────────────────────


def test_register_approver_sends_the_key_its_name_and_a_proof_made_here():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=APPROVER), signing_key=None)
    assert client.register_approver("Dana, credit review", SEED) == APPROVER
    assert (seen[0].method, seen[0].url.path) == ("POST", "/account/approvers")
    assert sent_body(seen[0]) == {
        "public_key": VECTOR["public_key"],
        "name": "Dana, credit review",
        "proof": VECTOR["approver_proof"],
    }
    assert SEED.hex() not in seen[0].content.decode()


def test_register_approver_takes_a_proof_built_on_the_approvers_machine():
    seen: list[httpx.Request] = []
    proven = approver_key_proof(APPROVER_SEED)
    client = sync_client(responder(seen, body=APPROVER))
    client.register_approver("Dana", proven)
    assert sent_body(seen[0]) == {**proven, "name": "Dana"}
    verifier_of(APPROVER_SEED).verify(
        base64.b64decode(proven["proof"]), approver_proof_preimage(proven["public_key"])
    )


def test_list_approvers():
    seen: list[httpx.Request] = []
    assert sync_client(responder(seen, body=APPROVERS)).list_approvers() == APPROVERS
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "GET",
        "/account/approvers",
        b"",
    )


def test_revoke_approver():
    seen: list[httpx.Request] = []
    assert sync_client(responder(seen, body=REVOKED)).revoke_approver(5) == REVOKED
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "DELETE",
        "/account/approvers/5",
        b"",
    )


def test_a_request_key_answer_from_the_server_raises():
    seen: list[httpx.Request] = []
    refused = {"error": "this key is a request key in the account"}
    client = sync_client(responder(seen, body=refused, status=409), signing_key=None)
    with pytest.raises(APIError) as caught:
        client.register_approver("Dana", SEED)
    assert caught.value.status_code == 409
    assert len(seen) == 1


@pytest.mark.parametrize(
    "name, key, message",
    [
        ("", APPROVER_SEED, "name is required"),
        ("   ", APPROVER_SEED, "name is required"),
        (None, APPROVER_SEED, "name is required"),
        ("x" * 201, APPROVER_SEED, "at most 200 bytes"),
        ("Dana", b"short", "32 raw bytes"),
        ("Dana", "a" * 32, "32 raw bytes"),
        ("Dana", {"public_key": VECTOR["public_key"]}, "public_key and proof"),
        ("Dana", {"public_key": "nope", "proof": VECTOR["approver_proof"]}, "public_key and"),
        ("Dana", {**approver_key_proof(APPROVER_SEED), "name": "x"}, "unknown fields: name"),
        (
            "Dana",
            {**approver_key_proof(APPROVER_SEED), "proof": VECTOR["approver_proof"]},
            "does not verify",
        ),
        (
            "Dana",
            {"public_key": VECTOR["public_key"], "proof": VECTOR["signoff_signature"]},
            "does not verify",
        ),
        ("Dana", SEED, "never a request key"),
        ("Dana", approver_key_proof(SEED), "never a request key"),
    ],
)
def test_register_approver_refuses_bad_input_without_a_request(name, key, message):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(responder(seen)).register_approver(name, key)
    assert seen == []


def test_register_approver_accepts_a_name_of_200_bytes():
    body = approver_body("x" * 200, APPROVER_SEED)
    assert body["name"] == "x" * 200


@pytest.mark.parametrize("approver_id", [0, -1, True, "5"])
def test_revoke_approver_refuses_a_bad_id(approver_id):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="approver_id"):
        sync_client(responder(seen)).revoke_approver(approver_id)
    assert seen == []


# ── sign_off ─────────────────────────────────────────────────────────────────


def test_sign_off_reads_the_newest_signs_and_submits():
    seen, handler = echo_record({("GET", "/signoffs/newest"): NEWEST}, "/signoffs")
    client = sync_client(handler, signing_key=None)
    record = client.sign_off(TARGET, "approve", SEED, note=NOTE)
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/signoffs/newest"),
        ("POST", "/signoffs"),
    ]
    body = sent_body(seen[1])
    assert set(body) == {
        "previous_signoff_hash",
        "target",
        "decision",
        "note_hash",
        "approver_key",
        "signature",
        "signed_at",
        "nonce",
    }
    assert body["previous_signoff_hash"] == NEWEST_HASH
    assert body["target"] == TARGET
    assert body["decision"] == "approve"
    assert body["note_hash"] == NOTE_HASH
    assert body["approver_key"] == VECTOR["public_key"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", body["nonce"])
    vector_public_key().verify(
        base64.b64decode(body["signature"]), expected_preimage(CHAIN, NEWEST_HASH, TARGET, body)
    )
    assert record["signature"] == body["signature"]
    assert record["signoff_hash"] == "f" * 64


def test_sign_off_as_owner_uses_the_owner_routes():
    seen, handler = echo_record({("GET", "/account/signoffs/newest"): NEWEST}, "/account/signoffs")
    sync_client(handler, signing_key=None).sign_off(TARGET, "reject", SEED, as_owner=True)
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account/signoffs/newest"),
        ("POST", "/account/signoffs"),
    ]
    assert sent_body(seen[1])["decision"] == "reject"


def test_sign_off_with_no_note_sends_no_note_hash():
    seen, handler = echo_record({("GET", "/signoffs/newest"): FIRST}, "/signoffs")
    sync_client(handler, signing_key=None).sign_off(TARGET, "approve", SEED)
    body = sent_body(seen[1])
    assert "note_hash" not in body
    assert body["previous_signoff_hash"] == ZERO
    vector_public_key().verify(
        base64.b64decode(body["signature"]), expected_preimage(CHAIN, ZERO, TARGET, body)
    )


def test_sign_off_on_a_job_and_a_receipt():
    seen, handler = echo_record({("GET", "/signoffs/newest"): NEWEST}, "/signoffs")
    client = sync_client(handler, signing_key=None)
    client.sign_off(JOB_TARGET, "approve", SEED)
    receipt = {"kind": "receipt", "run_id": 44, "digest": "c" * 64}
    client.sign_off(SignOffTarget(**receipt), "reject", SEED)
    job_body, receipt_body = sent_body(seen[1]), sent_body(seen[3])
    assert job_body["target"] == JOB_TARGET
    assert receipt_body["target"] == receipt
    for body in (job_body, receipt_body):
        vector_public_key().verify(
            base64.b64decode(body["signature"]),
            expected_preimage(CHAIN, NEWEST_HASH, body["target"], body),
        )


def test_the_note_text_never_appears_in_a_request():
    note = "the borrower's file was incomplete; approved after the call on 6 November"
    seen, handler = echo_record({("GET", "/signoffs/newest"): NEWEST}, "/signoffs")
    client = sync_client(handler, signing_key=None)
    client.sign_off(TARGET, "approve", SEED, note=note)
    client.sign_off(TARGET, "approve", SEED, note=note, as_owner=False)
    text = all_request_text(seen)
    assert note not in text
    assert "borrower" not in text
    assert json.dumps(note)[1:-1] not in text
    assert sent_body(seen[1])["note_hash"] == hashlib.sha256(note.encode()).hexdigest()


def test_the_approver_private_key_never_appears_in_a_request():
    seen, handler = echo_record({("GET", "/signoffs/newest"): NEWEST}, "/signoffs")
    sync_client(handler, signing_key=None).sign_off(TARGET, "approve", SEED)
    text = all_request_text(seen)
    assert SEED.hex() not in text
    assert base64.b64encode(SEED).decode() not in text


BAD_SIGNOFFS = [
    ({**TARGET, "kind": "run"}, "approve", SEED, None, False, "kind must be record"),
    ({**TARGET, "run_id": 0}, "approve", SEED, None, False, "run_id must be > 0"),
    ({**TARGET, "run_id": True}, "approve", SEED, None, False, "run_id must be an int"),
    ({**TARGET, "run_id": "42"}, "approve", SEED, None, False, "run_id must be an int"),
    ({**TARGET, "digest": "A" * 64}, "approve", SEED, None, False, "digest must be lowercase"),
    ({**TARGET, "digest": "a" * 63}, "approve", SEED, None, False, "digest must be 64"),
    ({**TARGET, "job_id": "loan-1"}, "approve", SEED, None, False, "only a job target"),
    ({**JOB_TARGET, "job_id": ""}, "approve", SEED, None, False, "only a job target"),
    ({**TARGET, "runid": 42}, "approve", SEED, None, False, "unknown fields: runid"),
    ([TARGET], "approve", SEED, None, False, "must be a SignOffTarget or a mapping"),
    (TARGET, "approved", SEED, None, False, "decision must be approve or reject"),
    (TARGET, "APPROVE", SEED, None, False, "decision must be approve or reject"),
    (TARGET, "approve", SEED, b"note", False, "note must be a str"),
    (TARGET, "approve", SEED, "", False, "note is empty"),
    (TARGET, "approve", SEED, "\ud800", False, "not valid Unicode"),
    (TARGET, "approve", b"short", None, False, "approver_key must be the 32 raw bytes"),
    (TARGET, "approve", None, None, False, "approver_key must be the 32 raw bytes"),
    (TARGET, "approve", SEED, None, "yes", "as_owner must be a bool"),
    (TARGET, "approve", SEED, None, 1, "as_owner must be a bool"),
]


@pytest.mark.parametrize("target, decision, key, note, as_owner, message", BAD_SIGNOFFS)
def test_sign_off_refuses_bad_input_without_a_request(
    target, decision, key, note, as_owner, message
):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=NEWEST), signing_key=None)
    with pytest.raises(ValidationError, match=message):
        client.sign_off(target, decision, key, note=note, as_owner=as_owner)
    assert seen == []


def test_sign_off_refuses_the_clients_own_signing_key_without_a_request():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="never a request key"):
        sync_client(responder(seen, body=NEWEST)).sign_off(TARGET, "approve", SEED)
    assert seen == []


def test_a_signing_client_signs_off_with_another_key():
    seen, handler = echo_record({("GET", "/signoffs/newest"): NEWEST}, "/signoffs")
    sync_client(handler).sign_off(TARGET, "approve", APPROVER_SEED)
    body = sent_body(seen[1])
    assert body["approver_key"] == public_key_of(APPROVER_SEED)
    verifier_of(APPROVER_SEED).verify(
        base64.b64decode(body["signature"]), expected_preimage(CHAIN, NEWEST_HASH, TARGET, body)
    )


def test_a_target_model_refuses_unknown_fields_and_loose_types():
    with pytest.raises(ValidationError, match="unknown fields: runid"):
        SignOffTarget(kind="record", runid=42, digest=DIGEST)  # type: ignore[call-arg]
    with pytest.raises(Exception):
        SignOffTarget(kind="record", run_id="42", digest=DIGEST)  # type: ignore[arg-type]
    assert signoff_target(SignOffTarget(**TARGET)) == TARGET


@pytest.mark.parametrize(
    "newest, message",
    [
        ({**NEWEST, "chain_id": ""}, "GET /signoffs/newest returned no account chain_id"),
        ({**NEWEST, "chain_id": "api-key-7"}, "returned no account chain_id"),
        ({**NEWEST, "chain_id": "account-0"}, "returned no account chain_id"),
        ({**NEWEST, "newest_signoff_hash": None}, "did not return a usable newest sign-off"),
        ({**NEWEST, "newest_signoff_hash": "E" * 64}, "did not return a usable newest"),
        ([], "GET /signoffs/newest did not return an object"),
    ],
)
def test_a_bad_newest_answer_is_refused_and_nothing_is_submitted(newest, message):
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, {("GET", "/signoffs/newest"): newest}), signing_key=None)
    with pytest.raises(VerdifaxError, match=message):
        client.sign_off(TARGET, "approve", SEED)
    assert [r.method for r in seen] == ["GET"]


def test_a_bad_owner_newest_answer_names_the_owner_route():
    seen: list[httpx.Request] = []
    answers = {("GET", "/account/signoffs/newest"): {**NEWEST, "chain_id": None}}
    client = sync_client(routed(seen, answers), signing_key=None)
    with pytest.raises(VerdifaxError, match="GET /account/signoffs/newest returned no"):
        client.sign_off(TARGET, "approve", SEED, as_owner=True)


def test_a_409_raises_and_is_not_retried():
    seen: list[httpx.Request] = []
    moved = httpx.Response(409, json={"error": "previous_signoff_hash is not the newest"})
    answers = {("GET", "/signoffs/newest"): NEWEST, ("POST", "/signoffs"): moved}
    with pytest.raises(APIError) as caught:
        sync_client(routed(seen, answers), signing_key=None).sign_off(TARGET, "approve", SEED)
    assert caught.value.status_code == 409
    assert [r.method for r in seen] == ["GET", "POST"]


@pytest.mark.parametrize(
    "answer, message",
    [
        ({"ok": True}, "no sign-off record"),
        ({"ok": True, "signoff": {**RECORD, "signature": "x"}}, "another signature"),
        ({"ok": True, "signoff": {**RECORD, "decision": "reject"}}, "another decision"),
        ({"ok": True, "signoff": {**RECORD, "target": JOB_TARGET}}, "another target"),
    ],
)
def test_a_record_that_is_not_the_signoff_sent_is_refused(answer, message):
    prepared = prepare_signoff(TARGET, "approve", SEED, NOTE)
    sent = signoff_body(prepared, FIRST, "GET /signoffs/newest", SIGNED_AT, NONCE)
    with pytest.raises(VerdifaxError, match=message):
        signoff_record(answer, sent)


def test_the_record_matching_the_vector_is_returned():
    prepared = prepare_signoff(TARGET, "approve", SEED, NOTE)
    sent = signoff_body(prepared, FIRST, "GET /signoffs/newest", SIGNED_AT, NONCE)
    assert signoff_record({"ok": True, "signoff": RECORD}, sent) == RECORD


def test_the_prepared_signoff_does_not_print_the_key():
    prepared = prepare_signoff(TARGET, "approve", SEED)
    assert " key=" not in repr(prepared) and "Ed25519" not in repr(prepared)
    assert "public_key=" in repr(prepared)
    assert load_approver_key(SEED).private_bytes_raw() == SEED


# ── reading sign-offs ────────────────────────────────────────────────────────


def test_get_signoffs_reads_a_members_run():
    seen: list[httpx.Request] = []
    assert sync_client(responder(seen, body=[RECORD])).get_signoffs(42) == [RECORD]
    assert (seen[0].method, seen[0].url.path) == ("GET", "/runs/42/signoffs")


def test_get_signoffs_as_owner_reads_any_run_of_the_account():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=[])).get_signoffs(42, as_owner=True)
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/runs/42/signoffs")


@pytest.mark.parametrize("run_id", [0, True, "42"])
def test_get_signoffs_refuses_a_bad_run_id(run_id):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="run_id"):
        sync_client(responder(seen)).get_signoffs(run_id)
    assert seen == []


def test_get_newest_signoff_for_a_member_and_the_owner():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=NEWEST))
    assert client.get_newest_signoff() == NEWEST
    assert client.get_newest_signoff(as_owner=True) == NEWEST
    assert [r.url.path for r in seen] == ["/signoffs/newest", "/account/signoffs/newest"]


def test_get_signoff_history():
    seen: list[httpx.Request] = []
    assert sync_client(responder(seen, body=HISTORY)).get_signoff_history() == HISTORY
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/signoffs/history")


def test_lists_that_are_not_lists_are_refused():
    client = sync_client(responder([], body={"ok": True}))
    with pytest.raises(VerdifaxError, match="sign-off list is not a list"):
        client.get_signoffs(42)
    with pytest.raises(VerdifaxError, match="sign-off history is not a list"):
        client.get_signoff_history()


def test_an_owner_export_carries_the_signoffs():
    seen: list[httpx.Request] = []
    body = {**EXPORT, "account_id": CHAIN, "signoffs": HISTORY}
    export = sync_client(responder(seen, body=body)).export_account_runs()
    assert isinstance(export, AccountRunsExport)
    assert export.signoffs == HISTORY


def test_a_member_export_has_no_signoffs():
    export = RunsExport.model_validate(EXPORT)
    assert export.signoffs == []


# ── the async client ──────────────────────────────────────────────────────────


async def test_async_signoff_methods_send_the_same_requests():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if request.method == "POST" and path in ("/signoffs", "/account/signoffs"):
            return httpx.Response(201, json={"ok": True, "signoff": sent_body(request)})
        answers = {
            "/account/approvers": APPROVERS if request.method == "GET" else APPROVER,
            "/account/approvers/5": REVOKED,
            "/signoffs/newest": NEWEST,
            "/account/signoffs/newest": NEWEST,
            "/runs/42/signoffs": [RECORD],
            "/account/runs/42/signoffs": [RECORD],
            "/account/signoffs/history": HISTORY,
            "/account/runs/export": {**EXPORT, "signoffs": HISTORY},
        }
        return httpx.Response(200, json=answers[path])

    async with async_client(handler, signing_key=None) as client:
        assert await client.register_approver("Dana", SEED) == APPROVER
        assert await client.list_approvers() == APPROVERS
        assert await client.revoke_approver(5) == REVOKED
        member = await client.sign_off(TARGET, "approve", SEED, note=NOTE)
        owner = await client.sign_off(JOB_TARGET, "reject", SEED, as_owner=True)
        assert await client.get_signoffs(42) == [RECORD]
        assert await client.get_signoffs(42, as_owner=True) == [RECORD]
        assert await client.get_newest_signoff() == NEWEST
        assert await client.get_newest_signoff(as_owner=True) == NEWEST
        assert await client.get_signoff_history() == HISTORY
        export = await client.export_account_runs()
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/account/approvers"),
        ("GET", "/account/approvers"),
        ("DELETE", "/account/approvers/5"),
        ("GET", "/signoffs/newest"),
        ("POST", "/signoffs"),
        ("GET", "/account/signoffs/newest"),
        ("POST", "/account/signoffs"),
        ("GET", "/runs/42/signoffs"),
        ("GET", "/account/runs/42/signoffs"),
        ("GET", "/signoffs/newest"),
        ("GET", "/account/signoffs/newest"),
        ("GET", "/account/signoffs/history"),
        ("GET", "/account/runs/export"),
    ]
    assert sent_body(seen[0]) == {
        "public_key": VECTOR["public_key"],
        "name": "Dana",
        "proof": VECTOR["approver_proof"],
    }
    for index, target in ((4, TARGET), (6, JOB_TARGET)):
        body = sent_body(seen[index])
        assert body["target"] == target
        vector_public_key().verify(
            base64.b64decode(body["signature"]),
            expected_preimage(CHAIN, NEWEST_HASH, target, body),
        )
    assert sent_body(seen[4])["note_hash"] == NOTE_HASH
    assert "note_hash" not in sent_body(seen[6])
    assert member["decision"] == "approve" and owner["decision"] == "reject"
    assert NOTE not in all_request_text(seen)
    assert export.signoffs == HISTORY


async def test_async_signoff_methods_refuse_bad_input_without_a_request():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=NEWEST)) as client:
        for target, decision, key, note, as_owner, message in BAD_SIGNOFFS:
            with pytest.raises(ValidationError, match=message):
                await client.sign_off(target, decision, key, note=note, as_owner=as_owner)
        with pytest.raises(ValidationError, match="never a request key"):
            await client.sign_off(TARGET, "approve", SEED)
        with pytest.raises(ValidationError, match="never a request key"):
            await client.register_approver("Dana", SEED)
        with pytest.raises(ValidationError, match="name is required"):
            await client.register_approver("", APPROVER_SEED)
        forged = {**approver_key_proof(APPROVER_SEED), "proof": VECTOR["approver_proof"]}
        with pytest.raises(ValidationError, match="does not verify"):
            await client.register_approver("Dana", forged)
        with pytest.raises(ValidationError, match="approver_id"):
            await client.revoke_approver(0)
        with pytest.raises(ValidationError, match="run_id"):
            await client.get_signoffs(0)
        with pytest.raises(ValidationError, match="as_owner"):
            await client.get_newest_signoff(as_owner="yes")  # type: ignore[arg-type]
    assert seen == []


async def test_async_a_bad_newest_answer_is_refused_and_nothing_is_submitted():
    seen: list[httpx.Request] = []
    answers = {("GET", "/signoffs/newest"): {**NEWEST, "chain_id": ""}}
    async with async_client(routed(seen, answers), signing_key=None) as client:
        with pytest.raises(VerdifaxError, match="returned no account chain_id"):
            await client.sign_off(TARGET, "approve", SEED)
    assert [r.method for r in seen] == ["GET"]


async def test_async_a_409_raises_and_is_not_retried():
    seen: list[httpx.Request] = []
    moved = httpx.Response(409, json={"error": "the chain moved"})
    async with async_client(scripted(seen, [httpx.Response(200, json=NEWEST), moved])) as client:
        with pytest.raises(APIError) as caught:
            await client.sign_off(TARGET, "approve", APPROVER_SEED)
    assert caught.value.status_code == 409
    assert [r.method for r in seen] == ["GET", "POST"]


async def test_async_lists_that_are_not_lists_are_refused():
    async with async_client(responder([], body={"ok": True})) as client:
        with pytest.raises(VerdifaxError, match="not a list"):
            await client.get_signoffs(42, as_owner=True)
        with pytest.raises(VerdifaxError, match="not a list"):
            await client.get_signoff_history()


# ── the README ────────────────────────────────────────────────────────────────


def test_the_readme_states_the_signoff_facts():
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Sign-off", 1)[1].split("\n## ", 1)[0]
    for sentence in (
        "An approver key is registered by the account's owner, and it is never a request key "
        "in the same account.",
        "A sign-off shows that the holder of a registered approver key signed that decision "
        "on that exact result, and that Verdifax logged it on the public log.",
        "It does not show that the review was careful, that the result is right, or who the "
        "person is: a key is not an identity.",
        "A sign-off gates nothing on its own.",
        "A later sign-off on the same result supersedes the earlier one, and nothing is deleted.",
        "Verdifax did not review the result.",
        "`verdifax-verify` reads sign-offs since v0.22.0.",
        "The note's text is never sent",
    ):
        assert sentence in section, sentence
    for name in SIGNOFF_METHODS:
        assert f"`{name}(" in readme, name
    for name in ("approver_key_proof", "signoff_preimage"):
        assert f"`verdifax.{name}(" in section, name
    assert "\u2014" not in section and "\u2013" not in section
