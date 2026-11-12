"""SDK 1.14: the owner's settings and deletions, and the admin's deletion and
owner-key replacement.

Requests go to ``httpx.MockTransport``, so nothing reaches the network. The
owner's signature is checked against bytes written out here independently of
the SDK, and against the round 60 test vector every SDK computes.
"""

from __future__ import annotations

import base64
import inspect
import json
import re
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import verdifax
from tests.test_accounts import parity_names
from tests.test_jobs import (
    SEED,
    VECTOR,
    async_client,
    sent_body,
    sync_client,
    vector_public_key,
)
from tests.test_policies import routed
from verdifax import (
    APIError,
    AsyncVerdifaxClient,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    owner_change_preimage,
)
from verdifax._requests import (
    ACCOUNT_SETTING_CHANGES,
    account_setting_body,
    run_deletion_body,
)
from verdifax._signing import load_signing_key, owner_change_signature

ROOT = Path(__file__).parent.parent

# The round 60 vector (sdk-spec-round60.md), computed with Go crypto/ed25519.
VECTOR_SEED = b"o" * 32
VECTOR_ACCOUNT = "account-7"
VECTOR_CHANGE = "setting.verdifax_deletion"
VECTOR_SUBJECT = "blocked"
VECTOR_SIGNED_AT = "2026-11-12T18:00:00Z"
VECTOR_NONCE = "0a" * 16
VECTOR_PUBLIC_KEY = "yG0BrYsvtpSyL/YOPJ2eftkNtWBHcrdEUNQJE7mpy68="
VECTOR_SIGNATURE = (
    "LuDMETlzleMt3lXhdED4f3qAy5tdgEsGW4uJmvJlv9Ld0mNlY0v8aIDLXxq1npkW3v5/gdPjIBent1yt5P/9Bw=="
)

ACCOUNT = {
    "ok": True,
    "account_id": "account-7",
    "id": 7,
    "name": "Acme",
    "owner_replacement": "allowed",
    "verdifax_deletion": "allowed",
}
RUN_ID = 42
RECORD_HASH = "c" * 64
CHANGE = {"format": "verdifax.account-change.v1", "action": "setting.verdifax_deletion"}
SETTING_ANSWER = {
    "ok": True,
    "setting": "verdifax-deletion",
    "value": "blocked",
    "account_change": CHANGE,
}
DELETION = {"format": "verdifax.run-deletion.v1", "run_id": RUN_ID, "record_hash": RECORD_HASH}
DELETE_ANSWER = {"ok": True, "run_id": RUN_ID, "deleted": True, "run_deletion": DELETION}
REPLACE_ANSWER = {
    "ok": True,
    "account_id": "account-7",
    "claim_expires": "2026-11-15T18:00:00Z",
    "account_change": {"action": "owner_key.replacement_requested"},
    "email": {"sent": True},
}
NEW_METHODS = ["set_account_setting", "delete_run", "admin_delete_run", "admin_replace_owner_key"]


def expected_owner_preimage(account: str, change: str, subject: str, sig: dict) -> bytes:
    """The bytes the server rebuilds (OwnerChangePreimage), written out here."""
    return (
        b"verdifax.owner-change-signature.v1\x00"
        + account.encode()
        + b"\x00"
        + change.encode()
        + b"\x00"
        + subject.encode()
        + b"\x00"
        + sig["signed_at"].encode()
        + b"\x00"
        + sig["nonce"].encode()
    )


def assert_owner_signature(sig: dict, account: str, change: str, subject: str) -> None:
    assert set(sig) == {"signature", "signed_at", "nonce"}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", sig["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", sig["nonce"])
    vector_public_key().verify(
        base64.b64decode(sig["signature"]), expected_owner_preimage(account, change, subject, sig)
    )


def setting_answers() -> dict[tuple[str, str], Any]:
    return {
        ("GET", "/account"): ACCOUNT,
        ("PUT", "/account/settings/owner-replacement"): SETTING_ANSWER,
        ("PUT", "/account/settings/verdifax-deletion"): SETTING_ANSWER,
        ("POST", f"/account/runs/{RUN_ID}/delete"): DELETE_ANSWER,
        ("POST", f"/admin/runs/{RUN_ID}/delete"): DELETE_ANSWER,
        ("POST", "/admin/accounts/7/owner-key/replace"): REPLACE_ANSWER,
    }


OWNER_PUBLIC_KEY = VECTOR["public_key"]


def sealed_setting(body: dict, setting: str) -> dict[str, Any]:
    """The answer the server gives for a change it sealed: the record carries what was sent."""
    return {
        "ok": True,
        "setting": setting,
        "value": body["value"],
        "account_change": {
            "format": "verdifax.account-change.v1",
            "action": ACCOUNT_SETTING_CHANGES[setting],
            "decided_by": "owner",
            "key_id": 0,
            "value": body["value"],
            "changed_at": "2026-11-12T18:00:01.5Z",
            "owner_signature": {"public_key": OWNER_PUBLIC_KEY, **body["owner_signature"]},
            "signal": {"account": "account-7", "sequence": 9},
            "account_change_hash": "a" * 64,
        },
    }


def sealed_deletion(body: dict, run_id: int) -> dict[str, Any]:
    """The answer the server gives for a deletion it sealed."""
    return {
        "ok": True,
        "run_id": run_id,
        "deleted": True,
        "run_deletion": {
            "format": "verdifax.run-deletion.v1",
            "decided_by": "owner",
            "run_id": run_id,
            "record_hash": body["record_hash"],
            "changed_at": "2026-11-12T18:00:01.5Z",
            "owner_signature": {"public_key": OWNER_PUBLIC_KEY, **body["owner_signature"]},
            "signal": {"account": "account-7", "sequence": 10},
            "deletion_hash": "b" * 64,
        },
    }


def owner_server(
    seen: list[httpx.Request],
    answered: list[dict[str, Any]],
    tamper: Callable[[dict[str, Any]], None] = lambda record: None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Answer an owner's change as the server does, with the record ``tamper`` may change."""
    static = routed(seen, setting_answers())

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "PUT" and path.startswith("/account/settings/"):
            answer = sealed_setting(json.loads(request.content), path.rsplit("/", 1)[1])
            tamper(answer["account_change"])
        elif request.method == "POST" and path.startswith("/account/runs/"):
            answer = sealed_deletion(json.loads(request.content), int(path.split("/")[3]))
            tamper(answer["run_deletion"])
        else:
            return static(request)
        seen.append(request)
        answered.append(answer)
        return httpx.Response(200, json=answer)

    return handler


# ── the vector, byte for byte ─────────────────────────────────────────────────


def test_the_vector_public_key():
    key = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    assert public == VECTOR_PUBLIC_KEY


def test_the_vector_preimage_matches_an_independent_build():
    sig = {"signed_at": VECTOR_SIGNED_AT, "nonce": VECTOR_NONCE}
    preimage = owner_change_preimage(
        VECTOR_ACCOUNT, VECTOR_CHANGE, VECTOR_SUBJECT, VECTOR_SIGNED_AT, VECTOR_NONCE
    )
    assert preimage == expected_owner_preimage(VECTOR_ACCOUNT, VECTOR_CHANGE, VECTOR_SUBJECT, sig)
    assert preimage.split(b"\x00") == [
        b"verdifax.owner-change-signature.v1",
        b"account-7",
        b"setting.verdifax_deletion",
        b"blocked",
        b"2026-11-12T18:00:00Z",
        b"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    ]


def test_the_vector_signature():
    sig = owner_change_signature(
        load_signing_key(VECTOR_SEED),
        VECTOR_ACCOUNT,
        VECTOR_CHANGE,
        VECTOR_SUBJECT,
        VECTOR_SIGNED_AT,
        VECTOR_NONCE,
    )
    assert sig == {
        "signature": VECTOR_SIGNATURE,
        "signed_at": VECTOR_SIGNED_AT,
        "nonce": VECTOR_NONCE,
    }
    Ed25519PublicKey.from_public_bytes(base64.b64decode(VECTOR_PUBLIC_KEY)).verify(
        base64.b64decode(VECTOR_SIGNATURE),
        owner_change_preimage(
            VECTOR_ACCOUNT, VECTOR_CHANGE, VECTOR_SUBJECT, VECTOR_SIGNED_AT, VECTOR_NONCE
        ),
    )


@pytest.mark.parametrize("field", ["account", "change", "subject", "signed_at", "nonce"])
def test_the_preimage_refuses_a_zero_byte_or_a_value_that_is_not_text(field):
    values = {
        "account": VECTOR_ACCOUNT,
        "change": VECTOR_CHANGE,
        "subject": VECTOR_SUBJECT,
        "signed_at": VECTOR_SIGNED_AT,
        "nonce": VECTOR_NONCE,
    }
    with pytest.raises(ValidationError, match=f"{field} cannot be signed"):
        owner_change_preimage(**{**values, field: "a\x00b"})
    with pytest.raises(ValidationError, match=f"{field} cannot be signed"):
        owner_change_preimage(**{**values, field: 7})


def test_the_preimage_helper_is_exported():
    assert "owner_change_preimage" in verdifax.__all__
    assert verdifax.owner_change_preimage is owner_change_preimage


def test_the_body_builders_sign_fresh_each_time():
    key = load_signing_key(SEED)
    first = account_setting_body(key, "account-7", "setting.owner_replacement", "blocked")
    second = account_setting_body(key, "account-7", "setting.owner_replacement", "blocked")
    assert first["owner_signature"]["nonce"] != second["owner_signature"]["nonce"]
    deletion = run_deletion_body(key, "account-7", RUN_ID, RECORD_HASH)
    assert list(deletion) == ["record_hash", "owner_signature"]
    assert_owner_signature(
        deletion["owner_signature"], "account-7", "run.deleted", f"{RUN_ID}:{RECORD_HASH}"
    )


# ── the shared parity map ─────────────────────────────────────────────────────


def test_the_parity_map_names_the_new_routes():
    for column in ("python", "python_async"):
        assert set(NEW_METHODS) <= set(parity_names(column))


@pytest.mark.parametrize("name", NEW_METHODS)
def test_the_async_signature_matches_the_sync_one(name):
    sync = inspect.signature(getattr(VerdifaxClient, name))
    async_ = inspect.signature(getattr(AsyncVerdifaxClient, name))
    assert list(sync.parameters) == list(async_.parameters)
    for param in sync.parameters:
        assert sync.parameters[param].default == async_.parameters[param].default
    assert inspect.iscoroutinefunction(getattr(AsyncVerdifaxClient, name))


@pytest.mark.parametrize(
    "name, params",
    [
        ("set_account_setting", ["self", "setting", "value", "account_id"]),
        ("delete_run", ["self", "run_id", "record_hash", "account_id"]),
        ("admin_delete_run", ["self", "run_id"]),
        ("admin_replace_owner_key", ["self", "account_id"]),
    ],
)
def test_the_parameters(name, params):
    assert list(inspect.signature(getattr(VerdifaxClient, name)).parameters) == params


def test_the_settings_are_the_servers():
    assert ACCOUNT_SETTING_CHANGES == {
        "owner-replacement": "setting.owner_replacement",
        "verdifax-deletion": "setting.verdifax_deletion",
    }


# ── set_account_setting ───────────────────────────────────────────────────────


@pytest.mark.parametrize("setting, change", sorted(ACCOUNT_SETTING_CHANGES.items()))
@pytest.mark.parametrize("value", ["allowed", "blocked"])
def test_set_account_setting_reads_the_account_and_signs_the_change(setting, change, value):
    seen: list[httpx.Request] = []
    answered: list[dict[str, Any]] = []
    client = sync_client(owner_server(seen, answered))
    assert client.set_account_setting(setting, value) == answered[0]
    assert answered[0]["account_change"]["action"] == change
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("PUT", f"/account/settings/{setting}"),
    ]
    body = sent_body(seen[1])
    assert list(body) == ["value", "owner_signature"]
    assert body["value"] == value
    assert_owner_signature(body["owner_signature"], "account-7", change, value)
    other = next(name for name in ACCOUNT_SETTING_CHANGES.values() if name != change)
    with pytest.raises(InvalidSignature):
        assert_owner_signature(body["owner_signature"], "account-7", other, value)
    with pytest.raises(InvalidSignature):
        assert_owner_signature(body["owner_signature"], "account-8", change, value)


def test_set_account_setting_with_the_account_given_sends_only_the_change():
    seen: list[httpx.Request] = []
    client = sync_client(owner_server(seen, []))
    client.set_account_setting("verdifax-deletion", "blocked", account_id="account-9")
    assert [(r.method, r.url.path) for r in seen] == [
        ("PUT", "/account/settings/verdifax-deletion")
    ]
    sig = sent_body(seen[0])["owner_signature"]
    assert_owner_signature(sig, "account-9", "setting.verdifax_deletion", "blocked")


def test_set_account_setting_returns_a_null_change_as_sent():
    seen: list[httpx.Request] = []
    unchanged = {**SETTING_ANSWER, "account_change": None}
    answers = {**setting_answers(), ("PUT", "/account/settings/verdifax-deletion"): unchanged}
    result = sync_client(routed(seen, answers)).set_account_setting("verdifax-deletion", "blocked")
    assert result == unchanged
    assert result["account_change"] is None


@pytest.mark.parametrize(
    "setting, value, message",
    [
        ("owner_replacement", "blocked", "setting must be one of"),
        ("Verdifax-Deletion", "blocked", "setting must be one of"),
        ("", "blocked", "setting must be one of"),
        (None, "blocked", "setting must be one of"),
        ("verdifax-deletion", "Blocked", "value must be one of"),
        ("verdifax-deletion", "block", "value must be one of"),
        ("verdifax-deletion", True, "value must be one of"),
        ("owner-replacement", "", "value must be one of"),
    ],
)
def test_set_account_setting_refuses_a_bad_setting_or_value_without_a_request(
    setting, value, message
):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(routed(seen, setting_answers())).set_account_setting(setting, value)
    assert seen == []


@pytest.mark.parametrize(
    "account_id", ["7", 7, "account-0", "account-07", "account-7 ", "", "acct-7"]
)
def test_owner_changes_refuse_a_bad_account_label_without_a_request(account_id):
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, setting_answers()))
    with pytest.raises(ValidationError, match="account_id must be the account's label"):
        client.set_account_setting("verdifax-deletion", "blocked", account_id=account_id)
    with pytest.raises(ValidationError, match="account_id must be the account's label"):
        client.delete_run(RUN_ID, RECORD_HASH, account_id=account_id)
    assert seen == []


def test_owner_changes_need_a_signing_key_and_send_nothing_without_one():
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, setting_answers()), signing_key=None)
    with pytest.raises(ValidationError, match="set_account_setting needs a client with a signing"):
        client.set_account_setting("verdifax-deletion", "blocked")
    with pytest.raises(ValidationError, match="delete_run needs a client with a signing_key"):
        client.delete_run(RUN_ID, RECORD_HASH)
    assert seen == []


@pytest.mark.parametrize("account", [{"ok": True}, {"account_id": ""}, {"account_id": 7}])
def test_an_account_with_no_usable_label_is_refused_before_the_change(account):
    seen: list[httpx.Request] = []
    answers = {**setting_answers(), ("GET", "/account"): account}
    client = sync_client(routed(seen, answers))
    with pytest.raises(VerdifaxError, match="GET /account returned no usable account_id"):
        client.set_account_setting("verdifax-deletion", "blocked")
    with pytest.raises(VerdifaxError, match="GET /account returned no usable account_id"):
        client.delete_run(RUN_ID, RECORD_HASH)
    assert [r.method for r in seen] == ["GET", "GET"]


def test_a_refused_signature_raises_and_is_not_retried():
    seen: list[httpx.Request] = []
    refused = httpx.Response(400, json={"error": "owner_signature does not verify"})
    answers = {**setting_answers(), ("PUT", "/account/settings/verdifax-deletion"): refused}
    with pytest.raises(APIError) as caught:
        sync_client(routed(seen, answers)).set_account_setting("verdifax-deletion", "blocked")
    assert caught.value.status_code == 400
    assert [r.method for r in seen] == ["GET", "PUT"]


def test_each_change_signs_a_fresh_nonce():
    seen: list[httpx.Request] = []
    client = sync_client(owner_server(seen, []))
    client.set_account_setting("verdifax-deletion", "blocked", account_id="account-7")
    client.set_account_setting("verdifax-deletion", "blocked", account_id="account-7")
    nonces = {sent_body(r)["owner_signature"]["nonce"] for r in seen}
    assert len(nonces) == 2


# ── delete_run ────────────────────────────────────────────────────────────────


def test_delete_run_signs_the_run_and_its_record_hash():
    seen: list[httpx.Request] = []
    answered: list[dict[str, Any]] = []
    client = sync_client(owner_server(seen, answered))
    assert client.delete_run(RUN_ID, RECORD_HASH) == answered[0]
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("POST", f"/account/runs/{RUN_ID}/delete"),
    ]
    body = sent_body(seen[1])
    assert list(body) == ["record_hash", "owner_signature"]
    assert body["record_hash"] == RECORD_HASH
    sig = body["owner_signature"]
    assert_owner_signature(sig, "account-7", "run.deleted", f"{RUN_ID}:{RECORD_HASH}")
    with pytest.raises(InvalidSignature):
        assert_owner_signature(sig, "account-7", "run.deleted", f"{RUN_ID + 1}:{RECORD_HASH}")
    with pytest.raises(InvalidSignature):
        assert_owner_signature(sig, "account-7", "run.deleted", f"{RUN_ID}:{'d' * 64}")


def test_delete_run_with_the_account_given_sends_only_the_deletion():
    seen: list[httpx.Request] = []
    sync_client(owner_server(seen, [])).delete_run(RUN_ID, RECORD_HASH, "account-7")
    assert [(r.method, r.url.path) for r in seen] == [("POST", f"/account/runs/{RUN_ID}/delete")]


@pytest.mark.parametrize(
    "run_id, record_hash, message",
    [
        (0, RECORD_HASH, "run_id must be > 0"),
        (-1, RECORD_HASH, "run_id must be > 0"),
        (True, RECORD_HASH, "run_id must be an int"),
        ("42", RECORD_HASH, "run_id must be an int"),
        (RUN_ID, "C" * 64, "record_hash must be lowercase hex"),
        (RUN_ID, "c" * 63, "record_hash must be 64-char hex"),
        (RUN_ID, "g" * 64, "record_hash must be lowercase hex"),
        (RUN_ID, None, "record_hash must be a string"),
    ],
)
def test_delete_run_refuses_bad_input_without_a_request(run_id, record_hash, message):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(routed(seen, setting_answers())).delete_run(run_id, record_hash)
    assert seen == []


def test_a_wrong_record_hash_raises_the_servers_409():
    seen: list[httpx.Request] = []
    moved = httpx.Response(409, json={"error": "record_hash is not this run's record hash"})
    answers = {**setting_answers(), ("POST", f"/account/runs/{RUN_ID}/delete"): moved}
    with pytest.raises(APIError) as caught:
        sync_client(routed(seen, answers)).delete_run(RUN_ID, RECORD_HASH, "account-7")
    assert caught.value.status_code == 409
    assert len(seen) == 1


# ── the answer seals exactly what was sent ────────────────────────────────────


def other_signature(record: dict[str, Any]) -> None:
    record["owner_signature"]["signature"] = base64.b64encode(b"x" * 64).decode("ascii")


def set_field(name: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def tamper(record: dict[str, Any]) -> None:
        record[name] = value

    return tamper


def set_signature_field(name: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def tamper(record: dict[str, Any]) -> None:
        record["owner_signature"][name] = value

    return tamper


SEALED_MISMATCHES = [
    pytest.param(set_field("decided_by", "verdifax_admin"), "decided_by", id="decided-by-verdifax"),
    pytest.param(set_field("decided_by", None), "decided_by", id="no-decided-by"),
    pytest.param(other_signature, "owner_signature signature", id="different-signature"),
    pytest.param(
        set_signature_field("signed_at", "2000-01-01T00:00:00Z"),
        "owner_signature signed_at",
        id="different-time",
    ),
    pytest.param(set_signature_field("nonce", "0" * 32), "owner_signature nonce", id="other-nonce"),
    pytest.param(
        set_signature_field("public_key", VECTOR_PUBLIC_KEY),
        "owner_signature public_key",
        id="other-public-key",
    ),
    pytest.param(set_field("owner_signature", None), "carries no owner_signature", id="unsigned"),
]


def test_a_matching_setting_record_is_returned_as_sent():
    seen: list[httpx.Request] = []
    answered: list[dict[str, Any]] = []
    client = sync_client(owner_server(seen, answered))
    result = client.set_account_setting("owner-replacement", "blocked", "account-7")
    record = result["account_change"]
    sent = sent_body(seen[0])["owner_signature"]
    assert record["decided_by"] == "owner"
    assert record["owner_signature"] == {"public_key": OWNER_PUBLIC_KEY, **sent}
    assert result == answered[0]


@pytest.mark.parametrize("tamper, message", SEALED_MISMATCHES)
def test_a_setting_record_that_differs_from_what_was_sent_is_refused(tamper, message):
    seen: list[httpx.Request] = []
    client = sync_client(owner_server(seen, [], tamper))
    with pytest.raises(VerdifaxError, match=f"account change record .*{message}"):
        client.set_account_setting("verdifax-deletion", "blocked", "account-7")


@pytest.mark.parametrize(
    "tamper, message",
    [
        pytest.param(set_field("value", "allowed"), "another value", id="changed-value"),
        pytest.param(
            set_field("action", "setting.owner_replacement"), "another action", id="other-action"
        ),
    ],
)
def test_a_setting_record_with_another_change_is_refused(tamper, message):
    seen: list[httpx.Request] = []
    client = sync_client(owner_server(seen, [], tamper))
    with pytest.raises(VerdifaxError, match=message):
        client.set_account_setting("verdifax-deletion", "blocked", "account-7")


@pytest.mark.parametrize(
    "answer, message",
    [
        ({"ok": True, "setting": "verdifax-deletion", "value": "blocked"}, "no account_change"),
        ({**SETTING_ANSWER, "account_change": "sealed"}, "not a record"),
        ([], "no account_change"),
    ],
)
def test_a_setting_answer_without_a_record_is_refused(answer, message):
    seen: list[httpx.Request] = []
    answers = {**setting_answers(), ("PUT", "/account/settings/verdifax-deletion"): answer}
    client = sync_client(routed(seen, answers))
    with pytest.raises(VerdifaxError, match=message):
        client.set_account_setting("verdifax-deletion", "blocked", "account-7")


def test_a_matching_deletion_record_is_returned_as_sent():
    seen: list[httpx.Request] = []
    answered: list[dict[str, Any]] = []
    result = sync_client(owner_server(seen, answered)).delete_run(RUN_ID, RECORD_HASH, "account-7")
    record = result["run_deletion"]
    assert (record["run_id"], record["record_hash"], record["decided_by"]) == (
        RUN_ID,
        RECORD_HASH,
        "owner",
    )
    sent = sent_body(seen[0])["owner_signature"]
    assert record["owner_signature"] == {"public_key": OWNER_PUBLIC_KEY, **sent}
    assert result == answered[0]


@pytest.mark.parametrize(
    "tamper, message",
    [
        *SEALED_MISMATCHES,
        pytest.param(set_field("run_id", RUN_ID + 1), "another run_id", id="other-run"),
        pytest.param(set_field("run_id", str(RUN_ID)), "another run_id", id="run-id-as-text"),
        pytest.param(set_field("record_hash", "d" * 64), "another record_hash", id="other-hash"),
    ],
)
def test_a_deletion_record_that_differs_from_what_was_sent_is_refused(tamper, message):
    seen: list[httpx.Request] = []
    client = sync_client(owner_server(seen, [], tamper))
    with pytest.raises(VerdifaxError, match=f"run deletion record .*{message}"):
        client.delete_run(RUN_ID, RECORD_HASH, "account-7")


@pytest.mark.parametrize(
    "answer",
    [{"ok": True, "run_id": RUN_ID, "deleted": True}, {**DELETE_ANSWER, "run_deletion": None}],
)
def test_a_deletion_answer_without_a_record_is_refused(answer):
    seen: list[httpx.Request] = []
    answers = {**setting_answers(), ("POST", f"/account/runs/{RUN_ID}/delete"): answer}
    with pytest.raises(VerdifaxError, match="no run_deletion record"):
        sync_client(routed(seen, answers)).delete_run(RUN_ID, RECORD_HASH, "account-7")


async def test_async_records_that_differ_from_what_was_sent_are_refused():
    seen: list[httpx.Request] = []
    async with async_client(owner_server(seen, [], set_field("decided_by", "verdifax_admin"))) as c:
        with pytest.raises(VerdifaxError, match="account change record has another decided_by"):
            await c.set_account_setting("verdifax-deletion", "blocked", "account-7")
        with pytest.raises(VerdifaxError, match="run deletion record has another decided_by"):
            await c.delete_run(RUN_ID, RECORD_HASH, "account-7")
    async with async_client(owner_server(seen, [], other_signature)) as c:
        with pytest.raises(VerdifaxError, match="owner_signature signature"):
            await c.set_account_setting("verdifax-deletion", "blocked", "account-7")
        with pytest.raises(VerdifaxError, match="owner_signature signature"):
            await c.delete_run(RUN_ID, RECORD_HASH, "account-7")
    async with async_client(owner_server(seen, [], set_field("value", "allowed"))) as c:
        with pytest.raises(VerdifaxError, match="another value"):
            await c.set_account_setting("verdifax-deletion", "blocked", "account-7")
    unchanged = {**SETTING_ANSWER, "account_change": None}
    answers = {**setting_answers(), ("PUT", "/account/settings/verdifax-deletion"): unchanged}
    async with async_client(routed(seen, answers)) as c:
        assert await c.set_account_setting("verdifax-deletion", "blocked", "account-7") == unchanged


# ── the admin's two ───────────────────────────────────────────────────────────


def test_admin_delete_run_posts_no_body():
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, setting_answers()), signing_key=None)
    assert client.admin_delete_run(RUN_ID) == DELETE_ANSWER
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "POST",
        f"/admin/runs/{RUN_ID}/delete",
        b"",
    )


def test_admin_replace_owner_key_posts_no_body_and_returns_no_link_or_key():
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, setting_answers()), signing_key=None)
    result = client.admin_replace_owner_key(7)
    assert result == REPLACE_ANSWER
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "POST",
        "/admin/accounts/7/owner-key/replace",
        b"",
    )


@pytest.mark.parametrize("bad", [0, -3, True, "7", "account-7", None])
def test_the_admin_methods_refuse_a_bad_id_without_a_request(bad):
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, setting_answers()))
    with pytest.raises(ValidationError, match="run_id"):
        client.admin_delete_run(bad)
    with pytest.raises(ValidationError, match="account_id"):
        client.admin_replace_owner_key(bad)
    assert seen == []


def test_a_blocked_admin_change_raises_the_servers_409_once():
    seen: list[httpx.Request] = []
    blocked = httpx.Response(409, json={"error": "the account's owner has blocked"})
    answers = {
        ("POST", f"/admin/runs/{RUN_ID}/delete"): blocked,
        ("POST", "/admin/accounts/7/owner-key/replace"): blocked,
    }
    client = sync_client(routed(seen, answers), signing_key=None)
    for call in (
        lambda: client.admin_delete_run(RUN_ID),
        lambda: client.admin_replace_owner_key(7),
    ):
        with pytest.raises(APIError) as caught:
            call()
        assert caught.value.status_code == 409
    assert len(seen) == 2


# ── the async client ──────────────────────────────────────────────────────────


async def test_async_new_methods_send_the_same_requests():
    seen: list[httpx.Request] = []
    answered: list[dict[str, Any]] = []
    async with async_client(owner_server(seen, answered)) as client:
        assert await client.set_account_setting("verdifax-deletion", "blocked") == answered[0]
        assert await client.delete_run(RUN_ID, RECORD_HASH) == answered[1]
        assert await client.set_account_setting("owner-replacement", "allowed", "account-7")
        assert await client.admin_delete_run(RUN_ID) == DELETE_ANSWER
        assert await client.admin_replace_owner_key(7) == REPLACE_ANSWER
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("PUT", "/account/settings/verdifax-deletion"),
        ("GET", "/account"),
        ("POST", f"/account/runs/{RUN_ID}/delete"),
        ("PUT", "/account/settings/owner-replacement"),
        ("POST", f"/admin/runs/{RUN_ID}/delete"),
        ("POST", "/admin/accounts/7/owner-key/replace"),
    ]
    assert_owner_signature(
        sent_body(seen[1])["owner_signature"], "account-7", "setting.verdifax_deletion", "blocked"
    )
    body = sent_body(seen[3])
    assert list(body) == ["record_hash", "owner_signature"]
    assert_owner_signature(
        body["owner_signature"], "account-7", "run.deleted", f"{RUN_ID}:{RECORD_HASH}"
    )
    assert_owner_signature(
        sent_body(seen[4])["owner_signature"], "account-7", "setting.owner_replacement", "allowed"
    )
    assert seen[5].content == b"" and seen[6].content == b""


async def test_async_new_methods_refuse_bad_input_without_a_request():
    seen: list[httpx.Request] = []
    async with async_client(routed(seen, setting_answers()), signing_key=None) as client:
        with pytest.raises(ValidationError, match="signing_key"):
            await client.set_account_setting("verdifax-deletion", "blocked")
        with pytest.raises(ValidationError, match="signing_key"):
            await client.delete_run(RUN_ID, RECORD_HASH)
        with pytest.raises(ValidationError, match="setting must be one of"):
            await client.set_account_setting("deletion", "blocked")
        with pytest.raises(ValidationError, match="record_hash"):
            await client.delete_run(RUN_ID, "x")
        with pytest.raises(ValidationError, match="run_id"):
            await client.admin_delete_run(0)
        with pytest.raises(ValidationError, match="account_id"):
            await client.admin_replace_owner_key("account-7")
    async with async_client(routed(seen, setting_answers())) as client:
        with pytest.raises(ValidationError, match="account_id must be the account's label"):
            await client.delete_run(RUN_ID, RECORD_HASH, account_id="7")
    assert seen == []


async def test_async_an_account_with_no_usable_label_is_refused():
    seen: list[httpx.Request] = []
    answers = {**setting_answers(), ("GET", "/account"): {"ok": True}}
    async with async_client(routed(seen, answers)) as client:
        with pytest.raises(VerdifaxError, match="no usable account_id"):
            await client.set_account_setting("verdifax-deletion", "blocked")
    assert [r.method for r in seen] == ["GET"]


# ── the README ────────────────────────────────────────────────────────────────


def test_the_readme_lists_the_new_methods_and_the_helper():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in NEW_METHODS:
        assert f"`{name}(" in readme, name
    assert "`owner_change_preimage`" in readme
    assert "`verdifax.owner_change_preimage(account, change, subject, signed_at, nonce)`" in readme
    for kind in ("`account.changed`", "`run.deleted`"):
        assert kind in readme, kind
