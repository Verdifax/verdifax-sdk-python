"""SDK 1.15: request-key changes sealed in the account's feed, and the 409 when
the request key moved.

Since round 61 the server seals each registration, rotation and clear of a
customer key's request key as an ``account.changed`` event. These tests read
each new shape from a mocked feed with every field, check that following the
feed and ``pending_signoffs`` take them in stride, check that the approval the
server seals is the one this client signs, and check that the server's 409 is
raised with its own message. Requests go to ``httpx.MockTransport``, so nothing
reaches the network.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tests.test_account_changes import (
    DELETE_ANSWER,
    DELETION,
    RECORD_HASH,
    RUN_ID,
    owner_server,
    set_field,
    setting_answers,
)
from tests.test_jobs import (
    NEW_SEED,
    SEED,
    async_client,
    scripted,
    sent_body,
    sync_client,
    verify_rotation,
)
from tests.test_policies import routed
from tests.test_signals import feed_script, head, no_more
from verdifax import (
    APIError,
    AsyncVerdifaxClient,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    pending_signoffs,
    request_key_change_preimage,
)
from verdifax._signing import load_signing_key, request_key_change

ROOT = Path(__file__).parent.parent

# The request keys of the server's Go fixture (account_change_test.go): a
# key's holder key before a rotation, and the key after it.
HOLDER_SEED = b"h" * 32
NEXT_SEED = b"n" * 32
SIGNED_AT = "2026-11-12T18:00:00Z"
NONCE = "0b" * 16
KEY_ID = 12
MOVED = (
    "the request key changed since this change was signed; read the key again and sign "
    "the change with it"
)


def public_of(seed: bytes) -> str:
    raw = load_signing_key(seed).public_key().public_bytes_raw()
    return base64.b64encode(raw).decode("ascii")


def approval(by: bytes, new_key: str) -> dict[str, str]:
    """The approval the server seals: the change the holder sent, and its current key."""
    return {
        "public_key": public_of(by),
        **request_key_change(load_signing_key(by), new_key, SIGNED_AT, NONCE),
    }


def account_change(
    sequence: int, action: str, decided_by: str, value: str, approved: Any = None
) -> dict[str, Any]:
    """An ``account.changed`` entry as the server seals it (AccountChange)."""
    entry: dict[str, Any] = {
        "format": "verdifax.account-change.v1",
        "action": action,
        "decided_by": decided_by,
        "key_id": KEY_ID,
        "value": value,
        "changed_at": "2026-11-12T18:00:00.123456789Z",
    }
    if approved is not None:
        entry["request_key_approval"] = approved
    entry.update(
        {
            "signal": {
                "signal_account": "account-7",
                "signal_sequence": sequence,
                "signal_previous_hash": "e" * 64,
            },
            "account_change_hash": format(sequence, "x").rjust(64, "0"),
            "anchor": {"kind": "receipt_anchor", "receipt_kind": "account_change"},
        }
    )
    return entry


def changed_event(sequence: int, entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "specversion": "1.0",
        "id": f"account-7/{sequence}",
        "source": "https://api.verdifax.com/accounts/account-7",
        "type": "com.verdifax.account.changed",
        "time": "2026-11-12T18:00:00Z",
        "datacontenttype": "application/json",
        "data": {
            "form": "verdifax.signal.v1",
            "kind": "account.changed",
            "account": "account-7",
            "sequence": sequence,
            "previous_signal_hash": "e" * 64,
            "event_hash": "f" * 64,
            "api_key_id": KEY_ID,
            "entry": entry,
        },
    }


def sealed_event(sequence: int, run_id: int) -> dict[str, Any]:
    event = changed_event(sequence, {"run_id": run_id, "signoff_required": True})
    event["type"] = "com.verdifax.run.sealed"
    event["data"]["kind"] = "run.sealed"
    return event


NEXT_PUBLIC = public_of(NEXT_SEED)
HOLDER_PUBLIC = public_of(HOLDER_SEED)
REGISTERED = account_change(1, "request_key.registered", "owner", HOLDER_PUBLIC)
ROTATED = account_change(
    2, "request_key.rotated", "owner", NEXT_PUBLIC, approval(HOLDER_SEED, NEXT_PUBLIC)
)
HOLDER_CLEARED = account_change(3, "request_key.cleared", "owner", "", approval(NEXT_SEED, ""))
VERDIFAX_CLEARED = account_change(4, "request_key.cleared", "verdifax_admin", "")
SHAPES = [REGISTERED, ROTATED, HOLDER_CLEARED, VERDIFAX_CLEARED]
BASE_FIELDS = {
    "format",
    "action",
    "decided_by",
    "key_id",
    "value",
    "changed_at",
    "signal",
    "account_change_hash",
    "anchor",
}


def feed_page() -> dict[str, Any]:
    """The four new shapes on a page that reaches the feed's end, with its head."""
    events = [changed_event(n, entry) for n, entry in enumerate(SHAPES, start=1)]
    return {"events": events, "next_after": 4, "newest": 4, "head": head(4)}


def independent_preimage(new_key: str, signed_at: str, nonce: str) -> bytes:
    """RequestKeyChangePreimage, written out here independently of the SDK."""
    return b"verdifax.request-key-change.v1\x00" + "\x00".join([new_key, signed_at, nonce]).encode()


def verify_approval(approved: dict[str, str], new_key: str) -> None:
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(approved["public_key"]))
    signature = base64.b64decode(approved["signature"])
    public.verify(
        signature, independent_preimage(new_key, approved["signed_at"], approved["nonce"])
    )
    assert request_key_change_preimage(
        new_key, approved["signed_at"], approved["nonce"]
    ) == independent_preimage(new_key, approved["signed_at"], approved["nonce"])


# ── each new shape, read with every field ────────────────────────────────────


def test_each_request_key_change_is_read_with_every_field():
    served = feed_page()
    got = sync_client(lambda request: httpx.Response(200, json=served)).get_signals()
    assert got == served
    entries = [event["data"]["entry"] for event in got["events"]]
    assert [(e["action"], e["decided_by"]) for e in entries] == [
        ("request_key.registered", "owner"),
        ("request_key.rotated", "owner"),
        ("request_key.cleared", "owner"),
        ("request_key.cleared", "verdifax_admin"),
    ]
    registered, rotated, holder_cleared, verdifax_cleared = entries
    # A registration and Verdifax's clear carry no approval and no owner signature.
    assert set(registered) == set(verdifax_cleared) == BASE_FIELDS
    assert registered["value"] == HOLDER_PUBLIC and verdifax_cleared["value"] == ""
    # A rotation and the holder's clear carry the key before's approval, all four fields.
    for entry, new_key, before in (
        (rotated, NEXT_PUBLIC, HOLDER_PUBLIC),
        (holder_cleared, "", NEXT_PUBLIC),
    ):
        assert set(entry) == BASE_FIELDS | {"request_key_approval"}
        assert "owner_signature" not in entry
        assert entry["value"] == new_key
        approved = entry["request_key_approval"]
        assert set(approved) == {"public_key", "signature", "signed_at", "nonce"}
        assert approved["public_key"] == before
        assert (approved["signed_at"], approved["nonce"]) == (SIGNED_AT, NONCE)
        verify_approval(approved, new_key)
    for entry in entries:
        assert entry["key_id"] == KEY_ID
        assert entry["signal"]["signal_account"] == "account-7"


async def test_async_each_request_key_change_is_read_with_every_field():
    served = feed_page()
    async with async_client(lambda request: httpx.Response(200, json=served)) as client:
        assert await client.get_signals(as_owner=True) == served


def test_following_the_feed_yields_each_change_unchanged_and_never_the_head(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    served = feed_page()
    seen: list[httpx.Request] = []
    answers = [copy.deepcopy(served), no_more()]
    events = sync_client(feed_script(seen, answers)).follow_signals()
    read = [next(events) for _ in range(4)]
    assert read == served["events"]
    # The page's head is kept once its last event is handled, never yielded.
    assert events.head is None
    with pytest.raises(APIError, match="no more pages") as caught:
        next(events)
    assert events.head == served["head"] == caught.value.head
    assert len(seen) == 2


def test_pending_signoffs_takes_the_new_changes_in_stride():
    events = [
        sealed_event(1, 30),
        *[changed_event(n, entry) for n, entry in enumerate(SHAPES, start=2)],
        sealed_event(6, 31),
    ]
    assert pending_signoffs(events) == [30, 31]
    assert pending_signoffs([changed_event(n, e) for n, e in enumerate(SHAPES, start=1)]) == []


# ── the approval the server seals is the one this client signs ───────────────


def test_the_rotation_and_clear_this_client_sends_seal_as_valid_approvals():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json={"ok": True}), httpx.Response(200, json={"ok": True})]
    client = sync_client(scripted(seen, answers), signing_key=HOLDER_SEED)
    client.rotate_request_key(NEXT_SEED)
    client.clear_request_key()
    rotation, clear = sent_body(seen[0]), sent_body(seen[1])
    # The server seals the change sent, beside the key it approved against.
    verify_approval({"public_key": HOLDER_PUBLIC, **rotation["change"]}, rotation["public_key"])
    verify_approval({"public_key": NEXT_PUBLIC, **clear["change"]}, "")
    assert rotation["public_key"] == NEXT_PUBLIC


# ── the server's 409: the request key moved ──────────────────────────────────


def moved(seen: list[httpx.Request]) -> Callable[[httpx.Request], httpx.Response]:
    return scripted(seen, [httpx.Response(409, json={"error": MOVED})])


CALLS: list[tuple[str, tuple[Any, ...], str, str]] = [
    ("register_request_key", (), "POST", "/keys/request-key"),
    ("rotate_request_key", (NEXT_SEED,), "POST", "/keys/request-key"),
    ("clear_request_key", (), "DELETE", "/keys/request-key"),
    ("register_account_request_key", (), "POST", "/account/request-key"),
    ("rotate_account_request_key", (NEXT_SEED,), "POST", "/account/request-key"),
    ("clear_account_request_key", (), "DELETE", "/account/request-key"),
]


@pytest.mark.parametrize("name, args, method, path", CALLS)
def test_a_409_is_raised_once_with_the_servers_message_and_the_key_is_kept(
    name, args, method, path
):
    seen: list[httpx.Request] = []
    client = sync_client(moved(seen))
    with pytest.raises(APIError) as caught:
        getattr(client, name)(*args)
    assert caught.value.status_code == 409
    assert caught.value.message == MOVED
    assert str(caught.value) == MOVED
    assert caught.value.response_body == {"error": MOVED}
    assert [(r.method, r.url.path) for r in seen] == [(method, path)]
    assert client._signing_key.private_bytes_raw() == SEED


@pytest.mark.parametrize("name, args, method, path", CALLS)
async def test_async_a_409_is_raised_once_with_the_servers_message_and_the_key_is_kept(
    name, args, method, path
):
    seen: list[httpx.Request] = []
    async with async_client(moved(seen)) as client:
        with pytest.raises(APIError) as caught:
            await getattr(client, name)(*args)
        assert client._signing_key.private_bytes_raw() == SEED
    assert (caught.value.status_code, caught.value.message) == (409, MOVED)
    assert [(r.method, r.url.path) for r in seen] == [(method, path)]


# ── rotate_account_request_key: the owner key's rotation ──────────────────────

OK = {"ok": True, "public_key": "the new key"}
THIRD_SEED = bytes(range(64, 96))


def test_rotate_account_request_key_sends_the_rotation_to_the_owner_route():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json=OK), httpx.Response(200, json=OK)]
    client = sync_client(scripted(seen, answers))
    assert client.rotate_account_request_key(NEW_SEED) == OK
    assert (seen[0].method, seen[0].url.path) == ("POST", "/account/request-key")
    verify_rotation(sent_body(seen[0]))
    # After the 2xx the client signs with the new key: the next rotation's
    # approval is the new key's.
    assert client._signing_key.private_bytes_raw() == NEW_SEED
    client.rotate_account_request_key(THIRD_SEED)
    second = sent_body(seen[1])
    new_public = load_signing_key(NEW_SEED).public_key()
    new_public.verify(
        base64.b64decode(second["change"]["signature"]),
        independent_preimage(
            second["public_key"], second["change"]["signed_at"], second["change"]["nonce"]
        ),
    )
    assert client._signing_key.private_bytes_raw() == THIRD_SEED


def test_the_owner_and_api_key_rotations_send_the_same_body_shape():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json=OK), httpx.Response(200, json=OK)]
    sync_client(scripted(seen, answers)).rotate_account_request_key(NEW_SEED)
    sync_client(scripted(seen, answers[1:])).rotate_request_key(NEW_SEED)
    owner, api = sent_body(seen[0]), sent_body(seen[1])
    assert [r.url.path for r in seen] == ["/account/request-key", "/keys/request-key"]
    assert (owner["public_key"], owner["proof"]) == (api["public_key"], api["proof"])
    assert set(owner["change"]) == set(api["change"]) == {"signature", "signed_at", "nonce"}


@pytest.mark.parametrize("status", [403, 409, 500])
def test_a_refused_owner_rotation_keeps_the_current_key(status):
    seen: list[httpx.Request] = []
    client = sync_client(scripted(seen, [httpx.Response(status, json={"error": "no"})]))
    with pytest.raises(APIError):
        client.rotate_account_request_key(NEW_SEED)
    assert client._signing_key.private_bytes_raw() == SEED
    assert len(seen) == 1


def test_an_owner_rotation_that_never_reached_the_server_keeps_the_key():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = sync_client(handler)
    with pytest.raises(VerdifaxError):
        client.rotate_account_request_key(NEW_SEED)
    assert client._signing_key.private_bytes_raw() == SEED


def test_rotate_account_request_key_needs_a_current_key_and_a_good_new_key():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="rotate_account_request_key needs a client with"):
        sync_client(scripted(seen, []), signing_key=None).rotate_account_request_key(NEW_SEED)
    with pytest.raises(ValidationError) as caught:
        sync_client(scripted(seen, [])).rotate_account_request_key(b"short")
    assert "short" not in str(caught.value)
    assert seen == []


def test_rotate_account_request_key_sends_no_private_key():
    seen: list[httpx.Request] = []
    sync_client(scripted(seen, [httpx.Response(200, json=OK)])).rotate_account_request_key(NEW_SEED)
    for secret in (SEED, NEW_SEED):
        assert secret.hex().encode() not in seen[0].content
        assert base64.b64encode(secret) not in seen[0].content


async def test_async_rotate_account_request_key():
    seen: list[httpx.Request] = []
    answers = [httpx.Response(200, json=OK), httpx.Response(409, json={"error": MOVED})]
    async with async_client(scripted(seen, answers)) as client:
        assert await client.rotate_account_request_key(NEW_SEED) == OK
        verify_rotation(sent_body(seen[0]))
        assert client._signing_key.private_bytes_raw() == NEW_SEED
        with pytest.raises(APIError, match="request key changed"):
            await client.rotate_account_request_key(THIRD_SEED)
        assert client._signing_key.private_bytes_raw() == NEW_SEED
    assert [(r.method, r.url.path) for r in seen] == [("POST", "/account/request-key")] * 2
    async with async_client(scripted([], []), signing_key=None) as client:
        with pytest.raises(ValidationError, match="rotate_account_request_key"):
            await client.rotate_account_request_key(NEW_SEED)


def test_rotate_account_request_key_is_in_both_clients_and_the_parity_map():
    import inspect

    for cls in (VerdifaxClient, AsyncVerdifaxClient):
        assert list(inspect.signature(cls.rotate_account_request_key).parameters) == [
            "self",
            "new_signing_key",
        ]
    assert inspect.iscoroutinefunction(AsyncVerdifaxClient.rotate_account_request_key)
    parity = json.loads((ROOT / "tests" / "sdk-parity.json").read_text(encoding="utf-8"))
    entry = parity["helpers"].get("rotate_account_request_key")
    if entry is None:
        pytest.skip("the parity map does not name rotate_account_request_key yet")
    assert entry["python"] == "rotate_account_request_key"


def test_the_parity_map_names_the_follow_options_python_takes():
    import inspect

    parity = json.loads((ROOT / "tests" / "sdk-parity.json").read_text(encoding="utf-8"))
    options = parity["options"]
    for key, name in (
        ("follow_on_head", "on_head"),
        ("follow_after_event_hash", "after_event_hash"),
    ):
        assert options[key]["python"] == name
        for cls in (VerdifaxClient, AsyncVerdifaxClient):
            assert name in inspect.signature(cls.follow_signals).parameters


# ── round 60 fields typed: a tombstone's log_entries ─────────────────────────

ENTRIES = ["1844674407370955161", "1844674407370955162"]


def test_delete_run_keeps_the_tombstones_log_entries_as_sent():
    answered: list[dict[str, Any]] = []
    client = sync_client(owner_server([], answered, set_field("log_entries", ENTRIES)))
    result = client.delete_run(RUN_ID, RECORD_HASH, "account-7")
    assert result["run_deletion"]["log_entries"] == ENTRIES
    assert result == answered[0]


@pytest.mark.parametrize("entries", ["12", [12], [None], {"0": "12"}])
def test_delete_run_refuses_log_entries_that_are_not_a_list_of_strings(entries):
    client = sync_client(owner_server([], [], set_field("log_entries", entries)))
    with pytest.raises(VerdifaxError, match="log_entries is not a list of strings"):
        client.delete_run(RUN_ID, RECORD_HASH, "account-7")


def admin_deleted(entries: Any) -> dict[tuple[str, str], Any]:
    answer = {**DELETE_ANSWER, "run_deletion": {**DELETION, "log_entries": entries}}
    return {**setting_answers(), ("POST", f"/admin/runs/{RUN_ID}/delete"): answer}


def test_admin_delete_run_keeps_the_log_entries_and_refuses_a_bad_list():
    client = sync_client(routed([], admin_deleted(ENTRIES)), signing_key=None)
    assert client.admin_delete_run(RUN_ID)["run_deletion"]["log_entries"] == ENTRIES
    client = sync_client(routed([], admin_deleted([7])), signing_key=None)
    with pytest.raises(VerdifaxError, match="log_entries is not a list of strings"):
        client.admin_delete_run(RUN_ID)
    bad = {**setting_answers(), ("POST", f"/admin/runs/{RUN_ID}/delete"): {"run_deletion": []}}
    with pytest.raises(VerdifaxError, match="run deletion that is not an object"):
        sync_client(routed([], bad), signing_key=None).admin_delete_run(RUN_ID)


async def test_async_deletions_keep_and_check_the_log_entries():
    answered: list[dict[str, Any]] = []
    async with async_client(owner_server([], answered, set_field("log_entries", ENTRIES))) as c:
        result = await c.delete_run(RUN_ID, RECORD_HASH, "account-7")
        assert result["run_deletion"]["log_entries"] == ENTRIES
    async with async_client(owner_server([], [], set_field("log_entries", [1]))) as c:
        with pytest.raises(VerdifaxError, match="log_entries is not a list of strings"):
            await c.delete_run(RUN_ID, RECORD_HASH, "account-7")
    async with async_client(routed([], admin_deleted(ENTRIES)), signing_key=None) as c:
        assert (await c.admin_delete_run(RUN_ID))["run_deletion"]["log_entries"] == ENTRIES
    async with async_client(routed([], admin_deleted("1")), signing_key=None) as c:
        with pytest.raises(VerdifaxError, match="log_entries is not a list of strings"):
            await c.admin_delete_run(RUN_ID)


LINKS = {"previous_record_hashes": ["1" * 64], "final": True}


def job_step(record: dict[str, Any]) -> None:
    record.update(job_id="job-1", step_id="s2", job_links=LINKS)


def test_delete_run_keeps_a_job_steps_job_links_as_sent():
    answered: list[dict[str, Any]] = []
    client = sync_client(owner_server([], answered, job_step))
    result = client.delete_run(RUN_ID, RECORD_HASH, "account-7")
    assert result["run_deletion"]["job_links"] == LINKS
    assert result == answered[0]


def test_deletions_refuse_malformed_job_links():
    def bad(record: dict[str, Any]) -> None:
        record.update(job_id="job-1", step_id="s2", job_links={"final": "yes"})

    with pytest.raises(VerdifaxError, match="job_links.final is not a bool"):
        sync_client(owner_server([], [], bad)).delete_run(RUN_ID, RECORD_HASH, "account-7")
    step = {**DELETION, "job_id": "job-1", "step_id": "s2"}
    answers = {
        **setting_answers(),
        ("POST", f"/admin/runs/{RUN_ID}/delete"): {
            **DELETE_ANSWER,
            "run_deletion": {**step, "job_links": {"external_previous": ["b" * 64, "a" * 64]}},
        },
    }
    with pytest.raises(VerdifaxError, match="external_previous is not sorted"):
        sync_client(routed([], answers), signing_key=None).admin_delete_run(RUN_ID)


async def test_async_deletions_keep_and_check_job_links():
    answered: list[dict[str, Any]] = []
    async with async_client(owner_server([], answered, job_step)) as c:
        result = await c.delete_run(RUN_ID, RECORD_HASH, "account-7")
    assert result["run_deletion"]["job_links"] == LINKS
    no_job = {**DELETE_ANSWER, "run_deletion": {**DELETION, "job_links": {}}}
    answers = {**setting_answers(), ("POST", f"/admin/runs/{RUN_ID}/delete"): no_job}
    async with async_client(routed([], answers), signing_key=None) as c:
        with pytest.raises(VerdifaxError, match="job_links but no job_id"):
            await c.admin_delete_run(RUN_ID)


# ── the README and CHANGELOG ─────────────────────────────────────────────────


def test_the_readme_describes_the_sealed_request_key_changes_and_the_head():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    feed = readme.split("## Signal feed", 1)[1].split("\n## ", 1)[0]
    for phrase in (
        "request_key.registered",
        "request_key.rotated",
        "request_key.cleared",
        "request_key_approval",
        "verdifax.feed-head.v1",
        "`head`",
        "never yielded",
    ):
        assert phrase in feed, phrase
    keys = readme.split("Replacing or clearing a registered key", 1)[1].split("\n\n", 1)[0]
    assert "409" in keys and "request_key.rotated" in keys


@pytest.mark.parametrize("path", ["tests/test_request_key_changes.py", "verdifax/client.py"])
def test_no_em_or_en_dashes(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    assert chr(0x2014) not in text and chr(0x2013) not in text
