"""SDK 1.5: the signal feed, feed keys, webhooks and failure receipts, on both clients.

Requests go to ``httpx.MockTransport``, so nothing reaches the network. The
event hash and the webhook delivery come from ``sdk-signature-vector.json``,
shared by the four SDKs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import json
import re
import typing
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NotRequired

import httpx
import pytest

import verdifax
from tests.test_accounts import parity_names
from tests.test_jobs import VECTOR, async_client, scripted, sent_body, sync_client
from tests.test_parity import responder
from verdifax import (
    FEED_HEAD_FORM,
    SIGNAL_KINDS,
    APIError,
    AsyncSignalFollower,
    AsyncVerdifaxClient,
    ConnectionError as VerdifaxConnectionError,
    SignalFollower,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    WebhookVerificationError,
    signal_event_hash,
    verify_webhook,
)
from verdifax._signals import feed_head, signals_timeout

SECRET = VECTOR["webhook_secret"]
STAMP = VECTOR["webhook_timestamp"]
NOW = int(STAMP)
BODY = VECTOR["webhook_body"]
HEADERS = {
    "webhook-id": VECTOR["webhook_id"],
    "webhook-timestamp": STAMP,
    "webhook-signature": VECTOR["webhook_signature"],
}
WRONG_V1 = "v1," + base64.b64encode(b"\x00" * 32).decode()

SIGNAL_METHODS = [
    "get_signals",
    "create_feed_key",
    "revoke_feed_key",
    "create_webhook",
    "list_webhooks",
    "delete_webhook",
    "list_webhook_deliveries",
    "get_failure_receipt",
]

FEED_KEY = {
    "ok": True,
    "id": 9,
    "name": "siem",
    "secret": "vfx_feed_secret",
    "hint": "Store this secret now.",
    "tier": "production",
    "account_id": "account-7",
}
WEBHOOK = {
    "ok": True,
    "id": 3,
    "url": "https://hooks.example.com/verdifax",
    "types": ["run.refused"],
    "created_at": "2026-11-07T12:00:00Z",
    "secret": SECRET,
    "hint": "Store this secret now.",
}
WEBHOOKS = {"ok": True, "webhooks": [{k: WEBHOOK[k] for k in ("id", "url", "types", "created_at")}]}
DELIVERIES = {
    "ok": True,
    "webhook_id": 3,
    "deliveries": [
        {
            "sequence": 12,
            "status": "delivered",
            "attempts": 1,
            "last_status_code": 200,
            "last_error": "",
            "created_at": "2026-11-07T12:00:00Z",
            "delivered_at": "2026-11-07T12:00:01Z",
        }
    ],
}
RECEIPT = {"ok": True, "run_id": 42, "failure_receipt": {"version": "vfa.failure_receipt.v1"}}


def event(sequence: int, kind: str = "run.refused") -> dict[str, Any]:
    return {
        "specversion": "1.0",
        "id": f"account-7/{sequence}",
        "source": "https://api.verdifax.com/accounts/account-7",
        "type": f"com.verdifax.{kind}",
        "time": "2026-11-07T12:00:00Z",
        "datacontenttype": "application/json",
        "data": {
            "form": "verdifax.signal.v1",
            "kind": kind,
            "account": "account-7",
            "sequence": sequence,
            "previous_signal_hash": "e" * 64,
            "event_hash": "f" * 64,
            "entry": {},
        },
    }


def page(sequences: list[int], after: int, newest: int = 9) -> dict[str, Any]:
    events = [event(s) for s in sequences]
    return {"events": events, "next_after": sequences[-1] if sequences else after, "newest": newest}


def sign(body: bytes, message_id: str = HEADERS["webhook-id"], stamp: str = STAMP) -> str:
    """A v1 signature written out independently of the SDK."""
    key = base64.b64decode(SECRET[len("whsec_") :])
    signed = message_id.encode() + b"." + stamp.encode() + b"." + body
    return "v1," + base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()


def flip(text: str, index: int = -2) -> str:
    """The text with one character changed."""
    character = text[index]
    return text[:index] + ("A" if character != "A" else "B") + text[index + 1 :]


def query(request: httpx.Request) -> str:
    return request.url.query.decode()


def read_timeout(request: httpx.Request) -> float:
    return float(request.extensions["timeout"]["read"])


# ── the vector: event hash ────────────────────────────────────────────────────


def test_vector_signal_event_hash():
    assert (
        signal_event_hash(
            VECTOR["signal_kind"],
            VECTOR["signal_entry_hash"],
            VECTOR["signal_account"],
            VECTOR["signal_sequence"],
            VECTOR["signal_previous_hash"],
        )
        == VECTOR["signal_event_hash"]
    )


def test_vector_signal_event_hash_matches_an_independent_build():
    fields = [
        "verdifax.signal.v1",
        VECTOR["signal_kind"],
        VECTOR["signal_entry_hash"],
        VECTOR["signal_account"],
        str(VECTOR["signal_sequence"]),
        VECTOR["signal_previous_hash"],
    ]
    digest = hashlib.sha256("\x00".join(fields).encode()).hexdigest()
    assert digest == VECTOR["signal_event_hash"]


def test_the_event_hash_changes_with_every_field():
    args = [VECTOR[f"signal_{n}"] for n in ("kind", "entry_hash", "account")]
    base = (*args, VECTOR["signal_sequence"], VECTOR["signal_previous_hash"])
    assert signal_event_hash(*base) == VECTOR["signal_event_hash"]
    for index in range(5):
        changed = list(base)
        changed[index] = changed[index] + 1 if index == 3 else flip(changed[index], 0)
        assert signal_event_hash(*changed) != VECTOR["signal_event_hash"]


@pytest.mark.parametrize(
    "args, message",
    [
        (("run.refused", "d" * 64, "account-7", 12, "e\x00e"), "zero byte"),
        (("run.refused", None, "account-7", 12, "e" * 64), "not text"),
        (("run.refused", "d" * 64, "account-7", True, "e" * 64), "sequence must be an int"),
        (("run.refused", "d" * 64, "account-7", "12", "e" * 64), "sequence must be an int"),
        (("run.refused", "d" * 64, "account-7", -1, "e" * 64), "sequence must be 0 or more"),
    ],
)
def test_the_event_hash_refuses_ambiguous_values(args, message):
    with pytest.raises(ValidationError, match=message):
        signal_event_hash(*args)


# ── the vector: webhook verification ──────────────────────────────────────────


def test_vector_webhook_verifies_and_returns_the_event():
    assert verify_webhook(HEADERS, BODY, SECRET, now=NOW) == json.loads(BODY)
    assert sign(BODY.encode()) == VECTOR["webhook_signature"]


def test_the_body_may_be_bytes_or_text():
    assert verify_webhook(HEADERS, BODY.encode(), SECRET, now=NOW)["id"] == "account-7/12"
    assert verify_webhook(HEADERS, bytearray(BODY.encode()), SECRET, now=NOW)["id"]


def test_header_names_are_read_in_any_case():
    upper = {name.upper(): value for name, value in HEADERS.items()}
    assert verify_webhook(upper, BODY, SECRET, now=NOW)["id"] == "account-7/12"
    mixed = httpx.Headers({name.title(): value for name, value in HEADERS.items()})
    assert verify_webhook(mixed, BODY, SECRET, now=NOW)["id"] == "account-7/12"
    pairs = [("Webhook-Signature", HEADERS["webhook-signature"])] + [
        (name, value) for name, value in HEADERS.items() if name != "webhook-signature"
    ]
    assert verify_webhook(pairs, BODY, SECRET, now=NOW)["id"] == "account-7/12"


def test_now_may_be_a_datetime():
    moment = datetime.fromtimestamp(NOW, tz=timezone.utc)
    assert verify_webhook(HEADERS, BODY, SECRET, now=moment)["id"] == "account-7/12"
    naive_utc = moment.replace(tzinfo=None)
    assert verify_webhook(HEADERS, BODY, SECRET, now=naive_utc)["id"] == "account-7/12"


def test_one_byte_changed_in_the_body_fails():
    with pytest.raises(WebhookVerificationError, match="webhook-signature") as caught:
        verify_webhook(HEADERS, BODY.replace("12", "13", 1), SECRET, now=NOW)
    assert caught.value.check == "webhook-signature"
    with pytest.raises(WebhookVerificationError, match="webhook-signature"):
        verify_webhook(HEADERS, BODY + " ", SECRET, now=NOW)


def test_one_byte_changed_in_the_id_fails():
    headers = {**HEADERS, "webhook-id": "account-7/13"}
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(headers, BODY, SECRET, now=NOW)
    assert caught.value.check == "webhook-signature"


def test_one_byte_changed_in_the_timestamp_fails():
    headers = {**HEADERS, "webhook-timestamp": str(NOW + 1)}
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(headers, BODY, SECRET, now=NOW)
    assert caught.value.check == "webhook-signature"


def test_one_byte_changed_in_the_signature_fails():
    headers = {**HEADERS, "webhook-signature": flip(VECTOR["webhook_signature"])}
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(headers, BODY, SECRET, now=NOW)
    assert caught.value.check == "webhook-signature"


@pytest.mark.parametrize("offset", [301, -301])
def test_a_timestamp_301_seconds_away_fails_with_the_default_tolerance(offset):
    with pytest.raises(WebhookVerificationError, match="more than 300 seconds") as caught:
        verify_webhook(HEADERS, BODY, SECRET, now=NOW + offset)
    assert caught.value.check == "webhook-timestamp"


@pytest.mark.parametrize("offset", [300, -300])
def test_a_timestamp_300_seconds_away_passes(offset):
    assert verify_webhook(HEADERS, BODY, SECRET, now=NOW + offset)["id"] == "account-7/12"


def test_the_tolerance_can_be_set():
    assert verify_webhook(HEADERS, BODY, SECRET, tolerance_seconds=600, now=NOW + 500)
    with pytest.raises(WebhookVerificationError, match="more than 10 seconds"):
        verify_webhook(HEADERS, BODY, SECRET, tolerance_seconds=10, now=NOW + 11)


def test_the_default_now_is_the_current_time(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.time", lambda: NOW + 120.0)
    assert verify_webhook(HEADERS, BODY, SECRET)["id"] == "account-7/12"
    monkeypatch.setattr("verdifax._signals.time.time", lambda: NOW + 301.0)
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(HEADERS, BODY, SECRET)
    assert caught.value.check == "webhook-timestamp"


@pytest.mark.parametrize(
    "signature",
    [
        f"{WRONG_V1} {VECTOR['webhook_signature']}",
        f"{VECTOR['webhook_signature']} {WRONG_V1}",
        f"v2,{VECTOR['webhook_signature'][3:]} {VECTOR['webhook_signature']}",
        f"v1,not-base64 {VECTOR['webhook_signature']}",
        f"v1a,xyz {VECTOR['webhook_signature']}",
    ],
)
def test_a_second_wrong_entry_beside_the_right_one_still_passes(signature):
    headers = {**HEADERS, "webhook-signature": signature}
    assert verify_webhook(headers, BODY, SECRET, now=NOW)["id"] == "account-7/12"


def test_only_wrong_entries_fail():
    headers = {**HEADERS, "webhook-signature": f"{WRONG_V1} v2,{VECTOR['webhook_signature'][3:]}"}
    with pytest.raises(WebhookVerificationError, match="no v1 signature matches"):
        verify_webhook(headers, BODY, SECRET, now=NOW)


@pytest.mark.parametrize(
    "secret",
    [
        SECRET[len("whsec_") :],
        "whsex_" + SECRET[len("whsec_") :],
        "WHSEC_" + SECRET[len("whsec_") :],
        "whsec_not base64!",
        "whsec_",
        None,
    ],
)
def test_a_wrong_secret_prefix_or_encoding_fails(secret):
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(HEADERS, BODY, secret, now=NOW)
    assert caught.value.check == "secret"


def test_another_secret_fails_the_signature_and_no_message_shows_a_secret():
    other = "whsec_" + base64.b64encode(b"\x01" * 32).decode()
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(HEADERS, BODY, other, now=NOW)
    assert caught.value.check == "webhook-signature"
    for secret in (other, SECRET):
        for bad in (secret, secret[len("whsec_") :]):
            with pytest.raises(WebhookVerificationError) as failed:
                verify_webhook(HEADERS, BODY + "x", bad, now=NOW)
            assert secret[len("whsec_") :] not in str(failed.value)


@pytest.mark.parametrize("missing", ["webhook-id", "webhook-timestamp", "webhook-signature"])
def test_a_missing_header_fails_naming_it(missing):
    headers = {name: value for name, value in HEADERS.items() if name != missing}
    with pytest.raises(WebhookVerificationError, match="missing") as caught:
        verify_webhook(headers, BODY, SECRET, now=NOW)
    assert caught.value.check == missing


def test_a_header_given_twice_with_two_values_fails():
    pairs = [*HEADERS.items(), ("Webhook-Id", "account-7/99")]
    with pytest.raises(WebhookVerificationError, match="twice") as caught:
        verify_webhook(pairs, BODY, SECRET, now=NOW)
    assert caught.value.check == "webhook-id"


@pytest.mark.parametrize(
    "stamp", ["", "-1794096000", "1794096000.0", "1e9", " 1794096000", "\u0661\u0662"]
)
def test_a_timestamp_that_is_not_whole_seconds_fails(stamp):
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook({**HEADERS, "webhook-timestamp": stamp}, BODY, SECRET, now=NOW)
    assert caught.value.check == "webhook-timestamp"


@pytest.mark.parametrize("body", [b"[]", b"not json", b"\xff\xfe"])
def test_a_signed_body_that_is_not_a_json_object_fails(body):
    headers = {**HEADERS, "webhook-signature": sign(body)}
    with pytest.raises(WebhookVerificationError) as caught:
        verify_webhook(headers, body, SECRET, now=NOW)
    assert caught.value.check == "body"


@pytest.mark.parametrize("event_id", ["account-7/13", "", 12, None, "missing"])
def test_a_signed_body_whose_id_differs_from_webhook_id_fails(event_id):
    event = json.loads(BODY)
    if event_id == "missing":
        del event["id"]
    else:
        event["id"] = event_id
    body = json.dumps(event).encode()
    headers = {**HEADERS, "webhook-signature": sign(body)}
    with pytest.raises(
        WebhookVerificationError, match="the event id in the body does not match webhook-id"
    ) as caught:
        verify_webhook(headers, body, SECRET, now=NOW)
    assert caught.value.check == "body"
    assert SECRET[len("whsec_") :] not in str(caught.value)


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"body": {"id": 1}}, "body must be the raw bytes"),
        ({"headers": "webhook-id"}, "headers must be"),
        ({"headers": [("webhook-id",)]}, "headers must be"),
        ({"tolerance_seconds": -1}, "tolerance_seconds must be 0 or more"),
        ({"tolerance_seconds": True}, "tolerance_seconds must be a number"),
        ({"now": "2026-11-07"}, "now must be"),
    ],
)
def test_bad_arguments_raise_validation_errors(kwargs, message):
    args = {"headers": HEADERS, "body": BODY, "secret": SECRET, "now": NOW, **kwargs}
    with pytest.raises(ValidationError, match=message):
        verify_webhook(**args)


def test_a_verification_error_is_a_verdifax_error():
    assert issubclass(WebhookVerificationError, VerdifaxError)
    assert not issubclass(WebhookVerificationError, ValidationError)


# ── exports and the shared parity map ─────────────────────────────────────────


def test_the_helpers_are_exported():
    for name in ("signal_event_hash", "verify_webhook", "WebhookVerificationError", "SIGNAL_KINDS"):
        assert name in verdifax.__all__
        assert hasattr(verdifax, name)
    assert SIGNAL_KINDS == (
        "run.refused",
        "run.halted",
        "run.failed",
        "policy.changed",
        "signoff.recorded",
        "approver.registered",
        "approver.revoked",
        "key.created",
        "key.revoked",
        "run.published",
        "run.unpublished",
        "chain.gap",
        "run.sealed",
        "chain.interrupted",
        "account.changed",
        "run.deleted",
    )


def test_the_signal_kinds_are_the_servers_in_its_order():
    server = (
        Path(__file__).parent.parent.parent / "verdifax-orchestrator/internal/artifacts/signal.go"
    )
    if not server.exists():
        pytest.skip("the orchestrator source is not beside this repository")
    text = server.read_text(encoding="utf-8")
    names = dict(re.findall(r'^\s*(Signal\w+)\s*=\s*"([a-z]+\.[a-z]+)"', text, re.M))
    for path in server.parent.glob("*.go"):
        names.update(
            re.findall(r'^\s*(Signal\w+)\s*=\s*"([a-z]+\.[a-z]+)"', path.read_text("utf-8"), re.M)
        )
    listed = re.search(r"var SignalKinds = \[\]string\{(.*?)\}", text, re.S)
    assert listed is not None
    order = [names[name.strip()] for name in listed.group(1).split(",") if name.strip()]
    assert SIGNAL_KINDS == tuple(order)


def test_the_parity_map_names_every_signal_method_for_both_clients():
    for column in ("python", "python_async"):
        assert set(SIGNAL_METHODS) <= set(parity_names(column))


def test_the_parity_map_names_the_signal_helpers():
    parity = json.loads((Path(__file__).parent / "sdk-parity.json").read_text(encoding="utf-8"))
    helpers = parity["helpers"]
    assert helpers["signal_event_hash"]["python"] == "signal_event_hash"
    assert helpers["verify_webhook"]["python"] == "verify_webhook"
    assert helpers["follow_signals"]["python"] == "follow_signals"
    for name in ("signal_event_hash", "verify_webhook"):
        assert callable(getattr(verdifax, name))
    assert callable(VerdifaxClient.follow_signals)
    assert callable(AsyncVerdifaxClient.follow_signals)
    assert parity["routes"]["GET /signals"]["python"] == ["get_signals"]
    assert parity["routes"]["GET /account/signals"]["python"] == ["get_signals"]


@pytest.mark.parametrize("name", [*SIGNAL_METHODS, "follow_signals"])
def test_the_async_signature_matches_the_sync_one(name):
    sync = inspect.signature(getattr(VerdifaxClient, name))
    async_ = inspect.signature(getattr(AsyncVerdifaxClient, name))
    assert list(sync.parameters) == list(async_.parameters)
    for param in sync.parameters:
        assert sync.parameters[param].default == async_.parameters[param].default
    if name != "follow_signals":
        assert inspect.iscoroutinefunction(getattr(AsyncVerdifaxClient, name))


@pytest.mark.parametrize(
    "name, params",
    [
        ("get_signals", ["self", "after", "limit", "wait", "as_owner"]),
        (
            "follow_signals",
            ["self", "after", "wait", "as_owner", "on_head", "after_event_hash"],
        ),
        ("create_feed_key", ["self", "name", "expires_at"]),
        ("revoke_feed_key", ["self", "id"]),
        ("create_webhook", ["self", "url", "types"]),
        ("list_webhooks", ["self"]),
        ("delete_webhook", ["self", "id"]),
        ("list_webhook_deliveries", ["self", "id", "limit"]),
        ("get_failure_receipt", ["self", "run_id"]),
    ],
)
def test_the_methods_take_the_documented_arguments(name, params):
    signature = inspect.signature(getattr(VerdifaxClient, name))
    assert list(signature.parameters) == params


def test_the_documented_defaults():
    get = inspect.signature(VerdifaxClient.get_signals).parameters
    assert (get["after"].default, get["limit"].default, get["wait"].default) == (0, None, 0)
    assert get["as_owner"].default is False
    follow = inspect.signature(VerdifaxClient.follow_signals).parameters
    assert (follow["after"].default, follow["wait"].default) == (0, 25)
    assert follow["as_owner"].default is False
    assert follow["on_head"].default is None
    assert follow["after_event_hash"].default is None
    hook = inspect.signature(verify_webhook).parameters
    assert (hook["tolerance_seconds"].default, hook["now"].default) == (300, None)


# ── reading the feed ──────────────────────────────────────────────────────────


def test_get_signals_sends_after_and_wait_to_the_feed_key_route():
    seen: list[httpx.Request] = []
    answer = page([1, 2], 0)
    assert sync_client(responder(seen, body=answer)).get_signals() == answer
    assert (seen[0].method, seen[0].url.path, query(seen[0]), seen[0].content) == (
        "GET",
        "/signals",
        "after=0&wait=0",
        b"",
    )


def test_get_signals_sends_every_argument():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=page([], 7))).get_signals(after=7, limit=500, wait=25)
    assert (seen[0].url.path, query(seen[0])) == ("/signals", "after=7&limit=500&wait=25")


def test_get_signals_as_owner_reads_the_account_route():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=page([], 3))).get_signals(after=3, limit=1, as_owner=True)
    assert (seen[0].method, seen[0].url.path, query(seen[0])) == (
        "GET",
        "/account/signals",
        "after=3&limit=1&wait=0",
    )


def test_get_signals_sends_the_api_key():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=page([], 0))).get_signals()
    assert seen[0].headers["X-Verdifax-Key"] == "k"


@pytest.mark.parametrize(
    "client_timeout, wait, expected",
    [(5, 25, 55.0), (5, 0, 30.0), (90, 25, 90.0), (90, 0, 90.0), (54.5, 25, 55.0)],
)
def test_the_http_timeout_is_at_least_the_wait_plus_30_seconds(client_timeout, wait, expected):
    seen: list[httpx.Request] = []
    client = VerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        timeout=client_timeout,
        transport=httpx.MockTransport(responder(seen, body=page([], 0))),
    )
    client.get_signals(wait=wait)
    assert read_timeout(seen[0]) == expected


def test_other_calls_keep_the_clients_timeout():
    seen: list[httpx.Request] = []
    client = VerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        timeout=5,
        transport=httpx.MockTransport(responder(seen, body=WEBHOOKS)),
    )
    client.list_webhooks()
    assert read_timeout(seen[0]) == 5.0


def test_a_client_with_no_timeout_keeps_none():
    assert signals_timeout(None, 25) is None


BAD_SIGNAL_ARGS: list[tuple[dict[str, Any], str]] = [
    ({"after": -1}, "after must be 0 or more"),
    ({"after": True}, "after must be an int"),
    ({"after": "0"}, "after must be an int"),
    ({"after": 1.5}, "after must be an int"),
    ({"after": None}, "after must be an int"),
    ({"limit": 0}, "limit must be 1 to 500"),
    ({"limit": 501}, "limit must be 1 to 500"),
    ({"limit": True}, "limit must be an int"),
    ({"limit": "5"}, "limit must be an int"),
    ({"wait": -1}, "wait must be 0 to 25 seconds"),
    ({"wait": 26}, "wait must be 0 to 25 seconds"),
    ({"wait": 1.5}, "wait must be an int"),
    ({"wait": False}, "wait must be an int"),
    ({"as_owner": "yes"}, "as_owner must be a bool"),
    ({"as_owner": 1}, "as_owner must be a bool"),
]


@pytest.mark.parametrize("kwargs, message", BAD_SIGNAL_ARGS)
def test_get_signals_refuses_bad_arguments_without_a_request(kwargs, message):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(responder(seen, body=page([], 0))).get_signals(**kwargs)
    assert seen == []


def test_get_signals_accepts_the_edges():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=page([], 0)))
    client.get_signals(after=0, limit=1, wait=0)
    client.get_signals(after=2**62, limit=500, wait=25)
    assert [query(r) for r in seen] == [
        "after=0&limit=1&wait=0",
        f"after={2**62}&limit=500&wait=25",
    ]


@pytest.mark.parametrize(
    "answer, message",
    [
        ([], "did not return an object"),
        ({"next_after": 0, "newest": 0}, "no events list"),
        ({"events": {}, "next_after": 0, "newest": 0}, "no events list"),
        ({"events": [], "newest": 0}, "no usable next_after"),
        ({"events": [], "next_after": "0", "newest": 0}, "no usable next_after"),
        ({"events": [], "next_after": True, "newest": 0}, "no usable next_after"),
        ({"events": [], "next_after": 0}, "no usable newest"),
        ({"events": [], "next_after": -1, "newest": 0}, "no usable next_after"),
    ],
)
def test_an_answer_that_is_not_a_feed_page_is_refused(answer, message):
    with pytest.raises(VerdifaxError, match=message):
        sync_client(responder([], body=answer)).get_signals()


def test_a_429_for_too_many_waits_raises():
    seen: list[httpx.Request] = []
    refused = {"error": "a key may hold at most 2 waits open at once"}
    client = VerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        max_retries=0,
        transport=httpx.MockTransport(responder(seen, body=refused, status=429)),
    )
    with pytest.raises(APIError, match="at most 2 waits") as caught:
        client.get_signals(wait=25)
    assert caught.value.status_code == 429


# ── following the feed ────────────────────────────────────────────────────────


def feed_script(seen: list[httpx.Request], pages: list[Any]) -> Any:
    answers = [p if isinstance(p, httpx.Response) else httpx.Response(200, json=p) for p in pages]
    return scripted(seen, answers)


def test_follow_signals_follows_next_after_and_stops_when_the_caller_stops(monkeypatch):
    pauses: list[float] = []
    monkeypatch.setattr("verdifax._signals.time.sleep", pauses.append)
    seen: list[httpx.Request] = []
    pages = [page([1, 2], 0), page([3], 2), page([], 3), page([4], 3)]
    client = sync_client(feed_script(seen, pages))
    read: list[int] = []
    for item in client.follow_signals():
        read.append(item["data"]["sequence"])
        if item["data"]["sequence"] == 4:
            break
    assert read == [1, 2, 3, 4]
    assert [(r.method, r.url.path, query(r)) for r in seen] == [
        ("GET", "/signals", "after=0&wait=25"),
        ("GET", "/signals", "after=2&wait=25"),
        ("GET", "/signals", "after=3&wait=25"),
        ("GET", "/signals", "after=3&wait=25"),
    ]
    assert pauses == []
    assert all(read_timeout(r) == 90.0 for r in seen)


def test_follow_signals_sends_nothing_until_read_and_nothing_after_the_caller_stops():
    seen: list[httpx.Request] = []
    client = sync_client(feed_script(seen, [page([5, 6], 4)]))
    events = client.follow_signals(after=4, wait=10, as_owner=True)
    assert seen == []
    assert next(events)["data"]["sequence"] == 5
    events.close()
    assert [(r.url.path, query(r)) for r in seen] == [("/account/signals", "after=4&wait=10")]


def test_follow_signals_with_no_wait_pauses_after_an_empty_page(monkeypatch):
    pauses: list[float] = []
    monkeypatch.setattr("verdifax._signals.time.sleep", pauses.append)
    seen: list[httpx.Request] = []
    client = sync_client(feed_script(seen, [page([], 0), page([1], 0)]))
    assert next(client.follow_signals(wait=0))["data"]["sequence"] == 1
    assert pauses == [1.0]
    assert [query(r) for r in seen] == ["after=0&wait=0", "after=0&wait=0"]


@pytest.mark.parametrize("kwargs, message", BAD_SIGNAL_ARGS[:5] + BAD_SIGNAL_ARGS[9:])
def test_follow_signals_refuses_bad_arguments_when_called(kwargs, message):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(responder(seen, body=page([], 0))).follow_signals(**kwargs)
    assert seen == []


def test_follow_signals_retries_a_failed_page_then_raises_with_the_last_sequence_read():
    seen: list[httpx.Request] = []
    down = httpx.Response(503, json={"error": "unavailable"})
    client = sync_client(feed_script(seen, [page([1, 2], 0), down, down, down, down]))
    read: list[int] = []
    with pytest.raises(APIError) as caught:
        for item in client.follow_signals():
            read.append(item["data"]["sequence"])
    assert read == [1, 2]
    assert caught.value.status_code == 503
    assert caught.value.last_sequence == 2
    assert [query(r) for r in seen] == ["after=0&wait=25"] + ["after=2&wait=25"] * 4


def test_follow_signals_goes_on_after_a_retried_page():
    seen: list[httpx.Request] = []
    down = httpx.Response(502, json={"error": "bad gateway"})
    client = sync_client(feed_script(seen, [page([1], 0), down, page([2], 1)]))
    events = client.follow_signals()
    assert [next(events)["data"]["sequence"] for _ in range(2)] == [1, 2]
    assert [query(r) for r in seen] == ["after=0&wait=25", "after=1&wait=25", "after=1&wait=25"]


def test_a_connection_error_carries_the_last_sequence_read():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["after"] == "0":
            return httpx.Response(200, json=page([1], 0))
        raise httpx.ConnectError("refused", request=request)

    events = sync_client(handler).follow_signals()
    assert next(events)["data"]["sequence"] == 1
    with pytest.raises(VerdifaxConnectionError) as caught:
        next(events)
    assert caught.value.last_sequence == 1


@pytest.mark.parametrize(
    "bad_page, message",
    [
        ({**page([2, 3], 1), "next_after": 5}, "would skip or repeat"),
        ({**page([], 0), "next_after": 3}, "would skip or repeat"),
        ({**page([2, 3], 1), "next_after": 2}, "would skip or repeat"),
        ({"events": [event(2), event(1)], "next_after": 1, "newest": 2}, "went backwards"),
        ({"events": [event(1), event(1)], "next_after": 1, "newest": 1}, "went backwards"),
        ({"events": [{"data": {}}], "next_after": 1, "newest": 1}, "no data.sequence"),
        ({"events": [], "newest": 1}, "no usable next_after"),
    ],
)
def test_a_page_that_would_skip_or_repeat_is_refused_and_nothing_from_it_is_yielded(
    bad_page, message
):
    seen: list[httpx.Request] = []
    client = sync_client(feed_script(seen, [page([1], 0), bad_page]))
    events = client.follow_signals(after=0)
    assert next(events)["data"]["sequence"] == 1
    with pytest.raises(VerdifaxError, match=message) as caught:
        next(events)
    assert caught.value.last_sequence == 1
    assert len(seen) == 2


def test_a_page_going_backwards_from_the_start_place_is_refused():
    client = sync_client(feed_script([], [page([3], 2)]))
    with pytest.raises(VerdifaxError, match="went backwards") as caught:
        next(client.follow_signals(after=5))
    assert caught.value.last_sequence == 5


def test_other_errors_carry_no_place():
    with pytest.raises(ValidationError) as caught:
        sync_client(responder([])).get_signals(after=-1)
    assert caught.value.last_sequence is None


# ── feed keys, webhooks, deliveries and failure receipts ──────────────────────


def test_create_feed_key():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=FEED_KEY, status=201))
    assert client.create_feed_key("siem") == FEED_KEY
    client.create_feed_key("siem", expires_at="2027-01-01T00:00:00Z")
    assert [(r.method, r.url.path, query(r)) for r in seen] == [
        ("POST", "/account/feed-keys", ""),
        ("POST", "/account/feed-keys", ""),
    ]
    assert sent_body(seen[0]) == {"name": "siem"}
    assert sent_body(seen[1]) == {"name": "siem", "expires_at": "2027-01-01T00:00:00Z"}


@pytest.mark.parametrize(
    "name, expires_at, message",
    [
        ("", None, "name is required"),
        ("   ", None, "name is required"),
        (None, None, "name is required"),
        ("siem", 20270101, "expires_at must be a str"),
    ],
)
def test_create_feed_key_refuses_bad_input_without_a_request(name, expires_at, message):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(responder(seen)).create_feed_key(name, expires_at=expires_at)
    assert seen == []


def test_revoke_feed_key():
    seen: list[httpx.Request] = []
    answer = {"ok": True, "id": 9, "revoked": True}
    assert sync_client(responder(seen, body=answer)).revoke_feed_key(9) == answer
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "DELETE",
        "/account/feed-keys/9",
        b"",
    )


def test_revoking_a_key_that_is_not_a_feed_key_raises_the_404():
    seen: list[httpx.Request] = []
    refused = {"error": "no such feed key in this account"}
    with pytest.raises(APIError) as caught:
        sync_client(responder(seen, body=refused, status=404)).revoke_feed_key(4)
    assert caught.value.status_code == 404
    assert len(seen) == 1


BAD_IDS: list[Any] = [0, -1, True, "3", 1.0, None]


@pytest.mark.parametrize("bad", BAD_IDS)
def test_every_id_method_refuses_a_bad_id_without_a_request(bad):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    for method, field in (
        (client.revoke_feed_key, "id"),
        (client.delete_webhook, "id"),
        (client.list_webhook_deliveries, "id"),
        (client.get_failure_receipt, "run_id"),
    ):
        with pytest.raises(ValidationError, match=field):
            method(bad)
    assert seen == []


def test_create_webhook_takes_every_kind_by_default():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=WEBHOOK, status=201))
    assert client.create_webhook("https://hooks.example.com/verdifax") == WEBHOOK
    client.create_webhook("https://hooks.example.com/verdifax", types=[])
    assert [(r.method, r.url.path) for r in seen] == [("POST", "/account/webhooks")] * 2
    assert sent_body(seen[0]) == {"url": "https://hooks.example.com/verdifax", "types": []}
    assert sent_body(seen[1]) == {"url": "https://hooks.example.com/verdifax", "types": []}


def test_create_webhook_sends_the_kinds_named():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=WEBHOOK, status=201))
    client.create_webhook("https://h.example.com", types=["run.refused", "run.halted"])
    client.create_webhook("https://h.example.com", types=tuple(SIGNAL_KINDS))
    assert sent_body(seen[0]) == {
        "url": "https://h.example.com",
        "types": ["run.refused", "run.halted"],
    }
    assert sent_body(seen[1])["types"] == list(SIGNAL_KINDS)


@pytest.mark.parametrize(
    "url, types, message",
    [
        ("http://h.example.com", None, "starting https://"),
        ("https://", None, "starting https://"),
        ("", None, "starting https://"),
        (None, None, "starting https://"),
        ("HTTPS://h.example.com", None, "starting https://"),
        (" https://h.example.com", None, "starting https://"),
        ("https://h.example.com", "run.refused", "list of signal kinds"),
        ("https://h.example.com", {"run.refused"}, "list of signal kinds"),
        ("https://h.example.com", ["run.refused", "run.refused"], "run.refused twice"),
        ("https://h.example.com", ["com.verdifax.run.refused"], "types must be signal kinds"),
        ("https://h.example.com", ["run.denied"], "types must be signal kinds"),
        ("https://h.example.com", [None], "types must be signal kinds"),
    ],
)
def test_create_webhook_refuses_bad_input_without_a_request(url, types, message):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match=message):
        sync_client(responder(seen)).create_webhook(url, types=types)
    assert seen == []


@pytest.mark.parametrize(
    "status, error",
    [
        (400, "the address is not public"),
        (409, "an account may hold 10 webhook subscriptions"),
        (503, "webhooks need the deployment's KMS key"),
    ],
)
def test_create_webhook_raises_the_servers_refusal(status, error):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"error": error}, status=status))
    with pytest.raises(APIError, match=error) as caught:
        client.create_webhook("https://h.example.com")
    assert caught.value.status_code == status
    assert len(seen) == 1


def test_list_webhooks():
    seen: list[httpx.Request] = []
    assert sync_client(responder(seen, body=WEBHOOKS)).list_webhooks() == WEBHOOKS
    assert (seen[0].method, seen[0].url.path, query(seen[0]), seen[0].content) == (
        "GET",
        "/account/webhooks",
        "",
        b"",
    )


def test_delete_webhook():
    seen: list[httpx.Request] = []
    answer = {"ok": True, "id": 3, "deleted": True}
    assert sync_client(responder(seen, body=answer)).delete_webhook(3) == answer
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "DELETE",
        "/account/webhooks/3",
        b"",
    )


def test_list_webhook_deliveries():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=DELIVERIES))
    assert client.list_webhook_deliveries(3) == DELIVERIES
    client.list_webhook_deliveries(3, limit=500)
    client.list_webhook_deliveries(3, limit=1)
    assert [(r.method, r.url.path, query(r)) for r in seen] == [
        ("GET", "/account/webhooks/3/deliveries", ""),
        ("GET", "/account/webhooks/3/deliveries", "limit=500"),
        ("GET", "/account/webhooks/3/deliveries", "limit=1"),
    ]


@pytest.mark.parametrize("limit", [0, 501, True, "50", 1.5])
def test_list_webhook_deliveries_refuses_a_bad_limit(limit):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="limit"):
        sync_client(responder(seen)).list_webhook_deliveries(3, limit=limit)
    assert seen == []


def test_get_failure_receipt():
    seen: list[httpx.Request] = []
    assert sync_client(responder(seen, body=RECEIPT)).get_failure_receipt(42) == RECEIPT
    assert (seen[0].method, seen[0].url.path, query(seen[0])) == (
        "GET",
        "/runs/42/failure-receipt",
        "",
    )


def test_a_failed_run_from_before_failure_receipts_raises_the_404():
    refused = {"error": "this run has no failure receipt"}
    with pytest.raises(APIError) as caught:
        sync_client(responder([], body=refused, status=404)).get_failure_receipt(41)
    assert caught.value.status_code == 404


# ── the async client ──────────────────────────────────────────────────────────


async def test_async_signal_methods_send_the_same_requests():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answers = {
            ("GET", "/signals"): page([1], 0),
            ("GET", "/account/signals"): page([], 4),
            ("POST", "/account/feed-keys"): FEED_KEY,
            ("DELETE", "/account/feed-keys/9"): {"ok": True, "id": 9, "revoked": True},
            ("POST", "/account/webhooks"): WEBHOOK,
            ("GET", "/account/webhooks"): WEBHOOKS,
            ("DELETE", "/account/webhooks/3"): {"ok": True, "id": 3, "deleted": True},
            ("GET", "/account/webhooks/3/deliveries"): DELIVERIES,
            ("GET", "/runs/42/failure-receipt"): RECEIPT,
        }
        return httpx.Response(200, json=answers[(request.method, request.url.path)])

    async with async_client(handler, signing_key=None) as client:
        assert await client.get_signals() == page([1], 0)
        assert await client.get_signals(after=4, limit=10, wait=25, as_owner=True) == page([], 4)
        assert await client.create_feed_key("siem", expires_at="2027-01-01T00:00:00Z") == FEED_KEY
        assert (await client.revoke_feed_key(9))["revoked"] is True
        assert await client.create_webhook("https://h.example.com", ["key.created"]) == WEBHOOK
        assert await client.list_webhooks() == WEBHOOKS
        assert (await client.delete_webhook(3))["deleted"] is True
        assert await client.list_webhook_deliveries(3, limit=5) == DELIVERIES
        assert await client.get_failure_receipt(42) == RECEIPT
    assert [(r.method, r.url.path, query(r)) for r in seen] == [
        ("GET", "/signals", "after=0&wait=0"),
        ("GET", "/account/signals", "after=4&limit=10&wait=25"),
        ("POST", "/account/feed-keys", ""),
        ("DELETE", "/account/feed-keys/9", ""),
        ("POST", "/account/webhooks", ""),
        ("GET", "/account/webhooks", ""),
        ("DELETE", "/account/webhooks/3", ""),
        ("GET", "/account/webhooks/3/deliveries", "limit=5"),
        ("GET", "/runs/42/failure-receipt", ""),
    ]
    assert sent_body(seen[2]) == {"name": "siem", "expires_at": "2027-01-01T00:00:00Z"}
    assert sent_body(seen[4]) == {"url": "https://h.example.com", "types": ["key.created"]}
    assert seen[3].content == seen[6].content == b""


async def test_async_the_http_timeout_is_at_least_the_wait_plus_30_seconds():
    seen: list[httpx.Request] = []
    async with AsyncVerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        timeout=5,
        transport=httpx.MockTransport(responder(seen, body=page([], 0))),
    ) as client:
        await client.get_signals(wait=25)
        await client.get_signals()
    assert [read_timeout(r) for r in seen] == [55.0, 30.0]


async def test_async_follow_signals_follows_next_after_and_stops_when_the_caller_stops(
    monkeypatch,
):
    pauses: list[float] = []

    async def pause(seconds: float) -> None:
        pauses.append(seconds)

    monkeypatch.setattr("verdifax._signals.asyncio.sleep", pause)
    seen: list[httpx.Request] = []
    pages = [page([1, 2], 0), page([3], 2), page([], 3), page([4], 3)]
    read: list[int] = []
    async with async_client(feed_script(seen, pages)) as client:
        events = client.follow_signals(as_owner=True)
        assert isinstance(events, AsyncSignalFollower)
        assert isinstance(events, AsyncIterator)
        assert events.head is None
        assert seen == []
        async for item in events:
            read.append(item["data"]["sequence"])
            if item["data"]["sequence"] == 4:
                break
    assert read == [1, 2, 3, 4]
    assert [(r.url.path, query(r)) for r in seen] == [
        ("/account/signals", "after=0&wait=25"),
        ("/account/signals", "after=2&wait=25"),
        ("/account/signals", "after=3&wait=25"),
        ("/account/signals", "after=3&wait=25"),
    ]
    assert pauses == []


async def test_async_follow_signals_with_no_wait_pauses_after_an_empty_page(monkeypatch):
    pauses: list[float] = []

    async def pause(seconds: float) -> None:
        pauses.append(seconds)

    monkeypatch.setattr("verdifax._signals.asyncio.sleep", pause)
    async with async_client(feed_script([], [page([], 0), page([1], 0)])) as client:
        async for item in client.follow_signals(wait=0):
            assert item["data"]["sequence"] == 1
            break
    assert pauses == [1.0]


async def test_async_follow_signals_raises_with_the_last_sequence_read():
    seen: list[httpx.Request] = []
    down = httpx.Response(504, json={"error": "timeout"})
    read: list[int] = []
    async with async_client(feed_script(seen, [page([7], 6), down, down, down, down])) as client:
        with pytest.raises(APIError) as caught:
            async for item in client.follow_signals(after=6):
                read.append(item["data"]["sequence"])
    assert read == [7]
    assert caught.value.last_sequence == 7
    assert len(seen) == 5


async def test_async_signal_methods_refuse_bad_input_without_a_request():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=page([], 0))) as client:
        for kwargs, message in BAD_SIGNAL_ARGS:
            with pytest.raises(ValidationError, match=message):
                await client.get_signals(**kwargs)
        for kwargs, message in BAD_SIGNAL_ARGS[:5] + BAD_SIGNAL_ARGS[9:]:
            with pytest.raises(ValidationError, match=message):
                client.follow_signals(**kwargs)
        with pytest.raises(ValidationError, match="name is required"):
            await client.create_feed_key("")
        with pytest.raises(ValidationError, match="starting https://"):
            await client.create_webhook("http://h.example.com")
        with pytest.raises(ValidationError, match="twice"):
            await client.create_webhook("https://h.example.com", ["key.revoked", "key.revoked"])
        with pytest.raises(ValidationError, match="limit must be 1 to 500"):
            await client.list_webhook_deliveries(3, limit=0)
        for bad in BAD_IDS:
            with pytest.raises(ValidationError, match="id"):
                await client.revoke_feed_key(bad)
            with pytest.raises(ValidationError, match="id"):
                await client.delete_webhook(bad)
            with pytest.raises(ValidationError, match="id"):
                await client.list_webhook_deliveries(bad)
            with pytest.raises(ValidationError, match="run_id"):
                await client.get_failure_receipt(bad)
    assert seen == []


# ── the feed head (round 61) ──────────────────────────────────────────────────


HEAD_VECTOR = json.loads(
    (Path(__file__).parent / "sdk-feed-head-vector.json").read_text(encoding="utf-8")
)


def head(sequence: int, stated_at: str = "2026-11-12T21:58:20.123456789Z") -> dict[str, Any]:
    """The head statement the server ends a page that reaches the feed's end with.

    A statement made again later (another ``stated_at``) has another hash.
    """
    statement = hashlib.sha256(f"{sequence}|{stated_at}".encode()).hexdigest()
    return {
        "format": "verdifax.feed-head.v1",
        "account": "account-7",
        "sequence": sequence,
        "head_hash": "f" * 64,
        "stated_at": stated_at,
        "head_statement_hash": statement,
        "anchor": {"kind": "receipt_anchor", "receipt_kind": "feed_head", "log_index": 41},
    }


def page_at_end(sequences: list[int], after: int, **head_fields: Any) -> dict[str, Any]:
    """A page that reaches the feed's end, with its head."""
    end = sequences[-1] if sequences else after
    stated = head(end, head_fields.pop("stated_at")) if "stated_at" in head_fields else head(end)
    return {**page(sequences, after, newest=end), "head": {**stated, **head_fields}}


LATER = "2026-11-12T22:03:20Z"


def no_more() -> httpx.Response:
    """A fresh answer to the read after a test's last page: an httpx response is read once."""
    return httpx.Response(400, json={"error": "no more pages in this test"})


def test_the_head_form_and_types_are_exported():
    assert FEED_HEAD_FORM == "verdifax.feed-head.v1"
    for name in (
        "FEED_HEAD_FORM",
        "FeedHead",
        "RunDeletion",
        "SignalFollower",
        "AsyncSignalFollower",
    ):
        assert name in verdifax.__all__
        assert hasattr(verdifax, name)
    assert set(verdifax.FeedHead.__annotations__) == set(head(1))
    hints = typing.get_type_hints(verdifax.RunDeletion, include_extras=True)
    assert hints["log_entries"] == NotRequired[list[str]]
    assert typing.get_type_hints(verdifax.FeedHead)["sequence"] is int


@pytest.mark.parametrize("as_owner, path", [(False, "/signals"), (True, "/account/signals")])
def test_get_signals_keeps_the_head_beside_the_events(as_owner, path):
    seen: list[httpx.Request] = []
    answer = page_at_end([8, 9], 7)
    got = sync_client(responder(seen, body=answer)).get_signals(after=7, as_owner=as_owner)
    assert got == answer
    assert got["head"] == head(9)
    assert set(got["head"]) == {
        "format",
        "account",
        "sequence",
        "head_hash",
        "stated_at",
        "head_statement_hash",
        "anchor",
    }
    assert [e["data"]["sequence"] for e in got["events"]] == [8, 9]
    assert seen[0].url.path == path


def test_an_empty_page_at_the_end_keeps_its_head():
    answer = page_at_end([], 9)
    assert sync_client(responder([], body=answer)).get_signals(after=9)["head"] == head(9)


def test_a_page_without_a_head_or_with_a_null_head_is_read_as_before():
    for answer in (page([8, 9], 7), {**page([8, 9], 7), "head": None}):
        assert sync_client(responder([], body=answer)).get_signals(after=7) == answer


def test_a_head_with_no_anchor_is_kept():
    answer = page_at_end([9], 8)
    del answer["head"]["anchor"]
    assert sync_client(responder([], body=answer)).get_signals(after=8) == answer


def test_a_head_stating_another_end_is_returned_as_served():
    """The page is the server's; following never keeps such a head (the vector)."""
    answer = page_at_end([8, 9], 7, sequence=10)
    assert sync_client(responder([], body=answer)).get_signals(after=7) == answer


@pytest.mark.parametrize(
    "tamper, message",
    [
        (lambda p: p.update(head=[]), "a head that is not an object"),
        (lambda p: p.update(head="head"), "a head that is not an object"),
        (
            lambda p: p["head"].update(format="verdifax.signoff-head.v1"),
            "not verdifax.feed-head.v1",
        ),
        (lambda p: p["head"].pop("format"), "not verdifax.feed-head.v1"),
        (lambda p: p["head"].update(account="7"), "no usable account"),
        (lambda p: p["head"].update(account="account-07"), "no usable account"),
        (lambda p: p["head"].pop("account"), "no usable account"),
        (lambda p: p["head"].update(sequence=0), "no usable sequence"),
        (lambda p: p["head"].update(sequence=True), "no usable sequence"),
        (lambda p: p["head"].update(sequence="9"), "no usable sequence"),
        (lambda p: p["head"].update(head_hash="F" * 64), "no usable head_hash"),
        (lambda p: p["head"].update(head_hash="f" * 63), "no usable head_hash"),
        (lambda p: p["head"].pop("head_statement_hash"), "no usable head_statement_hash"),
        (lambda p: p["head"].update(stated_at=""), "no usable stated_at"),
        (lambda p: p["head"].update(stated_at=1), "no usable stated_at"),
        (lambda p: p["head"].update(anchor="entry"), "anchor is not an object"),
    ],
)
def test_a_malformed_head_is_refused(tamper, message):
    answer = page_at_end([8, 9], 7)
    tamper(answer)
    with pytest.raises(VerdifaxError, match=message):
        sync_client(responder([], body=answer)).get_signals(after=7)


def test_feed_head_returns_the_head_and_makes_no_request():
    answer = page_at_end([9], 8)
    assert feed_head(answer, "a saved page") is answer["head"]
    with pytest.raises(VerdifaxError, match="a saved page returned a head with no usable sequence"):
        feed_head({**answer, "head": {**answer["head"], "sequence": -1}}, "a saved page")


# The shared vector (sdk-feed-head-vector.json), the same in all four SDKs.


def statement_hash(label: str) -> str:
    """The head_statement_hash a vector head's statement label stands for."""
    return hashlib.sha256(label.encode()).hexdigest()


def vector_event_hash(sequence: int) -> str:
    """The event_hash of the vector's event at ``sequence``."""
    return hashlib.sha256(f"e{sequence}".encode()).hexdigest()


def vector_page(spec: dict[str, Any], after: int) -> dict[str, Any]:
    served = page(spec["events"], after, newest=spec["next_after"])
    served["next_after"] = spec["next_after"]
    for served_event in served["events"]:
        served_event["data"]["event_hash"] = vector_event_hash(served_event["data"]["sequence"])
    if spec["head"] is not None:
        named = spec["head"].get("head_hash_of", spec["head"]["sequence"])
        served["head"] = {
            **head(spec["head"]["sequence"]),
            "head_hash": vector_event_hash(named),
            "head_statement_hash": statement_hash(spec["head"]["statement"]),
        }
    return served


def vector_start(case: dict[str, Any]) -> dict[str, Any]:
    """The follow_signals arguments a case starts with: after, and the saved hash."""
    start = case.get("start")
    if start is None:
        return {"after": 0}
    named = start["after_hash_of"]
    saved = None if named is None else vector_event_hash(named)
    return {"after": start["after"], "after_event_hash": saved}


def vector_pages(case: dict[str, Any]) -> list[dict[str, Any]]:
    pages, after = [], vector_start(case)["after"]
    for spec in case["pages"]:
        pages.append(vector_page(spec, after))
        after = spec["next_after"]
    return pages


def as_vector(case: dict[str, Any], kept: Any) -> Any:
    """A kept or reported head in the vector's form, {sequence, statement}."""
    if kept is None:
        return None
    labels = {
        statement_hash(spec["head"]["statement"]): spec["head"]["statement"]
        for spec in case["pages"]
        if spec["head"] is not None
    }
    return {"sequence": kept["sequence"], "statement": labels[kept["head_statement_hash"]]}


def test_the_vector_is_the_shared_one():
    shared = ROOT.parent / "scripts" / "sdk-feed-head-vector.json"
    if not shared.exists():
        pytest.skip("the shared scripts folder is not beside this repository")
    assert (Path(__file__).parent / "sdk-feed-head-vector.json").read_bytes() == (
        shared.read_bytes()
    )
    assert len(HEAD_VECTOR["cases"]) == 13


@pytest.mark.parametrize("case", HEAD_VECTOR["cases"], ids=lambda case: case["name"])
def test_the_follower_keeps_the_head_as_the_vector_says(case):
    reported: list[Any] = []
    client = sync_client(feed_script([], [*vector_pages(case), no_more()]))
    events = client.follow_signals(
        wait=1, on_head=lambda h: reported.append(as_vector(case, h)), **vector_start(case)
    )
    stop = case["handle_until"]
    handled: list[int] = []
    if stop is None:
        with pytest.raises(APIError, match="no more pages") as caught:
            for item in events:
                handled.append(item["data"]["sequence"])
        # The error that stops following carries the kept head.
        assert as_vector(case, caught.value.head) == case["expected_kept"]
    else:
        for item in events:
            handled.append(item["data"]["sequence"])
            if item["data"]["sequence"] == stop:
                break
    assert (
        handled
        == [n for spec in case["pages"] for n in spec["events"]][
            : None if stop is None else handled.index(stop) + 1
        ]
    )
    assert as_vector(case, events.head) == case["expected_kept"]
    assert reported == case["expected_reported"]


@pytest.mark.parametrize("case", HEAD_VECTOR["cases"], ids=lambda case: case["name"])
async def test_async_the_follower_keeps_the_head_as_the_vector_says(case):
    reported: list[Any] = []
    stop = case["handle_until"]
    async with async_client(feed_script([], [*vector_pages(case), no_more()])) as client:
        events = client.follow_signals(
            wait=1, on_head=lambda h: reported.append(as_vector(case, h)), **vector_start(case)
        )
        if stop is None:
            with pytest.raises(APIError, match="no more pages") as caught:
                async for item in events:
                    pass
            assert as_vector(case, caught.value.head) == case["expected_kept"]
        else:
            async for item in events:
                if item["data"]["sequence"] == stop:
                    break
            await events.aclose()
    assert as_vector(case, events.head) == case["expected_kept"]
    assert reported == case["expected_reported"]


# The rule, case by case, with whole heads.


def test_follow_signals_never_yields_the_head_and_keeps_it_after_its_page_is_handled(
    monkeypatch,
):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    seen: list[httpx.Request] = []
    pages = [
        page([1, 2], 0, newest=5),
        page_at_end([3, 4, 5], 2),
        page_at_end([], 5, stated_at=LATER),
        page_at_end([6], 5),
        page([7], 6, newest=8),
    ]
    reported: list[dict[str, Any]] = []
    events = sync_client(feed_script(seen, pages)).follow_signals(on_head=reported.append)
    assert isinstance(events, SignalFollower)
    assert isinstance(events, Iterator)
    assert iter(events) is events
    assert events.head is None
    heads: dict[int, Any] = {}
    read: list[dict[str, Any]] = []
    for item in events:
        read.append(item)
        heads[item["data"]["sequence"]] = events.head
        if item["data"]["sequence"] == 7:
            break
    assert [item["data"]["sequence"] for item in read] == [1, 2, 3, 4, 5, 6, 7]
    # Every item yielded is an event; no head is ever yielded.
    assert all(item["specversion"] == "1.0" and "format" not in item for item in read)
    # While events 3 to 5 are handled, their page's head is not yet kept.
    assert [heads[n] for n in (1, 2, 3, 4, 5)] == [None] * 5
    # Event 5 handled: head 5 kept, then restated by the empty page, then
    # head 6 kept once event 6 is handled. A page short of the end keeps it.
    assert heads[6] == head(5, LATER)
    assert heads[7] == head(6) and events.head == head(6)
    assert reported == [head(5), head(5, LATER), head(6)]
    assert [query(r) for r in seen] == [
        "after=0&wait=25",
        "after=2&wait=25",
        "after=5&wait=25",
        "after=5&wait=25",
        "after=6&wait=25",
    ]


def test_the_same_head_on_idle_reads_is_reported_once(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    pages = [page_at_end([5], 4), page_at_end([], 5), page_at_end([], 5), page([6], 5)]
    reported: list[dict[str, Any]] = []
    events = sync_client(feed_script([], pages)).follow_signals(after=4, on_head=reported.append)
    assert [next(events)["data"]["sequence"] for _ in range(2)] == [5, 6]
    assert events.head == head(5)
    assert reported == [head(5)]


def test_a_head_on_a_page_the_caller_did_not_finish_is_not_kept():
    seen: list[httpx.Request] = []
    reported: list[Any] = []
    client = sync_client(feed_script(seen, [page_at_end([5, 6], 4)]))
    events = client.follow_signals(after=4, on_head=reported.append)
    assert next(events)["data"]["sequence"] == 5
    assert next(events)["data"]["sequence"] == 6
    events.close()
    assert events.head is None and reported == []
    with pytest.raises(StopIteration):
        next(events)
    assert len(seen) == 1


def test_a_head_not_matching_next_after_is_not_kept(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    pages = [page_at_end([5], 4, sequence=6), page_at_end([6], 5, sequence=5), no_more()]
    reported: list[Any] = []
    events = sync_client(feed_script([], pages)).follow_signals(after=4, on_head=reported.append)
    with pytest.raises(APIError) as caught:
        list(events)
    assert events.head is None and caught.value.head is None and reported == []


def test_a_head_whose_head_hash_is_not_the_last_handled_events_is_not_kept(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    pages = [
        page_at_end([5], 4, head_hash="e" * 64),
        page_at_end([], 5, head_hash="e" * 64, stated_at=LATER),
        page_at_end([], 5, stated_at=LATER),
        no_more(),
    ]
    reported: list[Any] = []
    events = sync_client(feed_script([], pages)).follow_signals(after=4, on_head=reported.append)
    with pytest.raises(APIError):
        list(events)
    # Only the head carrying event 5's hash ("f" * 64 in these pages) is kept.
    assert reported == [head(5, LATER)] and events.head == head(5, LATER)


def test_no_head_is_kept_before_an_event_is_handled(monkeypatch):
    """With no event handled yet there is no last event to match, so a head on
    an empty page at the start is not kept; the next one, after an event, is."""
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    pages = [page_at_end([], 5), page_at_end([6], 5), no_more()]
    reported: list[Any] = []
    events = sync_client(feed_script([], pages)).follow_signals(after=5, on_head=reported.append)
    with pytest.raises(APIError):
        list(events)
    assert reported == [head(6)]


def test_a_resumed_follower_with_the_saved_hash_keeps_the_head_it_is_served(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    seen: list[httpx.Request] = []
    pages = [page_at_end([], 5), page_at_end([6], 5, head_hash="e" * 64), no_more()]
    reported: list[Any] = []
    events = sync_client(feed_script(seen, pages)).follow_signals(
        after=5, after_event_hash="f" * 64, on_head=reported.append
    )
    with pytest.raises(APIError) as caught:
        list(events)
    # Event 5's saved hash matches the first head. The second names another
    # hash than event 6's, the last handled, so it is not kept.
    assert reported == [head(5)] and events.head == head(5) == caught.value.head
    assert [query(r) for r in seen][:1] == ["after=5&wait=25"]


def test_a_resumed_follower_with_another_saved_hash_keeps_no_head(monkeypatch):
    monkeypatch.setattr("verdifax._signals.time.sleep", lambda seconds: None)
    pages = [page_at_end([], 5), no_more()]
    for saved in ("e" * 64, "", None):
        reported: list[Any] = []
        events = sync_client(feed_script([], list(pages))).follow_signals(
            after=5, after_event_hash=saved, on_head=reported.append
        )
        with pytest.raises(APIError):
            list(events)
        assert reported == [] and events.head is None
        pages = [page_at_end([], 5), no_more()]


BAD_HASHES = ["f" * 63, "F" * 64, "f" * 65, "g" * 64, 64]


@pytest.mark.parametrize("bad", BAD_HASHES)
def test_a_bad_after_event_hash_is_refused_before_anything_is_sent(bad):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="after_event_hash"):
        sync_client(responder(seen)).follow_signals(after=5, after_event_hash=bad)
    assert seen == []


async def test_async_after_event_hash_is_checked_and_used():
    seen: list[httpx.Request] = []
    async with async_client(feed_script(seen, [page_at_end([], 5), no_more()])) as client:
        for bad in BAD_HASHES:
            with pytest.raises(ValidationError, match="after_event_hash"):
                client.follow_signals(after=5, after_event_hash=bad)
        assert seen == []
        events = client.follow_signals(after=5, after_event_hash="f" * 64)
        with pytest.raises(APIError) as caught:
            async for item in events:
                pass
    assert events.head == head(5) == caught.value.head


def test_the_error_that_stops_following_carries_the_last_finished_events_hash():
    pages = [page([1, 2], 0, newest=2), no_more()]
    for served in pages[0]["events"]:
        served["data"]["event_hash"] = vector_event_hash(served["data"]["sequence"])
    events = sync_client(feed_script([], pages)).follow_signals()
    with pytest.raises(APIError) as caught:
        list(events)
    assert caught.value.last_sequence == 2
    assert caught.value.after_event_hash == vector_event_hash(2)
    # With no event finished, it is the hash given, or None.
    for given in (vector_event_hash(9), None):
        events = sync_client(feed_script([], [no_more()])).follow_signals(
            after=9, after_event_hash=given
        )
        with pytest.raises(APIError) as caught:
            next(events)
        assert (caught.value.last_sequence, caught.value.after_event_hash) == (9, given)


def test_a_bad_page_mid_feed_carries_the_hash_of_the_event_before_it():
    first = page([1], 0, newest=3)
    first["events"][0]["data"]["event_hash"] = vector_event_hash(1)
    bad = {**page([2, 3], 1), "next_after": 5}
    events = sync_client(feed_script([], [first, bad])).follow_signals()
    assert next(events)["data"]["sequence"] == 1
    with pytest.raises(VerdifaxError, match="would skip or repeat") as caught:
        next(events)
    assert (caught.value.last_sequence, caught.value.after_event_hash) == (1, vector_event_hash(1))


async def test_async_the_error_that_stops_following_carries_the_last_finished_events_hash():
    first = page([4], 3, newest=4)
    first["events"][0]["data"]["event_hash"] = vector_event_hash(4)
    async with async_client(feed_script([], [first, no_more()])) as client:
        with pytest.raises(APIError) as caught:
            async for item in client.follow_signals(after=3, after_event_hash=vector_event_hash(3)):
                pass
    assert (caught.value.last_sequence, caught.value.after_event_hash) == (4, vector_event_hash(4))
    async with async_client(feed_script([], [no_more()])) as client:
        with pytest.raises(APIError) as caught:
            async for item in client.follow_signals(after=3):
                pass
    assert (caught.value.last_sequence, caught.value.after_event_hash) == (3, None)


def test_other_errors_carry_no_after_event_hash():
    with pytest.raises(ValidationError) as caught:
        sync_client(responder([])).get_signals(after=-1)
    assert caught.value.after_event_hash is None


def test_an_error_while_following_carries_the_kept_head():
    bad = page_at_end([2, 3], 1, head_hash="E" * 64)
    events = sync_client(feed_script([], [page_at_end([1], 0), bad])).follow_signals()
    assert next(events)["data"]["sequence"] == 1
    with pytest.raises(VerdifaxError, match="no usable head_hash") as caught:
        next(events)
    assert caught.value.last_sequence == 1
    assert caught.value.head == head(1) == events.head


def test_on_head_must_be_a_function():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="on_head must be a function or None, got str"):
        sync_client(responder(seen)).follow_signals(on_head="print")
    assert seen == []


async def test_async_follow_signals_never_yields_the_head_and_keeps_it_after_its_page(
    monkeypatch,
):
    async def pause(seconds: float) -> None:
        return None

    monkeypatch.setattr("verdifax._signals.asyncio.sleep", pause)
    seen: list[httpx.Request] = []
    pages = [page([1], 0, newest=3), page_at_end([2, 3], 1), page([4], 3, newest=5)]
    read: list[dict[str, Any]] = []
    heads: list[Any] = []
    reported: list[Any] = []
    async with async_client(feed_script(seen, pages)) as client:
        events = client.follow_signals(as_owner=True, on_head=reported.append)
        assert isinstance(events, AsyncSignalFollower)
        assert events.__aiter__() is events
        async for item in events:
            read.append(item)
            heads.append(events.head)
            if item["data"]["sequence"] == 4:
                break
        await events.aclose()
        with pytest.raises(ValidationError, match="on_head must be a function"):
            client.follow_signals(on_head=1)
    assert [item["data"]["sequence"] for item in read] == [1, 2, 3, 4]
    assert all(item["specversion"] == "1.0" and "format" not in item for item in read)
    assert heads == [None, None, None, head(3)]
    assert reported == [head(3)]
    assert [r.url.path for r in seen] == ["/account/signals"] * 3


async def test_async_get_signals_keeps_the_head_and_refuses_a_malformed_one():
    answer = page_at_end([8, 9], 7)
    async with async_client(responder([], body=answer)) as client:
        assert (await client.get_signals(after=7))["head"] == head(9)
    bad = page_at_end([8, 9], 7, format="verdifax.feed-head.v2")
    async with async_client(responder([], body=bad)) as client:
        with pytest.raises(VerdifaxError, match="not verdifax.feed-head.v1"):
            await client.get_signals(after=7)


# ── a deleted record's tombstone in the feed (round 60 fields) ────────────────


JOB_LINKS = {
    "previous_record_hashes": ["1" * 64, "2" * 64],
    "external_previous": ["a" * 64],
    "final": True,
}


def tombstone(**fields: Any) -> dict[str, Any]:
    return {
        "format": "verdifax.run-deletion.v1",
        "decided_by": "owner",
        "run_id": 42,
        "record_hash": "c" * 64,
        "job_id": "job-1",
        "step_id": "s2",
        "job_links": JOB_LINKS,
        "log_entries": ["1844674407370955161", "1844674407370955162"],
        "changed_at": "2026-11-12T18:00:01.5Z",
        "owner_signature": {"public_key": "p", "signature": "s", "signed_at": "t", "nonce": "n"},
        "signal": {"signal_account": "account-7", "signal_sequence": 9},
        "deletion_hash": "b" * 64,
        "anchor": {"kind": "receipt_anchor", "receipt_kind": "run_deletion"},
        **fields,
    }


def deleted_event(sequence: int, deleted: Any) -> dict[str, Any]:
    """An event whose entry was a since deleted record: a refused run's receipt."""
    served = event(sequence, "run.refused")
    served["data"].update(entry=None, run_id=42, deleted=deleted)
    return served


def test_a_deleted_records_tombstone_is_read_with_every_field():
    answer = {"events": [event(8), deleted_event(9, tombstone())], "next_after": 9, "newest": 9}
    raw = json.dumps(answer)
    got = sync_client(lambda request: httpx.Response(200, text=raw)).get_signals(after=7)
    assert got == answer
    deleted = got["events"][1]["data"]["deleted"]
    assert deleted["log_entries"] == ["1844674407370955161", "1844674407370955162"]
    assert set(deleted) == set(verdifax.RunDeletion.__annotations__)
    # Saved again, the page is the bytes the server sent.
    assert json.dumps(got) == raw


@pytest.mark.parametrize(
    "deleted, message",
    [
        ([], "event 9 has a run deletion that is not an object"),
        ("gone", "event 9 has a run deletion that is not an object"),
        (tombstone(run_id="42"), "run_id is not a whole number"),
        (tombstone(run_id=True), "run_id is not a whole number"),
        (tombstone(log_entries="12"), "log_entries is not a list of strings"),
        (tombstone(log_entries=[12]), "log_entries is not a list of strings"),
        (tombstone(log_entries=[None]), "log_entries is not a list of strings"),
    ],
)
def test_a_malformed_tombstone_in_the_feed_is_refused(deleted, message):
    answer = {"events": [deleted_event(9, deleted)], "next_after": 9, "newest": 9}
    with pytest.raises(VerdifaxError, match=message):
        sync_client(responder([], body=answer)).get_signals(after=8)


def test_a_tombstone_with_no_log_entries_or_a_null_deleted_is_read():
    no_entries = tombstone()
    del no_entries["log_entries"]
    answer = {
        "events": [deleted_event(8, no_entries), deleted_event(9, None)],
        "next_after": 9,
        "newest": 9,
    }
    assert sync_client(responder([], body=answer)).get_signals(after=7) == answer


def test_job_links_are_read_as_sent_and_a_tombstone_without_them_too():
    older = tombstone()
    del older["job_links"]
    outside_a_job = tombstone()
    for name in ("job_id", "step_id", "job_links"):
        del outside_a_job[name]
    shapes = [tombstone(), tombstone(job_links={}), tombstone(job_links={"final": False}), older]
    events = [deleted_event(n, t) for n, t in enumerate([*shapes, outside_a_job], start=1)]
    answer = {"events": events, "next_after": 5, "newest": 5}
    raw = json.dumps(answer)
    got = sync_client(lambda request: httpx.Response(200, text=raw)).get_signals()
    assert got == answer and json.dumps(got) == raw
    assert got["events"][0]["data"]["deleted"]["job_links"] == JOB_LINKS
    assert got["events"][1]["data"]["deleted"]["job_links"] == {}
    assert "job_links" not in got["events"][3]["data"]["deleted"]
    hints = typing.get_type_hints(verdifax.RunDeletion, include_extras=True)
    assert hints["job_links"] == NotRequired[verdifax.DeletedJobLinks]
    assert set(verdifax.DeletedJobLinks.__annotations__) == set(JOB_LINKS)


TOO_MANY = [format(n, "064x") for n in range(65)]


@pytest.mark.parametrize(
    "links, message",
    [
        ([], "job_links is not an object"),
        ("final", "job_links is not an object"),
        (
            {"previous_record_hashes": "1" * 64},
            "previous_record_hashes is not a list of at most 64",
        ),
        (
            {"previous_record_hashes": TOO_MANY},
            "previous_record_hashes is not a list of at most 64",
        ),
        ({"external_previous": TOO_MANY[:17]}, "external_previous is not a list of at most 16"),
        ({"previous_record_hashes": ["1" * 63]}, r"previous_record_hashes\[0\] is not a 64"),
        ({"external_previous": ["A" * 64]}, r"external_previous\[0\] is not a 64"),
        ({"external_previous": [7]}, r"external_previous\[0\] is not a 64"),
        ({"previous_record_hashes": ["2" * 64, "1" * 64]}, "not sorted with no repeats"),
        ({"previous_record_hashes": ["1" * 64, "1" * 64]}, "not sorted with no repeats"),
        ({"final": "true"}, "job_links.final is not a bool"),
        ({"final": 1}, "job_links.final is not a bool"),
    ],
)
def test_malformed_job_links_are_refused(links, message):
    answer = {
        "events": [deleted_event(9, tombstone(job_links=links))],
        "next_after": 9,
        "newest": 9,
    }
    with pytest.raises(VerdifaxError, match=message):
        sync_client(responder([], body=answer)).get_signals(after=8)


def test_job_links_at_their_limits_are_read():
    links = {"previous_record_hashes": TOO_MANY[:64], "external_previous": TOO_MANY[:16]}
    answer = {
        "events": [deleted_event(9, tombstone(job_links=links))],
        "next_after": 9,
        "newest": 9,
    }
    assert sync_client(responder([], body=answer)).get_signals(after=8) == answer


def test_job_links_without_a_job_id_are_refused():
    record = tombstone(job_id="")
    answer = {"events": [deleted_event(9, record)], "next_after": 9, "newest": 9}
    with pytest.raises(VerdifaxError, match="job_links but no job_id"):
        sync_client(responder([], body=answer)).get_signals(after=8)


def deleted_run_feed() -> dict[str, Any]:
    """A feed as the server serves it after run 60 was deleted.

    Run 60's run.sealed event keeps its own entry; its run.deleted event
    names it. Run 62 was refused and then deleted: its receipt event is
    served with entry None and the tombstone in data["deleted"]."""
    sealed_60 = event(1, "run.sealed")
    sealed_60["data"]["entry"] = {"run_id": 60, "signoff_required": True}
    sealed_61 = event(2, "run.sealed")
    sealed_61["data"]["entry"] = {"run_id": 61, "signoff_required": True}
    refused_62 = deleted_event(3, tombstone(run_id=62))
    deleted_60 = event(4, "run.deleted")
    deleted_60["data"]["entry"] = tombstone(run_id=60)
    deleted_62 = event(5, "run.deleted")
    deleted_62["data"]["entry"] = tombstone(run_id=62)
    events = [sealed_60, sealed_61, refused_62, deleted_60, deleted_62]
    return {"events": events, "next_after": 5, "newest": 5}


def test_pending_signoffs_reads_a_feed_with_deleted_records_as_served():
    """A deleted run's run.sealed plus its run.deleted leaves the run out, and
    a deleted refused run's receipt event (entry None) is not read for runs."""
    from verdifax import pending_signoffs

    served = deleted_run_feed()
    assert pending_signoffs(served["events"]) == [61]
    page_read = sync_client(responder([], body=served)).get_signals()
    assert pending_signoffs(page_read["events"]) == [61]
    followed = sync_client(feed_script([], [served])).follow_signals()
    assert pending_signoffs([next(followed) for _ in range(5)]) == [61]
    # Without the run.deleted event, run 60 is still pending.
    assert pending_signoffs(served["events"][:3]) == [60, 61]


def test_pending_signoffs_refuses_a_run_sealed_event_with_a_null_entry():
    """The server never serves run.sealed with a null entry: it keeps its own
    entry. One that names no run is refused, with or without a tombstone."""
    from verdifax import pending_signoffs

    for deleted in (None, tombstone(run_id=60)):
        bad = event(5, "run.sealed")
        bad["data"].update(entry=None, deleted=deleted)
        with pytest.raises(
            VerdifaxError, match="run.sealed entry of event account-7/5 names no run"
        ):
            pending_signoffs([bad])


async def test_async_pending_signoffs_reads_a_feed_with_deleted_records_as_served():
    from verdifax import pending_signoffs

    served = deleted_run_feed()
    async with async_client(feed_script([], [served, served])) as client:
        events = client.follow_signals()
        assert pending_signoffs([await events.__anext__() for _ in range(5)]) == [61]
        await events.aclose()
        assert pending_signoffs((await client.get_signals(after=0))["events"]) == [61]


# The shared pending sign-offs vector (sdk-pending-signoffs-vector.json).

PENDING_VECTOR = json.loads(
    (Path(__file__).parent / "sdk-pending-signoffs-vector.json").read_text(encoding="utf-8")
)


def pending_feed(case: dict[str, Any]) -> dict[str, Any]:
    """A case's abstract events as served events on one feed page."""
    events = []
    for sequence, spec in enumerate(case["events"], start=1):
        served = event(sequence, spec["kind"])
        served["data"]["entry"] = spec["entry"]
        if spec["deleted"] is not None:
            served["data"]["deleted"] = tombstone(**spec["deleted"])
        events.append(served)
    return {"events": events, "next_after": len(events), "newest": len(events)}


def pending_answer(events: list[dict[str, Any]]) -> Any:
    from verdifax import pending_signoffs

    try:
        return pending_signoffs(events)
    except VerdifaxError as refused:
        assert "names no run" in str(refused)
        return "error"


def expected_pending(case: dict[str, Any]) -> Any:
    return "error" if case["expected_error"] else case["expected_pending"]


def test_the_pending_vector_is_the_shared_one():
    shared = ROOT.parent / "scripts" / "sdk-pending-signoffs-vector.json"
    if not shared.exists():
        pytest.skip("the shared scripts folder is not beside this repository")
    assert (Path(__file__).parent / "sdk-pending-signoffs-vector.json").read_bytes() == (
        shared.read_bytes()
    )
    assert len(PENDING_VECTOR["cases"]) == 8


@pytest.mark.parametrize("case", PENDING_VECTOR["cases"], ids=lambda case: case["name"])
def test_pending_signoffs_answers_as_the_vector_says(case):
    served = pending_feed(case)
    assert pending_answer(served["events"]) == expected_pending(case)
    # The same feed read through the client, as served.
    page_read = sync_client(responder([], body=served)).get_signals()
    assert pending_answer(page_read["events"]) == expected_pending(case)
    followed = sync_client(feed_script([], [served])).follow_signals()
    events = [next(followed) for _ in served["events"]]
    assert pending_answer(events) == expected_pending(case)


@pytest.mark.parametrize("case", PENDING_VECTOR["cases"], ids=lambda case: case["name"])
async def test_async_pending_signoffs_answers_as_the_vector_says(case):
    served = pending_feed(case)
    async with async_client(feed_script([], [served, served])) as client:
        page_read = await client.get_signals()
        followed = client.follow_signals()
        events = [await followed.__anext__() for _ in served["events"]]
        await followed.aclose()
    assert pending_answer(page_read["events"]) == expected_pending(case)
    assert pending_answer(events) == expected_pending(case)


# ── the README and CHANGELOG ──────────────────────────────────────────────────


ROOT = Path(__file__).parent.parent


def test_the_readme_states_the_signal_feed_facts():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Signal feed", 1)[1].split("\n## ", 1)[0]
    for sentence in (
        "The feed cannot show a signal Verdifax never recorded.",
        "A feed key reads the feed and nothing else.",
        "A delivery is a copy: the pull feed and the public log are the record.",
        "`verdifax-verify --signals` checks a saved feed.",
        "client.follow_signals(",
        "verdifax.verify_webhook(",
    ):
        assert sentence in section, sentence
    for name in [*SIGNAL_METHODS, "follow_signals"]:
        assert f"`{name}(" in readme, name
    for name in ("signal_event_hash", "verify_webhook"):
        assert f"`verdifax.{name}(" in section, name


def test_the_changelog_opens_with_1_15_0_and_the_earlier_releases_follow():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    newest = changelog.split("\n## ", 2)[1]
    assert newest.startswith("1.15.0\n")
    for phrase in (
        "request_key.registered",
        "request_key.rotated",
        "request_key.cleared",
        "request_key_approval",
        "verdifax.feed-head.v1",
        "SignalFollower",
        "AsyncSignalFollower",
        "rotate_account_request_key",
        "after_event_hash",
        "job_links",
        "409",
        "verdifax-python/1.15.0",
    ):
        assert phrase in newest, phrase
    newest = changelog.split("\n## ", 3)[2]
    assert newest.startswith("1.14.0\n")
    for phrase in (
        "set_account_setting",
        "delete_run",
        "admin_delete_run",
        "admin_replace_owner_key",
        "owner_change_preimage",
        "account.changed",
        "run.deleted",
        "owner_replacement",
        "verdifax_deletion",
        "verdifax.key-change.v2",
        "lenient=1",
    ):
        assert phrase in newest, phrase
    newest = changelog.split("\n## ", 4)[3]
    assert newest.startswith("1.13.0\n")
    for phrase in (
        "pending_signoffs",
        "signed_as",
        "own_decision",
        "verdifax.signoff-head.v1",
        "v0.31.0",
    ):
        assert phrase in newest, phrase
    newest = changelog.split("\n## ", 5)[4]
    assert newest.startswith("1.12.0\n")
    for phrase in ("data_quality", "pending_signoffs", "lenient", "fallback", "get_public_signoff"):
        assert phrase in newest, phrase
    newest = changelog.split("\n## ", 6)[5]
    assert newest.startswith("1.11.0\n")
    for phrase in ("chain.interrupted", "v0.29.0", "2^53"):
        assert phrase in newest, phrase
    newest = changelog.split("\n## ", 7)[6]
    assert newest.startswith("1.10.0\n")
    for phrase in (
        "run.sealed",
        "chain.gap",
        "ai_output_declared",
        "download_public_audit_pdf",
        "set_account_time_zone",
        "v0.28.0",
    ):
        assert phrase in newest, phrase
    entry = changelog.split("\n## ", 8)[7]
    assert entry.startswith("1.9.0\n")
    assert "aivp_trace_text" in entry
    entry = changelog.split("\n## ", 9)[8]
    assert entry.startswith("1.8.0\n")
    assert "decided_by" in entry
    entry = changelog.split("\n## ", 10)[9]
    assert entry.startswith("1.7.0\n")
    assert "public_receipt_url" in entry
    assert changelog.split("\n## ", 11)[10].startswith("1.6.1\n")
    entry = changelog.split("\n## ", 12)[11]
    assert entry.startswith("1.6.0\n")
    for phrase in ("publish_run", "unpublish_run", "run.published", "run.unpublished", "v0.24.0"):
        assert phrase in entry, phrase
    entry = changelog.split("\n## ", 13)[12]
    assert entry.startswith("1.5.0\n")
    for phrase in (
        "feed keys",
        "webhook",
        "failure receipt",
        "verify_webhook",
        "cannot show a signal verdifax never recorded",
        "verdifax-verify --signals",
    ):
        assert phrase in entry.lower(), phrase


@pytest.mark.parametrize(
    "path",
    ["README.md", "CHANGELOG.md", "verdifax/_signals.py", "tests/test_signals.py"],
)
def test_no_em_or_en_dashes(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    assert chr(0x2014) not in text and chr(0x2013) not in text


def test_pending_signoffs_lists_required_runs_without_an_approval_in_force():
    """Round 58, B7: pending until the last sign-off on the record is an approval."""
    from verdifax import pending_signoffs

    def ev(seq, kind, entry):
        return {"id": f"account-7/{seq}", "data": {"kind": kind, "sequence": seq, "entry": entry}}

    def sign_off(run, decision, kind):
        return {"decision": decision, "target": {"kind": kind, "run_id": run}}

    events = [
        ev(1, "run.sealed", {"run_id": 10, "signoff_required": True}),
        ev(2, "run.sealed", {"run_id": 11}),
        ev(3, "run.sealed", {"run_id": 12, "signoff_required": True}),
        ev(4, "run.sealed", {"run_id": 13, "signoff_required": True}),
        ev(5, "signoff.recorded", sign_off(10, "approve", "record")),
        ev(6, "signoff.recorded", sign_off(12, "approve", "record")),
        ev(7, "signoff.recorded", sign_off(12, "reject", "record")),
        ev(8, "signoff.recorded", sign_off(13, "approve", "receipt")),
    ]
    assert pending_signoffs(events) == [12, 13]
    import pytest

    from verdifax import VerdifaxError

    with pytest.raises(VerdifaxError):
        pending_signoffs([ev(1, "run.sealed", {})])


def test_pending_signoffs_reads_a_job_signoff_as_the_verifier_does():
    """Round 59, N15 and N19: a job sign-off on a run's record counts, and
    the job's decision governs the record's own, as the verifier reads it."""
    from verdifax import pending_signoffs

    def ev(seq, kind, entry):
        return {"id": f"account-7/{seq}", "data": {"kind": kind, "sequence": seq, "entry": entry}}

    def sign_off(run, decision, kind):
        return {"decision": decision, "target": {"kind": kind, "run_id": run}}

    events = [
        ev(1, "run.sealed", {"run_id": 20, "signoff_required": True}),
        ev(2, "run.sealed", {"run_id": 21, "signoff_required": True}),
        ev(3, "run.sealed", {"run_id": 22, "signoff_required": True}),
        ev(4, "signoff.recorded", sign_off(20, "approve", "job")),
        ev(5, "signoff.recorded", sign_off(21, "reject", "job")),
        ev(6, "signoff.recorded", sign_off(21, "approve", "record")),
        ev(7, "signoff.recorded", sign_off(22, "reject", "record")),
        ev(8, "signoff.recorded", sign_off(22, "approve", "job")),
    ]
    # 20: approved by its job. 21: the job's rejection governs its own
    # approval. 22: the job's approval governs its own rejection.
    assert pending_signoffs(events) == [21]


def test_pending_signoffs_leaves_out_a_deleted_run():
    """Round 60: a run.deleted event for a run, at any place in the feed
    given, removes the run from the pending list; another run stays."""
    from verdifax import VerdifaxError, pending_signoffs

    def ev(seq, kind, entry):
        return {"id": f"account-7/{seq}", "data": {"kind": kind, "sequence": seq, "entry": entry}}

    def deletion(run, decided_by="owner"):
        return {"format": "verdifax.run-deletion.v1", "decided_by": decided_by, "run_id": run}

    events = [
        ev(1, "run.sealed", {"run_id": 30, "signoff_required": True}),
        ev(2, "run.sealed", {"run_id": 31, "signoff_required": True}),
        ev(3, "run.deleted", deletion(30)),
    ]
    assert pending_signoffs(events) == [31]
    # A deletion before the run's sealed event, or by Verdifax, counts the same.
    events = [
        ev(1, "run.deleted", deletion(40, "verdifax_admin")),
        ev(2, "run.sealed", {"run_id": 40, "signoff_required": True}),
        ev(3, "run.sealed", {"run_id": 41, "signoff_required": True}),
        ev(
            4,
            "signoff.recorded",
            {"decision": "reject", "target": {"kind": "record", "run_id": 41}},
        ),
    ]
    assert pending_signoffs(events) == [41]
    # A deletion of another run removes nothing.
    events = [
        ev(1, "run.sealed", {"run_id": 50, "signoff_required": True}),
        ev(2, "run.deleted", deletion(51)),
    ]
    assert pending_signoffs(events) == [50]
    for entry in ({}, {"run_id": "50"}, {"run_id": True}):
        with pytest.raises(
            VerdifaxError, match="run.deleted entry of event account-7/2 names no run"
        ):
            pending_signoffs([events[0], ev(2, "run.deleted", entry)])
