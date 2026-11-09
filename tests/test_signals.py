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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

import verdifax
from tests.test_accounts import parity_names
from tests.test_jobs import VECTOR, async_client, scripted, sent_body, sync_client
from tests.test_parity import responder
from verdifax import (
    SIGNAL_KINDS,
    APIError,
    AsyncVerdifaxClient,
    ConnectionError as VerdifaxConnectionError,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    WebhookVerificationError,
    signal_event_hash,
    verify_webhook,
)
from verdifax._signals import signals_timeout

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
    )


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
        ("follow_signals", ["self", "after", "wait", "as_owner"]),
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
        assert inspect.isasyncgen(events)
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


def test_the_changelog_opens_with_1_9_0_and_the_earlier_releases_follow():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    newest = changelog.split("\n## ", 2)[1]
    assert newest.startswith("1.9.0\n")
    assert "aivp_trace_text" in newest
    entry = changelog.split("\n## ", 3)[2]
    assert entry.startswith("1.8.0\n")
    assert "decided_by" in entry
    entry = changelog.split("\n## ", 4)[3]
    assert entry.startswith("1.7.0\n")
    assert "public_receipt_url" in entry
    assert changelog.split("\n## ", 5)[4].startswith("1.6.1\n")
    entry = changelog.split("\n## ", 6)[5]
    assert entry.startswith("1.6.0\n")
    for phrase in ("publish_run", "unpublish_run", "run.published", "run.unpublished", "v0.24.0"):
        assert phrase in entry, phrase
    entry = changelog.split("\n## ", 7)[6]
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
