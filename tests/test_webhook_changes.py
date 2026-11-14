"""Round 62: the owner adds and removes a webhook only with a record in the
account's feed, signed by the owner key's request key over webhook_value, the
SHA-256 of the address and the kinds, never the address itself.

Requests go to ``httpx.MockTransport``; the fake server answers as the real one
does, with a record carrying what was sent, which a test may tamper with.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest
from cryptography.exceptions import InvalidSignature

import verdifax
from tests.test_account_changes import ACCOUNT, OWNER_PUBLIC_KEY, assert_owner_signature
from tests.test_jobs import async_client, sent_body, sync_client
from verdifax import ValidationError, VerdifaxError
from verdifax._signals import WEBHOOK_DELETED, WEBHOOK_SUBSCRIBED, webhook_value

VECTOR = json.loads(
    (Path(__file__).parent / "sdk-webhook-change-vector.json").read_text(encoding="utf-8")
)
URL = "https://hooks.example.com/verdifax?token=s3cret"
LISTED = {"id": 3, "url": URL, "types": ["run.refused"], "created_at": "2026-11-13T12:00:00Z"}


def record(change: str, value: str, body: dict) -> dict[str, Any]:
    return {
        "format": "verdifax.account-change.v1",
        "action": change,
        "decided_by": "owner",
        "key_id": 0,
        "value": value,
        "changed_at": "2026-11-13T12:00:01Z",
        "owner_signature": {"public_key": OWNER_PUBLIC_KEY, **body["owner_signature"]},
        "signal": {"account": "account-7", "sequence": 12},
        "account_change_hash": "a" * 64,
    }


def webhook_server(
    seen: list[httpx.Request], tamper: Callable[[dict[str, Any]], None] = lambda r: None
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if (request.method, path) == ("GET", "/account"):
            return httpx.Response(200, json=ACCOUNT)
        if (request.method, path) == ("GET", "/account/webhooks"):
            return httpx.Response(200, json={"ok": True, "webhooks": [LISTED]})
        if (request.method, path) == ("POST", "/account/webhooks"):
            body = json.loads(request.content)
            rec = record(WEBHOOK_SUBSCRIBED, webhook_value(body["url"], body["types"]), body)
            tamper(rec)
            return httpx.Response(
                201,
                json={
                    "ok": True,
                    "id": 3,
                    "url": body["url"],
                    "types": body["types"],
                    "created_at": "2026-11-13T12:00:00Z",
                    "secret": "whsec_x",
                    "hint": "Store this secret now.",
                    "account_change": rec,
                },
            )
        if request.method == "DELETE" and path == "/account/webhooks/3":
            body = json.loads(request.content)
            rec = record(WEBHOOK_DELETED, webhook_value(LISTED["url"], LISTED["types"]), body)
            tamper(rec)
            return httpx.Response(
                200, json={"ok": True, "id": 3, "deleted": True, "account_change": rec}
            )
        return httpx.Response(404, json={"error": "not found"})

    return handler


def test_the_value_matches_the_shared_vector():
    assert (WEBHOOK_SUBSCRIBED, WEBHOOK_DELETED) == (
        VECTOR["changes"]["subscribe"],
        VECTOR["changes"]["delete"],
    )
    for case in VECTOR["cases"]:
        assert verdifax.webhook_value(case["url"], case["types"] or []) == case["value"], case[
            "name"
        ]
    # Written out independently of the SDK.
    assert webhook_value(URL, ["run.refused", "account.changed"]) == (
        "sha256=" + hashlib.sha256(URL.encode()).hexdigest() + " kinds=account.changed,run.refused"
    )


def test_create_webhook_signs_the_subscription_and_checks_the_record():
    seen: list[httpx.Request] = []
    answer = sync_client(webhook_server(seen)).create_webhook(URL, types=["run.refused"])
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("POST", "/account/webhooks"),
    ]
    body = sent_body(seen[1])
    assert list(body) == ["url", "types", "owner_signature"]
    assert (body["url"], body["types"]) == (URL, ["run.refused"])
    value = webhook_value(URL, ["run.refused"])
    assert_owner_signature(body["owner_signature"], "account-7", WEBHOOK_SUBSCRIBED, value)
    with pytest.raises(InvalidSignature):
        assert_owner_signature(body["owner_signature"], "account-7", WEBHOOK_DELETED, value)
    assert answer["account_change"]["value"] == value and "s3cret" not in json.dumps(
        answer["account_change"]
    )


def test_create_webhook_with_the_account_given_sends_only_the_subscription():
    seen: list[httpx.Request] = []
    sync_client(webhook_server(seen)).create_webhook(URL, account_id="account-7")
    assert [(r.method, r.url.path) for r in seen] == [("POST", "/account/webhooks")]
    assert_owner_signature(
        sent_body(seen[0])["owner_signature"],
        "account-7",
        WEBHOOK_SUBSCRIBED,
        webhook_value(URL, []),
    )


def test_webhook_changes_need_a_signing_key_and_send_nothing_without_one():
    seen: list[httpx.Request] = []
    client = sync_client(webhook_server(seen), signing_key=None)
    with pytest.raises(ValidationError, match="signing_key"):
        client.create_webhook(URL)
    with pytest.raises(ValidationError, match="signing_key"):
        client.delete_webhook(3)
    assert seen == []


@pytest.mark.parametrize(
    "field, value",
    [
        ("action", "webhook.deleted"),
        ("value", "sha256=" + "0" * 64 + " kinds=all"),
        ("decided_by", "verdifax_admin"),
    ],
)
def test_a_record_that_does_not_carry_what_was_sent_is_refused(field, value):
    def tamper(rec: dict[str, Any]) -> None:
        rec[field] = value

    with pytest.raises(VerdifaxError):
        sync_client(webhook_server([], tamper)).create_webhook(URL, types=["run.refused"])


def test_delete_webhook_reads_the_subscription_and_signs_its_value():
    seen: list[httpx.Request] = []
    answer = sync_client(webhook_server(seen)).delete_webhook(3)
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("GET", "/account/webhooks"),
        ("DELETE", "/account/webhooks/3"),
    ]
    body = sent_body(seen[2])
    assert list(body) == ["owner_signature"]
    assert_owner_signature(
        body["owner_signature"], "account-7", WEBHOOK_DELETED, webhook_value(URL, ["run.refused"])
    )
    assert answer["deleted"] is True


def test_delete_webhook_of_no_such_subscription_sends_no_removal():
    seen: list[httpx.Request] = []
    with pytest.raises(VerdifaxError, match="no webhook 4"):
        sync_client(webhook_server(seen)).delete_webhook(4)
    assert all(r.method != "DELETE" for r in seen)


async def test_the_async_client_signs_the_same_way():
    seen: list[httpx.Request] = []
    async with async_client(webhook_server(seen)) as client:
        await client.create_webhook(URL, types=["run.refused"])
        await client.delete_webhook(3)
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("POST", "/account/webhooks"),
        ("GET", "/account"),
        ("GET", "/account/webhooks"),
        ("DELETE", "/account/webhooks/3"),
    ]
    value = webhook_value(URL, ["run.refused"])
    assert_owner_signature(
        sent_body(seen[1])["owner_signature"], "account-7", WEBHOOK_SUBSCRIBED, value
    )
    assert_owner_signature(
        sent_body(seen[4])["owner_signature"], "account-7", WEBHOOK_DELETED, value
    )
