"""The account owner publishes the account's records: publish_run and
unpublish_run post to the owner routes and hand back the server's answer
unchanged, the sealed publication included (R130)."""

from __future__ import annotations

import httpx
import pytest

from tests.test_parity import responder, sync_client
from verdifax import SIGNAL_KINDS, ValidationError, VerdifaxClient

PUBLICATION = {
    "format": "verdifax.run-publication.v2",
    "action": "run.published",
    "decided_by": "owner",
    "run_id": 41,
    "record_hash": "a" * 64,
    "job_id": "loan-1",
    "step_id": "verdict",
    "changed_at": "2026-11-08T20:00:00Z",
    "signal": {
        "signal_account": "account-7",
        "signal_sequence": 9,
        "signal_previous_hash": "b" * 64,
    },
    "publication_hash": "c" * 64,
    "later_field": 12345678901234567890,
}
ANSWER = {
    "ok": True,
    "run_id": 41,
    "public": True,
    "public_bundle_url": "https://api.verdifax.com/public/runs/tok/bundle.json",
    "verify_url": "https://verdifax.com/verify/?pt=tok",
    "publication": PUBLICATION,
}


def test_publish_and_unpublish_post_to_the_owner_routes_and_return_the_answer_as_sent():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=ANSWER))
    assert client.publish_run(41) == ANSWER
    assert client.unpublish_run(41) == ANSWER
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/account/runs/41/publish"),
        ("POST", "/account/runs/41/unpublish"),
    ]
    assert seen[0].content == b""
    assert client.publish_run(41)["publication"]["later_field"] == 12345678901234567890
    assert client.publish_run(41)["publication"]["decided_by"] == "owner"


def test_publish_refuses_a_bad_id_before_sending():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=ANSWER))
    for bad in (0, -1, 1.5, "41", None):
        with pytest.raises(ValidationError):
            client.publish_run(bad)  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            client.unpublish_run(bad)  # type: ignore[arg-type]
    assert seen == []


def test_the_publication_kinds_are_signal_kinds():
    assert "run.published" in SIGNAL_KINDS and "run.unpublished" in SIGNAL_KINDS
    assert isinstance(VerdifaxClient, type)


def test_publishing_a_stopped_run_returns_its_receipt_address():
    """A stopped run is published as its receipt: the answer names the
    receipt address and no bundle address (R156)."""
    stopped = {
        "ok": True,
        "run_id": 42,
        "public": True,
        "public_receipt_url": "https://api.verdifax.com/public/runs/tok/receipt.json",
        "verify_url": "https://verdifax.com/verify/?pt=tok&record=receipt",
        "publication": None,
    }
    client = sync_client(responder([], body=stopped))
    answer = client.publish_run(42)
    assert answer["public_receipt_url"] == stopped["public_receipt_url"]
    assert "public_bundle_url" not in answer
