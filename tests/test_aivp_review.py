"""The AI review's trace reaches the caller on a released run, with the
sealed review in the manifest, and on a halted run, in the APIError, so the
caller can keep it for verdifax-verify --aivp-trace."""

from __future__ import annotations

import httpx
import pytest

from tests.conftest import make_execute_response
from tests.test_jobs import ARGS, HASH_A, scripted, sync_client
from verdifax import APIError

TRACE = "1. The vault is always locked.\n\n2. The vault is never locked."
REVIEW = {
    "formula": "aivp-review.v1",
    "prompt_id": "statements-v1",
    "model": "claude-opus-5-5",
    "trace_hash": "c" * 64,
    "checker_id": "keyword-v1",
    "contradiction_mode": "record",
    "contradiction_outcome": "recorded",
    "finding": {
        "node_a": "node-0001",
        "node_b": "node-0002",
        "term": "always",
        "opposite": "never",
    },
}


def test_a_released_run_returns_the_trace_and_the_sealed_review():
    body = make_execute_response(manifest_hash=HASH_A)
    body["manifest"] = {
        **body["manifest"],
        "AivpReviewForm": "aivp-review.v1",
        "AivpReview": REVIEW,
    }
    body["aivp_trace_text"] = TRACE
    receipt = sync_client(scripted([], [httpx.Response(200, json=body)]), signing_key=None).attest(
        **ARGS
    )
    assert receipt.aivp_trace_text == TRACE
    review = receipt.manifest.aivp_review
    assert review is not None and review.contradiction_outcome == "recorded"
    assert review.finding is not None and (review.finding.term, review.finding.opposite) == (
        "always",
        "never",
    )


def test_a_run_with_no_review_has_none():
    receipt = sync_client(
        scripted([], [httpx.Response(200, json=make_execute_response(manifest_hash=HASH_A))]),
        signing_key=None,
    ).attest(**ARGS)
    assert receipt.aivp_trace_text is None and receipt.manifest.aivp_review is None


def test_a_halted_runs_error_carries_the_trace():
    answer = httpx.Response(
        422,
        json={
            "ok": False,
            "error": "aivp refused",
            "record_hash": HASH_A,
            "aivp_trace_text": TRACE,
        },
    )
    with pytest.raises(APIError) as caught:
        sync_client(scripted([], [answer]), signing_key=None).attest(**ARGS)
    assert caught.value.aivp_trace_text == TRACE and caught.value.record_hash == HASH_A
