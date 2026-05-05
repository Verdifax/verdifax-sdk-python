"""Integration test against a live local API server.

Skipped by default. To run:

    cd verdifax-orchestrator && make api &
    cd ../verdifax-sdk-python && VERDIFAX_INTEGRATION=1 pytest tests/test_integration.py

The fixture skips automatically if the API is not reachable so this file
remains safe in CI without the orchestrator running.
"""

from __future__ import annotations

import os

import httpx
import pytest

from verdifax import VerdifaxClient

INTEGRATION_BASE_URL = os.environ.get("VERDIFAX_INTEGRATION_URL", "http://localhost:9090")
INTEGRATION_ENABLED = os.environ.get("VERDIFAX_INTEGRATION") == "1"

PROGRAM_ID = "a" * 64
ROUTE_ID = "route-integration-test"
REGISTRY_RECORD_HASH = "b" * 64


def _api_reachable() -> bool:
    try:
        resp = httpx.get(f"{INTEGRATION_BASE_URL}/health", timeout=2.0)
    except httpx.HTTPError:
        return False
    return resp.status_code == 200


pytestmark = pytest.mark.skipif(
    not INTEGRATION_ENABLED or not _api_reachable(),
    reason="VERDIFAX_INTEGRATION!=1 or API not reachable at " + INTEGRATION_BASE_URL,
)


def test_health_against_live_api():
    client = VerdifaxClient(base_url=INTEGRATION_BASE_URL)
    assert client.health()["ok"] is True


def test_attest_against_live_api_returns_64_char_manifest_hash():
    client = VerdifaxClient(base_url=INTEGRATION_BASE_URL)
    receipt = client.attest(
        payload="integration test payload",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert len(receipt.manifest_hash) == 64
    assert receipt.manifest.formal_verifier_status == "VERIFIED_SOUND_COMPLETE_ZK"
    assert receipt.manifest.independent_verified is True


def test_two_runs_with_identical_inputs_produce_identical_manifest_hashes():
    client = VerdifaxClient(base_url=INTEGRATION_BASE_URL)
    inputs = dict(
        payload="determinism check",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    receipt_a = client.attest(**inputs)
    receipt_b = client.attest(**inputs)
    assert receipt_a.manifest_hash == receipt_b.manifest_hash


def test_verify_against_live_api():
    client = VerdifaxClient(base_url=INTEGRATION_BASE_URL)
    inputs = dict(
        payload="verify check",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    receipt = client.attest(**inputs)
    assert client.verify(manifest_hash=receipt.manifest_hash, **inputs) is True
