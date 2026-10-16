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
from verdifax.research import verify_determinism

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


def test_verify_determinism_against_live_api():
    # Two plain /execute calls never share a manifest hash: each run seals
    # its own admission clock, nonce, and public-log entry. The
    # determinism endpoint pins those for both replays, so equality there
    # is the meaningful check.
    client = VerdifaxClient(base_url=INTEGRATION_BASE_URL)
    result = verify_determinism(
        client,
        payload="determinism check",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert result.deterministic is True


def test_verify_run_against_live_api():
    client = VerdifaxClient(base_url=INTEGRATION_BASE_URL)
    receipt = client.attest(
        payload="verify check",
        program_id=PROGRAM_ID,
        route_id=ROUTE_ID,
        registry_record_hash=REGISTRY_RECORD_HASH,
    )
    assert receipt.run_id is not None
    result = client.verify_run(receipt.run_id)
    assert result.verified is True
    assert result.manifest_hash == receipt.manifest_hash
