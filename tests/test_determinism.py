"""Determinism tests: identical inputs must produce identical request bodies.

These tests don't require a live API, the orchestrator's determinism is
the responsibility of the Go pipeline. What the SDK guarantees is that
**the request body** it sends is byte-for-byte identical given identical
inputs (so any non-determinism in resulting manifest hashes is upstream).
"""

from __future__ import annotations

import json

import httpx

from verdifax import VerdifaxClient
from tests.conftest import PROGRAM_ID, REGISTRY_RECORD_HASH, ROUTE_ID, make_execute_response


def _capture_two_requests(payload):
    captured: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(bytes(request.content))
        return httpx.Response(200, json=make_execute_response())

    transport = httpx.MockTransport(handler)
    client = VerdifaxClient(base_url="http://test.invalid", transport=transport)
    for _ in range(2):
        client.attest(
            payload=payload,
            program_id=PROGRAM_ID,
            route_id=ROUTE_ID,
            registry_record_hash=REGISTRY_RECORD_HASH,
        )
    return captured


def test_identical_string_payload_produces_identical_request_body():
    bodies = _capture_two_requests("hello deterministic")
    assert bodies[0] == bodies[1]


def test_identical_bytes_payload_produces_identical_request_body():
    bodies = _capture_two_requests(b"\x01\x02\x03")
    assert bodies[0] == bodies[1]


def test_request_body_has_stable_field_set():
    bodies = _capture_two_requests("hi")
    decoded = [json.loads(b) for b in bodies]
    assert decoded[0].keys() == decoded[1].keys()
    expected_keys = {"payload_text", "program_id", "route_id", "registry_record_hash"}
    assert set(decoded[0].keys()) == expected_keys


def test_different_payloads_produce_different_request_bodies():
    bodies_a = _capture_two_requests("alpha")
    bodies_b = _capture_two_requests("beta")
    assert bodies_a[0] != bodies_b[0]
