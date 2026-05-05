"""Shared pytest fixtures and helpers.

The fixtures here build canonical valid inputs (a 64-char program_id,
a route_id, a registry record hash) and a representative API response
body so tests do not need to rebuild them inline.
"""

from __future__ import annotations

from typing import Any

import pytest


PROGRAM_ID = "a" * 64
ROUTE_ID = "route-test"
REGISTRY_RECORD_HASH = "b" * 64
MANIFEST_HASH = "9" * 64


def _hash_field(seed: str) -> str:
    """Build a deterministic 64-char hex string for fixtures."""
    return (seed * 64)[:64]


def make_manifest_dict(manifest_hash: str = MANIFEST_HASH) -> dict[str, Any]:
    """A manifest body shaped exactly the way the Go API serializes it."""
    return {
        "EnvelopeID": "env-0001",
        "EnvelopeHash": _hash_field("1"),
        "SequenceID": "seq-0001",
        "TransportHash": _hash_field("2"),
        "EpaHash": _hash_field("3"),
        "EfaHash": _hash_field("4"),
        "ExecutionIDs": [
            "dse-id",
            "tok-id",
            "dsc-id",
            "nrep-id",
            "aivp-id",
            "dcae-id",
        ],
        "AerHash": _hash_field("5"),
        "TranscriptHash": _hash_field("6"),
        "HardwareAttestationHash": _hash_field("7"),
        "LeakageBundleHash": _hash_field("8"),
        "FormalVerifierStatus": "VERIFIED_SOUND_COMPLETE_ZK",
        "ZkspBindingHash": _hash_field("a"),
        "MigrationTokenHash": _hash_field("b"),
        "ReplayFingerprint": _hash_field("c"),
        "PoteProofHash": _hash_field("d"),
        "LogEntryID": "log-0001",
        "RegistryArtifactCount": 18,
        "FinalVfaHash": _hash_field("e"),
        "IndependentVerified": True,
        "ManifestHash": manifest_hash,
    }


def make_execute_response(manifest_hash: str = MANIFEST_HASH) -> dict[str, Any]:
    """A full POST /execute success response body."""
    return {
        "ok": True,
        "duration_ms": 42,
        "manifest": make_manifest_dict(manifest_hash=manifest_hash),
    }


@pytest.fixture
def manifest_dict() -> dict[str, Any]:
    return make_manifest_dict()


@pytest.fixture
def execute_response() -> dict[str, Any]:
    return make_execute_response()


@pytest.fixture
def valid_inputs() -> dict[str, str]:
    return {
        "program_id": PROGRAM_ID,
        "route_id": ROUTE_ID,
        "registry_record_hash": REGISTRY_RECORD_HASH,
    }
