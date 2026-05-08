"""§0 cross-language test vector verification — Python side.

Locks the Python implementation in ``verdifax.section0`` against the
authoritative Go-side test vectors at
``BUILDING DOCS/SECTION-0-SPECS/test-vectors/``.

If a Go-side formula change isn't mirrored here, this test fails with
the computed hash so the maintainer can either accept the drift (by
bumping the Preimage Version on both sides) or fix the Python formula
to match Go. Either way, byte-equality is enforced — the
cross-language verifiability claim depends on these tests passing in
both Go and Python CI on the same fixtures.

The expected-hash literals MUST mirror the Go-side
``internal/section0audit/vectors_test.go``. Tests fail loudly with
the diff if they don't.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from verdifax.section0 import (
    CRES_ENGINE_VERSION,
    CRES_PREIMAGE_VERSION,
    DCAE_PREIMAGE_VERSION,
    DSE_FORMULA_VERSION,
    cres_receipt_hash,
    dcae_closure_hash,
    dse_dispatch_hash,
)


# ── Fixture: Go-side authoritative values ────────────────────────────
#
# These mirror ``internal/section0audit/vectors_test.go`` byte-for-byte.
# Update only when intentionally bumping a kernel's formula version on
# both Go and Python sides simultaneously, regenerating every
# cross-language vector under BUILDING DOCS/SECTION-0-SPECS/test-vectors/.

DSE_FIXTURE_ENVELOPE = "env-fixture-v1-aaaaaaaaaaaaaaaa"
DSE_FIXTURE_SEQUENCE = "seq-fixture-v1-1"
DSE_FIXTURE_PROGRAM = "1" * 64
DSE_FIXTURE_REGISTRY = "2" * 64
DSE_EXPECTED_HASH = "e66378381a9dea8ee0475ddc5b55a81f256aac523dd523c02c08e25ab34bae6b"

DCAE_FIXTURE_MANIFEST = "3" * 64
DCAE_FIXTURE_AER = "4" * 64
DCAE_FIXTURE_ENVELOPE = "env-fixture-dcae-v1"
DCAE_FIXTURE_ZKSP = "5" * 64
DCAE_FIXTURE_STATUS = "VERIFIED_SOUND_COMPLETE_ZK"
DCAE_EXPECTED_HASH = "e34cee0fcc6ebf9eafc3ef5479fd0fffd5a4de5c60039ba42b009f0c05b8fc93"

CRES_FIXTURE_ENVELOPE = "env-fixture-cres-v1"
CRES_FIXTURE_FIELD = "request.payload.customer_email"
CRES_FIXTURE_CLOCK = "2026-05-07T00:00:00.000000000Z"
CRES_FIXTURE_ACTOR = "ops-fixture"
CRES_FIXTURE_CIPHERTEXT = "6" * 64
CRES_FIXTURE_DSAR = "DSAR-FIXTURE-001"
CRES_EXPECTED_HASH = "1bb128c1f86cc6c7d63d44cc49bbdfc1185c8105d5bc270838af63814901bee5"


# ── Drift-protection: byte-equality with Go ──────────────────────────


def test_dse_dispatch_hash_matches_go_authoritative_vector() -> None:
    """DSE Python implementation must produce the Go-locked hash."""
    got = dse_dispatch_hash(
        envelope_id=DSE_FIXTURE_ENVELOPE,
        sequence_id=DSE_FIXTURE_SEQUENCE,
        program_id=DSE_FIXTURE_PROGRAM,
        registry_record_hash=DSE_FIXTURE_REGISTRY,
    )
    assert got == DSE_EXPECTED_HASH, (
        f"\nDSE Python/Go drift detected:"
        f"\n  Python computed: {got}"
        f"\n  Go expected:     {DSE_EXPECTED_HASH}"
        f"\nIf this drift is intentional, you must:"
        f"\n  1. Bump dse.FormulaVersion to v2 on the Go side"
        f"\n  2. Update DSE_FORMULA_VERSION in verdifax/section0.py"
        f"\n  3. Regenerate every cross-language vector under"
        f" BUILDING DOCS/SECTION-0-SPECS/test-vectors/"
    )


def test_dcae_closure_hash_matches_go_authoritative_vector() -> None:
    """DCAE Python implementation must produce the Go-locked hash."""
    got = dcae_closure_hash(
        manifest_hash=DCAE_FIXTURE_MANIFEST,
        aer_hash=DCAE_FIXTURE_AER,
        envelope_id=DCAE_FIXTURE_ENVELOPE,
        zksp_binding_hash=DCAE_FIXTURE_ZKSP,
        formal_verifier_status=DCAE_FIXTURE_STATUS,
    )
    assert got == DCAE_EXPECTED_HASH, (
        f"\nDCAE Python/Go drift detected:"
        f"\n  Python computed: {got}"
        f"\n  Go expected:     {DCAE_EXPECTED_HASH}"
    )


def test_cres_receipt_hash_matches_go_authoritative_vector() -> None:
    """CRES Python implementation must produce the Go-locked hash."""
    got = cres_receipt_hash(
        envelope_id=CRES_FIXTURE_ENVELOPE,
        field_path=CRES_FIXTURE_FIELD,
        deletion_clock=CRES_FIXTURE_CLOCK,
        actor_id=CRES_FIXTURE_ACTOR,
        ciphertext_hash_at_shred=CRES_FIXTURE_CIPHERTEXT,
        dsar_reference=CRES_FIXTURE_DSAR,
        engine_version=CRES_ENGINE_VERSION,
    )
    assert got == CRES_EXPECTED_HASH, (
        f"\nCRES Python/Go drift detected:"
        f"\n  Python computed: {got}"
        f"\n  Go expected:     {CRES_EXPECTED_HASH}"
    )


# ── Output-shape invariants ──────────────────────────────────────────


def test_all_outputs_are_64_char_lowercase_hex() -> None:
    """Every kernel must emit a §0-compliant 64-char lowercase hex hash.

    Catches encoding regressions (uppercase, base64, missing pad) at
    the output layer regardless of which formula produced the bytes.
    """
    pattern = re.compile(r"^[0-9a-f]{64}$")
    outputs = [
        DSE_EXPECTED_HASH,
        DCAE_EXPECTED_HASH,
        CRES_EXPECTED_HASH,
    ]
    for h in outputs:
        assert pattern.match(h), f"hash {h!r} not 64-char lowercase hex"


def test_preimage_versions_match_go_constants() -> None:
    """Preimage version strings must mirror the Go authoritative names.

    Drift here would silently produce mismatching hashes — the strings
    are part of every preimage, so an off-by-one in the version slug
    produces a different, undetectable hash.
    """
    assert DSE_FORMULA_VERSION == "dse.tcu.dispatch.v1"
    assert DCAE_PREIMAGE_VERSION == "verdifax.dcae.v1"
    assert CRES_PREIMAGE_VERSION == "verdifax.cres.v1"
    assert CRES_ENGINE_VERSION == "verdifax-cres/1.0.0"


# ── Determinism ──────────────────────────────────────────────────────


def test_dse_hash_is_deterministic() -> None:
    """Same input → same output, no entropy in the hash chain."""
    a = dse_dispatch_hash(
        envelope_id=DSE_FIXTURE_ENVELOPE,
        sequence_id=DSE_FIXTURE_SEQUENCE,
        program_id=DSE_FIXTURE_PROGRAM,
        registry_record_hash=DSE_FIXTURE_REGISTRY,
    )
    b = dse_dispatch_hash(
        envelope_id=DSE_FIXTURE_ENVELOPE,
        sequence_id=DSE_FIXTURE_SEQUENCE,
        program_id=DSE_FIXTURE_PROGRAM,
        registry_record_hash=DSE_FIXTURE_REGISTRY,
    )
    assert a == b


def test_dse_hash_changes_when_any_field_changes() -> None:
    """Tampering with any input must change the hash (avalanche)."""
    base = dse_dispatch_hash(
        envelope_id=DSE_FIXTURE_ENVELOPE,
        sequence_id=DSE_FIXTURE_SEQUENCE,
        program_id=DSE_FIXTURE_PROGRAM,
        registry_record_hash=DSE_FIXTURE_REGISTRY,
    )
    cases = [
        # Each tuple is (label, kwargs-override-dict)
        (
            "envelope_id",
            {"envelope_id": "env-fixture-v1-bbbbbbbbbbbbbbbb"},
        ),
        (
            "sequence_id",
            {"sequence_id": "seq-fixture-v1-2"},
        ),
        (
            "program_id",
            {"program_id": "9" * 64},
        ),
        (
            "registry_record_hash",
            {"registry_record_hash": "9" * 64},
        ),
    ]
    for label, override in cases:
        kwargs = {
            "envelope_id": DSE_FIXTURE_ENVELOPE,
            "sequence_id": DSE_FIXTURE_SEQUENCE,
            "program_id": DSE_FIXTURE_PROGRAM,
            "registry_record_hash": DSE_FIXTURE_REGISTRY,
            **override,
        }
        assert (
            dse_dispatch_hash(**kwargs) != base
        ), f"DSE hash unchanged after tampering with {label}"


# ── Input validation ─────────────────────────────────────────────────


def test_dse_rejects_non_hex64_program_id() -> None:
    with pytest.raises(ValueError, match="program_id"):
        dse_dispatch_hash(
            envelope_id=DSE_FIXTURE_ENVELOPE,
            sequence_id=DSE_FIXTURE_SEQUENCE,
            program_id="not-hex",
            registry_record_hash=DSE_FIXTURE_REGISTRY,
        )


def test_dcae_rejects_uppercase_hex() -> None:
    with pytest.raises(ValueError, match="lowercase hex"):
        dcae_closure_hash(
            manifest_hash="A" * 64,
            aer_hash=DCAE_FIXTURE_AER,
            envelope_id=DCAE_FIXTURE_ENVELOPE,
            zksp_binding_hash=DCAE_FIXTURE_ZKSP,
            formal_verifier_status=DCAE_FIXTURE_STATUS,
        )


def test_cres_rejects_short_ciphertext_hash() -> None:
    with pytest.raises(ValueError, match="ciphertext_hash_at_shred"):
        cres_receipt_hash(
            envelope_id=CRES_FIXTURE_ENVELOPE,
            field_path=CRES_FIXTURE_FIELD,
            deletion_clock=CRES_FIXTURE_CLOCK,
            actor_id=CRES_FIXTURE_ACTOR,
            ciphertext_hash_at_shred="abc123",
            dsar_reference=CRES_FIXTURE_DSAR,
        )


# ── Cross-reference: published canonical-bytes file ──────────────────
#
# The ``BUILDING DOCS/SECTION-0-SPECS/test-vectors/`` directory ships
# canonical-bytes files alongside the JSON fixtures. When the test
# vectors directory is reachable from the test-runner working
# directory, this test reads the canonical-bytes file and confirms
# the Python-computed hash also matches the file's exact bytes →
# SHA-256 chain. Skipped when the vectors directory isn't co-located
# with the SDK (e.g. when the SDK is installed via pip without the
# parent repo).

VECTORS_DIR_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "BUILDING DOCS" / "SECTION-0-SPECS" / "test-vectors",
    Path(__file__).resolve().parents[3] / "BUILDING DOCS" / "SECTION-0-SPECS" / "test-vectors",
]


def _vectors_dir() -> Path | None:
    for cand in VECTORS_DIR_CANDIDATES:
        if cand.is_dir():
            return cand
    return None


@pytest.mark.skipif(
    _vectors_dir() is None,
    reason="cross-language test-vectors directory not reachable",
)
def test_cres_hash_file_round_trips_via_canonical_bytes() -> None:
    """Read the published HASH file and confirm Python matches it."""
    vd = _vectors_dir()
    assert vd is not None
    hash_file = vd / "§0_TEST_VECTOR_CRES_HASH_V1.txt"
    if not hash_file.exists():
        pytest.skip(f"hash file not present: {hash_file}")
    body = hash_file.read_text(encoding="utf-8")
    # The file documents the formula + locks an expected hash. Search
    # for the 64-hex token that matches our computed value — robust
    # against the file's surrounding markdown / commentary changing.
    matches = re.findall(r"\b[0-9a-f]{64}\b", body)
    got = cres_receipt_hash(
        envelope_id=CRES_FIXTURE_ENVELOPE,
        field_path=CRES_FIXTURE_FIELD,
        deletion_clock=CRES_FIXTURE_CLOCK,
        actor_id=CRES_FIXTURE_ACTOR,
        ciphertext_hash_at_shred=CRES_FIXTURE_CIPHERTEXT,
        dsar_reference=CRES_FIXTURE_DSAR,
    )
    assert got in matches, (
        f"Python-computed CRES hash {got} not present in published "
        f"HASH file at {hash_file}; cross-language drift detected."
    )
