"""§0 cross-language canonical hash verifier, Python implementation.

This module exposes the three canonical preimage formulas used by the
Verdifax orchestrator's §0 attestation contract: DSE (Deterministic
State Engine dispatch), DCAE (Deterministic Closure-and-Audit Engine),
and CRES (Cryptographic Record Erasure System receipts).

The Go orchestrator at ``api.verdifax.com`` is the authoritative source
for these formulas, every formula here mirrors the corresponding Go
implementation byte-for-byte. The shared test vectors at
``BUILDING DOCS/SECTION-0-SPECS/test-vectors/`` are the contract: any
language implementation that claims §0 compliance MUST produce the
same hash from the same input.

Why this exists in the Python SDK:

* Cross-language verifiability is core to the Verdifax trust story , 
  buyers should be able to recompute manifest-bound hashes in their own
  language without trusting the orchestrator binary.
* The Go-side test vectors and drift-protection tests already lock the
  Go formulas. Adding a Python implementation that also passes the same
  vectors converts the claim "verifiable across languages" from
  documentation into evidence.
* Deployers integrating Verdifax via the Python SDK can sanity-check
  artifact bundles before they leave their environment, without
  shelling out to the Go verifier binary.

Usage:

    >>> from verdifax import section0
    >>> section0.dse_dispatch_hash(
    ...     envelope_id="env-fixture-v1-aaaaaaaaaaaaaaaa",
    ...     sequence_id="seq-fixture-v1-1",
    ...     program_id="11111111111111111111111111111111"
    ...                "11111111111111111111111111111111",
    ...     registry_record_hash="22222222222222222222222222222222"
    ...                          "22222222222222222222222222222222",
    ... )
    'e66378381a9dea8ee0475ddc5b55a81f256aac523dd523c02c08e25ab34bae6b'

DRIFT-PROTECTION CONTRACT
=========================

The expected hash literals below mirror the Go-side authoritative
values. The Go test ``TestSection0Vectors_*`` in
``internal/section0audit/vectors_test.go`` is the source of truth.
If you change a formula here, you MUST also change it on the Go side
AND regenerate every cross-language test vector AND bump the
corresponding ``PreimageVersion`` constant. Drift between the two
implementations breaks the cross-language verifiability claim.
"""

from __future__ import annotations

import hashlib
from typing import Final

# ── §0 invariants ───────────────────────────────────────────────────────
#
# Every kernel's canonical preimage is UTF-8 bytes with no BOM, no
# trailing newline, no whitespace except as part of declared field
# values. Hashes are SHA-256 rendered as 64 lowercase hex characters.

_HASH_HEX_LEN: Final[int] = 64


def _sha256_hex(b: bytes) -> str:
    """Return SHA-256 of ``b`` as a 64-character lowercase hex string.

    Centralized so future migrations (FIPS-validated hash modules,
    different encoding) only need to update one site.
    """
    return hashlib.sha256(b).hexdigest()


def _validate_hex64(value: str, name: str) -> None:
    """Raise ValueError if ``value`` isn't a 64-character lowercase hex string.

    §0 enforces 64-hex for every artifact_hash field. This is the
    Python-side equivalent of the orchestrator's ``is64HexLower`` check;
    catches misuse of the helpers (passing a UUID, a base64 blob, etc.)
    at the call site instead of producing a wrong canonical hash.
    """
    if not isinstance(value, str) or len(value) != _HASH_HEX_LEN:
        raise ValueError(
            f"section0: {name} must be a 64-character lowercase hex string; "
            f"got len={len(value) if isinstance(value, str) else 'non-str'}"
        )
    for ch in value:
        if ch not in "0123456789abcdef":
            raise ValueError(f"section0: {name} must be lowercase hex (0-9a-f); " f"found {ch!r}")


# ── DSE, Deterministic State Engine dispatch hash ──────────────────────

DSE_FORMULA_VERSION: Final[str] = "dse.tcu.dispatch.v1"
"""Verbatim mirror of ``internal/dse/dse.go`` ``FormulaVersion``."""


def dse_dispatch_hash(
    *,
    envelope_id: str,
    sequence_id: str,
    program_id: str,
    registry_record_hash: str,
) -> str:
    """Compute the canonical DSE dispatch hash.

    Mirrors the formula in ``internal/dse/dse.go``:

        FormulaVersion + "." + envelope_id + "." +
        sequence_id   + "." + program_id  + "." + registry_record_hash

    Note the separator is ``.`` (period), not ``|`` (pipe), the DSE
    kernel uses period-delimited canonical bytes by historical
    convention; later kernels (DCAE, CRES) standardized on ``|``.

    Args:
        envelope_id: Stable identifier of the EnvelopeV2 being
            dispatched. Free-form string but typically ``env-<hash>``.
        sequence_id: Per-envelope sequence identifier.
        program_id: 64-character lowercase hex SHA-256 of the program
            bytes the dispatch resolves to.
        registry_record_hash: 64-character lowercase hex SHA-256 of the
            program-registry record sealing the program's identity.

    Returns:
        64-character lowercase hex SHA-256 of the canonical preimage.

    Raises:
        ValueError: if ``program_id`` or ``registry_record_hash`` is
            not a 64-char lowercase hex string.
    """
    _validate_hex64(program_id, "program_id")
    _validate_hex64(registry_record_hash, "registry_record_hash")
    preimage = (
        f"{DSE_FORMULA_VERSION}.{envelope_id}.{sequence_id}." f"{program_id}.{registry_record_hash}"
    )
    return _sha256_hex(preimage.encode("utf-8"))


# ── DCAE, Deterministic Closure-and-Audit Engine ──────────────────────

DCAE_PREIMAGE_VERSION: Final[str] = "verdifax.dcae.v1"
"""Verbatim mirror of ``internal/dcae/dcae.go`` ``PreimageVersion``."""


def dcae_closure_hash(
    *,
    manifest_hash: str,
    aer_hash: str,
    envelope_id: str,
    zksp_binding_hash: str,
    formal_verifier_status: str,
) -> str:
    """Compute the canonical DCAE closure hash.

    Mirrors the formula in ``internal/dcae/dcae.go``:

        PreimageVersion || "|" || manifest_hash || "|" || aer_hash ||
        "|" || envelope_id || "|" || zksp_binding_hash || "|" ||
        formal_verifier_status

    Args:
        manifest_hash: 64-char lowercase hex sealing the run's manifest.
        aer_hash: 64-char lowercase hex of the Attestation Execution
            Record.
        envelope_id: Stable identifier of the EnvelopeV2 the closure
            describes.
        zksp_binding_hash: 64-char lowercase hex of the ZKSP layer's
            binding artifact.
        formal_verifier_status: Verifier status string (e.g.
            ``"VERIFIED_SOUND_COMPLETE_ZK"``).

    Returns:
        64-character lowercase hex SHA-256 of the canonical preimage.

    Raises:
        ValueError: if any required hex field isn't 64-char lowercase hex.
    """
    _validate_hex64(manifest_hash, "manifest_hash")
    _validate_hex64(aer_hash, "aer_hash")
    _validate_hex64(zksp_binding_hash, "zksp_binding_hash")
    parts = [
        DCAE_PREIMAGE_VERSION,
        manifest_hash,
        aer_hash,
        envelope_id,
        zksp_binding_hash,
        formal_verifier_status,
    ]
    preimage = "|".join(parts)
    return _sha256_hex(preimage.encode("utf-8"))


# ── CRES, Cryptographic Record Erasure System receipt ─────────────────

CRES_PREIMAGE_VERSION: Final[str] = "verdifax.cres.v1"
"""Verbatim mirror of ``internal/cres/cres.go`` ``PreimageVersion``."""

CRES_ENGINE_VERSION: Final[str] = "verdifax-cres/1.0.0"
"""Verbatim mirror of ``internal/cres/cres.go`` ``EngineVersion``."""


def cres_receipt_hash(
    *,
    envelope_id: str,
    field_path: str,
    deletion_clock: str,
    actor_id: str,
    ciphertext_hash_at_shred: str,
    dsar_reference: str,
    engine_version: str = CRES_ENGINE_VERSION,
) -> str:
    """Compute the canonical CRES DeletionReceipt hash.

    Mirrors ``ComputeReceiptHash`` in ``internal/cres/cres.go``:

        PreimageVersion || "|" || envelope_id || "|" || field_path ||
        "|" || deletion_clock || "|" || actor_id || "|" ||
        ciphertext_hash_at_shred || "|" || dsar_reference || "|" ||
        engine_version

    The receipt is sealed at deletion time and bound to the original
    run via ``envelope_id``. After the DEK is shredded, the receipt's
    hash is the only cryptographic anchor proving the deletion
    happened, recomputing it from the receipt fields gives an auditor
    independent verification of the chain of custody.

    Args:
        envelope_id: EnvelopeV2 identifier the deletion was applied to.
        field_path: Dotted path of the field that was erased (e.g.
            ``"request.payload.customer_email"``).
        deletion_clock: RFC 3339 UTC timestamp at deletion time.
        actor_id: Identity of the principal who issued the deletion.
        ciphertext_hash_at_shred: 64-char lowercase hex of the
            ciphertext at the moment of key destruction.
        dsar_reference: Free-form DSAR / customer-request identifier
            tying the deletion to its originating compliance event.
        engine_version: Engine version string. Defaults to
            ``CRES_ENGINE_VERSION``; pass an explicit value only when
            recomputing legacy receipts produced by a prior engine.

    Returns:
        64-character lowercase hex SHA-256 of the canonical preimage.

    Raises:
        ValueError: if ``ciphertext_hash_at_shred`` isn't 64-char
            lowercase hex.
    """
    _validate_hex64(ciphertext_hash_at_shred, "ciphertext_hash_at_shred")
    parts = [
        CRES_PREIMAGE_VERSION,
        envelope_id,
        field_path,
        deletion_clock,
        actor_id,
        ciphertext_hash_at_shred,
        dsar_reference,
        engine_version,
    ]
    preimage = "|".join(parts)
    return _sha256_hex(preimage.encode("utf-8"))


__all__ = [
    "DSE_FORMULA_VERSION",
    "DCAE_PREIMAGE_VERSION",
    "CRES_PREIMAGE_VERSION",
    "CRES_ENGINE_VERSION",
    "dse_dispatch_hash",
    "dcae_closure_hash",
    "cres_receipt_hash",
]
