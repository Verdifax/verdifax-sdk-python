"""Optional customer request signing, shared by the sync and async clients.

A customer can register an Ed25519 public key on an API key. From then on
the orchestrator accepts a run only with a signature by the matching
private key. The private key stays with the customer: it is never sent to
the server, logged, or placed in an error message.

Ed25519 needs the ``cryptography`` package, which is optional
(``pip install "verdifax[signing]"``) and imported only when signing is
used, so ``import verdifax`` works without it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Mapping, Optional

from ._validation import job_block, validate_hex64
from .exceptions import ValidationError, VerdifaxError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REQUEST_KEY_PATH = "/keys/request-key"
# An account owner key registers its own request key here, with the same body.
ACCOUNT_REQUEST_KEY_PATH = "/account/request-key"
_REQUEST_SIGNATURE_FORM = "verdifax.request.v1"
_REQUEST_SIGNATURE_FORM_V2 = "verdifax.request.v2"
_REQUEST_SIGNATURE_VERSION = "2"
_JOB_FORM = "verdifax.job.v1"
_REQUEST_KEY_PROOF_FORM = "verdifax.request-key.v1"
_REQUEST_KEY_CHANGE_FORM = "verdifax.request-key-change.v1"
_POLICY_ACTIVATION_FORM = "verdifax.policy-activation.v1"
_SIGNING_KEY_BYTES = 32


def _ed25519_private_key_class() -> "type[Ed25519PrivateKey]":
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise VerdifaxError(
            'request signing needs the "cryptography" package: ' 'pip install "verdifax[signing]"'
        ) from exc
    return Ed25519PrivateKey


@dataclass(frozen=True)
class RequestKeyPair:
    """A key pair from :func:`generate_request_key`, as raw bytes.

    Attributes:
        public_key: The 32-byte Ed25519 public key.
        private_key: The 32-byte Ed25519 private key. Keep it secret. It is
            left out of this object's ``repr``.
    """

    public_key: bytes
    private_key: bytes = field(repr=False)


def generate_request_key() -> RequestKeyPair:
    """Create a new Ed25519 key pair on this machine.

    Nothing is sent to the server. Pass ``private_key`` as ``signing_key``
    to a client, and store it as a secret.

    Raises:
        VerdifaxError: If the ``cryptography`` package is not installed.
    """
    key = _ed25519_private_key_class().generate()
    return RequestKeyPair(
        public_key=key.public_key().public_bytes_raw(),
        private_key=key.private_bytes_raw(),
    )


def load_signing_key(signing_key: Any) -> "Ed25519PrivateKey":
    """Turn the raw private key into a key object, which does not print its bytes."""
    if not isinstance(signing_key, (bytes, bytearray)) or len(signing_key) != _SIGNING_KEY_BYTES:
        raise ValidationError("signing_key must be the 32 raw bytes of an Ed25519 private key")
    return _ed25519_private_key_class().from_private_bytes(bytes(signing_key))


def _utf8(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} cannot be signed: it is not text")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        # A str holding a surrogate has no UTF-8 form, so no bytes can be signed.
        raise ValidationError(f"{field_name} cannot be signed: it is not valid Unicode") from exc


def payload_hash(body: Mapping[str, Any]) -> str:
    """Hash what the server treats as the payload.

    That is ``payload_text`` when it is non-empty, otherwise the ``payload``
    string exactly as sent. The server does not base64-decode it.
    """
    payload = body.get("payload_text") or body.get("payload") or ""
    return hashlib.sha256(_utf8(payload, "payload")).hexdigest()


def request_signature_preimage(
    payload_digest: str,
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    signed_at: str,
    nonce: str,
) -> bytes:
    """The bytes a version 1 request signature signs, joined with zero bytes.

    Matches the orchestrator's ``RequestSignaturePreimage``. A client sends
    version 2: see :func:`request_signature_preimage_v2`.
    """
    fields = (
        _REQUEST_SIGNATURE_FORM,
        payload_digest,
        program_id,
        route_id,
        registry_record_hash,
        signed_at,
        nonce,
    )
    return "\x00".join(fields).encode("utf-8")


def request_signature_preimage_v2(
    body_digest: str,
    payload_digest: str,
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    ai_output_digest: str,
    job: Optional[Mapping[str, Any]],
    signed_at: str,
    nonce: str,
) -> bytes:
    """The bytes a version 2 request signature signs, joined with zero bytes.

    ``job`` is a job block in its sorted form, or ``None``. Matches the
    orchestrator's ``RequestSignaturePreimageV2``.
    """
    link = job or {}
    fields = (
        _REQUEST_SIGNATURE_FORM_V2,
        body_digest,
        payload_digest,
        program_id,
        route_id,
        registry_record_hash,
        ai_output_digest,
        _JOB_FORM,
        link.get("job_id", ""),
        link.get("step_id", ""),
        ",".join(link.get("previous_record_hashes", ())),
        ",".join(link.get("external_previous", ())),
        "true" if link.get("final") else "false",
        signed_at,
        nonce,
    )
    return "\x00".join(fields).encode("utf-8")


def request_key_change_preimage(new_public_key: str, signed_at: str, nonce: str) -> bytes:
    """The bytes the current key signs to replace or clear itself.

    ``new_public_key`` is the new key in base64, or empty when clearing.
    Matches the orchestrator's ``RequestKeyChangePreimage``.
    """
    fields = (_REQUEST_KEY_CHANGE_FORM, new_public_key, signed_at, nonce)
    return "\x00".join(fields).encode("utf-8")


def policy_activation_preimage(
    chain_id: str,
    document_hash: str,
    previous_activation_hash: str,
    signed_at: str,
    nonce: str,
) -> bytes:
    """The bytes a request key signs to approve a policy activation.

    ``chain_id`` comes from ``GET /policies``, as does
    ``previous_activation_hash``, the newest change in that chain (64 zeros
    before the first). An account's policy change uses the same bytes, with
    both values from ``GET /account/policies`` (a chain like ``account-7``).
    Matches the orchestrator's ``PolicyActivationPreimage``.

    Raises:
        ValidationError: If a value is not text or holds a zero byte, which
            would make the joined bytes ambiguous.
    """
    fields = (
        ("chain_id", chain_id),
        ("document_hash", document_hash),
        ("previous_activation_hash", previous_activation_hash),
        ("signed_at", signed_at),
        ("nonce", nonce),
    )
    for name, value in fields:
        _utf8(value, name)
        if "\x00" in value:
            raise ValidationError(f"{name} cannot be signed: it holds a zero byte")
    values = (_POLICY_ACTIVATION_FORM, *(value for _, value in fields))
    return "\x00".join(values).encode("utf-8")


def _signing_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signing_nonce() -> str:
    return secrets.token_hex(16)


def serialize_request(body: Mapping[str, Any]) -> str:
    """Serialize a request once, to the JSON text that is signed and sent."""
    try:
        text = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"request cannot be signed: {exc}") from exc
    _utf8(text, "request")
    return text


def sign_envelope(
    key: "Ed25519PrivateKey",
    body: Mapping[str, Any],
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, Any]:
    """Build the version 2 body for one request: the exact text and its signature."""
    signed_at = _signing_time() if signed_at is None else signed_at
    nonce = _signing_nonce() if nonce is None else nonce
    text = serialize_request(body)
    ai_output = body.get("ai_output_text")
    preimage = request_signature_preimage_v2(
        hashlib.sha256(_utf8(text, "request")).hexdigest(),
        payload_hash(body),
        _utf8(body.get("program_id") or "", "program_id").decode("utf-8"),
        _utf8(body.get("route_id") or "", "route_id").decode("utf-8"),
        _utf8(body.get("registry_record_hash") or "", "registry_record_hash").decode("utf-8"),
        hashlib.sha256(_utf8(ai_output, "ai_output_text")).hexdigest() if ai_output else "",
        body.get("job"),
        signed_at,
        nonce,
    )
    return {
        "signed_request": text,
        "request_signature": {
            "version": _REQUEST_SIGNATURE_VERSION,
            "signature": base64.b64encode(key.sign(preimage)).decode("ascii"),
            "signed_at": signed_at,
            "nonce": nonce,
        },
    }


def sign_request_v2(
    signing_key: bytes,
    body: Mapping[str, Any],
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, Any]:
    """Build the body to send for ``body`` without sending it.

    The result is ``{"signed_request": ..., "request_signature": ...}``. A
    client with a ``signing_key`` does this itself. A ``job`` in ``body`` is
    checked and put in its sorted form first. ``signed_at`` and ``nonce``
    default to the current time and fresh random bytes. A nonce the server
    has already seen is refused.
    """
    key = load_signing_key(signing_key)
    if body.get("job") is not None:
        body = {**body, "job": job_block(body["job"])}
    return sign_envelope(key, body, signed_at, nonce)


def sign_body(
    key: "Ed25519PrivateKey",
    body: dict[str, Any],
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """Build the version 1 ``request_signature`` block for one request body."""
    signed_at = _signing_time() if signed_at is None else signed_at
    nonce = _signing_nonce() if nonce is None else nonce
    _utf8(body["route_id"], "route_id")
    preimage = request_signature_preimage(
        payload_hash(body),
        body["program_id"],
        body["route_id"],
        body["registry_record_hash"],
        signed_at,
        nonce,
    )
    return {
        "signature": base64.b64encode(key.sign(preimage)).decode("ascii"),
        "signed_at": signed_at,
        "nonce": nonce,
    }


def sign_request(
    signing_key: bytes,
    body: dict[str, Any],
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """Build a version 1 ``request_signature`` block for ``body``.

    A client sends version 2 (see :func:`sign_request_v2`), and the server
    refuses version 1 for a job step. ``signed_at`` and ``nonce`` default to
    the current time and fresh random bytes. A nonce the server has already
    seen is refused.
    """
    return sign_body(load_signing_key(signing_key), body, signed_at, nonce)


def request_key_registration_body(signing_key: bytes) -> dict[str, str]:
    """Build the body of ``POST /keys/request-key`` without sending it."""
    return request_key_body(load_signing_key(signing_key))


def attach_signature(key: "Optional[Ed25519PrivateKey]", body: dict[str, Any]) -> dict[str, Any]:
    """Return the version 2 signed form of ``body``; with no key, ``body`` itself."""
    if key is None:
        return body
    return sign_envelope(key, body)


def request_key_body(
    key: "Optional[Ed25519PrivateKey]", method: str = "register_request_key"
) -> dict[str, str]:
    """The body of ``POST /keys/request-key``: the public key and its proof.

    ``POST /account/request-key`` takes the same body. ``method`` names the
    caller in the error.
    """
    if key is None:
        raise ValidationError(f"{method} needs a client with a signing_key")
    public_key = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    proof = key.sign(f"{_REQUEST_KEY_PROOF_FORM}\x00{public_key}".encode("utf-8"))
    return {"public_key": public_key, "proof": base64.b64encode(proof).decode("ascii")}


def request_key_change(
    key: "Ed25519PrivateKey",
    new_public_key: str = "",
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """The ``change`` block: the current key approves a replacement or a clear."""
    signed_at = _signing_time() if signed_at is None else signed_at
    nonce = _signing_nonce() if nonce is None else nonce
    preimage = request_key_change_preimage(new_public_key, signed_at, nonce)
    return {
        "signature": base64.b64encode(key.sign(preimage)).decode("ascii"),
        "signed_at": signed_at,
        "nonce": nonce,
    }


def policy_activation_signature(
    key: "Ed25519PrivateKey",
    chain_id: str,
    document_hash: str,
    previous_activation_hash: str,
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """The ``signature`` block of an activation, signed by ``key``."""
    validate_hex64(document_hash, "document_hash")
    validate_hex64(previous_activation_hash, "previous_activation_hash")
    signed_at = _signing_time() if signed_at is None else signed_at
    nonce = _signing_nonce() if nonce is None else nonce
    preimage = policy_activation_preimage(
        chain_id, document_hash, previous_activation_hash, signed_at, nonce
    )
    return {
        "signature": base64.b64encode(key.sign(preimage)).decode("ascii"),
        "signed_at": signed_at,
        "nonce": nonce,
    }


def policy_activation_approval(
    signing_key: bytes,
    chain_id: str,
    document_hash: str,
    previous_activation_hash: str,
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """Build the ``signature`` block of ``POST /policies/{document_hash}/activate``.

    The request key approves making ``document_hash`` the policy in force,
    after ``previous_activation_hash`` in the chain ``chain_id``. Both come
    from ``GET /policies``, or from ``GET /account/policies`` for the block
    of ``POST /account/policies/{document_hash}/activate``. A client with a
    ``signing_key`` does this itself in ``activate_policy`` and
    ``activate_account_policy``. ``signed_at`` and ``nonce`` default to the current
    time and fresh random bytes. A nonce the server has already seen is
    refused.

    Raises:
        ValidationError: If the key is not 32 raw bytes, or a hash is not 64
            lowercase hex characters.
    """
    return policy_activation_signature(
        load_signing_key(signing_key),
        chain_id,
        document_hash,
        previous_activation_hash,
        signed_at,
        nonce,
    )


def request_key_rotation_body(
    current: "Optional[Ed25519PrivateKey]", new: "Ed25519PrivateKey"
) -> dict[str, Any]:
    """The body of ``POST /keys/request-key`` that replaces a registered key.

    ``proof`` is by the new key and ``change`` by the current one.
    """
    if current is None:
        raise ValidationError("rotate_request_key needs a client with a signing_key")
    body: dict[str, Any] = dict(request_key_body(new))
    body["change"] = request_key_change(current, body["public_key"])
    return body


def request_key_clear_body(key: "Optional[Ed25519PrivateKey]") -> Optional[dict[str, Any]]:
    """The body of ``DELETE /keys/request-key``, or ``None`` with no signing key."""
    if key is None:
        return None
    return {"change": request_key_change(key)}


__all__ = [
    "ACCOUNT_REQUEST_KEY_PATH",
    "REQUEST_KEY_PATH",
    "RequestKeyPair",
    "attach_signature",
    "generate_request_key",
    "load_signing_key",
    "payload_hash",
    "policy_activation_approval",
    "policy_activation_preimage",
    "policy_activation_signature",
    "request_key_body",
    "request_key_change",
    "request_key_change_preimage",
    "request_key_clear_body",
    "request_key_registration_body",
    "request_key_rotation_body",
    "request_signature_preimage",
    "request_signature_preimage_v2",
    "serialize_request",
    "sign_body",
    "sign_envelope",
    "sign_request",
    "sign_request_v2",
]
