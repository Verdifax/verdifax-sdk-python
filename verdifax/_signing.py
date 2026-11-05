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
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from .exceptions import ValidationError, VerdifaxError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REQUEST_KEY_PATH = "/keys/request-key"
_REQUEST_SIGNATURE_FORM = "verdifax.request.v1"
_REQUEST_KEY_PROOF_FORM = "verdifax.request-key.v1"
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


def _utf8(value: str, field_name: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        # A str holding a surrogate has no UTF-8 form, so no bytes can be signed.
        raise ValidationError(f"{field_name} cannot be signed: it is not valid Unicode") from exc


def payload_hash(body: dict[str, Any]) -> str:
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
    """The bytes a request signature signs, joined with single zero bytes.

    Matches the orchestrator's ``RequestSignaturePreimage``.
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


def sign_body(
    key: "Ed25519PrivateKey",
    body: dict[str, Any],
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """Build the ``request_signature`` block for one request body."""
    if signed_at is None:
        signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if nonce is None:
        nonce = secrets.token_hex(16)
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
    """Build the ``request_signature`` block for ``body`` without sending it.

    A client with a ``signing_key`` does this itself. ``signed_at`` and
    ``nonce`` default to the current time and fresh random bytes. A nonce
    the server has already seen is refused.
    """
    return sign_body(load_signing_key(signing_key), body, signed_at, nonce)


def request_key_registration_body(signing_key: bytes) -> dict[str, str]:
    """Build the body of ``POST /keys/request-key`` without sending it."""
    return request_key_body(load_signing_key(signing_key))


def attach_signature(key: "Optional[Ed25519PrivateKey]", body: dict[str, Any]) -> dict[str, Any]:
    """Return ``body`` with a fresh signature; with no key, return it unchanged."""
    if key is None:
        return body
    return {**body, "request_signature": sign_body(key, body)}


def request_key_body(key: "Optional[Ed25519PrivateKey]") -> dict[str, str]:
    """The body of ``POST /keys/request-key``: the public key and its proof."""
    if key is None:
        raise ValidationError("register_request_key needs a client with a signing_key")
    public_key = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    proof = key.sign(f"{_REQUEST_KEY_PROOF_FORM}\x00{public_key}".encode("utf-8"))
    return {"public_key": public_key, "proof": base64.b64encode(proof).decode("ascii")}


__all__ = [
    "REQUEST_KEY_PATH",
    "RequestKeyPair",
    "attach_signature",
    "generate_request_key",
    "load_signing_key",
    "payload_hash",
    "request_key_body",
    "request_key_registration_body",
    "request_signature_preimage",
    "sign_body",
    "sign_request",
]
