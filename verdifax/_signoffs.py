"""Customer sign-off on results, shared by the sync and async clients.

An account's owner registers approver keys. An approver signs a decision,
approve or reject, on one exact result, on the approver's own machine, and
any key in the account submits it. The server checks the signature, links
the sign-off to the account's previous one and logs it on the public log.

A sign-off shows that the holder of a registered approver key signed that
decision on that exact result, and that Verdifax logged it. It does not show
the review was careful, the result was right, or who the person is: a key
is not an identity. It gates nothing on its own. The approver's private key
and the note's text never leave this machine; only the note's SHA-256 is
sent.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping, Optional, Union

from ._signing import _ed25519_private_key_class, _signing_nonce, _signing_time, _utf8
from ._validation import validate_hex64, validate_positive_id
from .exceptions import ValidationError, VerdifaxError
from .models import SignOffTarget

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGNOFF_FORM = "verdifax.signoff.v1"
APPROVER_KEY_PROOF_FORM = "verdifax.approver-key.v1"
NO_PREVIOUS_SIGNOFF = "0" * 64
SIGNOFF_TARGET_KINDS = ("record", "receipt", "job")
SIGNOFF_DECISIONS = ("approve", "reject")
APPROVERS_PATH = "/account/approvers"
SIGNOFF_HISTORY_PATH = "/account/signoffs/history"
_TARGET_FIELDS = ("kind", "run_id", "digest", "job_id")
_CHAIN_PATTERN = re.compile(r"account-[1-9][0-9]{0,18}")
_APPROVER_NAME_MAX_BYTES = 200
_KEY_BYTES = 32
_SIGNATURE_BYTES = 64

SignOffTargetLike = Union[SignOffTarget, Mapping[str, Any]]
ApproverKeyLike = Union[bytes, bytearray, Mapping[str, Any]]


def _text(value: Any, field_name: str) -> str:
    """Refuse a value that is not text, or that holds a zero byte."""
    _utf8(value, field_name)
    if "\x00" in value:
        raise ValidationError(f"{field_name} cannot be signed: it holds a zero byte")
    result: str = value
    return result


def _target_fields(target: Any) -> dict[str, Any]:
    if isinstance(target, SignOffTarget):
        return target.model_dump()
    if not isinstance(target, Mapping):
        raise ValidationError(
            f"target must be a SignOffTarget or a mapping, got {type(target).__name__}"
        )
    unknown = sorted(str(name) for name in target if name not in _TARGET_FIELDS)
    if unknown:
        raise ValidationError(f"target has unknown fields: {', '.join(unknown)}")
    return dict(target)


def signoff_preimage(
    chain_id: str,
    previous_signoff_hash: str,
    target: SignOffTargetLike,
    decision: str,
    note_hash: str,
    signed_at: str,
    nonce: str,
) -> bytes:
    """The bytes an approver key signs for a sign-off, joined with zero bytes.

    They are ``verdifax.signoff.v1``, ``chain_id``, ``previous_signoff_hash``,
    the target's ``kind``, ``run_id`` and ``digest``, its ``job_id`` (empty
    unless the target is a job), ``decision``, ``note_hash`` (empty with no
    note), ``signed_at`` and ``nonce``. ``chain_id`` and
    ``previous_signoff_hash`` come from ``GET /signoffs/newest``. Matches the
    orchestrator's ``SignOffPreimage``. Makes no request.

    Raises:
        ValidationError: If a value is not text or holds a zero byte, which
            would make the joined bytes ambiguous, or ``run_id`` is not an
            ``int``.
    """
    fields = _target_fields(target)
    run_id = fields.get("run_id")
    if isinstance(run_id, bool) or not isinstance(run_id, int):
        raise ValidationError(f"target run_id must be an int, got {type(run_id).__name__}")
    values = (
        SIGNOFF_FORM,
        _text(chain_id, "chain_id"),
        _text(previous_signoff_hash, "previous_signoff_hash"),
        _text(fields.get("kind"), "target kind"),
        str(run_id),
        _text(fields.get("digest"), "target digest"),
        _text(fields.get("job_id") or "", "target job_id"),
        _text(decision, "decision"),
        _text(note_hash, "note_hash"),
        _text(signed_at, "signed_at"),
        _text(nonce, "nonce"),
    )
    return "\x00".join(values).encode("utf-8")


def approver_proof_preimage(public_key: str) -> bytes:
    """The bytes a new approver key signs: the form, a zero byte, the base64 key."""
    return f"{APPROVER_KEY_PROOF_FORM}\x00{public_key}".encode("utf-8")


def load_approver_key(approver_key: Any) -> "Ed25519PrivateKey":
    """Turn the approver's raw private key into a key object, which does not print its bytes."""
    if not isinstance(approver_key, (bytes, bytearray)) or len(approver_key) != _KEY_BYTES:
        raise ValidationError("approver_key must be the 32 raw bytes of an Ed25519 private key")
    return _ed25519_private_key_class().from_private_bytes(bytes(approver_key))


def _public_key_text(key: "Ed25519PrivateKey") -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")


def approver_key_proof(approver_key: bytes) -> dict[str, str]:
    """The approver key's public key and its proof, built on the approver's machine.

    ``proof`` is the key's Ed25519 signature over ``verdifax.approver-key.v1``,
    a zero byte and the base64 public key, which shows the server that
    whoever registers the key holds its private key. The approver can run
    this and hand the result to the account's owner, who passes it to
    ``register_approver``, so the private key never leaves the approver's
    machine. Makes no request.

    Returns:
        ``{"public_key": ..., "proof": ...}``, both base64.

    Raises:
        ValidationError: If ``approver_key`` is not 32 raw bytes.
    """
    key = load_approver_key(approver_key)
    public_key = _public_key_text(key)
    proof = key.sign(approver_proof_preimage(public_key))
    return {"public_key": public_key, "proof": base64.b64encode(proof).decode("ascii")}


def _base64_of_length(value: Any, length: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == length
    except ValueError:
        return False


def _signing_public_key(signing_key: "Optional[Ed25519PrivateKey]") -> Optional[str]:
    return None if signing_key is None else _public_key_text(signing_key)


def _refuse_request_key(public_key: str, signing_key: "Optional[Ed25519PrivateKey]") -> None:
    if public_key == _signing_public_key(signing_key):
        raise ValidationError(
            "approver_key is this client's signing_key: an approver key is never a "
            "request key in the same account"
        )


def _check_approver_proof(public_key: str, proof: str) -> None:
    """Refuse a ready-made proof that does not verify, before it is sent."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise VerdifaxError(
            'checking an approver proof needs the "cryptography" package: '
            'pip install "verdifax[signing]"'
        ) from exc
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
    try:
        key.verify(base64.b64decode(proof), approver_proof_preimage(public_key))
    except InvalidSignature as exc:
        raise ValidationError(
            "the approver proof does not verify: it must be the approver key's signature "
            "over verdifax.approver-key.v1, a zero byte and the base64 public key"
        ) from exc


def approver_body(
    name: Any, approver_key: Any, signing_key: "Optional[Ed25519PrivateKey]" = None
) -> dict[str, str]:
    """The body of ``POST /account/approvers``: the key, its name and its proof.

    ``approver_key`` is the approver's 32 raw private key bytes, and the proof
    is computed here, or the answer of :func:`approver_key_proof` built on the
    approver's machine, whose proof is verified here before it is sent.

    Raises:
        ValidationError: If ``name`` is empty or longer than 200 bytes, the
            key is not valid, a ready-made proof does not verify, or the key
            is this client's own ``signing_key``.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("name is required")
    if len(_utf8(name.strip(), "name")) > _APPROVER_NAME_MAX_BYTES:
        raise ValidationError(f"name must be at most {_APPROVER_NAME_MAX_BYTES} bytes")
    if isinstance(approver_key, Mapping):
        unknown = sorted(str(k) for k in approver_key if k not in ("public_key", "proof"))
        if unknown:
            raise ValidationError(f"approver_key has unknown fields: {', '.join(unknown)}")
        proven: dict[str, Any] = {
            "public_key": approver_key.get("public_key"),
            "proof": approver_key.get("proof"),
        }
        if not _base64_of_length(proven["public_key"], _KEY_BYTES) or not _base64_of_length(
            proven["proof"], _SIGNATURE_BYTES
        ):
            raise ValidationError(
                "approver_key must hold a base64 Ed25519 public_key and proof, "
                "as approver_key_proof returns them"
            )
        public_key: str = proven["public_key"]
        proof: str = proven["proof"]
        _check_approver_proof(public_key, proof)
    else:
        built = approver_key_proof(approver_key)
        public_key, proof = built["public_key"], built["proof"]
    _refuse_request_key(public_key, signing_key)
    return {"public_key": public_key, "name": name, "proof": proof}


def approver_path(approver_id: int) -> str:
    """Validate ``approver_id`` and build ``/account/approvers/{approver_id}``."""
    validate_positive_id(approver_id, "approver_id")
    return f"{APPROVERS_PATH}/{approver_id}"


def _owner_flag(as_owner: Any) -> bool:
    if not isinstance(as_owner, bool):
        raise ValidationError(f"as_owner must be a bool, got {type(as_owner).__name__}")
    return as_owner


def newest_signoff_path(as_owner: Any = False) -> str:
    """``/account/signoffs/newest`` for the owner key, else ``/signoffs/newest``."""
    return "/account/signoffs/newest" if _owner_flag(as_owner) else "/signoffs/newest"


def submit_signoff_path(as_owner: Any = False) -> str:
    """``/account/signoffs`` for the owner key, else ``/signoffs``."""
    return "/account/signoffs" if _owner_flag(as_owner) else "/signoffs"


def run_signoffs_path(run_id: int, as_owner: Any = False) -> str:
    """Validate ``run_id`` and build its sign-offs route, the owner key's or a member's."""
    validate_positive_id(run_id, "run_id")
    base = "/account/runs" if _owner_flag(as_owner) else "/runs"
    return f"{base}/{run_id}/signoffs"


def publication_path(run_id: int, verb: str) -> str:
    """Validate ``run_id`` and build the owner's publish or unpublish route."""
    validate_positive_id(run_id, "run_id")
    if verb not in ("publish", "unpublish"):
        raise ValidationError("verb must be publish or unpublish")
    return f"/account/runs/{run_id}/{verb}"


def signoff_target(target: Any) -> dict[str, Any]:
    """Check a target and return the block the server reads.

    Raises:
        ValidationError: If ``kind`` is not ``record``, ``receipt`` or
            ``job``, ``run_id`` is not a positive ``int``, ``digest`` is not
            64 lowercase hex characters, or ``job_id`` is missing for a job or
            set for anything else.
    """
    fields = _target_fields(target)
    kind: Any = fields.get("kind")
    if kind not in SIGNOFF_TARGET_KINDS:
        raise ValidationError("target kind must be record, receipt or job")
    run_id: Any = fields.get("run_id")
    if isinstance(run_id, bool) or not isinstance(run_id, int):
        raise ValidationError(f"target run_id must be an int, got {type(run_id).__name__}")
    validate_positive_id(run_id, "target run_id")
    digest: Any = fields.get("digest")
    validate_hex64(digest, "target digest")
    job_id = fields.get("job_id") or ""
    if (kind == "job") != (job_id != ""):
        raise ValidationError("a job target names its job_id, and only a job target does")
    block: dict[str, Any] = {"kind": kind, "run_id": run_id, "digest": digest}
    if job_id:
        block["job_id"] = _text(job_id, "target job_id")
    return block


def note_hash(note: Any) -> str:
    """The SHA-256 hex of the note's UTF-8 text, or empty with no note (``None``).

    Only this hash is sent. The note's text never leaves this machine. An
    empty note is refused rather than hashed: leave ``note`` out instead.

    Raises:
        ValidationError: If ``note`` is not ``None`` or a non-empty ``str``.
    """
    if note is None:
        return ""
    if not isinstance(note, str):
        raise ValidationError(f"note must be a str, got {type(note).__name__}")
    if note == "":
        raise ValidationError("note is empty: leave it out, or give the note's text")
    return hashlib.sha256(_utf8(note, "note")).hexdigest()


@dataclass(frozen=True)
class PreparedSignOff:
    """A sign-off checked and ready to sign once the chain's newest link is read."""

    target: dict[str, Any]
    decision: str
    note_hash: str
    key: "Ed25519PrivateKey" = field(repr=False)
    public_key: str


def prepare_signoff(
    target: Any,
    decision: Any,
    approver_key: Any,
    note: Any = None,
    signing_key: "Optional[Ed25519PrivateKey]" = None,
) -> PreparedSignOff:
    """Check every input of ``sign_off`` before anything is sent.

    Raises:
        ValidationError: For a bad target or decision, a note that is not
            text, an approver key that is not 32 raw bytes, or an approver key
            that is this client's own ``signing_key``.
    """
    block = signoff_target(target)
    if decision not in SIGNOFF_DECISIONS:
        raise ValidationError("decision must be approve or reject")
    hashed = note_hash(note)
    key = load_approver_key(approver_key)
    public_key = _public_key_text(key)
    _refuse_request_key(public_key, signing_key)
    return PreparedSignOff(block, decision, hashed, key, public_key)


def signoff_body(
    prepared: PreparedSignOff,
    newest: Any,
    source: str,
    signed_at: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, Any]:
    """The body of ``POST /signoffs``, signed over the chain ``newest`` names.

    ``newest`` is the answer of ``GET /signoffs/newest`` (or the owner's
    route); ``source`` names that route in the error.

    Raises:
        VerdifaxError: If ``newest`` has no account chain or no usable newest
            sign-off hash.
    """
    if not isinstance(newest, Mapping):
        raise VerdifaxError(f"{source} did not return an object")
    chain_id = newest.get("chain_id")
    if not isinstance(chain_id, str) or not _CHAIN_PATTERN.fullmatch(chain_id):
        raise VerdifaxError(f"{source} returned no account chain_id, so nothing can be signed")
    previous: Any = newest.get("newest_signoff_hash")
    try:
        validate_hex64(previous, "newest_signoff_hash")
    except ValidationError as exc:
        raise VerdifaxError(f"{source} did not return a usable newest sign-off: {exc}") from exc
    signed_at = _signing_time() if signed_at is None else signed_at
    nonce = _signing_nonce() if nonce is None else nonce
    preimage = signoff_preimage(
        chain_id,
        previous,
        prepared.target,
        prepared.decision,
        prepared.note_hash,
        signed_at,
        nonce,
    )
    body: dict[str, Any] = {
        "previous_signoff_hash": previous,
        "target": prepared.target,
        "decision": prepared.decision,
        "approver_key": prepared.public_key,
        "signature": base64.b64encode(prepared.key.sign(preimage)).decode("ascii"),
        "signed_at": signed_at,
        "nonce": nonce,
    }
    if prepared.note_hash:
        body["note_hash"] = prepared.note_hash
    return body


def signoff_record(response_body: Any, sent: Mapping[str, Any]) -> dict[str, Any]:
    """The sign-off record from a submit answer, checked against what was sent.

    Raises:
        VerdifaxError: If the answer has no ``signoff`` object, or its record
            does not carry the signature, key, decision and target sent.
    """
    record = response_body.get("signoff") if isinstance(response_body, Mapping) else None
    if not isinstance(record, dict):
        raise VerdifaxError("the server's answer has no sign-off record")
    for name in ("signature", "approver_key", "decision", "previous_signoff_hash"):
        if record.get(name) != sent[name]:
            raise VerdifaxError(f"the server's sign-off record has another {name} than was sent")
    recorded_target = record.get("target")
    if not isinstance(recorded_target, Mapping) or dict(recorded_target) != sent["target"]:
        raise VerdifaxError("the server's sign-off record names another target than was sent")
    return record


def signoff_list(body: Any, what: str) -> list[dict[str, Any]]:
    """Read a list of sign-off records, as the server sent it.

    Raises:
        VerdifaxError: If the server did not send a list.
    """
    if not isinstance(body, list):
        raise VerdifaxError(f"the server's {what} is not a list")
    return body


__all__ = [
    "APPROVERS_PATH",
    "APPROVER_KEY_PROOF_FORM",
    "NO_PREVIOUS_SIGNOFF",
    "PreparedSignOff",
    "SIGNOFF_DECISIONS",
    "SIGNOFF_FORM",
    "SIGNOFF_HISTORY_PATH",
    "SIGNOFF_TARGET_KINDS",
    "approver_body",
    "approver_key_proof",
    "approver_path",
    "approver_proof_preimage",
    "load_approver_key",
    "newest_signoff_path",
    "note_hash",
    "prepare_signoff",
    "run_signoffs_path",
    "signoff_body",
    "signoff_list",
    "signoff_preimage",
    "signoff_record",
    "signoff_target",
    "submit_signoff_path",
]
