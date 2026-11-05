"""Tests for optional customer request signing. No network access."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from unittest import mock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import verdifax
from tests.conftest import make_execute_response
from verdifax import (
    AsyncVerdifaxClient,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    attest_claude_response,
    attest_openai_response,
    cli,
    generate_request_key,
)
from verdifax import _signing
from verdifax.research import verify_determinism

# The vector shared by the four SDKs, so they cannot disagree.
SEED = bytes([1] * 32)
PROGRAM_ID = "1" * 64
ROUTE_ID = "r"
REGISTRY_RECORD_HASH = "2" * 64
SIGNED_AT = "2026-11-05T00:00:00Z"
NONCE = "00112233445566778899aabbccddeeff"
PAYLOAD_HASH = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
PUBLIC_KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
PROOF = "Vc0TtZ8UbLQgWVnUcwSFPzl3jMn1neQqYQEpbepGa7IYfJJ7kh5QcU0FT5tC5EDoAJNDZNxkLA2Dtf2JHsppBA=="
SIGNATURE = (
    "PWKn9IplkfrPmXSN+EfJX7aUPoRR0GHqjCvOLG2l1BAvPgupr7ZsJGNujNh6Wk2w/Y1zRaBVeNqOZ1QVrrBvCw=="
)

INPUTS = {
    "program_id": PROGRAM_ID,
    "route_id": ROUTE_ID,
    "registry_record_hash": REGISTRY_RECORD_HASH,
}


def preimage_for(body: dict, payload_bytes: bytes) -> bytes:
    """The bytes the server rebuilds, written out independently of the SDK."""
    sig = body["request_signature"]
    fields = [
        b"verdifax.request.v1",
        hashlib.sha256(payload_bytes).hexdigest().encode(),
        body["program_id"].encode(),
        body["route_id"].encode(),
        body["registry_record_hash"].encode(),
        sig["signed_at"].encode(),
        sig["nonce"].encode(),
    ]
    return b"\x00".join(fields)


def assert_verifies(body: dict, payload_bytes: bytes) -> None:
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY))
    signature = base64.b64decode(body["request_signature"]["signature"])
    public_key.verify(signature, preimage_for(body, payload_bytes))


def recording_transport(requests: list[httpx.Request], response: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=response or make_execute_response())

    return httpx.MockTransport(handler)


def client_with(requests: list[httpx.Request], signing_key=SEED, response=None) -> VerdifaxClient:
    return VerdifaxClient(
        base_url="http://test.invalid",
        api_key="vfx_test",
        transport=recording_transport(requests, response),
        signing_key=signing_key,
    )


def bodies(requests: list[httpx.Request]) -> list[dict]:
    return [json.loads(r.content) for r in requests]


# ── shared vector ─────────────────────────────────────────────────────────────


def test_shared_vector_signature():
    key = _signing.load_signing_key(SEED)
    body = {"payload_text": "hello", **INPUTS}
    assert _signing.payload_hash(body) == PAYLOAD_HASH
    signed = _signing.sign_body(key, body, signed_at=SIGNED_AT, nonce=NONCE)
    assert signed == {"signature": SIGNATURE, "signed_at": SIGNED_AT, "nonce": NONCE}


def test_shared_vector_signed_bytes():
    expected = (
        (b"verdifax.request.v1\x00" + PAYLOAD_HASH.encode() + b"\x00" + PROGRAM_ID.encode())
        + (b"\x00r\x00" + REGISTRY_RECORD_HASH.encode() + b"\x00" + SIGNED_AT.encode())
        + (b"\x00" + NONCE.encode())
    )
    assert (
        _signing.request_signature_preimage(
            PAYLOAD_HASH, PROGRAM_ID, ROUTE_ID, REGISTRY_RECORD_HASH, SIGNED_AT, NONCE
        )
        == expected
    )


def test_shared_vector_proof():
    body = _signing.request_key_body(_signing.load_signing_key(SEED))
    assert body == {"public_key": PUBLIC_KEY, "proof": PROOF}
    Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY)).verify(
        base64.b64decode(PROOF), b"verdifax.request-key.v1\x00" + PUBLIC_KEY.encode()
    )


# ── what each path sends ──────────────────────────────────────────────────────


def test_unsigned_client_sends_no_request_signature():
    requests: list[httpx.Request] = []
    client_with(requests, signing_key=None).attest(payload="hello", **INPUTS)
    assert "request_signature" not in bodies(requests)[0]


def test_attest_signs_and_the_signature_verifies():
    requests: list[httpx.Request] = []
    client_with(requests).attest(payload="hello", **INPUTS)
    body = bodies(requests)[0]
    assert_verifies(body, b"hello")
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["request_signature"]["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", body["request_signature"]["nonce"])


def test_execute_signs():
    requests: list[httpx.Request] = []
    client_with(requests).execute(payload="hello", **INPUTS)
    assert_verifies(bodies(requests)[0], b"hello")


def test_non_ascii_text_hashes_its_utf8_bytes():
    requests: list[httpx.Request] = []
    client_with(requests).attest(payload="caf\u00e9 \u4e16\u754c \U0001f600", **INPUTS)
    assert_verifies(bodies(requests)[0], "caf\u00e9 \u4e16\u754c \U0001f600".encode("utf-8"))


def test_utf8_bytes_are_sent_and_hashed_as_text():
    requests: list[httpx.Request] = []
    client_with(requests).attest(payload=b"hello", **INPUTS)
    body = bodies(requests)[0]
    assert body["payload_text"] == "hello"
    assert_verifies(body, b"hello")


def test_binary_payload_hashes_the_base64_string_not_the_decoded_bytes():
    requests: list[httpx.Request] = []
    client_with(requests).attest(payload=b"\xff\xfe\x00", **INPUTS)
    body = bodies(requests)[0]
    assert "payload_text" not in body
    assert_verifies(body, body["payload"].encode("ascii"))


def test_non_empty_payload_text_wins_over_payload():
    key = _signing.load_signing_key(SEED)
    both = {"payload_text": "text", "payload": "b64", **INPUTS}
    empty_text = {"payload_text": "", "payload": "b64", **INPUTS}
    assert _signing.payload_hash(both) == hashlib.sha256(b"text").hexdigest()
    assert _signing.payload_hash(empty_text) == hashlib.sha256(b"b64").hexdigest()
    assert _signing.sign_body(key, both, SIGNED_AT, NONCE) != _signing.sign_body(
        key, empty_text, SIGNED_AT, NONCE
    )


def test_text_with_no_utf8_form_is_refused():
    requests: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="not valid Unicode"):
        client_with(requests).attest(payload="bad \ud800", **INPUTS)
    assert requests == []


def test_nonce_differs_between_calls():
    requests: list[httpx.Request] = []
    client = client_with(requests)
    client.attest(payload="hello", **INPUTS)
    client.attest(payload="hello", **INPUTS)
    first, second = (b["request_signature"] for b in bodies(requests))
    assert first["nonce"] != second["nonce"]
    assert first["signature"] != second["signature"]


def test_module_level_attest_signs():
    requests: list[httpx.Request] = []
    real_init = VerdifaxClient.__init__

    def init(self, *args, **kwargs):
        kwargs["transport"] = recording_transport(requests)
        real_init(self, *args, **kwargs)

    with mock.patch.object(VerdifaxClient, "__init__", init):
        verdifax.attest(
            "hello", **INPUTS, base_url="http://test.invalid", api_key="k", signing_key=SEED
        )
    assert_verifies(bodies(requests)[0], b"hello")


@pytest.mark.parametrize("helper", [attest_claude_response, attest_openai_response])
def test_provider_helpers_sign_through_the_client(helper):
    requests: list[httpx.Request] = []
    helper("prompt", "response", **INPUTS, client=client_with(requests))
    body = bodies(requests)[0]
    assert_verifies(body, body["payload_text"].encode("utf-8"))


@pytest.mark.parametrize("helper", [attest_claude_response, attest_openai_response])
def test_provider_helpers_sign_with_a_temporary_client(helper):
    requests: list[httpx.Request] = []
    real_init = VerdifaxClient.__init__

    def init(self, *args, **kwargs):
        kwargs["transport"] = recording_transport(requests)
        kwargs["base_url"] = "http://test.invalid"
        real_init(self, *args, **kwargs)

    with mock.patch.object(VerdifaxClient, "__init__", init):
        helper("prompt", "response", **INPUTS, signing_key=SEED)
    body = bodies(requests)[0]
    assert_verifies(body, body["payload_text"].encode("utf-8"))


def test_provider_helper_refuses_a_key_beside_a_client():
    with pytest.raises(ValidationError):
        attest_claude_response("p", "r", **INPUTS, client=client_with([]), signing_key=SEED)


def determinism_response() -> dict:
    row = {
        "run_id": 1,
        "manifest_hash": "a" * 64,
        "bundle_hash": "b" * 64,
        "duration_ms": 1,
        "status": "ok",
    }
    diff = {"differs": False, "manifest_hash_differs": False, "bundle_hash_differs": False}
    return {"ok": True, "deterministic": True, "first": row, "second": row, "diff": diff}


def test_verify_determinism_signs():
    requests: list[httpx.Request] = []
    client = client_with(requests, response=determinism_response())
    verify_determinism(client, "hello", **INPUTS)
    assert requests[0].url.path == "/execute/verify-determinism"
    assert_verifies(bodies(requests)[0], b"hello")


def test_verify_determinism_binary_payload_hashes_the_base64_string():
    requests: list[httpx.Request] = []
    client = client_with(requests, response=determinism_response())
    verify_determinism(client, b"\xff\xfe", **INPUTS)
    body = bodies(requests)[0]
    assert_verifies(body, body["payload"].encode("ascii"))


def test_verify_determinism_unsigned_client_sends_no_request_signature():
    requests: list[httpx.Request] = []
    client = client_with(requests, signing_key=None, response=determinism_response())
    verify_determinism(client, "hello", **INPUTS)
    assert "request_signature" not in bodies(requests)[0]


def test_shadow_cli_signs_each_row(tmp_path):
    src = tmp_path / "rows.csv"
    src.write_text("id,value\n1,a\n2,b\n")
    key_file = tmp_path / "request.key"
    key_file.write_text(base64.b64encode(SEED).decode() + "\n")
    requests: list[httpx.Request] = []
    real_init = VerdifaxClient.__init__

    def init(self, *args, **kwargs):
        kwargs["transport"] = recording_transport(requests)
        real_init(self, *args, **kwargs)

    with mock.patch.object(VerdifaxClient, "__init__", init):
        rc = cli.main(
            ["shadow", str(src), "--key", "k", "--base-url", "http://test.invalid"]
            + ["--signing-key-file", str(key_file)]
        )
    assert rc == 0
    rows = bodies(requests)
    assert len(rows) == 2
    for body in rows:
        assert_verifies(body, body["payload_text"].encode("utf-8"))
    assert rows[0]["request_signature"]["nonce"] != rows[1]["request_signature"]["nonce"]


def test_shadow_cli_refuses_a_bad_key_file_without_printing_it(tmp_path, capsys):
    src = tmp_path / "rows.csv"
    src.write_text("id\n1\n")
    key_file = tmp_path / "request.key"
    key_file.write_text("c2VjcmV0")
    assert cli.main(["shadow", str(src), "--signing-key-file", str(key_file)]) == 2
    err = capsys.readouterr().err
    assert "signing_key must be" in err
    assert "c2VjcmV0" not in err


# ── async client ──────────────────────────────────────────────────────────────


def async_client_with(requests: list[httpx.Request], signing_key=SEED, response=None):
    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=response or make_execute_response())

    return AsyncVerdifaxClient(
        base_url="http://test.invalid",
        api_key="vfx_test",
        transport=httpx.MockTransport(handler),
        signing_key=signing_key,
    )


async def test_async_attest_and_execute_sign():
    requests: list[httpx.Request] = []
    async with async_client_with(requests) as client:
        await client.attest(payload="hello", **INPUTS)
        await client.execute(payload="hello", **INPUTS)
    first, second = bodies(requests)
    assert_verifies(first, b"hello")
    assert_verifies(second, b"hello")
    assert first["request_signature"]["nonce"] != second["request_signature"]["nonce"]


async def test_async_unsigned_client_sends_no_request_signature():
    requests: list[httpx.Request] = []
    async with async_client_with(requests, signing_key=None) as client:
        await client.attest(payload="hello", **INPUTS)
    assert "request_signature" not in bodies(requests)[0]


async def test_async_register_and_clear():
    requests: list[httpx.Request] = []
    response = {"ok": True, "public_key": PUBLIC_KEY}
    async with async_client_with(requests, response=response) as client:
        assert (await client.register_request_key())["public_key"] == PUBLIC_KEY
        await client.clear_request_key()
    assert (requests[0].method, requests[0].url.path) == ("POST", "/keys/request-key")
    assert json.loads(requests[0].content) == {"public_key": PUBLIC_KEY, "proof": PROOF}
    assert (requests[1].method, requests[1].url.path) == ("DELETE", "/keys/request-key")


async def test_async_register_needs_a_signing_key():
    async with async_client_with([], signing_key=None) as client:
        with pytest.raises(ValidationError, match="signing_key"):
            await client.register_request_key()


# ── register, clear, keys ─────────────────────────────────────────────────────


def test_register_and_clear():
    requests: list[httpx.Request] = []
    client = client_with(requests, response={"ok": True, "public_key": PUBLIC_KEY})
    assert client.register_request_key() == {"ok": True, "public_key": PUBLIC_KEY}
    client.clear_request_key()
    assert (requests[0].method, requests[0].url.path) == ("POST", "/keys/request-key")
    assert json.loads(requests[0].content) == {"public_key": PUBLIC_KEY, "proof": PROOF}
    assert (requests[1].method, requests[1].url.path) == ("DELETE", "/keys/request-key")


def test_register_needs_a_signing_key():
    requests: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="signing_key"):
        client_with(requests, signing_key=None).register_request_key()
    assert requests == []


def test_generated_key_pair_is_raw_and_works():
    pair = generate_request_key()
    assert len(pair.public_key) == 32
    assert len(pair.private_key) == 32
    assert pair.private_key.hex() not in repr(pair)
    assert repr(pair.private_key) not in repr(pair)
    message = b"message"
    signature = _signing.load_signing_key(pair.private_key).sign(message)
    Ed25519PublicKey.from_public_bytes(pair.public_key).verify(signature, message)


@pytest.mark.parametrize("bad", [b"", b"short", bytes(33), "0" * 32, 123])
def test_a_bad_signing_key_is_refused_without_echoing_it(bad):
    with pytest.raises(ValidationError) as excinfo:
        VerdifaxClient(base_url="http://test.invalid", signing_key=bad)
    if bad:
        assert repr(bad) not in str(excinfo.value)


def test_private_key_is_not_sent_and_not_in_the_client_repr():
    requests: list[httpx.Request] = []
    client = client_with(requests)
    client.register_request_key()
    client.attest(payload="hello", **INPUTS)
    encoded = base64.b64encode(SEED)
    for request in requests:
        assert SEED.hex().encode() not in request.content
        assert encoded not in request.content
        assert all(encoded.decode() not in value for value in request.headers.values())
    for text in (repr(client), repr(vars(client))):
        assert SEED.hex() not in text
        assert encoded.decode() not in text


def test_server_refusal_does_not_carry_the_private_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "request signature does not match this request"})

    client = VerdifaxClient(
        base_url="http://test.invalid",
        api_key="k",
        transport=httpx.MockTransport(handler),
        signing_key=SEED,
    )
    with pytest.raises(verdifax.APIError) as excinfo:
        client.attest(payload="hello", **INPUTS)
    assert excinfo.value.status_code == 403
    assert SEED.hex() not in repr(excinfo.value)
    assert base64.b64encode(SEED).decode() not in str(excinfo.value)


# ── the optional dependency ───────────────────────────────────────────────────


def test_importing_verdifax_does_not_import_cryptography():
    code = (
        "import sys, verdifax\n"
        "assert not any(m.split('.')[0] == 'cryptography' for m in sys.modules)\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


@pytest.mark.parametrize(
    "call",
    [generate_request_key, lambda: VerdifaxClient(signing_key=SEED)],
    ids=["generate", "client"],
)
def test_missing_cryptography_gives_a_clear_error(call, monkeypatch):
    module = "cryptography.hazmat.primitives.asymmetric.ed25519"
    monkeypatch.setitem(sys.modules, module, None)
    with pytest.raises(VerdifaxError, match=r"verdifax\[signing\]"):
        call()


def test_missing_cryptography_leaves_an_unsigned_client_working(monkeypatch):
    module = "cryptography.hazmat.primitives.asymmetric.ed25519"
    monkeypatch.setitem(sys.modules, module, None)
    requests: list[httpx.Request] = []
    client_with(requests, signing_key=None).attest(payload="hello", **INPUTS)
    assert len(requests) == 1
