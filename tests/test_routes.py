"""Every remaining route, sync and async, and the shared helpers.

Requests go to ``httpx.MockTransport``, so nothing reaches the network.
"""

from __future__ import annotations

import inspect
import json
from typing import Any

import httpx
import pytest

import verdifax
from tests.test_parity import async_client, responder, sent, sync_client
from tests.test_signing import (
    INPUTS,
    NONCE,
    PAYLOAD_HASH,
    PROOF,
    PUBLIC_KEY,
    SEED,
    SIGNATURE,
    SIGNED_AT,
)
from verdifax import (
    APIError,
    AttestedContext,
    RUN_STATUSES,
    ValidationError,
    VerdifaxClient,
    format_provider_payload,
    request_key_registration_body,
    request_signature_preimage,
    sign_request,
    validate_hex64,
    validate_route_id,
)
from verdifax._requests import admin_erase_body, governed_text, parse_export_csv, run_path
from verdifax._validation import validate_positive_id, validate_run_id
from verdifax.research import ReproducibilityContext, determinism_body

ROUTES = [
    ("version", (), "/version"),
    ("get_openapi", (), "/openapi.json"),
    ("get_stats", (), "/stats"),
    ("list_attestations", (), "/attestations"),
    ("get_attestation", (7,), "/attestations/7"),
    ("get_allow_token", (7,), "/runs/7/allow-token"),
    ("get_deny_receipt", (7,), "/runs/7/deny-receipt"),
    ("get_ccv_halt_receipt", (7,), "/runs/7/ccv-halt-receipt"),
    ("get_macc_halt_receipt", (7,), "/runs/7/macc-halt-receipt"),
    ("get_aivp_t4_halt_receipt", (7,), "/runs/7/aivp-t4-halt-receipt"),
    ("get_attestation_gap_receipt", (7,), "/runs/7/attestation-gap-receipt"),
    ("get_ces_audit_record", (7,), "/runs/7/ces-audit-record"),
    ("get_run_report", (7,), "/runs/7/report"),
    ("get_run_artifacts", (7,), "/runs/7/artifacts"),
    ("get_public_bundle", (7,), "/runs/7/bundle.json"),
    ("get_public_bundle_by_token", ("a b/c",), "/public/runs/a%20b%2Fc/bundle.json"),
    ("get_public_receipt_by_token", ("a b/c",), "/public/runs/a%20b%2Fc/receipt.json"),
    ("list_deletion_receipts", (7,), "/runs/7/deletion-receipts"),
    ("admin_list_keys", (), "/admin/keys"),
]
BODY = {"ok": True, "report": {"run_id": 7}, "receipts": [{"id": 1}], "keys": [{"id": 2}]}
ERASE_ARGS = (7, "request.payload.email", "c" * 64)
PROOF_BUNDLE = {"envelope_id": "e", "manifest_hash": "a" * 64}


@pytest.mark.parametrize("method,args,path", ROUTES, ids=[r[0] for r in ROUTES])
def test_sync_route(method, args, path):
    seen: list[httpx.Request] = []
    getattr(sync_client(responder(seen, body=BODY)), method)(*args)
    assert seen[0].method == "GET"
    assert seen[0].url.raw_path.decode() == path


@pytest.mark.parametrize("method,args,path", ROUTES, ids=[r[0] for r in ROUTES])
async def test_async_route(method, args, path):
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=BODY)) as client:
        await getattr(client, method)(*args)
    assert seen[0].method == "GET"
    assert seen[0].url.raw_path.decode() == path


def test_every_sync_method_has_an_async_twin():
    def public(cls):
        return {name for name, _ in inspect.getmembers(cls, inspect.isfunction) if name[0] != "_"}

    missing = public(VerdifaxClient) - public(verdifax.AsyncVerdifaxClient)
    assert missing == set()


def test_list_attestations_sends_paging():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=BODY)).list_attestations(limit=5, offset=10)
    assert dict(seen[0].url.params) == {"limit": "5", "offset": "10"}


def test_run_report_and_lists_unwrap_the_body():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BODY))
    assert client.get_run_report(7) == {"run_id": 7}
    assert client.list_deletion_receipts(7) == [{"id": 1}]
    assert client.admin_list_keys() == [{"id": 2}]


def test_bundle_methods_return_the_exact_text():
    text = '{"input_nonce": 1780000000123456789 ,\n "hash":"a"}'
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, text=text))
    assert client.get_run_artifacts(7) == text
    assert client.get_public_bundle(7) == text
    assert client.get_public_bundle_by_token("t") == text


async def test_async_bundle_methods_return_the_exact_text():
    text = '{"input_nonce": 1780000000123456789}'
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, text=text)) as client:
        assert await client.get_run_artifacts(7) == text
        assert await client.get_public_bundle(7) == text
        assert await client.get_public_bundle_by_token("t") == text


def test_public_routes_send_no_key_without_one(monkeypatch):
    monkeypatch.delenv("VERDIFAX_API_KEY", raising=False)
    seen: list[httpx.Request] = []
    client = VerdifaxClient(
        base_url="http://test.invalid", transport=httpx.MockTransport(responder(seen, text="{}"))
    )
    client.get_public_bundle(7)
    client.get_public_bundle_by_token("t")
    assert all("x-verdifax-key" not in request.headers for request in seen)


@pytest.mark.parametrize("fmt", ["comprehensive", "brief"])
def test_download_audit_pdf_returns_bytes(fmt):
    pdf = b"%PDF-1.7\xff\xfe"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/runs/7/report.pdf"
        assert dict(request.url.params) == {"format": fmt}
        return httpx.Response(200, content=pdf, headers={"Content-Type": "application/pdf"})

    assert sync_client(handler).download_audit_pdf(7, fmt) == pdf


async def test_async_download_audit_pdf_and_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs/7/report.pdf":
            return httpx.Response(200, content=b"%PDF")
        return httpx.Response(404, json={"error": "run not found"})

    async with async_client(handler) as client:
        assert await client.download_audit_pdf(7) == b"%PDF"
        with pytest.raises(APIError) as caught:
            await client.download_audit_pdf(8)
    assert caught.value.status_code == 404


def test_dcae_verify_posts_the_bundle():
    seen: list[httpx.Request] = []
    out = sync_client(responder(seen, body={"verified": True})).dcae_verify(PROOF_BUNDLE)
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/dcae/verify"
    assert sent(seen[0]) == PROOF_BUNDLE
    assert out == {"verified": True}


async def test_async_dcae_verify_posts_the_bundle():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body={"verified": False})) as client:
        await client.dcae_verify(PROOF_BUNDLE)
    assert sent(seen[0]) == PROOF_BUNDLE


def test_admin_helpers():
    seen: list[httpx.Request] = []
    body = {"ok": True, "id": 2, "secret": "s", "deletion_receipt": {"receipt_hash": "r"}}
    client = sync_client(responder(seen, body=body))
    assert client.admin_create_key("name")["secret"] == "s"
    assert client.admin_revoke_key(2) is None
    assert client.admin_erase(*ERASE_ARGS, dsar_reference="D1") == {"receipt_hash": "r"}
    assert (seen[0].method, seen[0].url.path) == ("POST", "/admin/keys")
    assert sent(seen[0]) == {"name": "name"}
    assert (seen[1].method, seen[1].url.path) == ("DELETE", "/admin/keys/2")
    assert (seen[2].method, seen[2].url.path) == ("POST", "/admin/erase")
    assert sent(seen[2]) == {
        "run_id": 7,
        "field_path": "request.payload.email",
        "ciphertext_hash": "c" * 64,
        "dsar_reference": "D1",
    }


async def test_async_admin_helpers():
    seen: list[httpx.Request] = []
    body = {"ok": True, "keys": [], "deletion_receipt": {"receipt_hash": "r"}}
    async with async_client(responder(seen, body=body)) as client:
        await client.admin_create_key("name")
        assert await client.admin_list_keys() == []
        await client.admin_revoke_key(2)
        assert await client.admin_erase(*ERASE_ARGS) == {"receipt_hash": "r"}
    assert [request.method for request in seen] == ["POST", "GET", "DELETE", "POST"]


def test_admin_helpers_refuse_bad_input_without_a_request():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError):
        client.admin_create_key("")
    with pytest.raises(ValidationError):
        client.admin_revoke_key(0)
    with pytest.raises(ValidationError):
        client.admin_erase(7, "", "c" * 64)
    with pytest.raises(ValidationError):
        client.admin_erase(7, "field", "short")
    assert seen == []


def test_admin_erase_body_omits_an_unset_reference():
    assert "dsar_reference" not in admin_erase_body(*ERASE_ARGS)


def test_bad_ids_are_refused_without_a_request():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError):
        client.get_attestation(0)
    with pytest.raises(ValidationError):
        client.get_run_artifacts(-1)
    with pytest.raises(ValidationError):
        client.get_public_bundle_by_token("")
    with pytest.raises(ValidationError):
        validate_positive_id(True, "id")
    with pytest.raises(ValidationError):
        run_path(0)
    assert run_path(7) == "/runs/7"
    assert seen == []


def test_validate_run_id_names_the_field():
    validate_run_id(1)
    with pytest.raises(ValidationError, match="run_id"):
        validate_run_id(0)


def test_shared_request_helpers_parse_json_and_send_bodies():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"ok": True}))
    assert client._get_json("/stats", {"a": 1}) == {"ok": True}
    assert client._send_json("POST", "/dcae/verify", {"b": 2}) == {"ok": True}
    assert dict(seen[0].url.params) == {"a": "1"}
    assert sent(seen[1]) == {"b": 2}


def test_new_routes_report_the_servers_errors():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"error": "run not found"}, status=404))
    with pytest.raises(APIError) as caught:
        client.get_deny_receipt(7)
    assert caught.value.status_code == 404
    assert caught.value.message == "run not found"


def test_transport_failure_on_a_new_route_is_wrapped():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    with pytest.raises(verdifax.ConnectionError):
        sync_client(handler).get_stats()
    with pytest.raises(verdifax.ConnectionError):
        sync_client(handler).admin_create_key("name")


def test_parse_export_csv_reads_the_counts():
    response = httpx.Response(
        200, text="a\n", headers={"X-Verdifax-Total": "3", "X-Verdifax-Truncated": "true"}
    )
    assert parse_export_csv(response).model_dump() == {"csv": "a\n", "total": 3, "truncated": True}


def test_client_provider_helpers_match_the_module_helpers():
    seen: list[httpx.Request] = []
    from tests.conftest import make_execute_response

    client = sync_client(responder(seen, body=make_execute_response()))
    client.attest_claude_response("p", "r", **INPUTS, govern=True)
    client.attest_openai_response("p", "r", **INPUTS)
    verdifax.attest_claude_response("p", "r", **INPUTS, govern=True, client=client)
    assert sent(seen[0]) == sent(seen[2])
    assert sent(seen[0])["payload_text"] == format_provider_payload("anthropic", "p", "r")
    assert sent(seen[0])["ai_output_text"] == "r"
    assert sent(seen[0])["attested_context"]["model_provider"] == "anthropic"
    assert sent(seen[0])["attested_context"]["attested"] is True
    assert sent(seen[1])["payload_text"] == format_provider_payload("openai", "p", "r")
    assert "ai_output_text" not in sent(seen[1])


async def test_async_provider_helpers():
    from tests.conftest import make_execute_response

    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=make_execute_response())) as client:
        await client.attest_claude_response("p", b"r", **INPUTS)
        await client.attest_openai_response("p", "r", **INPUTS, govern=True)
    assert sent(seen[0])["payload_text"] == format_provider_payload("anthropic", "p", "r")
    assert "ai_output_text" not in sent(seen[0])
    assert sent(seen[1])["ai_output_text"] == "r"


def test_governed_text_decodes_bytes():
    assert governed_text(b"r") == "r"
    assert governed_text("r") == "r"


async def test_async_attest_sends_reproducibility_context():
    from tests.conftest import make_execute_response

    seen: list[httpx.Request] = []
    context = ReproducibilityContext(runtime_name="python", pinned_dependencies=["a==1"])
    async with async_client(responder(seen, body=make_execute_response())) as client:
        await client.attest("hello", **INPUTS, reproducibility_context=context)
        await client.execute("hello", **INPUTS, reproducibility_context=context)
    for request in seen:
        block = sent(request)["reproducibility_context"]
        assert block["declared"] is True
        assert block["pinned_dependencies"] == ["a==1"]


def test_execute_accepts_context_and_ai_output():
    from tests.conftest import make_execute_response

    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=make_execute_response()))
    client.execute(
        "hello", **INPUTS, reproducibility_context={"runtime_name": "x"}, ai_output_text="o"
    )
    body = sent(seen[0])
    assert body["reproducibility_context"] == {"runtime_name": "x", "declared": True}
    assert body["ai_output_text"] == "o"


def test_determinism_carries_attested_context():
    assert "attested_context" not in determinism_body("hello", **INPUTS)
    body = determinism_body(
        "hello", **INPUTS, attested_context=AttestedContext(actor_role="reviewer")
    )
    assert body["attested_context"]["attested"] is True
    json.dumps(body)


def test_run_statuses_is_the_set_the_server_uses():
    assert set(RUN_STATUSES) == {
        "ok",
        "probe",
        "pepg_deny",
        "ccv_halt",
        "macc_halt",
        "aivp_t4_halt",
        "attestation_gap",
        "stage_error",
    }


def test_run_models_accept_every_status():
    for status in RUN_STATUSES:
        assert verdifax.RunSummary(id=1, status=status).status == status


def test_public_signing_helpers_match_the_shared_vector():
    body: dict[str, Any] = {"payload_text": "hello", **INPUTS}
    assert sign_request(SEED, body, signed_at=SIGNED_AT, nonce=NONCE) == {
        "signature": SIGNATURE,
        "signed_at": SIGNED_AT,
        "nonce": NONCE,
    }
    assert request_key_registration_body(SEED) == {"public_key": PUBLIC_KEY, "proof": PROOF}
    preimage = request_signature_preimage(
        PAYLOAD_HASH, INPUTS["program_id"], "r", INPUTS["registry_record_hash"], SIGNED_AT, NONCE
    )
    assert preimage.count(b"\x00") == 6


def test_public_validators():
    validate_hex64("a" * 64, "field")
    validate_route_id("r")
    with pytest.raises(ValidationError):
        validate_hex64("A" * 64, "field")
    with pytest.raises(ValidationError):
        validate_route_id("")
