"""SDK 1.3: the account layer, for an account's owner key and the admin.

Requests go to ``httpx.MockTransport``, so nothing reaches the network. The
account activation bytes come from ``sdk-signature-vector.json``, shared by
the four SDKs, with the same seed, document hash, previous hash, signed_at
and nonce as the key's activation vector.
"""

from __future__ import annotations

import base64
import inspect
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.exceptions import InvalidSignature

from tests.test_jobs import (
    SEED,
    VECTOR,
    async_client,
    scripted,
    sent_body,
    sync_client,
    vector_public_key,
)
from tests.test_parity import CSV_TEXT, EXPORT, responder
from tests.test_policies import (
    ACTIVATION,
    DOCUMENT,
    DOCUMENT_HASH,
    HISTORY,
    NEWEST,
    NONCE,
    PREVIOUS,
    SIGNED_AT,
    TESTED,
    UPLOADED,
    expected_preimage,
    routed,
)
from verdifax import (
    AccountRunsExport,
    APIError,
    AsyncVerdifaxClient,
    RunList,
    RunsExportCSV,
    ValidationError,
    VerdifaxClient,
    VerdifaxError,
    policy_activation_approval,
    policy_activation_preimage,
)
from verdifax._requests import (
    account_key_body,
    admin_account_body,
    admin_accounts,
    admin_key_body,
    policy_activation_body,
)
from verdifax._signing import load_signing_key, policy_activation_signature, request_key_body

PARITY_FILE = Path(__file__).parent / "sdk-parity.json"
ACCOUNT_CHAIN = VECTOR["account_activation_chain_id"]

ACCOUNT = {
    "ok": True,
    "account_id": ACCOUNT_CHAIN,
    "id": 7,
    "name": "Acme",
    "tier": "trial",
    "created_at": "2026-11-07T12:00:00Z",
    "member_keys": 2,
    "owner_keys": 1,
    "chain_id": ACCOUNT_CHAIN,
}
MEMBER_KEY = {
    "ok": True,
    "id": 21,
    "name": "customer:payments",
    "account_id": ACCOUNT_CHAIN,
    "owner": False,
    "tier": "trial",
    "created_at": "2026-11-07T12:00:00Z",
    "secret": "vfx_secret",
    "request_key_required": True,
    "hint": "Store this secret now, it will never be shown again.",
}
KEYS = {
    "ok": True,
    "account_id": ACCOUNT_CHAIN,
    "keys": [
        {"id": 20, "name": "customer:Acme owner", "account_id": ACCOUNT_CHAIN, "owner": True},
        {"id": 21, "name": "customer:payments", "account_id": ACCOUNT_CHAIN, "owner": False},
    ],
}
REVOKED = {"ok": True, "id": 21, "revoked": True}
RUN_LIST = {
    "ok": True,
    "total": 9,
    "limit": 2,
    "offset": 4,
    "runs": [{"id": 7, "status": "ok"}, {"id": 8, "status": "pepg_deny"}],
}
ACCOUNT_EXPORT = {
    **EXPORT,
    "account_id": ACCOUNT_CHAIN,
    "account_policy_documents": [{**UPLOADED, "document": DOCUMENT}],
    "account_policy_history": HISTORY,
}
ACCOUNT_LISTING = {
    "ok": True,
    "chain_id": ACCOUNT_CHAIN,
    "newest_activation_hash": NEWEST,
    "active_document_hash": "",
    "policies": [UPLOADED],
}
ACCOUNT_ACTIVATION = {**ACTIVATION, "chain_id": ACCOUNT_CHAIN}
CREATED_ACCOUNT = {
    "ok": True,
    "account": ACCOUNT,
    "owner_key": {**MEMBER_KEY, "id": 20, "name": "customer:Acme owner", "owner": True},
}


def account_activation_answers(
    overrides: "dict[tuple[str, str], Any] | None" = None,
) -> dict[tuple[str, str], Any]:
    answers: dict[tuple[str, str], Any] = {
        ("GET", "/account/policies"): ACCOUNT_LISTING,
        ("POST", f"/account/policies/{DOCUMENT_HASH}/activate"): {
            "ok": True,
            "activation": ACCOUNT_ACTIVATION,
        },
    }
    answers.update(overrides or {})
    return answers


def ok(body: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


# ── the vector, byte for byte ─────────────────────────────────────────────────


def test_the_account_vector_uses_the_key_vector_inputs():
    assert ACCOUNT_CHAIN == "account-7"
    assert VECTOR["account_activation_preimage_hex"] != VECTOR["activation_preimage_hex"]


def test_vector_account_activation_preimage():
    preimage = policy_activation_preimage(ACCOUNT_CHAIN, DOCUMENT_HASH, PREVIOUS, SIGNED_AT, NONCE)
    assert preimage.hex() == VECTOR["account_activation_preimage_hex"]


def test_vector_account_activation_preimage_matches_an_independent_build():
    sig = {"signed_at": SIGNED_AT, "nonce": NONCE}
    preimage = expected_preimage(ACCOUNT_CHAIN, DOCUMENT_HASH, PREVIOUS, sig)
    assert preimage.hex() == VECTOR["account_activation_preimage_hex"]


def test_vector_account_activation_signature_through_the_public_function():
    approval = policy_activation_approval(
        SEED, ACCOUNT_CHAIN, DOCUMENT_HASH, PREVIOUS, signed_at=SIGNED_AT, nonce=NONCE
    )
    assert approval == {
        "signature": VECTOR["account_activation_signature"],
        "signed_at": SIGNED_AT,
        "nonce": NONCE,
    }


def test_vector_account_activation_signature_through_the_signing_helper():
    approval = policy_activation_signature(
        load_signing_key(SEED), ACCOUNT_CHAIN, DOCUMENT_HASH, PREVIOUS, SIGNED_AT, NONCE
    )
    assert approval["signature"] == VECTOR["account_activation_signature"]
    vector_public_key().verify(
        base64.b64decode(approval["signature"]),
        bytes.fromhex(VECTOR["account_activation_preimage_hex"]),
    )


def test_the_account_signature_does_not_verify_for_the_key_chain():
    with pytest.raises(InvalidSignature):
        vector_public_key().verify(
            base64.b64decode(VECTOR["account_activation_signature"]),
            bytes.fromhex(VECTOR["activation_preimage_hex"]),
        )


# ── the shared parity map ─────────────────────────────────────────────────────


def parity_names(column: str) -> list[str]:
    parity = json.loads(PARITY_FILE.read_text(encoding="utf-8"))
    entries = {**parity["routes"], **parity["admin_routes"]}
    return sorted({name for names in entries.values() for name in names[column]})


@pytest.mark.parametrize("name", parity_names("python"))
def test_every_python_name_in_the_parity_map_is_a_sync_method(name):
    assert callable(getattr(VerdifaxClient, name, None)), name


@pytest.mark.parametrize("name", parity_names("python_async"))
def test_every_python_async_name_in_the_parity_map_is_a_coroutine(name):
    method = getattr(AsyncVerdifaxClient, name, None)
    assert inspect.iscoroutinefunction(method), name


ACCOUNT_METHODS = [
    "get_account",
    "create_account_key",
    "list_account_keys",
    "revoke_account_key",
    "register_account_request_key",
    "clear_account_request_key",
    "list_account_runs",
    "export_account_runs",
    "export_account_runs_csv",
    "upload_account_policy",
    "list_account_policies",
    "test_account_policy",
    "get_account_policy_history",
    "get_account_policy",
    "activate_account_policy",
    "admin_create_account",
    "admin_list_accounts",
]


def test_the_parity_map_names_every_account_method_for_both_clients():
    for column in ("python", "python_async"):
        assert set(ACCOUNT_METHODS) <= set(parity_names(column))


@pytest.mark.parametrize("name", ACCOUNT_METHODS + ["admin_create_key"])
def test_the_async_signature_matches_the_sync_one(name):
    sync = inspect.signature(getattr(VerdifaxClient, name))
    async_ = inspect.signature(getattr(AsyncVerdifaxClient, name))
    assert list(sync.parameters) == list(async_.parameters)
    for param in sync.parameters:
        assert sync.parameters[param].default == async_.parameters[param].default


# ── each method: method, path, body and parsing ───────────────────────────────


def test_get_account():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=ACCOUNT), signing_key=None)
    assert client.get_account() == ACCOUNT
    assert (seen[0].method, seen[0].url.path, seen[0].content) == ("GET", "/account", b"")


def test_create_account_key_sends_the_name_and_returns_the_secret():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=MEMBER_KEY, status=201), signing_key=None)
    created = client.create_account_key("payments")
    assert created == MEMBER_KEY
    assert created["secret"] == "vfx_secret"
    assert (seen[0].method, seen[0].url.path) == ("POST", "/account/keys")
    assert sent_body(seen[0]) == {"name": "payments"}


def test_create_account_key_sends_expires_at():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=MEMBER_KEY, status=201), signing_key=None)
    client.create_account_key("payments", expires_at="2027-01-01")
    assert sent_body(seen[0]) == {"name": "payments", "expires_at": "2027-01-01"}


def test_list_account_keys():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=KEYS), signing_key=None)
    assert client.list_account_keys() == KEYS
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/keys")


def test_revoke_account_key():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=REVOKED), signing_key=None)
    assert client.revoke_account_key(21) == REVOKED
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "DELETE",
        "/account/keys/21",
        b"",
    )


def test_revoking_a_key_outside_the_account_raises_the_servers_404():
    seen: list[httpx.Request] = []
    answer = {"error": "no such member key in this account"}
    client = sync_client(responder(seen, body=answer, status=404), signing_key=None)
    with pytest.raises(APIError) as caught:
        client.revoke_account_key(99)
    assert caught.value.status_code == 404
    assert len(seen) == 1


def test_register_account_request_key_sends_the_key_and_its_proof():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"ok": True, "public_key": VECTOR["public_key"]}))
    assert client.register_account_request_key()["public_key"] == VECTOR["public_key"]
    assert (seen[0].method, seen[0].url.path) == ("POST", "/account/request-key")
    assert sent_body(seen[0]) == request_key_body(load_signing_key(SEED))
    assert sent_body(seen[0])["public_key"] == VECTOR["public_key"]


def test_clear_account_request_key_sends_the_approval_and_drops_the_signing_key():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"ok": True}))
    assert client.clear_account_request_key() == {"ok": True}
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/account/request-key")
    change = sent_body(seen[0])["change"]
    preimage = "\x00".join(
        ["verdifax.request-key-change.v1", "", change["signed_at"], change["nonce"]]
    )
    vector_public_key().verify(base64.b64decode(change["signature"]), preimage.encode("utf-8"))
    assert client._signing_key is None


def test_clear_account_request_key_without_a_signing_key_sends_no_body():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"ok": True}), signing_key=None)
    client.clear_account_request_key()
    assert seen[0].content == b""


def test_a_refused_clear_keeps_the_signing_key():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body={"error": "no"}, status=403))
    with pytest.raises(APIError):
        client.clear_account_request_key()
    assert client._signing_key.private_bytes_raw() == SEED


def test_list_account_runs_sends_the_page_and_parses_it():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=RUN_LIST), signing_key=None)
    runs = client.list_account_runs(limit=2, offset=4)
    assert isinstance(runs, RunList)
    assert (runs.total, [run.id for run in runs.runs]) == (9, [7, 8])
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/runs")
    assert dict(seen[0].url.params) == {"limit": "2", "offset": "4"}


def test_list_account_runs_without_a_page_sends_no_query():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=RUN_LIST), signing_key=None).list_account_runs()
    assert dict(seen[0].url.params) == {}


def test_export_account_runs_parses_the_account_fields():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=ACCOUNT_EXPORT), signing_key=None)
    out = client.export_account_runs(
        from_="2026-11-01T00:00:00Z", to="2026-12-01T00:00:00Z", job_id="loan-1"
    )
    assert isinstance(out, AccountRunsExport)
    assert (out.total, out.truncated, out.runs[0].run_id) == (3, True, 1)
    assert out.account_id == ACCOUNT_CHAIN
    assert out.account_policy_documents == [{**UPLOADED, "document": DOCUMENT}]
    assert out.account_policy_history == HISTORY
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/runs/export")
    assert dict(seen[0].url.params) == {
        "format": "json",
        "job_id": "loan-1",
        "from": "2026-11-01T00:00:00Z",
        "to": "2026-12-01T00:00:00Z",
    }


def test_an_account_export_with_no_policy_has_empty_policy_lists():
    client = sync_client(responder([], body={**EXPORT, "account_id": ACCOUNT_CHAIN}))
    out = client.export_account_runs()
    assert (out.account_policy_documents, out.account_policy_history) == ([], [])


def test_a_member_export_keeps_its_policies_and_its_accounts():
    body = {
        **ACCOUNT_EXPORT,
        "policy_documents": [{**UPLOADED, "document": DOCUMENT}],
        "policy_history": HISTORY,
    }
    out = sync_client(responder([], body=body)).export_runs()
    assert out.policy_documents == [{**UPLOADED, "document": DOCUMENT}]
    assert out.policy_history == HISTORY
    assert out.account_id == ACCOUNT_CHAIN
    assert out.account_policy_documents == [{**UPLOADED, "document": DOCUMENT}]
    assert out.account_policy_history == HISTORY


def test_rows_name_the_key_that_requested_each_run():
    body = {
        **ACCOUNT_EXPORT,
        "runs": [{"run_id": 1, "api_key_id": 21}, {"run_id": 2, "api_key_id": 22}],
    }
    out = sync_client(responder([], body=body), signing_key=None).export_account_runs()
    assert [(r.run_id, r.api_key_id) for r in out.runs] == [(1, 21), (2, 22)]
    listed = sync_client(
        responder([], body={**RUN_LIST, "runs": [{"id": 7, "api_key_id": 21}]})
    ).list_runs()
    assert listed.runs[0].api_key_id == 21


def test_export_account_runs_csv():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, text=CSV_TEXT), signing_key=None)
    out = client.export_account_runs_csv(job_id="loan-1")
    assert isinstance(out, RunsExportCSV)
    assert (out.csv, out.total, out.truncated) == (CSV_TEXT, 1, False)
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/runs/export")
    assert dict(seen[0].url.params) == {"format": "csv", "job_id": "loan-1"}


def test_an_account_csv_without_its_counts_is_refused():
    client = sync_client(responder([], text=CSV_TEXT, headers={}), signing_key=None)
    with pytest.raises(VerdifaxError, match="use export_account_runs instead"):
        client.export_account_runs_csv()


def test_upload_account_policy_sends_the_exact_text():
    seen: list[httpx.Request] = []
    document = DOCUMENT + "\r\n  "
    client = sync_client(responder(seen, body=UPLOADED, status=201), signing_key=None)
    assert client.upload_account_policy(document) == UPLOADED
    assert (seen[0].method, seen[0].url.path) == ("POST", "/account/policies")
    assert sent_body(seen[0]) == {"document": document}


def test_list_account_policies():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=ACCOUNT_LISTING), signing_key=None)
    assert client.list_account_policies()["chain_id"] == ACCOUNT_CHAIN
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/policies")


def test_test_account_policy_sends_inputs_with_a_document_or_a_hash():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=TESTED), signing_key=None)
    assert client.test_account_policy({"route_id": "r"}, document=DOCUMENT) == TESTED
    client.test_account_policy({"route_id": "r"}, document_hash=DOCUMENT_HASH)
    assert [(r.method, r.url.path) for r in seen] == [("POST", "/account/policies/test")] * 2
    assert sent_body(seen[0]) == {"inputs": {"route_id": "r"}, "document": DOCUMENT}
    assert sent_body(seen[1]) == {"inputs": {"route_id": "r"}, "document_hash": DOCUMENT_HASH}


def test_get_account_policy_history_returns_the_list_as_sent():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=HISTORY), signing_key=None)
    assert client.get_account_policy_history() == HISTORY
    assert (seen[0].method, seen[0].url.path) == ("GET", "/account/policies/history")


def test_an_account_history_that_is_not_a_list_is_refused():
    client = sync_client(responder([], body={"ok": True}), signing_key=None)
    with pytest.raises(VerdifaxError, match="not a list"):
        client.get_account_policy_history()


def test_get_account_policy():
    seen: list[httpx.Request] = []
    answer = {**UPLOADED, "document": DOCUMENT}
    client = sync_client(responder(seen, body=answer), signing_key=None)
    assert client.get_account_policy(DOCUMENT_HASH) == answer
    assert (seen[0].method, seen[0].url.path) == ("GET", f"/account/policies/{DOCUMENT_HASH}")


def test_admin_create_account():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=CREATED_ACCOUNT, status=201), signing_key=None)
    out = client.admin_create_account("Acme", tier="production", expires_at="2027-01-01")
    assert out == CREATED_ACCOUNT
    assert out["owner_key"]["owner"] is True
    assert (seen[0].method, seen[0].url.path) == ("POST", "/admin/accounts")
    assert sent_body(seen[0]) == {"name": "Acme", "tier": "production", "expires_at": "2027-01-01"}


def test_admin_create_account_leaves_the_tier_to_the_server():
    seen: list[httpx.Request] = []
    sync_client(responder(seen, body=CREATED_ACCOUNT), signing_key=None).admin_create_account("A")
    assert sent_body(seen[0]) == {"name": "A"}


def test_admin_list_accounts():
    seen: list[httpx.Request] = []
    body = {"ok": True, "accounts": [ACCOUNT]}
    assert sync_client(responder(seen, body=body), signing_key=None).admin_list_accounts() == [
        ACCOUNT
    ]
    assert (seen[0].method, seen[0].url.path) == ("GET", "/admin/accounts")


def test_admin_accounts_reads_the_list():
    assert admin_accounts({"ok": True}) == []
    assert admin_accounts({"accounts": []}) == []
    with pytest.raises(VerdifaxError, match="not a list"):
        admin_accounts({"accounts": {"id": 1}})


def test_admin_create_key_puts_the_key_in_an_account():
    seen: list[httpx.Request] = []
    answer = {"ok": True, "id": 22, "secret": "s", "account_id": ACCOUNT_CHAIN}
    client = sync_client(responder(seen, body=answer), signing_key=None)
    assert client.admin_create_key("payments", account_id=7)["account_id"] == ACCOUNT_CHAIN
    assert (seen[0].method, seen[0].url.path) == ("POST", "/admin/keys")
    assert sent_body(seen[0]) == {"name": "payments", "account_id": 7}


def test_admin_create_key_without_an_account_sends_only_the_name():
    seen: list[httpx.Request] = []
    sync_client(responder(seen), signing_key=None).admin_create_key("payments")
    assert sent_body(seen[0]) == {"name": "payments"}


# ── what the methods refuse before sending ────────────────────────────────────


@pytest.mark.parametrize("account_id", [0, -1, True, "7", 7.0])
def test_admin_create_key_refuses_a_bad_account_id(account_id):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="account_id"):
        sync_client(responder(seen)).admin_create_key("payments", account_id=account_id)
    assert seen == []


@pytest.mark.parametrize("name", ["", "   ", None, 7])
def test_account_names_are_required(name):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError, match="name"):
        client.create_account_key(name)
    with pytest.raises(ValidationError, match="name"):
        client.admin_create_account(name)
    assert seen == []


def test_optional_account_fields_must_be_text():
    with pytest.raises(ValidationError, match="expires_at"):
        account_key_body("k", expires_at=20270101)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="tier"):
        admin_account_body("a", tier=1)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="expires_at"):
        admin_account_body("a", expires_at=1)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="name"):
        admin_key_body("")


@pytest.mark.parametrize("key_id", [0, -1, True, "21"])
def test_revoke_account_key_refuses_a_bad_id(key_id):
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="key_id"):
        sync_client(responder(seen)).revoke_account_key(key_id)
    assert seen == []


def test_register_account_request_key_needs_a_signing_key():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen), signing_key=None)
    with pytest.raises(ValidationError, match="register_account_request_key needs"):
        client.register_account_request_key()
    assert seen == []


@pytest.mark.parametrize("bad", ["A" * 64, "a" * 63, "", 7, None])
def test_get_and_activate_account_policy_refuse_a_bad_hash(bad):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError, match="document_hash"):
        client.get_account_policy(bad)
    with pytest.raises(ValidationError, match="document_hash"):
        client.activate_account_policy(bad)
    assert seen == []


def test_upload_account_policy_refuses_a_document_that_is_not_text():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="exact text"):
        sync_client(responder(seen)).upload_account_policy({"rules": []})  # type: ignore[arg-type]
    assert seen == []


def test_test_account_policy_refuses_both_or_neither():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    with pytest.raises(ValidationError, match="exactly one"):
        client.test_account_policy({})
    with pytest.raises(ValidationError, match="exactly one"):
        client.test_account_policy({}, document=DOCUMENT, document_hash=DOCUMENT_HASH)
    assert seen == []


# ── account activation ────────────────────────────────────────────────────────


def test_activate_account_policy_signs_over_the_account_chain():
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, account_activation_answers()))
    assert client.activate_account_policy(DOCUMENT_HASH) == ACCOUNT_ACTIVATION
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account/policies"),
        ("POST", f"/account/policies/{DOCUMENT_HASH}/activate"),
    ]
    body = sent_body(seen[1])
    assert set(body) == {"previous_activation_hash", "signature"}
    assert body["previous_activation_hash"] == NEWEST
    sig = body["signature"]
    assert set(sig) == {"signature", "signed_at", "nonce"}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", sig["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", sig["nonce"])
    signature = base64.b64decode(sig["signature"])
    vector_public_key().verify(
        signature, expected_preimage(ACCOUNT_CHAIN, DOCUMENT_HASH, NEWEST, sig)
    )
    with pytest.raises(InvalidSignature):
        vector_public_key().verify(
            signature, expected_preimage("api-key-7", DOCUMENT_HASH, NEWEST, sig)
        )


def test_a_first_account_activation_reproduces_the_vector():
    listing = {**ACCOUNT_LISTING, "newest_activation_hash": PREVIOUS}
    key = load_signing_key(SEED)
    body = policy_activation_body(key, listing, DOCUMENT_HASH, "GET /account/policies")
    assert body["previous_activation_hash"] == PREVIOUS
    sig = body["signature"]
    vector_public_key().verify(
        base64.b64decode(sig["signature"]),
        expected_preimage(ACCOUNT_CHAIN, DOCUMENT_HASH, PREVIOUS, sig),
    )
    pinned = policy_activation_signature(
        key, listing["chain_id"], DOCUMENT_HASH, PREVIOUS, SIGNED_AT, NONCE
    )
    assert pinned["signature"] == VECTOR["account_activation_signature"]


def test_activate_account_policy_needs_a_signing_key_and_sends_nothing_without_one():
    seen: list[httpx.Request] = []
    client = sync_client(routed(seen, account_activation_answers()), signing_key=None)
    with pytest.raises(ValidationError, match="signing_key"):
        client.activate_account_policy(DOCUMENT_HASH)
    assert seen == []


def test_an_account_listing_with_no_chain_is_refused_and_names_the_route():
    seen: list[httpx.Request] = []
    listing = {**ACCOUNT_LISTING, "chain_id": ""}
    answers = account_activation_answers({("GET", "/account/policies"): listing})
    with pytest.raises(VerdifaxError, match="GET /account/policies returned no chain_id"):
        sync_client(routed(seen, answers)).activate_account_policy(DOCUMENT_HASH)
    assert [r.method for r in seen] == ["GET"]


def test_an_account_listing_with_no_newest_change_is_refused():
    seen: list[httpx.Request] = []
    listing = {**ACCOUNT_LISTING, "newest_activation_hash": None}
    answers = account_activation_answers({("GET", "/account/policies"): listing})
    with pytest.raises(VerdifaxError, match="GET /account/policies did not return"):
        sync_client(routed(seen, answers)).activate_account_policy(DOCUMENT_HASH)
    assert [r.method for r in seen] == ["GET"]


def test_an_account_409_raises_and_is_not_retried():
    seen: list[httpx.Request] = []
    moved = httpx.Response(409, json={"error": "previous_activation_hash is not the newest change"})
    answers = account_activation_answers(
        {("POST", f"/account/policies/{DOCUMENT_HASH}/activate"): moved}
    )
    with pytest.raises(APIError) as caught:
        sync_client(routed(seen, answers)).activate_account_policy(DOCUMENT_HASH)
    assert caught.value.status_code == 409
    assert [r.method for r in seen] == ["GET", "POST"]


def test_the_servers_refusal_of_an_unsigned_change_raises():
    seen: list[httpx.Request] = []
    refused = httpx.Response(403, json={"error": "an account policy change must be signed"})
    answers = account_activation_answers(
        {("POST", f"/account/policies/{DOCUMENT_HASH}/activate"): refused}
    )
    with pytest.raises(APIError) as caught:
        sync_client(routed(seen, answers)).activate_account_policy(DOCUMENT_HASH)
    assert caught.value.status_code == 403


def test_the_key_and_account_activations_use_their_own_routes():
    seen: list[httpx.Request] = []
    answers = {
        **account_activation_answers(),
        ("GET", "/policies"): {**ACCOUNT_LISTING, "chain_id": "api-key-7"},
        ("POST", f"/policies/{DOCUMENT_HASH}/activate"): {"ok": True, "activation": ACTIVATION},
    }
    client = sync_client(routed(seen, answers))
    client.activate_policy(DOCUMENT_HASH)
    client.activate_account_policy(DOCUMENT_HASH)
    key_sig = sent_body(seen[1])["signature"]
    account_sig = sent_body(seen[3])["signature"]
    vector_public_key().verify(
        base64.b64decode(key_sig["signature"]),
        expected_preimage("api-key-7", DOCUMENT_HASH, NEWEST, key_sig),
    )
    vector_public_key().verify(
        base64.b64decode(account_sig["signature"]),
        expected_preimage(ACCOUNT_CHAIN, DOCUMENT_HASH, NEWEST, account_sig),
    )


# ── the async client ──────────────────────────────────────────────────────────


async def test_async_account_methods_send_the_same_requests():
    seen: list[httpx.Request] = []
    answers = [
        ok(ACCOUNT),
        ok(MEMBER_KEY, 201),
        ok(KEYS),
        ok(REVOKED),
        ok({"ok": True, "public_key": VECTOR["public_key"]}),
        ok(RUN_LIST),
        ok(ACCOUNT_EXPORT),
        httpx.Response(
            200,
            text=CSV_TEXT,
            headers={"X-Verdifax-Total": "1", "X-Verdifax-Truncated": "false"},
        ),
        ok(UPLOADED, 201),
        ok(ACCOUNT_LISTING),
        ok(TESTED),
        ok(HISTORY),
        ok({**UPLOADED, "document": DOCUMENT}),
        ok(ACCOUNT_LISTING),
        ok({"ok": True, "activation": ACCOUNT_ACTIVATION}),
        ok(CREATED_ACCOUNT, 201),
        ok({"ok": True, "accounts": [ACCOUNT]}),
        ok({"ok": True, "id": 22, "account_id": ACCOUNT_CHAIN}),
        ok({"ok": True}),
    ]
    async with async_client(scripted(seen, answers)) as client:
        assert await client.get_account() == ACCOUNT
        assert await client.create_account_key("payments", expires_at="2027-01-01") == MEMBER_KEY
        assert await client.list_account_keys() == KEYS
        assert await client.revoke_account_key(21) == REVOKED
        await client.register_account_request_key()
        runs = await client.list_account_runs(limit=2, offset=4)
        export = await client.export_account_runs(from_="2026-11-01T00:00:00Z")
        csv = await client.export_account_runs_csv(job_id="loan-1")
        assert await client.upload_account_policy(DOCUMENT) == UPLOADED
        assert await client.list_account_policies() == ACCOUNT_LISTING
        assert await client.test_account_policy({"route_id": "r"}, document=DOCUMENT) == TESTED
        assert await client.get_account_policy_history() == HISTORY
        assert (await client.get_account_policy(DOCUMENT_HASH))["document"] == DOCUMENT
        assert await client.activate_account_policy(DOCUMENT_HASH) == ACCOUNT_ACTIVATION
        assert await client.admin_create_account("Acme") == CREATED_ACCOUNT
        assert await client.admin_list_accounts() == [ACCOUNT]
        await client.admin_create_key("payments", account_id=7)
        await client.clear_account_request_key()
        assert client._signing_key is None
    assert isinstance(runs, RunList) and runs.total == 9
    assert isinstance(export, AccountRunsExport)
    assert (export.account_id, export.account_policy_history) == (ACCOUNT_CHAIN, HISTORY)
    assert isinstance(csv, RunsExportCSV) and csv.csv == CSV_TEXT
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account"),
        ("POST", "/account/keys"),
        ("GET", "/account/keys"),
        ("DELETE", "/account/keys/21"),
        ("POST", "/account/request-key"),
        ("GET", "/account/runs"),
        ("GET", "/account/runs/export"),
        ("GET", "/account/runs/export"),
        ("POST", "/account/policies"),
        ("GET", "/account/policies"),
        ("POST", "/account/policies/test"),
        ("GET", "/account/policies/history"),
        ("GET", f"/account/policies/{DOCUMENT_HASH}"),
        ("GET", "/account/policies"),
        ("POST", f"/account/policies/{DOCUMENT_HASH}/activate"),
        ("POST", "/admin/accounts"),
        ("GET", "/admin/accounts"),
        ("POST", "/admin/keys"),
        ("DELETE", "/account/request-key"),
    ]
    assert sent_body(seen[1]) == {"name": "payments", "expires_at": "2027-01-01"}
    assert sent_body(seen[4]) == request_key_body(load_signing_key(SEED))
    assert dict(seen[5].url.params) == {"limit": "2", "offset": "4"}
    assert dict(seen[6].url.params) == {"format": "json", "from": "2026-11-01T00:00:00Z"}
    assert dict(seen[7].url.params) == {"format": "csv", "job_id": "loan-1"}
    assert sent_body(seen[8]) == {"document": DOCUMENT}
    assert sent_body(seen[10]) == {"inputs": {"route_id": "r"}, "document": DOCUMENT}
    assert sent_body(seen[15]) == {"name": "Acme"}
    assert seen[16].content == b""
    assert sent_body(seen[17]) == {"name": "payments", "account_id": 7}
    assert set(sent_body(seen[18])) == {"change"}


async def test_async_activate_account_policy_signs_over_the_account_chain():
    seen: list[httpx.Request] = []
    async with async_client(routed(seen, account_activation_answers())) as client:
        assert await client.activate_account_policy(DOCUMENT_HASH) == ACCOUNT_ACTIVATION
    assert [r.method for r in seen] == ["GET", "POST"]
    sig = sent_body(seen[1])["signature"]
    vector_public_key().verify(
        base64.b64decode(sig["signature"]),
        expected_preimage(ACCOUNT_CHAIN, DOCUMENT_HASH, NEWEST, sig),
    )


async def test_async_account_methods_refuse_bad_input_without_a_request():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen), signing_key=None) as client:
        with pytest.raises(ValidationError, match="signing_key"):
            await client.activate_account_policy(DOCUMENT_HASH)
        with pytest.raises(ValidationError, match="document_hash"):
            await client.activate_account_policy("A" * 64)
        with pytest.raises(ValidationError, match="document_hash"):
            await client.get_account_policy("A" * 64)
        with pytest.raises(ValidationError, match="register_account_request_key needs"):
            await client.register_account_request_key()
        with pytest.raises(ValidationError, match="key_id"):
            await client.revoke_account_key(0)
        with pytest.raises(ValidationError, match="name"):
            await client.create_account_key("")
        with pytest.raises(ValidationError, match="name"):
            await client.admin_create_account("")
        with pytest.raises(ValidationError, match="account_id"):
            await client.admin_create_key("payments", account_id=0)
        with pytest.raises(ValidationError, match="exactly one"):
            await client.test_account_policy({})
        with pytest.raises(ValidationError, match="exact text"):
            await client.upload_account_policy(b"rules")  # type: ignore[arg-type]
    assert seen == []


async def test_async_clear_account_request_key_without_a_signing_key_sends_no_body():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body={"ok": True}), signing_key=None) as client:
        await client.clear_account_request_key()
    assert (seen[0].method, seen[0].url.path, seen[0].content) == (
        "DELETE",
        "/account/request-key",
        b"",
    )


async def test_async_an_account_csv_without_its_counts_is_refused():
    async with async_client(responder([], text=CSV_TEXT, headers={}), signing_key=None) as client:
        with pytest.raises(VerdifaxError, match="use export_account_runs instead"):
            await client.export_account_runs_csv()


async def test_async_an_account_history_that_is_not_a_list_is_refused():
    async with async_client(responder([], body={"ok": True}), signing_key=None) as client:
        with pytest.raises(VerdifaxError, match="not a list"):
            await client.get_account_policy_history()


# ── the README ────────────────────────────────────────────────────────────────


def test_the_readme_states_the_account_facts():
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    for sentence in (
        "The account number is a label Verdifax assigned, not a verified company identity.",
        "An account policy is your own. Verdifax did not write, review or approve it.",
        "Every key in the account must pass the account policy on top of its own, "
        "and a run is admitted only when both allow it.",
        "The account's view covers the runs its keys made through Verdifax, "
        "not runs made elsewhere.",
        "An owner key cannot run anything.",
    ):
        assert sentence in readme, sentence
    for name in ACCOUNT_METHODS:
        assert f"`{name}(" in readme, name


def test_a_determinism_answer_keeps_receipts_and_its_reason():
    from verdifax.research import DeterminismResult

    receipt = {"fired_rule_id": "no-restricted", "hash": "aa"}
    out = DeterminismResult.model_validate(
        {
            "ok": True,
            "deterministic": True,
            "first": {
                "run_id": 1,
                "manifest_hash": "m",
                "duration_ms": 0,
                "status": "pepg_deny",
                "receipt": receipt,
            },
            "second": {
                "run_id": 2,
                "manifest_hash": "m",
                "duration_ms": 0,
                "status": "pepg_deny",
                "receipt": receipt,
            },
            "diff": {
                "differs": False,
                "manifest_hash_differs": False,
                "bundle_hash_differs": False,
                "reason": "r",
            },
        }
    )
    assert out.deterministic and out.first.receipt == receipt and out.second.status == "pepg_deny"
    assert out.diff.reason == "r"
