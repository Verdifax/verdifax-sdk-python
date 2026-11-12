"""No silently dropped request field (SDK 1.2 spec, section 7).

The server ignores a key it does not know, so a misspelt field would be
dropped with no error. The client refuses it instead. Requests go to
``httpx.MockTransport``, so nothing reaches the network.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any, Mapping

import httpx
import pytest

import verdifax
from tests.conftest import make_execute_response, make_manifest_dict
from tests.test_jobs import ARGS, SEED, async_client, sync_client
from tests.test_parity import BATCH, DETERMINISM, responder
from tests.test_signing import INPUTS
from verdifax import (
    AsyncVerdifaxClient,
    AttestationReceipt,
    AttestedContext,
    ExecuteBatchResponse,
    ExecuteRequest,
    ExecutionManifest,
    Run,
    ValidationError,
    VerdifaxClient,
    VerifyResponse,
)
from verdifax._requests import attested_block, batch_body, batch_row
from verdifax._validation import ATTESTED_CONTEXT_FIELDS, EXECUTE_FIELDS
from verdifax.research import DeterminismResult, ReproducibilityContext, determinism_body

# A copy of the shared scripts/sdk-parity.json, held identical to it by a
# replay rule, so this check runs in CI.
PARITY_FILE = Path(__file__).parent / "sdk-parity.json"
SPEC_ATTESTED_FIELDS = [
    "attested",
    "actor_id",
    "actor_role",
    "authorization_policy",
    "actor_signature",
    "model_provider",
    "model_name",
    "model_version",
    "model_temperature",
    "prompt_hash",
    "decision_kind",
    "decision_result",
    "decision_note",
]
# Sent by the client itself when it signs, so no caller argument names them.
_SIGNED_FORM_FIELDS = {"request_signature", "signed_request"}


# ── the lists ─────────────────────────────────────────────────────────────────


def test_the_execute_field_list_equals_the_shared_parity_file():
    shared = json.loads(PARITY_FILE.read_text(encoding="utf-8"))["execute_fields"]
    assert sorted(EXECUTE_FIELDS) == sorted(shared)
    assert len(EXECUTE_FIELDS) == len(set(EXECUTE_FIELDS)) == len(shared)


def test_the_execute_request_model_has_every_field_a_caller_sets():
    assert set(ExecuteRequest.model_fields) == set(EXECUTE_FIELDS) - _SIGNED_FORM_FIELDS


@pytest.mark.parametrize("method", ["attest", "execute"])
@pytest.mark.parametrize("client_class", [VerdifaxClient, AsyncVerdifaxClient])
def test_every_run_argument_is_an_execute_field(client_class, method):
    names = set(inspect.signature(getattr(client_class, method)).parameters) - {"self"}
    assert names == set(EXECUTE_FIELDS) - _SIGNED_FORM_FIELDS - {"payload_text"}


@pytest.mark.parametrize("client_class", [VerdifaxClient, AsyncVerdifaxClient])
def test_every_determinism_argument_is_an_execute_field(client_class):
    names = set(inspect.signature(client_class.verify_determinism).parameters) - {"self"}
    assert names <= set(EXECUTE_FIELDS)


def test_the_attested_context_list_is_the_spec_list_and_the_model():
    assert list(ATTESTED_CONTEXT_FIELDS) == SPEC_ATTESTED_FIELDS
    assert list(AttestedContext.model_fields) == SPEC_ATTESTED_FIELDS


# ── request models refuse an unknown field ───────────────────────────────────


def test_execute_request_refuses_an_unknown_field_naming_it():
    with pytest.raises(ValidationError, match="ExecuteRequest has unknown fields: polcy_context"):
        ExecuteRequest(payload_text="hello", **INPUTS, polcy_context={})


def test_execute_request_refuses_a_nested_unknown_attested_field():
    with pytest.raises(ValidationError, match="AttestedContext has unknown fields: actorid"):
        ExecuteRequest(payload_text="hello", **INPUTS, attested_context={"actorid": "a"})


def test_execute_request_refuses_the_signed_form_fields():
    # The client builds those itself when it signs.
    with pytest.raises(ValidationError, match="signed_request"):
        ExecuteRequest(payload_text="hello", **INPUTS, signed_request="{}")


@pytest.mark.parametrize("typo", ["actorid", "model", "decision", "Attested"])
def test_attested_context_refuses_an_unknown_field_naming_it(typo):
    with pytest.raises(ValidationError, match=f"AttestedContext has unknown fields: {typo}"):
        AttestedContext(**{typo: "x"})


def test_attested_context_accepts_every_listed_field():
    values: dict[str, Any] = {name: "x" for name in SPEC_ATTESTED_FIELDS}
    values["attested"] = True
    values["model_temperature"] = 0.2
    assert AttestedContext(**values).model_dump()["decision_note"] == "x"


def test_reproducibility_context_refuses_an_unknown_field_naming_it():
    with pytest.raises(ValidationError, match="ReproducibilityContext has unknown fields: runtime"):
        ReproducibilityContext(runtime="python")


def test_a_model_built_with_model_validate_refuses_too():
    with pytest.raises(ValidationError, match="jobb"):
        ExecuteRequest.model_validate({"payload_text": "hello", **INPUTS, "jobb": {}})


def test_the_error_is_the_sdks_own():
    with pytest.raises(verdifax.VerdifaxError):
        AttestedContext(actorid="a")


# ── response models keep ignoring unknown fields ─────────────────────────────


def test_response_models_ignore_a_field_a_newer_server_adds():
    manifest = {**make_manifest_dict(), "NewServerField": 1}
    assert ExecutionManifest.model_validate(manifest).manifest_hash
    receipt = AttestationReceipt.from_api_response({**make_execute_response(), "added": True})
    assert receipt.manifest_hash
    run = Run.model_validate(
        {"id": 1, "created_at": "2026-11-07T00:00:00Z", "status": "ok", "added": 1}
    )
    assert run.id == 1
    VerifyResponse.model_validate({"ok": True, "verified": True, "added": "x"})
    ExecuteBatchResponse.model_validate({**BATCH, "added": 1})
    DeterminismResult.model_validate({**DETERMINISM, "added": 1})


# ── mapping rows and dict blocks refuse an unknown key ───────────────────────


@pytest.mark.parametrize("typo", ["jobb", "policy_contxt", "attested_contxt", "programid"])
@pytest.mark.parametrize("signing_key", [SEED, None], ids=["signed", "unsigned"])
def test_a_batch_row_with_an_unknown_key_is_refused_before_sending(typo, signing_key):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH), signing_key=signing_key)
    with pytest.raises(ValidationError, match=f"run has unknown fields: {typo}"):
        client.execute_batch([ARGS, {**ARGS, typo: {}}])
    assert seen == []


async def test_async_batch_row_with_an_unknown_key_is_refused_before_sending():
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=BATCH)) as client:
        with pytest.raises(ValidationError, match="expected_policy_hsh"):
            await client.execute_batch([{**ARGS, "expected_policy_hsh": "f" * 64}])
    assert seen == []


def test_a_batch_row_may_use_every_listed_name():
    row = {name: None for name in EXECUTE_FIELDS}
    row.update(ARGS)
    body = batch_row(row)
    assert set(body) <= set(EXECUTE_FIELDS)


def test_a_batch_row_attested_context_mapping_refuses_an_unknown_key():
    row = {**ARGS, "attested_context": {"actor_id": "a", "actorrole": "b"}}
    with pytest.raises(ValidationError, match="attested_context has unknown fields: actorrole"):
        batch_body([row])


def test_a_batch_row_attested_context_mapping_with_listed_keys_passes():
    row = {**ARGS, "attested_context": {"actor_id": "a", "decision_kind": "approve"}}
    sent = batch_body([row])["runs"][0]
    assert sent["attested_context"] == {
        "actor_id": "a",
        "decision_kind": "approve",
        "attested": True,
    }


def test_a_batch_row_model_still_passes():
    row = ExecuteRequest(payload_text="hello", **INPUTS, attested_context=AttestedContext())
    assert batch_body([row])["runs"][0]["program_id"] == INPUTS["program_id"]


def test_the_determinism_check_refuses_an_unknown_attested_context_key():
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=DETERMINISM))
    with pytest.raises(ValidationError, match="attested_context has unknown fields: modelname"):
        client.verify_determinism(
            "hello", **INPUTS, attested_context={"modelname": "m"}  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError):
        determinism_body("hello", **INPUTS, attested_context={"modelname": "m"})  # type: ignore[arg-type]
    assert seen == []


def test_attested_block_refuses_an_unknown_key_and_derives_the_flag():
    with pytest.raises(ValidationError):
        attested_block({"actor": "a"})
    assert attested_block({"actor_id": "a"}) == {"actor_id": "a", "attested": True}


# ── keyword arguments are checked by Python itself ───────────────────────────


@pytest.mark.parametrize("method", ["attest", "execute", "verify_determinism"])
def test_a_misspelt_keyword_raises_type_error_naming_it(method):
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen))
    call = getattr(client, method)
    with pytest.raises(TypeError, match="polcy_context"):
        if method == "verify_determinism":
            call("hello", **INPUTS, polcy_context={})
        else:
            call(**ARGS, polcy_context={})
    assert seen == []


def test_a_job_step_refuses_a_misspelt_option_with_the_sdks_error():
    seen: list[httpx.Request] = []
    with pytest.raises(ValidationError, match="polcy_context"):
        sync_client(responder(seen)).job("j").step("s", **ARGS, polcy_context={})
    assert seen == []


# ── every body the SDK builds holds only fields the server defines ───────────
#
# Since round 60 the server refuses a field it does not define in a run body
# (400, naming it), unless the request asks lenient=1. These read the
# server's own structs when its source is beside this repository, and build
# each body with every block the SDK itself fills, signed and unsigned.

ORCHESTRATOR = Path(__file__).parent.parent.parent / "verdifax-orchestrator"


def server_fields(relative: str, struct: str) -> set[str]:
    """The JSON names of one Go struct in the orchestrator's source."""
    path = ORCHESTRATOR / relative
    if not path.exists():
        pytest.skip("the orchestrator source is not beside this repository")
    text = path.read_text(encoding="utf-8")
    body = re.search(rf"^type {struct} struct \{{\n(.*?)^\}}", text, re.M | re.S)
    assert body is not None, struct
    return {
        tag.split(",")[0]
        for tag in re.findall(r'^\s*\w+\s+[^`\n]+`json:"([^"]+)"', body.group(1), re.M)
        if tag.split(",")[0] != "-"
    }


def server_shape() -> dict[str, set[str]]:
    return {
        "": server_fields("internal/api/server.go", "executeRequest"),
        "request_signature": server_fields(
            "internal/api/request_signature.go", "requestSignatureInput"
        ),
        "job": server_fields("internal/artifacts/job.go", "JobLink"),
        "policy_context": server_fields("internal/api/policy_gate.go", "policyContextInput"),
        "policy_context.data_quality": server_fields("internal/psleval/inputs.go", "DataQuality"),
        "policy_context.data_quality.checks": server_fields(
            "internal/psleval/inputs.go", "DataCheck"
        ),
        "attested_context": server_fields("internal/artifacts/types.go", "AttestedContext"),
        "reproducibility_context": server_fields(
            "internal/artifacts/category6_reproducibility.go", "ReproducibilityContext"
        ),
    }


def assert_server_fields(
    body: Mapping[str, Any], shape: dict[str, set[str]], where: str = ""
) -> None:
    unknown = set(body) - shape[where]
    assert not unknown, (where or "body", sorted(unknown))
    for name, value in body.items():
        place = f"{where}.{name}" if where else name
        if place not in shape:
            continue
        for item in value if isinstance(value, list) else [value]:
            assert_server_fields(item, shape, place)


def assert_run_body(sent: Mapping[str, Any], shape: dict[str, set[str]], signed: bool) -> None:
    if signed:
        assert set(sent) == {"signed_request", "request_signature"}
        assert_server_fields(sent, shape)
        inner = json.loads(sent["signed_request"])
        assert "signed_request" not in inner and "request_signature" not in inner
        assert_server_fields(inner, shape)
    else:
        assert_server_fields(sent, shape)


FULL_RUN: dict[str, Any] = {
    **ARGS,
    "ai_output_text": "answer",
    "attested_context": AttestedContext(actor_id="u-1", model_temperature=0.2),
    "reproducibility_context": ReproducibilityContext(runtime_name="cpython", random_seeds=["a=1"]),
    "policy_context": {
        "actor_type": "user",
        "mfa_satisfied": True,
        "session_age_seconds": 5,
        "object_type": "text",
        "object_id": "o",
        "classification": "PUBLIC",
        "data_quality": {
            "source": "crm",
            "as_of": "2026-11-11T09:00:00Z",
            "checks": [{"name": "rows", "result": "pass"}],
        },
    },
    "expected_policy_hash": "e" * 64,
}


def test_the_sdks_field_lists_equal_the_servers_structs():
    from verdifax._validation import (
        _DATA_CHECK_FIELDS,
        _DATA_QUALITY_FIELDS,
        _JOB_FIELDS,
        _POLICY_CONTEXT_FIELDS,
    )

    shape = server_shape()
    assert set(EXECUTE_FIELDS) == shape[""]
    assert set(ATTESTED_CONTEXT_FIELDS) == shape["attested_context"]
    assert set(_POLICY_CONTEXT_FIELDS) == shape["policy_context"]
    assert set(_DATA_QUALITY_FIELDS) == shape["policy_context.data_quality"]
    assert set(_DATA_CHECK_FIELDS) == shape["policy_context.data_quality.checks"]
    assert set(_JOB_FIELDS) == shape["job"]
    # The server's hash is computed by the server, so the model leaves it out.
    assert set(ReproducibilityContext.model_fields) == shape["reproducibility_context"] - {"hash"}


@pytest.mark.parametrize("signing_key", [SEED, None], ids=["signed", "unsigned"])
def test_attest_and_a_job_step_send_only_server_fields(signing_key):
    shape = server_shape()
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=make_execute_response()), signing_key=signing_key)
    client.attest(**FULL_RUN)
    client.job("job-1").step("step-1", external_previous=["f" * 64], **FULL_RUN, final=True)
    assert len(seen) == 2
    for request in seen:
        assert_run_body(json.loads(request.content), shape, signing_key is not None)


@pytest.mark.parametrize("signing_key", [SEED, None], ids=["signed", "unsigned"])
def test_a_batch_sends_only_server_fields(signing_key):
    shape = server_shape()
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=BATCH), signing_key=signing_key)
    row = {key: value for key, value in FULL_RUN.items() if key != "attested_context"}
    row["attested_context"] = {"actor_id": "u-1"}
    model_row = ExecuteRequest(payload_text="hello", **INPUTS, attested_context=AttestedContext())
    client.execute_batch([row, model_row, {**ARGS, "payload": b"\xff\x00"}])
    sent = json.loads(seen[0].content)
    assert set(sent) == {"runs"}
    for run in sent["runs"]:
        assert_run_body(run, shape, signing_key is not None)


@pytest.mark.parametrize("signing_key", [SEED, None], ids=["signed", "unsigned"])
def test_a_determinism_check_sends_only_server_fields(signing_key):
    shape = server_shape()
    seen: list[httpx.Request] = []
    client = sync_client(responder(seen, body=DETERMINISM), signing_key=signing_key)
    args = {key: value for key, value in FULL_RUN.items() if key not in INPUTS and key != "payload"}
    client.verify_determinism("hello", **INPUTS, **args)
    assert_run_body(json.loads(seen[0].content), shape, signing_key is not None)


async def test_async_run_bodies_send_only_server_fields():
    shape = server_shape()
    seen: list[httpx.Request] = []
    async with async_client(responder(seen, body=make_execute_response())) as client:
        await client.attest(**FULL_RUN)
    assert_run_body(json.loads(seen[0].content), shape, True)
