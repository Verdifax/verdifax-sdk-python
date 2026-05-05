"""Tests for Pydantic model serialization and deserialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from verdifax.models import (
    KERNEL_NAMES,
    STAGE_NAMES,
    AttestationReceipt,
    AttestedContext,
    ExecuteRequest,
    ExecutionManifest,
    StageResult,
)
from tests.conftest import make_execute_response, make_manifest_dict


def test_manifest_parses_pascal_case_keys(manifest_dict):
    manifest = ExecutionManifest.model_validate(manifest_dict)
    assert manifest.envelope_id == "env-0001"
    assert manifest.formal_verifier_status == "VERIFIED_SOUND_COMPLETE_ZK"
    assert manifest.registry_artifact_count == 18
    assert manifest.independent_verified is True
    assert manifest.manifest_hash == "9" * 64
    assert manifest.execution_ids == [
        "dse-id",
        "tok-id",
        "dsc-id",
        "nrep-id",
        "aivp-id",
        "dcae-id",
    ]


def test_manifest_kernel_executions_map_uses_canonical_names(manifest_dict):
    manifest = ExecutionManifest.model_validate(manifest_dict)
    kernels = manifest.kernel_executions()
    assert list(kernels.keys()) == list(KERNEL_NAMES)
    assert kernels["DSE"] == "dse-id"
    assert kernels["DCAE"] == "dcae-id"


def test_manifest_stages_returns_nine_in_order(manifest_dict):
    manifest = ExecutionManifest.model_validate(manifest_dict)
    stages = manifest.stages()
    assert len(stages) == 9
    assert [s.stage_name for s in stages] == list(STAGE_NAMES)
    assert [s.stage_number for s in stages] == list(range(1, 10))


def test_manifest_iter_yields_stage_results(manifest_dict):
    manifest = ExecutionManifest.model_validate(manifest_dict)
    stages = list(manifest)
    assert len(stages) == 9
    assert all(isinstance(s, StageResult) for s in stages)


def test_manifest_rejects_short_execution_ids(manifest_dict):
    manifest_dict = dict(manifest_dict)
    manifest_dict["ExecutionIDs"] = ["only-one"]
    with pytest.raises(PydanticValidationError):
        ExecutionManifest.model_validate(manifest_dict)


def test_manifest_round_trip_preserves_fields(manifest_dict):
    manifest = ExecutionManifest.model_validate(manifest_dict)
    dumped = manifest.model_dump(by_alias=True)
    re_parsed = ExecutionManifest.model_validate(dumped)
    assert manifest == re_parsed


def test_manifest_dump_uses_snake_case_when_no_alias_requested(manifest_dict):
    manifest = ExecutionManifest.model_validate(manifest_dict)
    dumped = manifest.model_dump()
    assert "envelope_id" in dumped
    assert "EnvelopeID" not in dumped


def test_attestation_receipt_from_api_response_extracts_manifest_hash():
    response = make_execute_response(manifest_hash="f" * 64)
    receipt = AttestationReceipt.from_api_response(response)
    assert receipt.ok is True
    assert receipt.duration_ms == 42
    assert receipt.manifest_hash == "f" * 64
    assert receipt.manifest.manifest_hash == "f" * 64
    assert receipt.received_at.tzinfo is not None


def test_stage_result_rejects_out_of_range_number():
    with pytest.raises(PydanticValidationError):
        StageResult(stage_number=0, stage_name="DOG", artifacts={})
    with pytest.raises(PydanticValidationError):
        StageResult(stage_number=10, stage_name="DOG", artifacts={})


def test_manifest_rejects_negative_artifact_count(manifest_dict):
    manifest_dict = dict(manifest_dict)
    manifest_dict["RegistryArtifactCount"] = -1
    with pytest.raises(PydanticValidationError):
        ExecutionManifest.model_validate(manifest_dict)


# ── AttestedContext ────────────────────────────────────────────────────────

def test_attested_context_default_is_unattested():
    ctx = AttestedContext()
    assert ctx.attested is False
    assert ctx.actor_id is None


def test_attested_context_round_trip_omits_unset_fields():
    ctx = AttestedContext(
        actor_id="user-42",
        actor_role="compliance_officer",
        decision_kind="approve",
        decision_result="approved",
    )
    dumped = ctx.model_dump(exclude_none=True)
    # `attested` is defaulted to False, so it stays in the dump unless the
    # caller went through with_auto_attested(); other unset optionals drop out.
    assert "actor_id" in dumped
    assert "model_provider" not in dumped
    assert "decision_kind" in dumped


def test_attested_context_with_auto_attested_sets_flag_when_any_field_set():
    ctx = AttestedContext(actor_id="user-42").with_auto_attested()
    assert ctx.attested is True
    # Everything else should be preserved.
    assert ctx.actor_id == "user-42"


def test_attested_context_with_auto_attested_leaves_flag_false_when_empty():
    ctx = AttestedContext().with_auto_attested()
    assert ctx.attested is False


def test_attested_context_serializes_temperature_as_float():
    ctx = AttestedContext(model_temperature=0.2)
    dumped = ctx.model_dump(exclude_none=True)
    assert dumped["model_temperature"] == 0.2


def test_execute_request_serializes_attested_context_block():
    ctx = AttestedContext(actor_id="user-1", decision_kind="approve").with_auto_attested()
    req = ExecuteRequest(
        payload_text="hello",
        program_id="a" * 64,
        route_id="r",
        registry_record_hash="b" * 64,
        attested_context=ctx,
    )
    body = req.model_dump_request()
    assert "attested_context" in body
    block = body["attested_context"]
    assert block["attested"] is True
    assert block["actor_id"] == "user-1"
    assert block["decision_kind"] == "approve"
    # Unset optional fields must NOT be sent (saves bytes; matches Go's
    # `,omitempty` JSON tags).
    assert "model_provider" not in block
    assert "actor_signature" not in block


def test_execute_request_omits_attested_context_when_absent():
    req = ExecuteRequest(
        payload_text="hello",
        program_id="a" * 64,
        route_id="r",
        registry_record_hash="b" * 64,
    )
    body = req.model_dump_request()
    assert "attested_context" not in body
