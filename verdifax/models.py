"""Pydantic models for Verdifax API requests, responses, and manifests.

The Verdifax orchestrator's REST API serializes its Go ``ExecutionManifest``
struct using Go's default JSON marshaller, which emits ``PascalCase`` field
names. We expose Pythonic ``snake_case`` attributes here and use Pydantic
field aliases to bridge the two naming styles transparently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

# ── Stage metadata ──────────────────────────────────────────────────────────────
# Names and ordering kept in sync with verdifax-orchestrator/internal/pipeline.
STAGE_NAMES: Tuple[str, ...] = (
    "DOG",
    "DTL",
    "DKEC",
    "AER",
    "ZKSP",
    "PHASE4",
    "LEDGER",
    "REGISTRY",
    "DLA",
)

# Names of the six DKEC kernel execution IDs in their canonical order.
KERNEL_NAMES: Tuple[str, ...] = (
    "DSE",
    "TOK",
    "DSC",
    "NREP",
    "AIVP",
    "DCAE",
)


class _AliasedModel(BaseModel):
    """Base for models that mirror Go-side PascalCase JSON keys."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


class StageResult(_AliasedModel):
    """One stage of the nine-stage pipeline, projected from the manifest.

    Each stage produces one or more hash artifacts. ``StageResult`` groups
    those artifacts together with the stage's ordinal position and short
    name for ergonomic iteration.
    """

    stage_number: int = Field(..., ge=1, le=9, description="1-indexed stage position")
    stage_name: str = Field(..., description="Short stage code, e.g. 'DOG' or 'ZKSP'")
    artifacts: dict[str, Any] = Field(
        default_factory=dict,
        description="Map of artifact-name to hash/value produced by this stage",
    )


class ExecutionManifest(_AliasedModel):
    """The complete cryptographic manifest of one orchestrated pipeline run.

    Every stage writes its output hashes here so the chain can be audited,
    replayed, or anchored into a ``.VFA`` artifact. The ``manifest_hash``
    field seals the entire manifest with SHA-256.
    """

    # Stage 1, DOG: Deterministic Oracle Gateway
    envelope_id: str = Field(..., alias="EnvelopeID")
    envelope_hash: str = Field(..., alias="EnvelopeHash")

    # Stage 2, DTL: Deterministic Transport Layer
    sequence_id: str = Field(..., alias="SequenceID")
    transport_hash: str = Field(..., alias="TransportHash")

    # Stage 3, DKEC: Deterministic Kernel Execution Controller
    epa_hash: str = Field(..., alias="EpaHash")
    efa_hash: str = Field(..., alias="EfaHash")
    execution_ids: List[str] = Field(
        ...,
        alias="ExecutionIDs",
        description="Six DKEC kernel IDs in order: DSE, TOK, DSC, NREP, AIVP, DCAE",
        min_length=6,
        max_length=6,
    )

    # Stage 4, AER: Attestation Execution Record
    aer_hash: str = Field(..., alias="AerHash")

    # Stage 5, ZKSP L7→L10
    transcript_hash: str = Field(..., alias="TranscriptHash")
    hardware_attestation_hash: str = Field(..., alias="HardwareAttestationHash")
    leakage_bundle_hash: str = Field(..., alias="LeakageBundleHash")
    formal_verifier_status: str = Field(..., alias="FormalVerifierStatus")

    # Stage 6, Proof & State Binding
    zksp_binding_hash: str = Field(..., alias="ZkspBindingHash")
    migration_token_hash: str = Field(..., alias="MigrationTokenHash")
    replay_fingerprint: str = Field(..., alias="ReplayFingerprint")

    # Stage 7, Ledger
    pote_proof_hash: str = Field(..., alias="PoteProofHash")
    log_entry_id: str = Field(..., alias="LogEntryID")

    # Stage 8, Artifact Registry
    registry_artifact_count: int = Field(..., alias="RegistryArtifactCount", ge=0)

    # Stage 9, DLA / .VFA
    final_vfa_hash: str = Field(..., alias="FinalVfaHash")
    independent_verified: bool = Field(..., alias="IndependentVerified")

    # Sealing hash
    manifest_hash: str = Field(..., alias="ManifestHash")

    def kernel_executions(self) -> dict[str, str]:
        """Return a name→ID map for the six DKEC kernels."""
        return dict(zip(KERNEL_NAMES, self.execution_ids))

    def stages(self) -> List[StageResult]:
        """Project the manifest into a list of nine ``StageResult`` objects."""
        return [
            StageResult(
                stage_number=1,
                stage_name="DOG",
                artifacts={
                    "envelope_id": self.envelope_id,
                    "envelope_hash": self.envelope_hash,
                },
            ),
            StageResult(
                stage_number=2,
                stage_name="DTL",
                artifacts={
                    "sequence_id": self.sequence_id,
                    "transport_hash": self.transport_hash,
                },
            ),
            StageResult(
                stage_number=3,
                stage_name="DKEC",
                artifacts={
                    "epa_hash": self.epa_hash,
                    "efa_hash": self.efa_hash,
                    **{
                        f"execution_id_{name}": exec_id
                        for name, exec_id in self.kernel_executions().items()
                    },
                },
            ),
            StageResult(
                stage_number=4,
                stage_name="AER",
                artifacts={"aer_hash": self.aer_hash},
            ),
            StageResult(
                stage_number=5,
                stage_name="ZKSP",
                artifacts={
                    "transcript_hash": self.transcript_hash,
                    "hardware_attestation_hash": self.hardware_attestation_hash,
                    "leakage_bundle_hash": self.leakage_bundle_hash,
                    "formal_verifier_status": self.formal_verifier_status,
                },
            ),
            StageResult(
                stage_number=6,
                stage_name="PHASE4",
                artifacts={
                    "zksp_binding_hash": self.zksp_binding_hash,
                    "migration_token_hash": self.migration_token_hash,
                    "replay_fingerprint": self.replay_fingerprint,
                },
            ),
            StageResult(
                stage_number=7,
                stage_name="LEDGER",
                artifacts={
                    "pote_proof_hash": self.pote_proof_hash,
                    "log_entry_id": self.log_entry_id,
                },
            ),
            StageResult(
                stage_number=8,
                stage_name="REGISTRY",
                artifacts={"registry_artifact_count": self.registry_artifact_count},
            ),
            StageResult(
                stage_number=9,
                stage_name="DLA",
                artifacts={
                    "final_vfa_hash": self.final_vfa_hash,
                    "independent_verified": self.independent_verified,
                },
            ),
        ]

    def __iter__(self) -> Iterator[StageResult]:  # type: ignore[override]
        return iter(self.stages())


class AttestationReceipt(_AliasedModel):
    """Top-level receipt returned from a successful ``attest`` call.

    ``manifest_hash`` is exposed at the top level for ergonomic access; it
    is identical to ``manifest.manifest_hash`` and is the value that should
    be persisted alongside the original payload for audit purposes.

    When the API server has SQLite persistence enabled (Phase 3+), the
    response also carries a server-side ``run_id`` that can be passed to
    the compliance endpoints (``GET /runs/{id}``, ``/runs/{id}/verify``,
    ``/runs/{id}/report.pdf``) to fetch full audit artifacts.
    """

    ok: bool = True
    run_id: Optional[int] = Field(
        default=None, description="server-side run ID from /runs (Phase 3+)"
    )
    duration_ms: int = Field(..., ge=0)
    manifest_hash: str
    manifest: ExecutionManifest
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_api_response(cls, body: dict[str, Any]) -> "AttestationReceipt":
        """Construct a receipt from a raw POST /execute response body."""
        manifest = ExecutionManifest.model_validate(body["manifest"])
        return cls(
            ok=bool(body.get("ok", True)),
            run_id=body.get("run_id"),
            duration_ms=int(body.get("duration_ms", 0)),
            manifest_hash=manifest.manifest_hash,
            manifest=manifest,
        )


class AttestedContext(_AliasedModel):
    """Caller-supplied "what was happening when this run was triggered".

    Verdifax does not call an AI or evaluate a business policy itself ,
    it produces a sealed manifest of what the *caller* did. The
    ``attested_context`` block is recorded verbatim into the EPA audit
    artifact for the run, becoming a permanent part of the audit
    projection (visible on the dashboard and the audit PDF).

    Every field is optional. When omitted entirely, the bundle records
    ``attested: false`` and the EPA's actor / model fields read as
    ``self_attested_deterministic``, meaning "the caller did not declare
    a human actor or AI model; the run is the deterministic pipeline
    alone."

    Mirrors ``internal/artifacts.AttestedContext`` in the orchestrator;
    the field set is the source of truth there. The SDK's
    :meth:`AttestedContext.with_auto_attested` helper sets ``attested =
    True`` automatically when any other field carries a value, matching
    the orchestrator's convention.
    """

    attested: bool = Field(
        default=False,
        description="True when the caller supplied at least one field.",
    )

    # Actor, who initiated the action.
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    authorization_policy: Optional[str] = None
    actor_signature: Optional[str] = Field(
        default=None,
        description="Base64-encoded signature, optional.",
    )

    # Model, which AI (if any) the caller invoked before /execute.
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    model_temperature: Optional[float] = None
    prompt_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hex of the prompt the model received.",
    )

    # Decision, the caller's interpretation of the result.
    decision_kind: Optional[str] = Field(
        default=None,
        description='Free-form, e.g. "approve", "deny", "advise".',
    )
    decision_result: Optional[str] = Field(
        default=None,
        description='Free-form, e.g. "approved".',
    )
    decision_note: Optional[str] = None

    # Forbid pydantic frozen behavior here, callers will mutate fields
    # while building the block, then hand it off. We keep validation but
    # not immutability.
    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",
        frozen=False,
    )

    def with_auto_attested(self) -> "AttestedContext":
        """Return a copy with ``attested = True`` if any other field is set.

        This matches the orchestrator's convention: ``attested`` is the
        boolean "did the caller declare anything?" and is computed from
        the presence of the other fields rather than being something
        the caller has to remember to set.
        """
        # Pydantic v2.11+ deprecates accessing model_fields on the
        # instance, must access through the class instead. Resolved
        # via type(self) so the same code path works for any subclass.
        any_set = any(
            getattr(self, fld) not in (None, "", False)
            for fld in type(self).model_fields
            if fld != "attested"
        )
        return self.model_copy(update={"attested": bool(any_set)})


class ExecuteRequest(_AliasedModel):
    """Body of POST /execute.

    Exactly one of ``payload_text`` or ``payload`` must be provided. The
    Verdifax API treats ``payload_text`` as a UTF-8 string and ``payload``
    as raw bytes.

    ``attested_context`` is optional. When supplied, the orchestrator
    records the block verbatim into the EPA audit artifact for the run.
    See :class:`AttestedContext` for the schema.
    """

    payload_text: Optional[str] = Field(default=None)
    payload: Optional[str] = Field(default=None)
    program_id: str
    route_id: str
    registry_record_hash: str
    attested_context: Optional[AttestedContext] = Field(
        default=None,
        description="Caller-attested actor / model / decision block (optional).",
    )
    # Reproducibility context, caller-declared runtime fingerprint
    # (container image hash, runtime version, pinned deps, git SHA,
    # random seeds, platform). Optional. Serialized to the JSON
    # field "reproducibility_context" which the orchestrator binds
    # into the audit bundle (Category 6). Built via
    # :func:`verdifax.research.capture_environment` or constructed
    # manually. Typed as ``dict`` here to avoid a forward import on
    # ``verdifax.research``; the structure is validated server-side.
    reproducibility_context: Optional[dict[str, Any]] = Field(
        default=None,
        description="Caller-declared runtime fingerprint (optional).",
    )

    def model_dump_request(self) -> dict[str, Any]:
        """Serialize to the JSON shape the API expects (snake_case, no nulls)."""
        data = self.model_dump(exclude_none=True)
        return data


__all__ = [
    "AttestationReceipt",
    "AttestedContext",
    "ExecuteRequest",
    "ExecutionManifest",
    "KERNEL_NAMES",
    "STAGE_NAMES",
    "StageResult",
]
