"""Pydantic models for Verdifax API requests, responses, and manifests.

The Verdifax orchestrator's REST API serializes its Go ``ExecutionManifest``
struct using Go's default JSON marshaller, which emits ``PascalCase`` field
names. We expose Pythonic ``snake_case`` attributes here and use Pydantic
field aliases to bridge the two naming styles transparently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .exceptions import ValidationError

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


# Every status the server gives a run. A newer server may add others, so
# the models type ``status`` as a plain string.
RUN_STATUSES: Tuple[str, ...] = (
    "ok",
    "probe",
    "pepg_deny",
    "ccv_halt",
    "macc_halt",
    "aivp_t4_halt",
    "attestation_gap",
    "stage_error",
)


def is_provided(value: Any) -> bool:
    """A field counts as provided unless it is ``None``, empty text or ``False``."""
    return value is not None and value is not False and value != ""


class _AliasedModel(BaseModel):
    """Base for models that mirror Go-side PascalCase JSON keys."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


def refuse_unknown_fields(model: type[BaseModel], data: Any) -> Any:
    """Refuse a field a request model does not have, naming it.

    The server ignores a key it does not know, so a misspelt field would be
    dropped with no error. Response models keep ignoring unknown fields, as a
    newer server may add some.

    Raises:
        ValidationError: The SDK's own error, which pydantic passes through.
    """
    if isinstance(data, dict):
        known = set(model.model_fields)
        known.update(info.alias for info in model.model_fields.values() if info.alias)
        unknown = sorted(str(name) for name in data if name not in known)
        if unknown:
            raise ValidationError(f"{model.__name__} has unknown fields: {', '.join(unknown)}")
    return data


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
    record_hash: Optional[str] = Field(
        default=None,
        description=(
            "the hash that places this run in a job map: the response's record_hash, "
            "then its top-level manifest_hash, then the manifest's own hash"
        ),
    )
    signed_request: Optional[str] = Field(
        default=None,
        description="the exact signed text, for verdifax-verify --request, when signed",
    )

    @classmethod
    def from_api_response(
        cls, body: dict[str, Any], signed_request: Optional[str] = None
    ) -> "AttestationReceipt":
        """Construct a receipt from a raw POST /execute response body."""
        manifest = ExecutionManifest.model_validate(body["manifest"])
        return cls(
            ok=bool(body.get("ok", True)),
            run_id=body.get("run_id"),
            duration_ms=int(body.get("duration_ms", 0)),
            manifest_hash=manifest.manifest_hash,
            manifest=manifest,
            record_hash=(
                body.get("record_hash")
                or body.get("manifest_hash")
                or manifest.manifest_hash
                or None
            ),
            signed_request=signed_request,
        )


class DCAEEngineHint(_AliasedModel):
    """Pointer to the orchestrator's DCAE verification endpoint and engine version.

    Returned inside :class:`VerifyResponse` so a caller that wants to
    go on to DCAE proof-bundle verification knows where to send it.
    """

    available_at: str = ""
    engine_version: str = ""


class VerifyResponse(_AliasedModel):
    """Response body of ``GET /runs/{id}/verify``.

    Mirrors ``VerifyResponse`` in the Go and Node SDKs. For a run that
    completed, the orchestrator loads the run's stored manifest,
    re-derives the manifest hash from those stored fields with the
    formula version the run was sealed under, and compares it with the
    recorded seal. ``verified`` is ``True`` exactly when
    ``recomputed_hash == manifest_hash``.

    For a run that was recorded as a stage error there is no stored
    manifest to recompute. The server then returns ``ok=True``,
    ``verified=False``, the recorded ``manifest_hash`` (which may be
    empty), and a ``reason`` string; ``recomputed_hash``,
    ``verification_at``, ``verification_kind``, ``formula_version`` and
    ``dcae_engine_hint`` are absent and read as ``None`` here.
    """

    ok: bool
    verified: bool
    manifest_hash: str = ""
    recomputed_hash: Optional[str] = None
    verification_at: Optional[str] = Field(
        default=None,
        description="Server time of the check, RFC 3339 with nanoseconds (UTC).",
    )
    verification_kind: Optional[str] = Field(
        default=None,
        description='What was checked; "manifest-self-seal" for a completed run.',
    )
    formula_version: Optional[str] = Field(
        default=None,
        description="Manifest-hash formula the stored manifest was recomputed under.",
    )
    dcae_engine_hint: Optional[DCAEEngineHint] = None
    reason: Optional[str] = Field(
        default=None,
        description="Set when the run has no manifest to verify (stage_error runs).",
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
    # not immutability. A request model refuses an unknown field.
    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        frozen=False,
    )

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown(cls, data: Any) -> Any:
        return refuse_unknown_fields(cls, data)

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
            is_provided(getattr(self, fld)) for fld in type(self).model_fields if fld != "attested"
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
    # AI output text, when supplied the orchestrator routes the run
    # through the AIVP governance stage against the configured
    # adapter (the live Claude adapter in production). The sealed
    # manifest then carries the adapter ID and the AI-output hash,
    # and the audit PDF's maturity table classifies the AIVP stage
    # accordingly. Omitted = the run is attested without AI-output
    # governance (adapter records an empty input).
    ai_output_text: Optional[str] = Field(
        default=None,
        description="AI output text for AIVP governance (optional).",
    )
    # The four caller-supplied blocks. Each is recorded as supplied and is
    # not checked by Verdifax. Leave out ``request_substance.origin``'s
    # ``source_ip_hash`` and ``user_agent_hash``: the server computes
    # those and refuses them.
    request_substance: Optional[dict[str, Any]] = Field(
        default=None,
        description="Prompt, output, cost, latency and origin metadata (optional).",
    )
    authorization_chain: Optional[dict[str, Any]] = Field(
        default=None,
        description="Approval chain (optional).",
    )
    regulatory_scaffolding: Optional[dict[str, Any]] = Field(
        default=None,
        description="Regulatory metadata (optional).",
    )
    causal_graph: Optional[dict[str, Any]] = Field(
        default=None,
        description="What led to this run (optional).",
    )
    job: Optional[dict[str, Any]] = Field(
        default=None,
        description="Where this run sits in a job map (optional).",
    )
    # What the request declares for the rules of the active policy to read.
    # The client checks it before sending. A rule on it judges what was
    # declared; it cannot show the declared facts are true.
    policy_context: Optional[dict[str, Any]] = Field(
        default=None,
        description="Declared facts for the active policy's rules (optional).",
    )
    expected_policy_hash: Optional[str] = Field(
        default=None,
        description="The policy_hash this run must be decided under (optional).",
    )

    # A request model refuses an unknown field, so a typo cannot be dropped.
    model_config = ConfigDict(populate_by_name=True, extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown(cls, data: Any) -> Any:
        return refuse_unknown_fields(cls, data)

    def model_dump_request(self) -> dict[str, Any]:
        """Serialize to the JSON shape the API expects (snake_case, no nulls)."""
        data = self.model_dump(exclude_none=True)
        return data


class Run(_AliasedModel):
    """One recorded run, from ``GET /runs/{id}``.

    ``manifest`` is the stored JSON as a ``dict``: a refused or halted run
    stores a manifest together with its receipt, so its shape varies.
    """

    id: int
    created_at: str = ""
    payload_hash: str = ""
    program_id: str = ""
    route_id: str = ""
    manifest_hash: str = ""
    duration_ms: int = 0
    status: str = ""
    error_stage: str = ""
    error_message: str = ""
    manifest: Optional[dict[str, Any]] = None


class RunSummary(_AliasedModel):
    """One row of ``GET /runs`` or ``GET /runs/search``.

    ``api_key_id`` is the key that requested the run.
    """

    id: int
    api_key_id: int = 0
    created_at: str = ""
    program_id: str = ""
    route_id: str = ""
    manifest_hash: str = ""
    duration_ms: int = 0
    status: str = ""
    outcome_kind: str = ""
    error_stage: str = ""
    execution_region: str = ""


class RunList(_AliasedModel):
    """A page of runs. ``total`` counts every match, not just this page."""

    total: int = 0
    limit: int = 0
    offset: int = 0
    runs: List[RunSummary] = Field(default_factory=list)


class ExportRow(_AliasedModel):
    """One run in an evidence export: what the server stored, not a verdict.

    ``api_key_id`` is the key that requested the run, so an account's export
    can be grouped by key.
    """

    run_id: int
    api_key_id: int = 0
    created_at: str = ""
    status: str = ""
    error_stage: str = ""
    route_id: str = ""
    manifest_hash: str = ""
    log_entry_id: str = ""
    leaf_hash: str = ""
    complete_record_entry_id: str = ""
    complete_record_leaf_hash: str = ""
    anchor_source: str = ""
    job_id: str = ""
    step_id: str = ""


class RunsExport(_AliasedModel):
    """The JSON form of ``GET /runs/export``.

    ``to`` is the upper bound the server used. ``total`` counts the runs
    held for the period, ``returned`` the rows in ``runs``, and
    ``truncated`` is ``True`` when the period holds more rows than this
    response. ``by_status`` counts the rows returned.

    ``policy_documents`` and ``policy_history`` are the key's own policy
    documents, with their exact text, and the chain of its changes, oldest
    first; they stay empty while the key has no policy document.
    ``account_id`` is the key's account, such as ``account-7``: a label
    Verdifax assigned, not a verified company identity.
    ``account_policy_documents`` and ``account_policy_history`` are the
    account's, and stay empty while the account has no policy document.
    ``signoffs`` is the account's whole chain of sign-offs, oldest first,
    in an owner key's export; it stays empty in a member key's export.
    """

    ok: bool = True
    to: str = ""
    total: int = 0
    returned: int = 0
    truncated: bool = False
    by_status: dict[str, int] = Field(default_factory=dict)
    runs: List[ExportRow] = Field(default_factory=list)
    policy_documents: List[dict[str, Any]] = Field(default_factory=list)
    policy_history: List[dict[str, Any]] = Field(default_factory=list)
    account_id: str = ""
    account_policy_documents: List[dict[str, Any]] = Field(default_factory=list)
    account_policy_history: List[dict[str, Any]] = Field(default_factory=list)
    signoffs: List[dict[str, Any]] = Field(default_factory=list)


class AccountRunsExport(RunsExport):
    """The JSON form of ``GET /account/runs/export``, for an owner key.

    ``runs`` holds the runs every key in the account made through Verdifax,
    not runs made elsewhere. An owner key has no policy of its own, so
    ``policy_documents`` and ``policy_history`` stay empty; the account's
    are in ``account_policy_documents`` and ``account_policy_history``.
    ``signoffs`` holds the account's sign-offs, oldest first, in the form
    ``verdifax-verify --signoff-history`` reads.
    """


class SignOffTarget(_AliasedModel):
    """The exact result a sign-off names, for :meth:`VerdifaxClient.sign_off`.

    ``kind`` is ``record`` for a completed run, ``receipt`` for a refused or
    halted run, or ``job`` for a whole job by its final step. ``digest`` is
    what the result's public-log entry covers: for a record, the
    ``bundle_anchor`` ``anchored_digest`` in :meth:`VerdifaxClient.get_run_artifacts`;
    for a receipt, the receipt's ``hash``; for a job, the final step's record
    digest, found as a record's is. ``job_id`` is set for a job and only for a
    job. The client checks each value before anything is sent.
    """

    kind: str
    run_id: int
    digest: str
    job_id: str = ""

    # A request model refuses an unknown field, so a typo cannot be dropped,
    # and strict types, so a run_id of True or "42" is not converted.
    model_config = ConfigDict(populate_by_name=True, extra="forbid", frozen=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown(cls, data: Any) -> Any:
        return refuse_unknown_fields(cls, data)


class RunsExportCSV(_AliasedModel):
    """The CSV form of ``GET /runs/export``.

    ``csv`` is the text, unparsed. ``total`` counts the runs held for the
    period, and ``truncated`` is ``True`` when the period holds more rows
    than ``csv``.
    """

    csv: str
    total: int
    truncated: bool


class ExecuteBatchResult(_AliasedModel):
    """One row of a batch response.

    A successful row has ``manifest``. A failed row has ``error``, and
    ``error_stage`` and a typed receipt when the pipeline halted. A row
    refused before it ran has no ``run_id``. The manifest fields stay as
    ``dict`` so that no row fails to parse. ``signed_request`` is the exact
    text of a signed row.
    """

    index: int
    ok: bool
    run_id: Optional[int] = None
    record_hash: Optional[str] = None
    signed_request: Optional[str] = None
    manifest_hash: Optional[str] = None
    manifest: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    error_stage: Optional[str] = None
    duration_ms: int = 0
    partial_manifest: Optional[dict[str, Any]] = None
    deny_receipt: Optional[dict[str, Any]] = None
    ccv_halt_receipt: Optional[dict[str, Any]] = None
    macc_halt_receipt: Optional[dict[str, Any]] = None
    aivp_t4_halt_receipt: Optional[dict[str, Any]] = None
    attestation_gap_receipt: Optional[dict[str, Any]] = None


class ExecuteBatchResponse(_AliasedModel):
    """The body of ``POST /execute/batch``. Failed rows are in ``results``."""

    ok: bool = True
    total: int = 0
    successful: int = 0
    failed: int = 0
    duration_ms: int = 0
    results: List[ExecuteBatchResult] = Field(default_factory=list)


__all__ = [
    "AccountRunsExport",
    "AttestationReceipt",
    "AttestedContext",
    "DCAEEngineHint",
    "ExecuteBatchResponse",
    "ExecuteBatchResult",
    "ExecuteRequest",
    "ExecutionManifest",
    "ExportRow",
    "KERNEL_NAMES",
    "RUN_STATUSES",
    "Run",
    "RunList",
    "RunSummary",
    "RunsExport",
    "RunsExportCSV",
    "STAGE_NAMES",
    "SignOffTarget",
    "StageResult",
    "VerifyResponse",
]
