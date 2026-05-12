"""Reproducible-research helpers for the Verdifax Python SDK.

This module adds reproducibility-aware attestation on top of the
base SDK. The three building blocks:

  - :class:`ReproducibilityContext`
      A Pydantic model mirroring the orchestrator's Category-6
      audit-bundle field. Serialized into the ``/execute`` request
      body so the manifest binds (payload, code, environment)
      jointly.

  - :func:`capture_environment`
      Best-effort auto-detection of the current Python runtime,
      pinned dependencies, git commit SHA, platform descriptor, and
      Docker container ID. Returns a populated
      :class:`ReproducibilityContext` the caller can pass straight
      into :func:`VerdifaxClient.attest`.

  - :func:`verify_determinism`
      Wraps the orchestrator's ``POST /execute/verify-determinism``
      endpoint (Option B Phase 2). Runs the same payload twice and
      reports whether both invocations produced the same canonical
      manifest hash.

Typical use::

    from verdifax import VerdifaxClient
    from verdifax.research import capture_environment, verify_determinism

    # 1. Auto-capture the current research environment
    context = capture_environment(declared_seeds={"numpy": 42})

    # 2. Attest with the context bound into the bundle
    client = VerdifaxClient()
    receipt = client.attest(
        payload="my-analysis-output",
        program_id="...",
        route_id="paper-figure-3",
        registry_record_hash="...",
        reproducibility_context=context,
    )

    # 3. Verify the pipeline is deterministic on replay
    determinism = verify_determinism(
        client=client,
        payload="my-analysis-output",
        program_id="...",
        route_id="paper-figure-3",
        registry_record_hash="...",
        reproducibility_context=context,
    )
    assert determinism.deterministic, determinism.diff.differing_fields

The auto-capture functions are best-effort: they swallow any
exception and leave the corresponding field blank rather than
fail the call. The orchestrator records empty values as "not
declared" — better than fabricating an environment claim.
"""

from __future__ import annotations

import os
import platform as _platform
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional, Union

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ._transport import parse_response, wrap_transport_error
from ._validation import normalize_payload, validate_hex64, validate_route_id

# ── ReproducibilityContext model ────────────────────────────────────────────


class ReproducibilityContext(BaseModel):
    """Caller-declared runtime fingerprint sealed into the audit bundle.

    All fields are optional. When the model is populated and passed
    into :meth:`VerdifaxClient.attest`, the orchestrator records the
    values verbatim into the bundle's Category-6 section and includes
    them in the bundle hash. Two runs with the same payload + same
    context produce the same bundle hash; differences surface as
    diverging hashes that can be diffed by an auditor.

    Field names use snake_case to match the orchestrator's JSON
    contract (``internal/artifacts/category6_reproducibility.go``).
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    declared: bool = Field(
        default=False,
        description=(
            "Auto-derived flag: true when any other field is non-empty. "
            "Callers don't need to set this manually; "
            ":meth:`with_auto_declared` (called by the client) does it for you."
        ),
    )
    container_image_hash: Optional[str] = Field(
        default=None,
        description=(
            "SHA-256 of the OCI / Docker container image hosting "
            "the execution (64-char hex; omit the 'sha256:' prefix)."
        ),
    )
    runtime_name: Optional[str] = Field(
        default=None,
        description="Language runtime, e.g. 'python', 'R', 'julia'.",
    )
    runtime_version: Optional[str] = Field(
        default=None,
        description="Pinned runtime version, e.g. '3.11.5'.",
    )
    pinned_dependencies: Optional[List[str]] = Field(
        default=None,
        description=(
            "Direct + transitive deps as 'name==version' strings, "
            "sorted by name for canonical determinism."
        ),
    )
    git_commit_sha: Optional[str] = Field(
        default=None,
        description="40-char (or 64-char SHA-256) hex commit hash.",
    )
    random_seeds: Optional[List[str]] = Field(
        default=None,
        description=(
            "PRNG declarations as 'library=seed' strings (e.g. 'numpy=42'). "
            "Sorted by library name."
        ),
    )
    platform: Optional[str] = Field(
        default=None,
        description="GOOS/GOARCH-style descriptor, e.g. 'linux/amd64'.",
    )

    def with_auto_declared(self) -> "ReproducibilityContext":
        """Return a copy with the ``declared`` flag auto-set.

        The flag is set to ``True`` when any of the descriptive fields
        is non-empty. Mirrors the orchestrator's logic in
        ``internal/artifacts/builder.go`` so the round-trip is
        symmetric.
        """
        declared = any(
            (
                self.container_image_hash,
                self.runtime_name,
                self.runtime_version,
                self.pinned_dependencies,
                self.git_commit_sha,
                self.random_seeds,
                self.platform,
            )
        )
        return self.model_copy(update={"declared": declared})


# ── Auto-capture helpers ────────────────────────────────────────────────────


def capture_environment(
    *,
    declared_seeds: Optional[Mapping[str, Any]] = None,
    include_dependencies: bool = True,
    include_git: bool = True,
    include_container: bool = True,
) -> ReproducibilityContext:
    """Auto-detect the current Python research environment.

    Args:
        declared_seeds: Optional mapping of PRNG library name to seed
            value. Caller is responsible for actually seeding those
            libraries in their code; this function records the
            declaration verbatim. Example::

                declared_seeds={"numpy": 42, "torch": 1337}

        include_dependencies: When ``True`` (default), enumerate every
            installed distribution via ``importlib.metadata`` and emit
            ``name==version`` strings for each. Pass ``False`` to skip
            in test or sandbox scenarios where the dep list is noisy.

        include_git: When ``True`` (default), attempt to read the
            current commit SHA via ``git rev-parse HEAD``. Silently
            falls back to ``None`` if not in a git repo or git is
            unavailable.

        include_container: When ``True`` (default), attempt to read
            the Docker container ID from ``/proc/self/cgroup`` on
            Linux. Silently falls back to ``None`` outside containers
            or on non-Linux platforms.

    Returns:
        A populated :class:`ReproducibilityContext` ready to pass into
        :meth:`VerdifaxClient.attest`.
    """
    runtime_name = _platform.python_implementation().lower()  # "cpython"
    if runtime_name == "cpython":
        runtime_name = "python"  # match the orchestrator's convention
    runtime_version = _platform.python_version()  # e.g. "3.11.5"

    # GOOS/GOARCH-style platform descriptor.
    system = _platform.system().lower()  # 'linux', 'darwin', 'windows'
    machine = _platform.machine().lower()  # 'x86_64', 'arm64', 'aarch64'
    if machine == "x86_64":
        machine = "amd64"  # match Go's GOARCH naming
    if machine == "aarch64":
        machine = "arm64"
    platform_descriptor = f"{system}/{machine}"

    pinned: Optional[List[str]] = None
    if include_dependencies:
        pinned = _enumerate_dependencies()

    git_sha = _detect_git_sha() if include_git else None
    container_hash = _detect_container_hash() if include_container else None

    seeds_list: Optional[List[str]] = None
    if declared_seeds:
        seeds_list = sorted(f"{name}={value}" for name, value in declared_seeds.items())

    context = ReproducibilityContext(
        container_image_hash=container_hash,
        runtime_name=runtime_name,
        runtime_version=runtime_version,
        pinned_dependencies=pinned,
        git_commit_sha=git_sha,
        random_seeds=seeds_list,
        platform=platform_descriptor,
    )
    return context.with_auto_declared()


def _enumerate_dependencies() -> List[str]:
    """Best-effort list of installed packages as 'name==version' strings.

    Sorted by package name (lowercased) so the canonical JSON is
    deterministic across runs. Distributions without a parseable
    version are skipped.
    """
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover — only Python 2.x and absurdly old
        return []

    pinned = []
    try:
        for dist in metadata.distributions():
            # PackageMetadata in newer Python typing stubs doesn't expose
            # .get() as a typed method, but __getitem__ is stable across
            # 3.9 (where dist.metadata is an email.message.Message) and
            # 3.10+ (where it's a PackageMetadata protocol). Try the
            # canonical 'Name' key first, fall back to 'name' for
            # PEP-handling quirks, swallow missing-key cases.
            name = None
            try:
                name = dist.metadata["Name"]
            except (KeyError, TypeError):
                pass
            if not name:
                try:
                    name = dist.metadata["name"]
                except (KeyError, TypeError):
                    pass
            version = dist.version
            if not name or not version:
                continue
            pinned.append(f"{name}=={version}")
    except Exception:
        return []
    pinned.sort(key=str.lower)
    return pinned


def _detect_git_sha() -> Optional[str]:
    """Best-effort detection of the current git commit SHA.

    Tries ``git rev-parse HEAD`` in the current working directory.
    Returns the 40-char hex SHA on success, ``None`` on any failure
    (not in a git repo, git not installed, etc.).
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        sha = result.stdout.strip()
        # Sanity: should be 40 chars (sha1) or 64 chars (sha256-mode).
        if len(sha) in (40, 64) and all(c in "0123456789abcdef" for c in sha.lower()):
            return sha.lower()
        return None
    except Exception:
        return None


def _detect_container_hash() -> Optional[str]:
    """Best-effort detection of the Docker / OCI container ID.

    Reads ``/proc/self/cgroup`` on Linux and parses out the container
    ID if running inside Docker / containerd / podman / Kubernetes.
    Returns the 64-char hex container ID, or ``None`` outside a
    container or on non-Linux platforms.

    Note: the container ID is NOT the IMAGE hash. Capturing the
    image hash requires asking the container runtime, which varies
    by environment. The image hash should be supplied explicitly by
    the caller (e.g. via a CI/CD pipeline that knows the image it
    just pulled). This function captures the container ID as a
    fallback fingerprint when the image hash isn't known.
    """
    cgroup_path = "/proc/self/cgroup"
    if not os.path.exists(cgroup_path):
        return None
    try:
        with open(cgroup_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    # Each line ends with the cgroup path. Docker / containerd encode
    # the container ID in the last path segment when running in a
    # container. Example line:
    #   12:cpu:/docker/abc123...def
    # We look for any segment that's exactly 64 hex chars.
    for line in content.splitlines():
        for segment in line.split("/"):
            segment = segment.strip()
            if len(segment) == 64 and all(c in "0123456789abcdef" for c in segment):
                return segment
    return None


# ── Determinism verification ────────────────────────────────────────────────


class DeterminismResultRow(BaseModel):
    """One of the two runs produced by ``verify_determinism``."""

    model_config = ConfigDict(extra="ignore")

    run_id: int
    manifest_hash: Optional[str] = None
    bundle_hash: Optional[str] = None
    duration_ms: int
    status: str
    error: Optional[str] = None


class DeterminismDiff(BaseModel):
    """Comparison summary of the two determinism-check runs."""

    model_config = ConfigDict(extra="ignore")

    differs: bool
    manifest_hash_differs: bool
    bundle_hash_differs: bool
    differing_fields: List[str] = Field(default_factory=list)


class DeterminismResult(BaseModel):
    """Top-level response from POST /execute/verify-determinism.

    Use :attr:`deterministic` as the primary signal — it's grounded
    on manifest-hash equality, which is the canonical seal of the
    pipeline output. Bundle-hash differences are surfaced in
    :attr:`diff` as informational metadata (server-observed timing
    measurements vary call-to-call by design).
    """

    model_config = ConfigDict(extra="ignore")

    ok: bool
    deterministic: bool
    first: DeterminismResultRow
    second: DeterminismResultRow
    diff: DeterminismDiff


def verify_determinism(
    client: Any,  # VerdifaxClient — Any to avoid circular import
    payload: Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    reproducibility_context: Optional[ReproducibilityContext] = None,
    ai_output_text: Optional[str] = None,
) -> DeterminismResult:
    """Run the same payload through the pipeline twice and report the comparison.

    Wraps the orchestrator's ``POST /execute/verify-determinism``
    endpoint. Both invocations use a pinned wall-clock epoch (set
    server-side) so the comparison evaluates the rest of the pipeline,
    independent of clock variation. Both runs are persisted as normal
    ``/runs/{id}``-retrievable records.

    The top-level :attr:`DeterminismResult.deterministic` flag is
    grounded on **manifest hash** equality — the canonical seal of
    the pipeline output. Bundle-hash differences (when surfaced in
    :attr:`DeterminismResult.diff.differing_fields`) indicate
    server-observed timing variation, not a non-deterministic
    computation.

    Args:
        client: A :class:`VerdifaxClient` instance with an
            authenticated transport.
        payload: The payload to verify. Strings sent as text; bytes
            sent as text if UTF-8-decodable, otherwise base64.
        program_id: 64-char lowercase hex program ID.
        route_id: Non-empty deterministic route identifier.
        registry_record_hash: 64-char lowercase hex §0 hash.
        reproducibility_context: Optional caller-declared environment
            fingerprint. Both invocations use the same context.
        ai_output_text: Optional AI output text for AIVP-T4
            governance (mirrors the same parameter on ``attest``).

    Returns:
        A :class:`DeterminismResult` with the comparison summary.

    Raises:
        ValidationError, StageError, APIError, ConnectionError — same
        as :meth:`VerdifaxClient.attest`.
    """
    validate_hex64(program_id, "program_id")
    validate_hex64(registry_record_hash, "registry_record_hash")
    validate_route_id(route_id)
    payload_text, payload_b64 = normalize_payload(payload)

    body: Dict[str, Any] = {
        "program_id": program_id,
        "route_id": route_id,
        "registry_record_hash": registry_record_hash,
    }
    if payload_text:
        body["payload_text"] = payload_text
    elif payload_b64:
        body["payload"] = payload_b64
    if ai_output_text:
        body["ai_output_text"] = ai_output_text
    if reproducibility_context is not None:
        ctx = reproducibility_context.with_auto_declared()
        body["reproducibility_context"] = ctx.model_dump(
            mode="json",
            exclude_none=True,
        )

    try:
        response = client._http.post("/execute/verify-determinism", json=body)
    except httpx.HTTPError as exc:
        raise wrap_transport_error(exc) from exc

    parsed = parse_response(response)
    return DeterminismResult.model_validate(parsed)


__all__ = [
    "DeterminismDiff",
    "DeterminismResult",
    "DeterminismResultRow",
    "ReproducibilityContext",
    "capture_environment",
    "verify_determinism",
]
