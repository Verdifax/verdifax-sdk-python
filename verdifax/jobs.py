"""The job helper: run the steps of one job and link them into a map.

A job is a map of sealed steps. Each step names the records it directly
follows, so a missing, swapped or repeated step is visible, and work can
split into branches and join again. The helper keeps the map's hashes on
this side, so a caller names steps rather than hashes.

A job map covers what was sent. It cannot show a step that was never sent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Optional

from ._validation import validate_job_name
from .exceptions import APIError, ValidationError, VerdifaxError
from .models import AttestationReceipt

if TYPE_CHECKING:
    from .async_client import AsyncVerdifaxClient
    from .client import VerdifaxClient


# What a step passes on to attest. ``job`` is left out because the helper builds it.
_STEP_ATTEST_OPTIONS = frozenset(
    {
        "payload",
        "program_id",
        "route_id",
        "registry_record_hash",
        "attested_context",
        "reproducibility_context",
        "ai_output_text",
        "request_substance",
        "authorization_chain",
        "regulatory_scaffolding",
        "causal_graph",
    }
)


def _refuse_unknown_options(options: Mapping[str, Any]) -> None:
    """Refuse a typo here, so ``afer`` can never silently use the default link."""
    unknown = sorted(name for name in options if name not in _STEP_ATTEST_OPTIONS)
    if unknown:
        raise ValidationError(f"step has unknown options: {', '.join(unknown)}")


class _JobMap:
    """What the sync and async helpers share: the map and each step's job block."""

    def __init__(self, job_id: str) -> None:
        validate_job_name(job_id, "job_id")
        self.job_id = job_id
        self._hashes: dict[str, str] = {}
        self._signed_requests: dict[str, str] = {}
        self._last_step: Optional[str] = None

    @property
    def record_hashes(self) -> dict[str, str]:
        """Each recorded step id with its record hash, refused steps included."""
        return dict(self._hashes)

    @property
    def signed_requests(self) -> dict[str, str]:
        """Each recorded step id with its exact signed text, refused steps included.

        A step sent by a client with no ``signing_key`` has no entry.
        """
        return dict(self._signed_requests)

    def _link(
        self,
        step_id: str,
        after: Optional[list[str]],
        external_previous: Optional[list[str]],
        final: bool,
    ) -> dict[str, Any]:
        link: dict[str, Any] = {
            "job_id": self.job_id,
            "step_id": step_id,
            "previous_record_hashes": self._previous(after),
            "final": final,
        }
        if external_previous is not None:
            link["external_previous"] = external_previous
        return link

    def _previous(self, after: Optional[list[str]]) -> list[str]:
        if after is None:
            after = [] if self._last_step is None else [self._last_step]
        if not isinstance(after, list):
            raise ValidationError("after must be a list of step ids")
        unknown = [step for step in after if step not in self._hashes]
        if unknown:
            raise ValidationError(f"after names steps not in this job: {unknown!r}")
        return [self._hashes[step] for step in after]

    def _record(
        self, step_id: str, record_hash: Optional[str], signed_request: Optional[str]
    ) -> None:
        # A call that sealed nothing has no hash, so the map stays as it was
        # and the next step does not follow it.
        if not record_hash:
            return
        self._hashes[step_id] = record_hash
        self._last_step = step_id
        if signed_request is not None:
            self._signed_requests[step_id] = signed_request

    def _record_sealed(self, step_id: str, receipt: AttestationReceipt) -> None:
        record_hash = receipt.record_hash
        if not record_hash:
            raise VerdifaxError(
                f"step {step_id} came back with no record_hash and no manifest_hash, "
                "so it cannot join the job map"
            )
        self._record(step_id, record_hash, receipt.signed_request)


class Job(_JobMap):
    """Runs the steps of one job. Build one with :meth:`VerdifaxClient.job`."""

    def __init__(self, client: "VerdifaxClient", job_id: str) -> None:
        super().__init__(job_id)
        self._client = client

    def step(
        self,
        step_id: str,
        after: Optional[list[str]] = None,
        external_previous: Optional[list[str]] = None,
        final: bool = False,
        **attest_args: Any,
    ) -> AttestationReceipt:
        """Run one step, taking everything :meth:`VerdifaxClient.attest` takes.

        Args:
            step_id: This step's name in the job.
            after: The step ids in this job that this step directly follows.
                When omitted, the step follows the one run just before it
                through this helper, or nothing for the first step. An empty
                list starts another root step.
            external_previous: Record hashes from another account that this
                step follows.
            final: True for the step that ends the job.

        Raises:
            ValidationError: If an option is unknown, ``job`` included,
                ``after`` names an unknown step, or a name is invalid. Nothing
                is sent.
            StageError: As :meth:`VerdifaxClient.attest` raises it. A refused
                or halted step is recorded first, with its signed text, so a
                later step can name it.
            APIError: As :meth:`VerdifaxClient.attest` raises it.
            ConnectionError: If the API was unreachable. Nothing is recorded,
                though the server may have run the step.
            VerdifaxError: If a successful response has no ``record_hash``, no
                top-level ``manifest_hash`` and no hash in its manifest, so the
                map never silently gets a gap.
        """
        _refuse_unknown_options(attest_args)
        job = self._link(step_id, after, external_previous, final)
        try:
            receipt = self._client.attest(job=job, **attest_args)
        except APIError as exc:
            self._record(step_id, exc.record_hash, exc.signed_request)
            raise
        self._record_sealed(step_id, receipt)
        return receipt


class AsyncJob(_JobMap):
    """Async version of :class:`Job`. Build one with :meth:`AsyncVerdifaxClient.job`."""

    def __init__(self, client: "AsyncVerdifaxClient", job_id: str) -> None:
        super().__init__(job_id)
        self._client = client

    async def step(
        self,
        step_id: str,
        after: Optional[list[str]] = None,
        external_previous: Optional[list[str]] = None,
        final: bool = False,
        **attest_args: Any,
    ) -> AttestationReceipt:
        """Async version of :meth:`Job.step`."""
        _refuse_unknown_options(attest_args)
        job = self._link(step_id, after, external_previous, final)
        try:
            receipt = await self._client.attest(job=job, **attest_args)
        except APIError as exc:
            self._record(step_id, exc.record_hash, exc.signed_request)
            raise
        self._record_sealed(step_id, receipt)
        return receipt


__all__ = ["AsyncJob", "Job"]
