"""Exception hierarchy for the Verdifax SDK.

All errors raised by the SDK derive from :class:`VerdifaxError`. Callers
that want a single ``except`` clause covering everything the SDK might
raise can catch ``VerdifaxError``; callers that care about specific
failure modes can catch the more specific subclasses below.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional


class VerdifaxError(Exception):
    """Base class for every exception raised by the Verdifax SDK.

    Attributes:
        last_sequence: Set on an error ``follow_signals`` raises: the last
            sequence of the feed it read. Pass it as ``after`` to go on from
            the same place. ``None`` on every other error.
        head: Set on an error ``follow_signals`` raises: the newest feed
            head it kept, ``None`` when it kept none. ``None`` on every
            other error.
        after_event_hash: Set on an error ``follow_signals`` raises: the
            ``event_hash`` of event ``last_sequence``, the last event
            finished, or the ``after_event_hash`` given when none was
            finished (``None`` when neither). Pass it back with
            ``last_sequence`` to resume. ``None`` on every other error.
    """

    last_sequence: Optional[int] = None
    head: Optional[Mapping[str, Any]] = None
    after_event_hash: Optional[str] = None


class ValidationError(VerdifaxError):
    """Raised when a request payload fails client-side validation.

    This is raised before any HTTP call is made, for example when a
    ``program_id`` is not a 64-character lowercase hex string.
    """


class ConnectionError(VerdifaxError):
    """Raised when the SDK cannot reach the Verdifax API.

    This wraps transport-level failures (DNS, TCP, TLS, timeouts) so
    callers do not need to import ``httpx`` to catch them.
    """


class UnsupportedOperationError(VerdifaxError):
    """Raised when a caller invokes an SDK method that can no longer give a true answer.

    ``verify()`` raises this as of 0.6.0: it re-ran the pipeline and
    compared manifest hashes, a comparison that cannot succeed against
    the production orchestrator. The message names the replacement.
    """


class APIError(VerdifaxError):
    """Raised when the Verdifax API returns a non-success HTTP response.

    Attributes:
        status_code: HTTP status returned by the API.
        message: Human-readable error message from the response body, if any.
        response_body: The decoded JSON response body, when available.
        signed_request: The exact signed text, when the refused call was signed.
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.response_body = response_body
        self.signed_request: Optional[str] = None

    @property
    def record_hash(self) -> Optional[str]:
        """The sealed record of a refused or halted run, from the error body."""
        value = (self.response_body or {}).get("record_hash")
        return value if isinstance(value, str) and value else None

    @property
    def aivp_trace_text(self) -> Optional[str]:
        """The text the AI review checked, on a run its review halted: returned
        once, and the halt receipt seals its hash."""
        value = (self.response_body or {}).get("aivp_trace_text")
        return value if isinstance(value, str) and value else None

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"APIError(status_code={self.status_code!r}, message={self.message!r})"


class WebhookVerificationError(VerdifaxError):
    """Raised when a webhook delivery fails a check, so it must not be trusted.

    Attributes:
        check: Which check failed: ``secret``, ``webhook-id``,
            ``webhook-timestamp``, ``webhook-signature`` or ``body``.
    """

    def __init__(self, check: str, message: str) -> None:
        super().__init__(f"{check}: {message}")
        self.check = check


class StageError(APIError):
    """Raised when a specific pipeline stage rejects a run.

    The Verdifax orchestrator returns ``error_stage`` in its response when
    one of the nine pipeline stages fails. The SDK surfaces that stage name
    on this exception so callers can branch on which stage rejected the
    request (DOG, DTL, DKEC, AER, ZKSP, PHASE4, LEDGER, REGISTRY, DLA).
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        stage: str,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, status_code=status_code, response_body=response_body)
        self.stage = stage

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"StageError(stage={self.stage!r}, status_code={self.status_code!r}, message={self.message!r})"


__all__ = [
    "APIError",
    "ConnectionError",
    "StageError",
    "UnsupportedOperationError",
    "ValidationError",
    "VerdifaxError",
    "WebhookVerificationError",
]
