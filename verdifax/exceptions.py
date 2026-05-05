"""Exception hierarchy for the Verdifax SDK.

All errors raised by the SDK derive from :class:`VerdifaxError`. Callers
that want a single ``except`` clause covering everything the SDK might
raise can catch ``VerdifaxError``; callers that care about specific
failure modes can catch the more specific subclasses below.
"""

from __future__ import annotations

from typing import Any, Optional


class VerdifaxError(Exception):
    """Base class for every exception raised by the Verdifax SDK."""


class ValidationError(VerdifaxError):
    """Raised when a request payload fails client-side validation.

    This is raised before any HTTP call is made — for example when a
    ``program_id`` is not a 64-character lowercase hex string.
    """


class ConnectionError(VerdifaxError):
    """Raised when the SDK cannot reach the Verdifax API.

    This wraps transport-level failures (DNS, TCP, TLS, timeouts) so
    callers do not need to import ``httpx`` to catch them.
    """


class APIError(VerdifaxError):
    """Raised when the Verdifax API returns a non-success HTTP response.

    Attributes:
        status_code: HTTP status returned by the API.
        message: Human-readable error message from the response body, if any.
        response_body: The decoded JSON response body, when available.
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

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"APIError(status_code={self.status_code!r}, message={self.message!r})"


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
    "ValidationError",
    "VerdifaxError",
]
