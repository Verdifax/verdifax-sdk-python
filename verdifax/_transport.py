"""Shared response handling for sync and async clients.

Centralizing this logic keeps :class:`VerdifaxClient` and
:class:`AsyncVerdifaxClient` from duplicating error-translation code.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .exceptions import APIError, ConnectionError as VerdifaxConnectionError, StageError


def parse_response(response: httpx.Response) -> dict[str, Any]:
    """Validate an HTTP response and return its decoded JSON body.

    Raises :class:`StageError` for orchestrator stage failures (HTTP 422
    with an ``error_stage`` in the body), :class:`APIError` for any other
    non-2xx response, and returns the JSON body on success.
    """
    try:
        body: dict[str, Any] = response.json()
    except ValueError:
        body = {}

    if response.is_success:
        return body

    message = _extract_message(body) or response.reason_phrase or "request failed"
    stage = body.get("error_stage") if isinstance(body, dict) else None
    if response.status_code == 422 and stage:
        raise StageError(
            message=message,
            status_code=response.status_code,
            stage=str(stage),
            response_body=body if isinstance(body, dict) else None,
        )
    raise APIError(
        message=message,
        status_code=response.status_code,
        response_body=body if isinstance(body, dict) else None,
    )


def _extract_message(body: Any) -> Optional[str]:
    if isinstance(body, dict):
        for key in ("error", "message", "detail"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def wrap_transport_error(exc: httpx.HTTPError) -> VerdifaxConnectionError:
    """Translate an httpx transport error into a Verdifax ``ConnectionError``."""
    return VerdifaxConnectionError(f"verdifax: failed to reach API: {exc}")


__all__ = ["parse_response", "wrap_transport_error"]
