"""Retries for idempotent requests, shared by the sync and async clients.

GET, HEAD and OPTIONS are retried after a transport failure or an HTTP
429, 502, 503 or 504, with exponential backoff and full jitter, the same
attempts and backoff as the Node and Go SDKs. POST, PUT and DELETE are
never retried: replaying one could run it twice, and a retried signed
request would be refused as a replay.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_DELAY = 0.2

_RETRYABLE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})


def attempts_for(request: httpx.Request, max_retries: int) -> int:
    """How many times ``request`` may be sent."""
    if request.method.upper() in _RETRYABLE_METHODS:
        return max(0, max_retries) + 1
    return 1


def backoff_delay(base_delay: float, attempt: int) -> float:
    """Seconds to wait before retry ``attempt``: rand(0, base * 2^(attempt - 1))."""
    return random.uniform(0, base_delay * 2 ** (attempt - 1))


class RetryingClient(httpx.Client):
    """``httpx.Client`` that retries idempotent requests."""

    def __init__(self, *, max_retries: int, retry_base_delay: float, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay

    def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        attempts = attempts_for(request, self._max_retries)
        attempt = 0
        while True:
            try:
                response = super().send(request, **kwargs)
            except httpx.TransportError:
                if attempt + 1 >= attempts:
                    raise
            else:
                if response.status_code not in _RETRYABLE_STATUSES or attempt + 1 >= attempts:
                    return response
                response.close()
            attempt += 1
            time.sleep(backoff_delay(self._retry_base_delay, attempt))


class AsyncRetryingClient(httpx.AsyncClient):
    """``httpx.AsyncClient`` that retries idempotent requests."""

    def __init__(self, *, max_retries: int, retry_base_delay: float, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        attempts = attempts_for(request, self._max_retries)
        attempt = 0
        while True:
            try:
                response = await super().send(request, **kwargs)
            except httpx.TransportError:
                if attempt + 1 >= attempts:
                    raise
            else:
                if response.status_code not in _RETRYABLE_STATUSES or attempt + 1 >= attempts:
                    return response
                await response.aclose()
            attempt += 1
            await asyncio.sleep(backoff_delay(self._retry_base_delay, attempt))


__all__ = [
    "AsyncRetryingClient",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_RETRY_BASE_DELAY",
    "RetryingClient",
    "attempts_for",
    "backoff_delay",
]
