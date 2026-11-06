"""Convenience helpers for popular AI providers.

These attest a model prompt/response pair in a single call, as one
canonical JSON payload: see :func:`verdifax.format_provider_payload`.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Union

from .client import VerdifaxClient
from .exceptions import ValidationError
from .models import AttestationReceipt


def _resolve_client(
    client: Optional[VerdifaxClient], signing_key: Optional[bytes]
) -> VerdifaxClient:
    """Use the caller's client, or a temporary one with ``signing_key``."""
    if client is None:
        return VerdifaxClient(signing_key=signing_key)
    if signing_key is not None:
        raise ValidationError("pass signing_key to the client, not alongside client=")
    return client


def attest_claude_response(
    prompt: str,
    response: Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    govern: bool = False,
    client: Optional[VerdifaxClient] = None,
    signing_key: Optional[bytes] = None,
    job: Optional[Mapping[str, Any]] = None,
) -> AttestationReceipt:
    """Attest an Anthropic Claude prompt/response pair, as provider ``anthropic``.

    Pass an explicit ``client`` to reuse an existing connection pool;
    otherwise a temporary client is created from environment variables.

    ``govern=True`` also sends the response text for the orchestrator's
    AIVP review, which runs on Anthropic in production and can block or
    halt the run before it seals. It is off by default, so the text goes
    for review only when the caller asks.

    A ``client`` with a ``signing_key`` signs the request. Without a
    ``client``, pass ``signing_key`` for the temporary client to use.

    ``job`` places the run in a job map, the same block
    :meth:`VerdifaxClient.attest` takes. The receipt has ``record_hash`` and,
    when signed, ``signed_request``, as :meth:`VerdifaxClient.attest` gives.
    """
    own_client = client is None
    client = _resolve_client(client, signing_key)
    try:
        return client.attest_claude_response(
            prompt, response, program_id, route_id, registry_record_hash, govern=govern, job=job
        )
    finally:
        if own_client:
            client.close()


def attest_openai_response(
    prompt: str,
    response: Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    govern: bool = False,
    client: Optional[VerdifaxClient] = None,
    signing_key: Optional[bytes] = None,
    job: Optional[Mapping[str, Any]] = None,
) -> AttestationReceipt:
    """Attest an OpenAI prompt/response pair, as provider ``openai``.

    Same shape as :func:`attest_claude_response`.
    """
    own_client = client is None
    client = _resolve_client(client, signing_key)
    try:
        return client.attest_openai_response(
            prompt, response, program_id, route_id, registry_record_hash, govern=govern, job=job
        )
    finally:
        if own_client:
            client.close()


__all__ = ["attest_claude_response", "attest_openai_response"]
