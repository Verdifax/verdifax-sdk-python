"""Convenience helpers for popular AI providers.

These wrap :func:`verdifax.attest` so callers can attest a model
prompt/response pair in a single call. The helpers concatenate the
prompt and response into a deterministic payload string before
attesting; identical inputs produce identical manifest hashes.
"""

from __future__ import annotations

from typing import Optional, Union

from .client import VerdifaxClient
from .models import AttestationReceipt

# Use US ASCII record/group separators so they are vanishingly unlikely to
# appear inside real prompt/response text and split it ambiguously.
_RECORD_SEP = "\x1e"
_PROMPT_PREFIX = "verdifax.helper.prompt.v1"
_RESPONSE_PREFIX = "verdifax.helper.response.v1"


def _format_payload(provider: str, prompt: str, response: Union[str, bytes]) -> str:
    if isinstance(response, bytes):
        # Keep the bytes value typed as bytes for the except branch so
        # mypy can resolve b64encode's argument type. Reassigning
        # ``response`` to str inside the try-block narrows the union but
        # also widens the binding back to ``Union[str, bytes]`` in the
        # except branch, capturing the raw bytes separately keeps the
        # type discriminator clean.
        raw_bytes = response
        try:
            response = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            import base64

            response = "base64:" + base64.b64encode(raw_bytes).decode("ascii")
    return _RECORD_SEP.join(
        [
            f"verdifax.helper.{provider}.v1",
            _PROMPT_PREFIX,
            prompt,
            _RESPONSE_PREFIX,
            response,
        ]
    )


def attest_claude_response(
    prompt: str,
    response: Union[str, bytes],
    program_id: str,
    route_id: str,
    registry_record_hash: str,
    *,
    client: Optional[VerdifaxClient] = None,
) -> AttestationReceipt:
    """Attest an Anthropic Claude prompt/response pair.

    Concatenates the prompt and response into a deterministic payload and
    runs the standard Verdifax pipeline against it. Pass an explicit
    ``client`` to reuse an existing connection pool; otherwise a temporary
    client is created from environment variables.
    """
    payload = _format_payload("claude", prompt, response)
    own_client = client is None
    if client is None:
        client = VerdifaxClient()
    try:
        return client.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
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
    client: Optional[VerdifaxClient] = None,
) -> AttestationReceipt:
    """Attest an OpenAI prompt/response pair.

    Same shape as :func:`attest_claude_response` but tags the payload as
    OpenAI-sourced so identical text under different providers produces
    different manifest hashes.
    """
    payload = _format_payload("openai", prompt, response)
    own_client = client is None
    if client is None:
        client = VerdifaxClient()
    try:
        return client.attest(
            payload=payload,
            program_id=program_id,
            route_id=route_id,
            registry_record_hash=registry_record_hash,
        )
    finally:
        if own_client:
            client.close()


__all__ = ["attest_claude_response", "attest_openai_response"]
