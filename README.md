# Verdifax Python SDK

Cryptographic attestation for AI inference. Three lines: send a payload, get a signed manifest hash you can give to an auditor.

## Install

```bash
pip install verdifax
```

## Quickstart

```python
import verdifax

receipt = verdifax.attest(
    payload="hello verdifax",
    program_id="a" * 64,
    route_id="route-test",
    registry_record_hash="b" * 64,
)
print(receipt.manifest_hash)
```

That's it. The receipt's `manifest_hash` is a 64-char SHA-256 that seals every input, every kernel execution ID, the hardware attestation, the ZK transcript, the formal verifier status, and the final VFA. Anyone with the same inputs can re-derive the same hash.

## Configuration

By default the SDK talks to a Verdifax API at `http://localhost:9090` (the orchestrator's REST server). Override with environment variables:

```bash
export VERDIFAX_API_URL=https://api.verdifax.example.com
export VERDIFAX_API_KEY=your-api-key
```

Or construct a client explicitly:

```python
from verdifax import VerdifaxClient

client = VerdifaxClient(base_url="https://api.verdifax.example.com", api_key="...")
receipt = client.attest(payload="...", program_id="...", route_id="...", registry_record_hash="...")
```

## Async

```python
import asyncio
from verdifax import AsyncVerdifaxClient

async def main():
    async with AsyncVerdifaxClient() as client:
        receipt = await client.attest(
            payload="hello verdifax",
            program_id="a" * 64,
            route_id="route-test",
            registry_record_hash="b" * 64,
        )
        print(receipt.manifest_hash)

asyncio.run(main())
```

## Verification

Re-derive the manifest hash from the same inputs and confirm it matches a previously issued receipt:

```python
ok = client.verify(
    manifest_hash=receipt.manifest_hash,
    payload="hello verdifax",
    program_id="a" * 64,
    route_id="route-test",
    registry_record_hash="b" * 64,
)
```

## Helpers for popular providers

```python
import verdifax

receipt = verdifax.attest_claude_response(
    prompt="What is the boiling point of water?",
    response="100 °C at sea level.",
    program_id="a" * 64,
    route_id="claude-route",
    registry_record_hash="b" * 64,
)
```

There is also `verdifax.attest_openai_response(...)` with the same signature.

## License

MIT
