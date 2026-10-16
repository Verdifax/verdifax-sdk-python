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

That's it. The receipt's `manifest_hash` is a 64-char SHA-256 that seals every input, every kernel execution ID, the hardware attestation, the ZK transcript, the formal verifier status, and the final VFA. You can later ask the server to re-derive it from the run's stored manifest with `verify_run(receipt.run_id)`; see [Verification](#verification).

## Configuration

By default the SDK talks to the production API at `https://api.verdifax.com`. Override with environment variables (for example, to point at a local orchestrator):

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

Ask the server to re-derive a recorded run's manifest hash and compare it with the recorded seal:

```python
result = client.verify_run(receipt.run_id)
assert result.verified, result
```

`verify_run` calls `GET /runs/{run_id}/verify` with your API key. The server loads the run's stored manifest fields, recomputes the manifest hash from them, and compares it with the hash it recorded when the run was sealed. It does not re-run the pipeline, and it is a check performed by Verdifax. For an independent offline check of the sealed audit bundle, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify) CLI. It recomputes the section hashes, the bundle hash, the pre-anchor digest and the anchored leaf; it does not recompute the manifest hash itself.

`verdifax.verify_run(run_id)` and `AsyncVerdifaxClient.verify_run(run_id)` do the same thing.

### `verify()` raises as of 0.6.0

`verify()` used to call `attest()` again with the same inputs and compare manifest hashes. That comparison can never match in production: every run seals its own admission clock, nonce, and public-log entry into its manifest hash. It now raises `verdifax.UnsupportedOperationError` explaining this. Use `verify_run(run_id)` for a recorded run, or `verdifax.research.verify_determinism(...)` to check that the pipeline replays deterministically under a pinned clock and nonce.

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
