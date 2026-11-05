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

## Versioning

From 1.0, a breaking change needs a new major version.

## Configuration

By default the SDK talks to the production API at `https://api.verdifax.com`. Override with environment variables (for example, to point at a local orchestrator):

```bash
export VERDIFAX_BASE_URL=https://api.verdifax.example.com
export VERDIFAX_API_KEY=your-api-key
```

| Setting | Argument | Environment variable | Default |
| --- | --- | --- | --- |
| Base URL | `base_url` | `VERDIFAX_BASE_URL`, then `VERDIFAX_API_URL` | `https://api.verdifax.com` |
| API key | `api_key` | `VERDIFAX_API_KEY` | none |
| Timeout | `timeout`, in seconds | `VERDIFAX_TIMEOUT_MS` | 90 seconds |
| User agent | `user_agent` | `VERDIFAX_USER_AGENT` | `verdifax-python/<version>` |
| Retries | `max_retries` | `VERDIFAX_MAX_RETRIES` | 3 |
| First retry delay | `retry_base_delay`, in seconds | none | 0.2 seconds |

Both clients read the base URL and API key from the environment. `verdifax.from_env()` also reads the timeout, user agent and retry variables.

GET, HEAD and OPTIONS requests are retried after a transport failure or an HTTP 429, 502, 503 or 504, with exponential backoff and full jitter. POST is never retried.

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

## Methods

`VerdifaxClient` has these methods, and `AsyncVerdifaxClient` has each of them as a coroutine.

| Method | Endpoint | Auth |
| --- | --- | --- |
| `health()` | `GET /health` | none |
| `version()` | `GET /version` | none |
| `get_openapi()` | `GET /openapi.json` | none |
| `get_stats()` | `GET /stats` | required |
| `attest(...)` | `POST /execute` | required |
| `execute(...)` | `POST /execute` | required |
| `attest_claude_response(...)` | `POST /execute` | required |
| `attest_openai_response(...)` | `POST /execute` | required |
| `execute_batch(runs)` | `POST /execute/batch` | required |
| `verify_determinism(...)` | `POST /execute/verify-determinism` | required |
| `get_run(run_id)` | `GET /runs/{run_id}` | required |
| `verify_run(run_id)` | `GET /runs/{run_id}/verify` | required |
| `list_runs(limit, offset)` | `GET /runs` | required |
| `search_runs(...)` | `GET /runs/search` | required |
| `export_runs(from_, to)` | `GET /runs/export` | required |
| `export_runs_csv(from_, to)` | `GET /runs/export?format=csv` | required |
| `get_run_artifacts(run_id)` | `GET /runs/{run_id}/artifacts` | required |
| `get_run_report(run_id)` | `GET /runs/{run_id}/report` | required |
| `download_audit_pdf(run_id, format)` | `GET /runs/{run_id}/report.pdf` | required |
| `get_allow_token(run_id)` | `GET /runs/{run_id}/allow-token` | required |
| `get_deny_receipt(run_id)` | `GET /runs/{run_id}/deny-receipt` | required |
| `get_ccv_halt_receipt(run_id)` | `GET /runs/{run_id}/ccv-halt-receipt` | required |
| `get_macc_halt_receipt(run_id)` | `GET /runs/{run_id}/macc-halt-receipt` | required |
| `get_aivp_t4_halt_receipt(run_id)` | `GET /runs/{run_id}/aivp-t4-halt-receipt` | required |
| `get_attestation_gap_receipt(run_id)` | `GET /runs/{run_id}/attestation-gap-receipt` | required |
| `get_ces_audit_record(run_id)` | `GET /runs/{run_id}/ces-audit-record` | required |
| `list_deletion_receipts(run_id)` | `GET /runs/{run_id}/deletion-receipts` | required |
| `list_attestations(limit, offset)` | `GET /attestations` | required |
| `get_attestation(attestation_id)` | `GET /attestations/{id}` | required |
| `get_public_bundle(run_id)` | `GET /runs/{run_id}/bundle.json` | none |
| `get_public_bundle_by_token(token)` | `GET /public/runs/{token}/bundle.json` | none |
| `dcae_verify(bundle)` | `POST /dcae/verify` | none |
| `register_request_key()` | `POST /keys/request-key` | required |
| `clear_request_key()` | `DELETE /keys/request-key` | required |
| `admin_create_key(name)` | `POST /admin/keys` | admin |
| `admin_list_keys()` | `GET /admin/keys` | admin |
| `admin_revoke_key(key_id)` | `DELETE /admin/keys/{id}` | admin |
| `admin_erase(...)` | `POST /admin/erase` | admin |

These functions make no request: `verdifax.research.capture_environment`, `format_provider_payload`, `sign_request`, `request_key_registration_body`, `request_signature_preimage`, `generate_request_key`, `validate_hex64`, `validate_route_id`, and in `verdifax.section0`, `dse_dispatch_hash`, `dcae_closure_hash` and `cres_receipt_hash`. `RUN_STATUSES` lists every run status the server uses.

`get_run_artifacts`, `get_public_bundle` and `get_public_bundle_by_token` return the exact JSON text the server sent, so you can save it and check it with `verdifax-verify`.

## Batch runs

`execute_batch(runs)` sends up to 1,000 runs in one request and raises `ValidationError` for more, before sending anything. A row that fails comes back in `results` with `ok` set to `False`, so the call does not raise for it. Each row is an `ExecuteRequest`, or a mapping with the same names as `attest()`.

```python
batch = client.execute_batch([
    {"payload": "first", "program_id": "a" * 64, "route_id": "route-test", "registry_record_hash": "b" * 64},
    {"payload": "second", "program_id": "a" * 64, "route_id": "route-test", "registry_record_hash": "b" * 64},
])

for row in batch.results:
    print(row.index, row.ok, row.run_id, row.error)
```

The client's `timeout` covers the whole batch, so raise it for a large one. A batch is one POST and it is never retried. After a timeout the server may have run some or all of the rows, so list your runs before you send them again.

## Evidence export

`export_runs` lists the runs the server holds for your key in a period, failures included, with up to 10,000 rows per export. `export_runs_csv` returns the same rows as raw CSV text.

```python
evidence = client.export_runs(from_="2026-11-01T00:00:00Z", to="2026-12-01T00:00:00Z")
print(evidence.total, evidence.truncated, evidence.by_status)

export = client.export_runs_csv(from_="2026-11-01T00:00:00Z", to="2026-12-01T00:00:00Z")
if export.truncated:
    print(f"The CSV holds part of {export.total} runs. Use a narrower period.")
csv_text = export.csv
```

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `truncated`. `export_runs_csv` reads `total` and `truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and raises `VerdifaxError` if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`.

## Determinism check

`client.verify_determinism(...)` runs one payload twice on the server and compares the manifest hashes. `deterministic` is true when both runs ended `ok` and the two hashes match. Both runs are recorded, with the status `probe`. `verdifax.research.verify_determinism(client, ...)` is the same call for a sync client.

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

## Request signing

Request signing is optional. A client with no signing key sends the same requests as before.

You can register an Ed25519 public key on your API key, so that each run must also be signed with a private key that only you hold. The key pair is created on your machine, and Verdifax receives only the public key. Signing needs the `cryptography` package:

```bash
pip install "verdifax[signing]"
```

```python
import verdifax
from verdifax import VerdifaxClient

# Run once, then store private_key as a secret. It is 32 raw bytes.
private_key = verdifax.generate_request_key().private_key

client = VerdifaxClient(signing_key=private_key)
client.register_request_key()  # sends the public key with its proof

# attest, execute, the provider helpers, execute_batch and verify_determinism
# now sign.
receipt = client.attest(
    payload="first signed attestation",
    program_id="a" * 64,
    route_id="route-test",
    registry_record_hash="b" * 64,
)

client.clear_request_key()  # stops requiring signatures on this API key
```

`AsyncVerdifaxClient` takes the same `signing_key` and has the same two methods. `verdifax.attest` and the provider helpers accept `signing_key=` when they build their own client, and `verdifax shadow` takes `--signing-key-file`, a file holding the base64 private key.

Registering a key changes that API key for every client that uses it: the server then refuses a run without a valid signature, so every caller on the key needs the private key. Each request carries the time and a fresh random nonce. The server refuses a repeated nonce and a time more than five minutes from its own clock.

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

The signature shows the holder of the key requested the run. It does not show the key holder accepted the outcome.

## Optional execute fields

`attest`, `execute`, `execute_batch` and `verify_determinism` accept `attested_context`, `reproducibility_context`, `request_substance`, `authorization_chain`, `regulatory_scaffolding` and `causal_graph`. Each is recorded as supplied and Verdifax does not check it. The client derives `attested` and `declared` from the fields you provide. Leave out `request_substance["origin"]["source_ip_hash"]` and `["user_agent_hash"]`: the server computes them. `attest`, `execute` and `verify_determinism` refuse them before sending, and a batch row that sets them fails in `results`.

These methods check that `program_id` and `registry_record_hash` are 64 lowercase hex characters and that `route_id` is 1 to 256 printable ASCII characters. A `route_id` outside that range now raises `ValidationError` here, although the server accepts a wider set.

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

There is also `verdifax.attest_openai_response(...)` with the same signature, and both are methods on `VerdifaxClient` and `AsyncVerdifaxClient`.

The helpers attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `verdifax.format_provider_payload` builds that text. All four Verdifax SDKs produce the same bytes. A helper call from an earlier version used a different payload, so it gave a different hash for the same text; records already stored are not touched.

`govern` is false by default. Set `govern=True` to also send the response text as `ai_output_text` for the AIVP review, which runs on Anthropic in production. Without it, the AI output text is not sent for review.

## License

MIT
