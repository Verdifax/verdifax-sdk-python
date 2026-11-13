# Verdifax Python SDK

Cryptographic attestation for AI inference. Register a request key, then send a signed payload, get a sealed manifest hash, anchored on a public log, you can give to an auditor.

## Install

```bash
pip install verdifax
```

## Quickstart

On a trial key, register a request key first and give the client that key: see [Request signing](#request-signing). Without it, a trial key refuses the run.

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

That's it. The receipt's `manifest_hash` is a 64-char SHA-256 that seals the envelope (the payload's hash, the program and the route), every kernel execution ID, the hardware attestation hash, the ZK transcript hash, the formal verifier status and the final VFA hash, among other fields. The context blocks you declare (`attested_context`, `request_substance` and the others) are sealed by their own section hashes in the run's audit bundle, not by the manifest hash. You can later ask the server to re-derive it from the run's stored manifest with `verify_run(receipt.run_id)`; see [Verification](#verification).

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
| `list_runs(limit, offset, lenient=False)` | `GET /runs`. A value the server cannot read raises `APIError` (400) unless `lenient=True`; `search_runs`, `list_account_runs` and `list_attestations` take `lenient` too | required |
| `search_runs(...)` | `GET /runs/search` | required |
| `export_runs(from_, to, job_id)` | `GET /runs/export` | required |
| `export_runs_csv(from_, to, job_id)` | `GET /runs/export?format=csv` | required |
| `get_run_artifacts(run_id)` | `GET /runs/{run_id}/artifacts` | required |
| `get_run_report(run_id)` | `GET /runs/{run_id}/report` | required |
| `download_audit_pdf(run_id, format, ai_output_text=None, fallback=None)` | `GET /runs/{run_id}/report.pdf`, or `POST` with the AI's answer, printed when its SHA-256 is the sealed hash. An unknown format raises `APIError` (400) unless `fallback="comprehensive"` | required |
| `download_public_audit_pdf(token, format, ai_output_text=None, fallback=None)` | `GET` or `POST /public/runs/{token}/report.pdf` | none |
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
| `get_public_signoff(run_id)` | `GET /runs/{run_id}/signoff.json`: the sign-off a published run's audit report prints, and its job's decision in force | none |
| `get_public_signoff_by_token(token)` | `GET /public/runs/{token}/signoff.json` | none |
| `dcae_verify(bundle)` | `POST /dcae/verify` | none |
| `register_request_key()` | `POST /keys/request-key` | required |
| `rotate_request_key(new_signing_key)` | `POST /keys/request-key` | required |
| `clear_request_key()` | `DELETE /keys/request-key` | required |
| `upload_policy(document)` | `POST /policies` | required |
| `list_policies()` | `GET /policies` | required |
| `get_policy(document_hash)` | `GET /policies/{document_hash}` | required |
| `test_policy(inputs, document=None, document_hash=None)` | `POST /policies/test` | required |
| `get_policy_history()` | `GET /policies/history` | required |
| `activate_policy(document_hash)` | `GET /policies`, then `POST /policies/{document_hash}/activate` | required |
| `get_account()` | `GET /account` | owner key |
| `set_account_setting(setting, value, account_id=None)` | `GET /account` unless `account_id` is given, then `PUT /account/settings/{setting}`, signed by the owner key's request key | owner key |
| `create_account_key(name, expires_at=None)` | `POST /account/keys` | owner key |
| `list_account_keys()` | `GET /account/keys` | owner key |
| `revoke_account_key(key_id)` | `DELETE /account/keys/{id}` | owner key |
| `register_account_request_key()` | `POST /account/request-key` | owner key |
| `rotate_account_request_key(new_signing_key)` | `POST /account/request-key` | owner key |
| `clear_account_request_key()` | `DELETE /account/request-key` | owner key |
| `list_account_runs(limit, offset)` | `GET /account/runs` | owner key |
| `export_account_runs(from_, to, job_id)` | `GET /account/runs/export` | owner key |
| `export_account_runs_csv(from_, to, job_id)` | `GET /account/runs/export?format=csv` | owner key |
| `upload_account_policy(document)` | `POST /account/policies` | owner key |
| `list_account_policies()` | `GET /account/policies` | owner key |
| `get_account_policy(document_hash)` | `GET /account/policies/{document_hash}` | owner key |
| `test_account_policy(inputs, document=None, document_hash=None)` | `POST /account/policies/test` | owner key |
| `get_account_policy_history()` | `GET /account/policies/history` | owner key |
| `activate_account_policy(document_hash)` | `GET /account/policies`, then `POST /account/policies/{document_hash}/activate` | owner key |
| `delete_run(run_id, record_hash, account_id=None)` | `GET /account` unless `account_id` is given, then `POST /account/runs/{run_id}/delete`, signed by the owner key's request key | owner key |
| `register_approver(name, approver_key)` | `POST /account/approvers` | owner key |
| `list_approvers()` | `GET /account/approvers` | owner key |
| `revoke_approver(approver_id)` | `DELETE /account/approvers/{id}` | owner key |
| `sign_off(target, decision, approver_key, note=None, as_owner=False)` | `GET /signoffs/newest`, then `POST /signoffs`; with `as_owner=True`, `GET /account/signoffs/newest`, then `POST /account/signoffs` | required, or owner key |
| `get_signoffs(run_id, as_owner=False)` | `GET /runs/{run_id}/signoffs`; with `as_owner=True`, `GET /account/runs/{run_id}/signoffs` | required, or owner key |
| `get_newest_signoff(as_owner=False)` | `GET /signoffs/newest`; with `as_owner=True`, `GET /account/signoffs/newest` | required, or owner key |
| `get_signoff_history()` | `GET /account/signoffs/history` | owner key |
| `get_signals(after=0, limit=None, wait=0, as_owner=False)` | `GET /signals`; with `as_owner=True`, `GET /account/signals` | feed key, or owner key |
| `follow_signals(after=0, wait=25, as_owner=False, on_head=None, after_event_hash=None)` | `GET /signals`, page after page; with `as_owner=True`, `GET /account/signals` | feed key, or owner key |
| `create_feed_key(name, expires_at=None)` | `POST /account/feed-keys` | owner key |
| `revoke_feed_key(id)` | `DELETE /account/feed-keys/{id}` | owner key |
| `create_webhook(url, types=None)` | `POST /account/webhooks` | owner key |
| `list_webhooks()` | `GET /account/webhooks` | owner key |
| `delete_webhook(id)` | `DELETE /account/webhooks/{id}` | owner key |
| `list_webhook_deliveries(id, limit=None)` | `GET /account/webhooks/{id}/deliveries` | owner key |
| `get_failure_receipt(run_id)` | `GET /runs/{run_id}/failure-receipt` | required |
| `admin_create_account(name, tier=None, expires_at=None)` | `POST /admin/accounts` | admin |
| `admin_list_accounts()` | `GET /admin/accounts` | admin |
| `admin_create_key(name, account_id=None)` | `POST /admin/keys` | admin |
| `admin_list_keys()` | `GET /admin/keys` | admin |
| `admin_revoke_key(key_id)` | `DELETE /admin/keys/{id}` | admin |
| `admin_clear_request_key(key_id)` | `DELETE /admin/keys/{id}/request-key` | admin |
| `admin_delete_run(run_id)` | `POST /admin/runs/{id}/delete` | admin |
| `admin_replace_owner_key(account_id)` | `POST /admin/accounts/{id}/owner-key/replace` | admin |
| `admin_erase(...)` | `POST /admin/erase` | admin |

These functions make no request: `verdifax.research.capture_environment`, `format_provider_payload`, `sign_request`, `sign_request_v2`, `request_key_registration_body`, `request_signature_preimage`, `request_signature_preimage_v2`, `request_key_change_preimage`, `policy_activation_preimage`, `owner_change_preimage`, `policy_activation_approval`, `signoff_preimage`, `approver_key_proof`, `signal_event_hash`, `verify_webhook`, `generate_request_key`, `validate_hex64`, `validate_route_id`, and in `verdifax.section0`, `dse_dispatch_hash`, `dcae_closure_hash` and `cres_receipt_hash`. `RUN_STATUSES` lists every run status the server uses.

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

A row given as a mapping raises `ValidationError` for a key the server does not read, before anything is sent, because the server would drop a misspelt field with no error. A row can carry a `job` block, which is checked before sending. With a signing key each result row has its own `signed_request`, and every row that sealed a record has its `record_hash`.

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

Pass `job_id` to either method to export one job. Rows carry `anchor_source`, `job_id` and `step_id`.

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `truncated`. `export_runs_csv` reads `total` and `truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and raises `VerdifaxError` if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`.

## Jobs

A job is a map of sealed steps. Each step names the records it directly follows, so a missing, swapped or repeated step is visible, and work can split into branches and join again.

`client.job(job_id)` returns a helper that keeps the map for you. `step` takes everything `attest` takes, runs one step, and links it by step id. It raises `ValidationError` for any other option, `job` included, before anything is sent, so a typo like `afer` can never silently use the default link:

```python
run = {"program_id": "a" * 64, "route_id": "route-test", "registry_record_hash": "b" * 64}

job = client.job("loan-1")
job.step("intake", payload="application", **run)

# Two steps after intake.
job.step("credit", after=["intake"], payload="credit check", **run)
job.step("fraud", after=["intake"], payload="fraud check", **run)

# A final step joining them.
job.step("decide", after=["credit", "fraud"], final=True, payload="decision", **run)

print(job.record_hashes)  # step id to record hash
```

Without `after`, a step follows the step run just before it through this helper, or nothing if it is the first. `after=[]` starts another root step. An `after` naming a step the helper has not recorded raises `ValidationError` before anything is sent. `external_previous` takes record hashes from another account. `AsyncVerdifaxClient.job` returns the same helper with `step` as a coroutine.

A refused or halted step still seals a record. The helper records its hash, then raises the same error `attest` raises, so a later step can name the refused step in `after`. A call that sealed nothing, such as a step id already taken, a timeout or a connection failure, is not recorded and does not change which step comes next by default. After a timeout or a connection failure the server may have run the step. A successful step with no `record_hash` uses a top-level `manifest_hash`, then the manifest's own hash, and with none of them the helper raises `VerdifaxError`, so the map never silently gets a gap.

Without the helper, pass `job={"job_id": ..., "step_id": ..., "previous_record_hashes": [...], "external_previous": [...], "final": True}` to `attest`, `execute` or a provider helper, or put it in a batch row. A determinism check runs twice, so it cannot be a job step. `job_id` and `step_id` are 1 to 128 letters, digits, `.`, `_`, `:` or `-`, and the client raises `ValidationError` for any other name. It also refuses an unknown field, a `final` that is not a `bool` and a hash list that is not a `list`, because a typo must never silently drop a link. It sorts both lists and removes repeats for you.

The receipt from `attest` has `record_hash`, and an error from a refused or halted run has it too.

A job map covers what was sent. It cannot show a step that was never sent.

## Determinism check

`client.verify_determinism(...)` runs one payload twice on the server and compares the manifest hashes. `deterministic` is true when both runs ended `ok` and the two hashes match. Both runs are recorded, with the status `probe`, or `stage_error` for a replay that sealed nothing or whose record could not be anchored on the probe's in-process ledger. `verdifax.research.verify_determinism(client, ...)` is the same call for a sync client.

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

A trial key, which is what a pilot receives, needs a request key: it seals nothing until one is registered. Its holder can then replace the request key but not clear it; only Verdifax can clear it, for a holder who lost it, after which the trial key again seals nothing until a new one is registered, and for a key in an account the clearing is sealed in that account's feed as an account change. On a production key, request signing is optional, and a client with no signing key sends the same requests as before.

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
# now sign, and activate_policy signs each policy change.
receipt = client.attest(
    payload="first signed attestation",
    program_id="a" * 64,
    route_id="route-test",
    registry_record_hash="b" * 64,
)

# The current key approves its replacement. This client then signs with the new key.
client.rotate_request_key(verdifax.generate_request_key().private_key)

client.clear_request_key()  # stops requiring signatures on this API key
```

`AsyncVerdifaxClient` takes the same `signing_key` and has the same three methods. `verdifax.attest` and the provider helpers accept `signing_key=` when they build their own client, and `verdifax shadow` takes `--signing-key-file`, a file holding the base64 private key.

A signed call sends the request once, as exact JSON text, with a signature that covers those bytes and the job block:

```json
{"signed_request": "<the JSON text>", "request_signature": {"version": "2", "signature": "...", "signed_at": "...", "nonce": "..."}}
```

The receipt keeps that text as `signed_request`. Save it to a file to check the record with `verdifax-verify --request FILE`. An error from a refused or halted run carries `signed_request` as an attribute, and it is left out of the error's message, so it does not reach your logs. `execute` returns only the manifest, so use `attest` to keep the text from a sealed run. `DeterminismResult` and each row of a batch result carry it too. The job helper keeps it in `job.signed_requests`, step id to text, beside `job.record_hashes`, refused and halted steps included.

Replacing or clearing a registered key needs the approval of the current key, and `rotate_request_key` and `clear_request_key` send it for you. For a key in a customer's account, the server seals each registration, rotation and clear in the account's feed (`request_key.registered`, `request_key.rotated`, `request_key.cleared`), with the approval the client sent, in the same transaction as the change: see [Signal feed](#signal-feed). When another change to the key came first, the server answers 409, "the request key changed since this change was signed", and the client raises `APIError` with that message, does not retry, and keeps its signing key: read the key again before you repeat the change. After a clear the client drops its signing key and sends unsigned requests, because the server refuses a signature on an API key with no registered key. If you lost the key, an administrator can clear it with `admin_clear_request_key(key_id)`. That call does not change the admin client's own signing key.

Registering a key changes that API key for every client that uses it: the server then refuses a run without a valid signature, so every caller on the key needs the private key. Each request carries the time and a fresh random nonce. The server refuses a repeated nonce and a time more than five minutes from its own clock.

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

A signature shows who requested the run, not that they accepted the outcome.

`sign_request` and `request_signature_preimage` still build the earlier version 1 signature, which the server refuses for a job step. `sign_request_v2` and `request_signature_preimage_v2` build what a client sends.

## Policies

A policy is your own set of rules for which runs your API key admits. You write it as a JSON document, store it, try it on sample inputs, and then make it the policy in force. Until you activate one, your key runs under the built-in policy.

Verdifax did not write, review or approve your policy. A pass means the rules ran, not that they are good rules.

```python
from pathlib import Path

# Read the bytes and decode them, so the text is sent exactly, line endings included.
document = Path("policy.json").read_bytes().decode("utf-8")

uploaded = client.upload_policy(document)  # stores the text; nothing changes yet
document_hash = uploaded["document_hash"]

# Which rule would fire on sample inputs. This seals nothing.
trial = client.test_policy(
    {"subject_type": "agent", "verb": "wire-transfer", "object_type": "transaction",
     "classification": "CONFIDENTIAL", "mfa_satisfied": False},
    document_hash=document_hash,
)
print(trial["outcome"], trial["fired_rule_id"], trial["reason_code"])

record = client.activate_policy(document_hash)  # the change record
```

`upload_policy` sends the string it is given, unchanged, because the server hashes those exact bytes as `document_hash`. It raises `ValidationError` for anything that is not a `str`, such as a dict, because serializing an object here would change the hash. `test_policy` takes exactly one of `document` and `document_hash`. `get_policy(document_hash)` returns the stored text as `document`, and `list_policies()` returns your documents with `chain_id`, `newest_activation_hash` and `active_document_hash`.

`activate_policy` reads `GET /policies` for the chain and its newest change, then sends the change naming that newest change. With a `signing_key`, the client signs the change with your request key, which the server requires once a request key is registered on the API key. Without a registered request key, use a client with no `signing_key`: the server refuses a signature it has no key to check. A 409 means another change came first, or the document is not yet effective. The client raises `APIError` with the server's message and does not retry: list the policies again before you decide to repeat the change.

Rolling back is activating an earlier document. It adds one more change to the chain, so the change it undoes stays on the record:

```python
client.activate_policy(earlier_document_hash)
```

A run declares the facts the rules read in `policy_context`, and can name the policy it expects with `expected_policy_hash`:

```python
from verdifax import AttestedContext

receipt = client.attest(
    payload="transfer 1042",
    program_id="a" * 64,
    route_id="wire-transfer",
    registry_record_hash="b" * 64,
    attested_context=AttestedContext(actor_id="payments-agent-7", actor_role="payments_agent"),
    policy_context={
        "actor_type": "agent",
        "mfa_satisfied": True,
        "session_age_seconds": 120,
        "object_type": "transaction",
        "object_id": "txn-1042",
        "classification": "CONFIDENTIAL",
    },
    expected_policy_hash=uploaded["policy_hash"],
)
```

Every key of `policy_context` is optional. `actor_type` is `agent`, `user`, `service` or `system`; `mfa_satisfied` is a `bool`; `session_age_seconds` is a non-negative `int`; `object_type` is `text`, `transaction`, `code`, `data`, `model` or `file`; `object_id` is a string of at most 256 bytes; `classification` is `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `TOP_SECRET` or `TS_SCI`; and `data_quality` is described below. The client raises `ValidationError` for an unknown key or any other value before sending, because a misspelt field must never be dropped: a rule on it would read its zero value. `actor_type`, `mfa_satisfied` and `session_age_seconds` describe the attested actor, so they need an `attested_context` that names the actor, such as its `actor_id`; the client and the server refuse them without one. `object_type`, `object_id` and `classification` work without it. The provider helpers attest an AI assistant, so they can send all seven.

`data_quality` is your declaration about the data the decision used, a mapping of `source` (at most 200 bytes), `as_of` (a time such as `2026-11-11T09:00:00Z` or `2026-11-11T09:00:00+05:30`) and `checks`, a list of up to 50 mappings, each a distinct `name` of at most 100 bytes and a `result` of `pass`, `fail` or `warn`. It needs no attested actor. It is sealed with the other values, a policy's `data_quality` condition can require and test it, and Verdifax judges none of it. The client raises `ValidationError` for a declaration the server would refuse before sending.

`expected_policy_hash` is 64 lowercase hex characters. When another policy is active, the server refuses the run with 409, and the client raises `APIError`. `attest`, `execute`, each row of `execute_batch`, `verify_determinism`, the provider helpers and job steps all take both fields. They go into the request before it is signed, so a signed request covers them.

A policy judges what you declared. It cannot show the declared facts are true.

A run the rules refuse still seals a record, and `attest` raises `StageError` with stage `PEPG`, carrying `record_hash`. A refusal stops the action only if your system waits for the answer.

`get_policy_history()` returns the list of changes, oldest first. Save it to a file and check the chain with `verdifax-verify --policy-history FILE`:

```python
import json

history = client.get_policy_history()
Path("policy-history.json").write_text(json.dumps(history), encoding="utf-8")
# verdifax-verify --policy-history policy-history.json
```

`verdifax.policy_activation_approval(signing_key, chain_id, document_hash, previous_activation_hash)` builds the change's `signature` block without sending anything, and `verdifax.policy_activation_preimage(...)` returns the bytes it signs.

## Accounts

An account is a company. Every API key belongs to one account for life. The account's owner key manages the account: it creates and revokes member keys, sets the account's policy and reads the runs of every key in the account. Member keys are the keys that run, and they work as API keys always have.

An owner key cannot run anything. The server refuses it, with 403, on every route that needs an API key other than the `/account` routes.

```python
from pathlib import Path

import verdifax
from verdifax import VerdifaxClient

# The admin creates the account and its first owner key.
admin = VerdifaxClient(api_key="admin key")
created = admin.admin_create_account("Acme", tier="production")
print(created["account"]["account_id"])  # for example account-7
owner_secret = created["owner_key"]["secret"]  # shown this once

# The owner key's request key signs every change to the account's policy.
owner_signing_key = verdifax.generate_request_key().private_key  # store it as a secret
owner = VerdifaxClient(api_key=owner_secret, signing_key=owner_signing_key)
owner.register_account_request_key()

# The owner creates the member keys that run.
member = owner.create_account_key("payments")
print(member["secret"])  # shown this once

# The owner stores, tries and activates the account's policy.
document = Path("account-policy.json").read_bytes().decode("utf-8")
uploaded = owner.upload_account_policy(document)
owner.test_account_policy({"verb": "wire-transfer"}, document_hash=uploaded["document_hash"])
owner.activate_account_policy(uploaded["document_hash"])

# The owner exports the runs of every key in the account.
evidence = owner.export_account_runs(from_="2026-11-01T00:00:00Z", to="2026-12-01T00:00:00Z")
print(evidence.account_id, evidence.total, evidence.truncated)
```

The account number is a label Verdifax assigned, not a verified company identity.

An account policy is your own. Verdifax did not write, review or approve it. Every key in the account must pass the account policy on top of its own, and a run is admitted only when both allow it.

The account policy methods take the same arguments and return the same objects as the [Policies](#policies) methods, on the account's documents. `list_account_policies()` returns the account's chain as `chain_id`, such as `account-7`. `activate_account_policy` reads `GET /account/policies` for that chain and its newest change, and signs the change exactly as `activate_policy` does, with the owner key's request key. The server refuses every unsigned change to an account's policy, so `activate_account_policy` raises `ValidationError` on a client with no `signing_key`, before it sends anything. `get_account_policy_history()` returns the account's changes, oldest first, as the server sent them.

`list_account_runs` and `export_account_runs` cover every key in the account. The account's view covers the runs its keys made through Verdifax, not runs made elsewhere. `export_account_runs` returns an `AccountRunsExport`: the fields of `export_runs` with `account_id`, `account_policy_documents`, `account_policy_history` and `signoffs`, the account's sign-offs, oldest first. `export_account_runs_csv` returns the same rows as raw CSV text, and checks the count headers as `export_runs_csv` does.

`create_account_key(name, expires_at=None)` returns the new key with its `secret`, shown this once. The key takes the account's tier, and a key on a trial account needs a request key before it can run, as every trial key does. `revoke_account_key(key_id)` revokes a member key. For a key outside the account, or an owner key, the server answers 404 and the client raises `APIError`. `rotate_account_request_key(new_signing_key)` works as `rotate_request_key()` on the owner key: the current key approves the new one, the client signs with the new key only after the server accepts it, and keeps its key after a refusal, including a 409 when another change came first. The rotation is sealed in the feed as `request_key.rotated`, so the owner key's request-key chain can be followed from its registration. `clear_account_request_key()` works as `clear_request_key()`: the client then drops its signing key, and the account's policy cannot be changed until the owner registers another request key.

An administrator can put a new customer key in an existing account with `admin_create_key(name, account_id=7)`, where `7` is the number in `account-7`. Without `account_id`, the key gets an account of its own. A key never changes account.

### Owner settings and deleting records

The owner decides two blocks on Verdifax. While `owner-replacement` is `blocked`, Verdifax cannot replace or revoke the account's owner key, or start a replacement. While `verdifax-deletion` is `blocked`, Verdifax cannot delete one of the account's records. `get_account()` returns both, as `owner_replacement` and `verdifax_deletion`, each `allowed` or `blocked`.

```python
owner = VerdifaxClient(api_key=owner_secret, signing_key=owner_signing_key)
owner.set_account_setting("verdifax-deletion", "blocked")
owner.set_account_setting("owner-replacement", "blocked")

# The owner deletes one record, naming the exact record it read.
owner.delete_run(42, record_hash)
```

`set_account_setting(setting, value, account_id=None)` takes `owner-replacement` or `verdifax-deletion`, and `allowed` or `blocked`; anything else raises `ValidationError` before anything is sent. The answer's `account_change` is the sealed record, or `None` when the value was already set and nothing changed.

`delete_run(run_id, record_hash, account_id=None)` deletes one of the account's records. `record_hash` is the record's hash, 64 lowercase hex characters: a completed run's `record_hash`, or a stopped run's receipt hash. The server refuses a hash that is not the run's with 409, and a public record with 409 until `unpublish_run(run_id)` withdraws it. The owner's own deletions are never blocked. The answer's `run_deletion` is the tombstone, which stays in the account's feed.

Both are signed on this machine by the client's `signing_key`, the owner key's request key, so register it first with `register_account_request_key()`. The record seals the signature. Verdifax never holds the owner's request key, so it cannot make a signature with it, and `verdifax-verify --signals --owner-request-key` confirms every owner change in the feed was signed with the owner's key. A client with no `signing_key` raises `ValidationError` before anything is sent. The signature covers the account's label, which the client reads from `GET /account` unless you pass `account_id`, such as `account-7`. `verdifax.owner_change_preimage(account, change, subject, signed_at, nonce)` returns the signed bytes: `verdifax.owner-change-signature.v1`, the account, the change (`setting.owner_replacement`, `setting.verdifax_deletion` or `run.deleted`), the subject (the value, or `RUN_ID:RECORD_HASH`), the time and the nonce, joined by zero bytes. It makes no request. Each change is placed in the account's signal feed, as an `account.changed` or `run.deleted` event decided by the owner. The client checks the server's answer seals exactly what was sent: the record must carry the change and its value, or the run and its record hash, `decided_by` `owner`, and the owner's signature, time and nonce that were sent, with the public key of this client's `signing_key`. Any other record raises `VerdifaxError`, as `sign_off` does for a record that is not the sign-off sent.

An administrator deletes a record with `admin_delete_run(run_id)`, and starts the replacement of a lost owner key, on the owner's written request, with `admin_replace_owner_key(account_id)`, where `account_id` is the account's number, `7` for `account-7`. The server emails a one-time link to the address of the access request that made the account; the new key is made when the link is opened, shown once to whoever opens it and stored only as a hash, and this call's answer never holds the link or a key. Each is sealed in the account's feed as decided by Verdifax, and the server refuses each (409) while the owner blocks it.

## Sign-off

An approver signs a decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step. The approver signs on their own machine with an approver key, and any key in the account submits the sign-off.

An approver key is registered by the account's owner, and it is never a request key in the same account. The server refuses to register a key that is a request key in the account, so the key that requested a run can never sign it off, and the client refuses an approver key that is its own `signing_key` before sending anything.

```python
import json
from pathlib import Path

import verdifax
from verdifax import VerdifaxClient

# The approver makes a new Ed25519 key pair on their own machine, keeps the
# private key secret, and never registers it as a request key.
approver = verdifax.generate_request_key()
proven = verdifax.approver_key_proof(approver.private_key)  # public key and proof only

# The owner registers it. Only the public key, the name and the proof are sent.
owner = VerdifaxClient(api_key=owner_secret)
owner.register_approver("Dana, credit review", proven)

# The digest is what the result's public-log entry covers. The member key that
# made run 42 reads its record.
member = VerdifaxClient(api_key=member_secret)
artifacts = json.loads(member.get_run_artifacts(42))
digest = artifacts["bundle_anchor"]["anchored_digest"]

# The approver signs and submits. The note's text stays here; only its hash is sent.
record = member.sign_off(
    {"kind": "record", "run_id": 42, "digest": digest},
    "approve",
    approver.private_key,
    note="checked against the loan file",
)
print(record["sequence"], record["signoff_hash"])

# Save the run's sign-offs and check them offline.
Path("signoffs.json").write_text(json.dumps(member.get_signoffs(42)), encoding="utf-8")
# verdifax-verify --signoff signoffs.json ...
```

`register_approver(name, approver_key)` takes the approver's 32 raw private key bytes, and computes the proof on this machine, or the answer of `approver_key_proof(private_key)`, which the approver can build on their own machine so the private key never leaves it. A ready-made proof is verified on this machine, and one that does not verify raises `ValidationError` before anything is sent. Either way only the public key, the name and the proof are sent. `list_approvers()` lists the account's approver keys, revoked ones included, and `revoke_approver(approver_id)` revokes one. A revoked key's earlier sign-offs stay on the record.

`sign_off(target, decision, approver_key, note=None, as_owner=False)` checks every input first and raises `ValidationError` before anything is sent: the target's `kind` is `record`, `receipt` or `job`; `run_id` is a positive `int`; `digest` is 64 lowercase hex characters; `job_id` is set for a job and only for a job; `decision` is `approve` or `reject`. The target is a `SignOffTarget` or a mapping with those names. Then it reads the account's chain and newest sign-off from `GET /signoffs/newest`, signs on this machine, and submits with `POST /signoffs`. The owner key passes `as_owner=True` to use `GET /account/signoffs/newest` and `POST /account/signoffs`, and `get_signoffs` and `get_newest_signoff` take `as_owner` the same way. A 409 means another sign-off came first, or the target is not a result of the account or its digest is not the one its public-log entry covers; the client raises `APIError` and does not retry.

The digest is what the result's public-log entry covers. A record's digest is the `bundle_anchor` `anchored_digest` in the JSON `get_run_artifacts(run_id)` returns. A receipt's digest is its `hash`, from `get_deny_receipt(run_id)` or the other receipt methods. A job's digest is its final step's record digest, with the job's `job_id`.

The note's text is never sent. The client sends only its SHA-256 as `note_hash`, so keep the text yourself to show which note was signed. An empty `note` raises `ValidationError`; with no note, leave `note` out and the body carries no `note_hash`. `signed_at` is the current time and the nonce is 32 fresh hex characters.

A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show that the review was careful, that the result is right, or who the person is: a key is not an identity. A sign-off gates nothing on its own. A later sign-off on the same result supersedes the earlier one, and nothing is deleted. Verdifax did not review the result.

`get_signoffs(run_id)` returns a run's sign-offs, oldest first, in the form `verdifax-verify --signoff FILE` reads; the decision in force is the latest, except on a job's final step, where the latest sign-off on the whole job governs; `verdifax-verify --signoff` names it. `get_signoff_history()` returns the account's whole chain for the owner key, in the form `verdifax-verify --signoff-history FILE` reads, ending with the chain's head statement (`verdifax.signoff-head.v1`), anchored on the public log, from which the verifier reports the history complete as of that time (since v0.31.0), and the owner's `export_account_runs` carries the same chain as `signoffs`. `verdifax-verify` reads sign-offs since v0.22.0.

`verdifax.signoff_preimage(chain_id, previous_signoff_hash, target, decision, note_hash, signed_at, nonce)` returns the bytes an approver key signs, and `verdifax.approver_key_proof(private_key)` returns the public key and proof to register. Neither makes a request.

## Signal feed

The feed lists every control signal Verdifax recorded for the account, in order: a run sealed (`run.sealed`), a run refused, halted or failed, a policy changed, a sign-off recorded, an approver key registered or revoked, a key created or revoked, a record made public or withdrawn (`run.published`, `run.unpublished`), a change to the account or a key's terms (`account.changed`), a record deleted (`run.deleted`), a restore gap (`chain.gap`) and an interrupted entry (`chain.interrupted`). `verdifax.SIGNAL_KINDS` lists every kind. A change records who decided it, the owner or Verdifax; a key change in `verdifax.key-change.v2` carries `decided_by`. Each event is a CloudEvent whose `data` carries its `kind`, its `sequence` in the account's feed, the `previous_signal_hash`, its own `event_hash` and the sealed `entry` it names; an event whose entry is a record that was since deleted (for example a refused run's receipt event) carries `entry` null and the record's tombstone in `deleted`; an event that is its own sealed record, such as `run.sealed`, keeps its own `entry`. The feed cannot show a signal Verdifax never recorded.

Each registration, rotation and clear of a customer key's request key is sealed in the feed as an `account.changed` event, decided by the account's side (`owner`), in the same transaction as the change: `request_key.registered` (the `value` is the new public key), `request_key.rotated` (the `value` is the new public key, and `request_key_approval` is the replaced key's approval, its `public_key`, `signature`, `signed_at` and `nonce`), and `request_key.cleared` (an empty `value`; the holder's own clear carries the approval, and a clear by Verdifax is decided by `verdifax_admin` and carries none). Each entry names the key in `key_id`, so `verdifax-verify --signals` can follow each key's request-key chain from its registration.

The owner key creates a feed key with `create_feed_key(name, expires_at=None)` and revokes it with `revoke_feed_key(id)`. A feed key reads the feed and nothing else. It reads `GET /signals`, and the owner key reads the same feed with `as_owner=True`.

```python
from verdifax import VerdifaxClient

owner = VerdifaxClient(api_key=owner_secret)
feed_key = owner.create_feed_key("siem")  # its secret is shown this once

client = VerdifaxClient(api_key=feed_key["secret"])
last_sequence_read = 0  # or the place saved last time
for event in client.follow_signals(after=last_sequence_read):
    data = event["data"]
    handle(data["kind"], data["entry"])
    last_sequence_read = data["sequence"]  # keep it, to go on from here next time
```

`get_signals(after=0, limit=None, wait=0, as_owner=False)` reads one page: `events`, `next_after` and `newest`. A page that reaches the feed's end also carries `head`, the feed's head statement (`verdifax.feed-head.v1`): the account, the feed's highest event (`sequence`) and that event's hash (`head_hash`), `stated_at`, `head_statement_hash` and its public-log `anchor`, so a saved feed shows it was complete as of that entry's time. The head is not an event, and `verdifax.FeedHead` types it. The page is returned as the server sent it; the client raises `VerdifaxError` for a head with a missing or malformed field. An event whose entry is a record that was since deleted (for example a refused run's receipt event) carries `data["entry"]` `None` and the record's tombstone in `data["deleted"]`, typed as `verdifax.RunDeletion`, whose `log_entries` are the record's public-log entries as decimal strings and whose `job_links`, on a job step deleted since this release, are the step's own job links; an event that is its own sealed record, such as `run.sealed`, keeps its own `entry`. `after` is the last sequence read, `limit` is 1 to 500 (the server's default is 100) and `wait` is 0 to 25 seconds, the time the server holds the request open when there is nothing after `after`. Anything else raises `ValidationError` before anything is sent. The HTTP timeout of a feed read is at least `wait` plus 30 seconds, whatever the client's own timeout.

`follow_signals(after=0, wait=25, as_owner=False, on_head=None, after_event_hash=None)` reads page after page, going on from each page's `next_after`, so it never skips or repeats an event; a page that would skip or repeat one raises `VerdifaxError`. It returns a `SignalFollower`, an iterator, and an `AsyncSignalFollower` on `AsyncVerdifaxClient` (use `async for`); stop by leaving the loop, or with `close()` (`aclose()`). A page's head is never yielded as an event. The follower keeps a head once every event on its page has been handled (the loop asked for the item after the page's last event), when its `sequence` is that page's `next_after` and its `head_hash` is the `event_hash` of the last event handled, and when it is another statement than the head kept, at the same event or later; a head repeated on idle reads is not kept again. Before an event is handled, the last event handled is event `after`: save each event's `event_hash` with its `sequence`, and pass it back as `after_event_hash` with `after`, so a follower resuming at the feed's end keeps the head it is served. Without it, no head is kept until an event is handled. A non-empty `after_event_hash` that is not 64 lowercase hex characters raises `ValidationError` before anything is sent. The kept head is in the follower's `head` (`None` until one is kept), also after the loop stops; `follow_signals(on_head=fn)` passes each newly kept head to `fn`; and an error raised while following carries it as `head`, beside `last_sequence` and `after_event_hash`, the `event_hash` of the last event finished (or the one you gave, when none was): pass both back to resume. Save it beside the events you keep. A failed page is retried with the client's normal retry policy, and the error it then raises carries `last_sequence`, the last sequence read, to pass as `after` to go on. With `wait=0` it pauses one second after an empty page.

Save a page with `json.dump(client.get_signals(), file)`. `verdifax-verify --signals` checks a saved feed. `verdifax.signal_event_hash(kind, entry_hash, account, sequence, previous_signal_hash)` recomputes an event's hash, the hex SHA-256 of `verdifax.signal.v1` and those values joined by zero bytes, and makes no request.

`verdifax.pending_signoffs(events)` returns, in feed order, the run ids whose allowing policy rule requires a person's sign-off (their `run.sealed` event says `signoff_required`) and on which no approval is in force, read as `verdifax-verify` reads it: the latest sign-off on the run's whole job governs when there is one, and otherwise the latest sign-off on its record; a receipt sign-off does not count. A run whose deletion is in the events given (a `run.deleted` event naming it, at any place) is left out, since its record is gone. A `run.sealed` or `run.deleted` event that names no run, or a `run_id` of 0 or less, raises `VerdifaxError`. Pass the feed from its start, or pages that include each run's sign-offs and deletions. It makes no request.

### Webhooks

The owner key subscribes a webhook with `create_webhook(url, types=None)`. The url must start `https://`, and `types` lists signal kinds from `verdifax.SIGNAL_KINDS`, each at most once; with no types the webhook takes every kind. The server checks the address too, and answers 409 when the account holds ten webhooks already. The answer carries the webhook's `secret`, shown this once. `list_webhooks()`, `delete_webhook(id)` and `list_webhook_deliveries(id, limit=None)` manage the subscriptions and show each delivery's attempts.

A delivery is a copy: the pull feed and the public log are the record. Check every delivery before acting on it:

```python
import verdifax

def receive(headers, raw_body):
    try:
        event = verdifax.verify_webhook(headers, raw_body, webhook_secret)
    except verdifax.WebhookVerificationError as failed:
        return 400  # failed.check names the check that failed
    handle(event["data"]["kind"], event["data"]["entry"])
    return 204
```

`verdifax.verify_webhook(headers, body, secret, tolerance_seconds=300, now=None)` follows the Standard Webhooks scheme. The secret is `whsec_` and base64. The signed content is `webhook-id`, a dot, `webhook-timestamp`, a dot and the raw body bytes, and `webhook-signature` lists `v1,<base64>` entries, any one of which may match; each is compared in constant time. A timestamp more than `tolerance_seconds` from now, in either direction, is refused. Header names are read in any case. Pass the body exactly as received, bytes or text, before any JSON parsing. It returns the CloudEvent, or raises `WebhookVerificationError` naming the check that failed. It makes no request and never logs the secret.

### Failure receipts

`get_failure_receipt(run_id)` returns the sealed failure receipt of a run that failed with a server error, as `failure_receipt`, with its `receipt_anchor` when it has one. A failed run from before failure receipts answers 404.

## Optional execute fields

`attest`, `execute`, `execute_batch` and `verify_determinism` accept `attested_context`, `reproducibility_context`, `request_substance`, `authorization_chain`, `regulatory_scaffolding` and `causal_graph`. In a completed run's sealed record each is recorded as supplied, except the values the server observes itself (in `request_substance`, `latency.total_ms`, the authentication method and key, and the origin hashes it fills; in `regulatory_scaffolding`, empty data-residency regions it fills), and Verdifax does not check that what you declare is true. A refused or halted run's receipt holds none of these blocks, but its `receipt_context` seals the declared policy inputs (such as subject and object identifiers) when the policy names its author and its rules ran. The client derives `attested` and `declared` from the fields you provide. `AttestedContext`, `ReproducibilityContext` and `ExecuteRequest` raise `ValidationError` for a field they do not have, and so does an `attested_context` given as a mapping, because the server would drop a misspelt field with no error. A misspelt keyword argument to `attest`, `execute` or `verify_determinism` raises Python's own `TypeError`. Leave out `request_substance["origin"]["source_ip_hash"]` and `["user_agent_hash"]`: the server computes them. `attest`, `execute` and `verify_determinism` refuse them before sending, and a batch row that sets them fails in `results`.

They also accept `policy_context` and `expected_policy_hash`, which the client checks before sending: see [Policies](#policies).

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

There is also `verdifax.attest_openai_response(...)` with the same signature, and both are methods on `VerdifaxClient` and `AsyncVerdifaxClient`. Both accept the same optional `job` block as `attest`, and return `record_hash` and `signed_request` the same way.

The helpers attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `verdifax.format_provider_payload` builds that text. All four Verdifax SDKs produce the same bytes. A helper call from an earlier version used a different payload, so it gave a different hash for the same text; records already stored are not touched.

`govern` is false by default. Set `govern=True` to also send the response text as `ai_output_text` for the AIVP review, which runs on Anthropic in production. Without it, the AI output text is not sent for review.

## License

MIT
