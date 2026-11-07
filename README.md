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
| `export_runs(from_, to, job_id)` | `GET /runs/export` | required |
| `export_runs_csv(from_, to, job_id)` | `GET /runs/export?format=csv` | required |
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
| `rotate_request_key(new_signing_key)` | `POST /keys/request-key` | required |
| `clear_request_key()` | `DELETE /keys/request-key` | required |
| `upload_policy(document)` | `POST /policies` | required |
| `list_policies()` | `GET /policies` | required |
| `get_policy(document_hash)` | `GET /policies/{document_hash}` | required |
| `test_policy(inputs, document=None, document_hash=None)` | `POST /policies/test` | required |
| `get_policy_history()` | `GET /policies/history` | required |
| `activate_policy(document_hash)` | `GET /policies`, then `POST /policies/{document_hash}/activate` | required |
| `get_account()` | `GET /account` | owner key |
| `create_account_key(name, expires_at=None)` | `POST /account/keys` | owner key |
| `list_account_keys()` | `GET /account/keys` | owner key |
| `revoke_account_key(key_id)` | `DELETE /account/keys/{id}` | owner key |
| `register_account_request_key()` | `POST /account/request-key` | owner key |
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
| `admin_create_account(name, tier=None, expires_at=None)` | `POST /admin/accounts` | admin |
| `admin_list_accounts()` | `GET /admin/accounts` | admin |
| `admin_create_key(name, account_id=None)` | `POST /admin/keys` | admin |
| `admin_list_keys()` | `GET /admin/keys` | admin |
| `admin_revoke_key(key_id)` | `DELETE /admin/keys/{id}` | admin |
| `admin_clear_request_key(key_id)` | `DELETE /admin/keys/{id}/request-key` | admin |
| `admin_erase(...)` | `POST /admin/erase` | admin |

These functions make no request: `verdifax.research.capture_environment`, `format_provider_payload`, `sign_request`, `sign_request_v2`, `request_key_registration_body`, `request_signature_preimage`, `request_signature_preimage_v2`, `request_key_change_preimage`, `policy_activation_preimage`, `policy_activation_approval`, `generate_request_key`, `validate_hex64`, `validate_route_id`, and in `verdifax.section0`, `dse_dispatch_hash`, `dcae_closure_hash` and `cres_receipt_hash`. `RUN_STATUSES` lists every run status the server uses.

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

A trial key, which is what a pilot receives, needs a request key: it seals nothing until one is registered, and the key can then be replaced but not cleared. On a production key, request signing is optional, and a client with no signing key sends the same requests as before.

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

Replacing or clearing a registered key needs the approval of the current key, and `rotate_request_key` and `clear_request_key` send it for you. After a clear the client drops its signing key and sends unsigned requests, because the server refuses a signature on an API key with no registered key. If you lost the key, an administrator can clear it with `admin_clear_request_key(key_id)`. That call does not change the admin client's own signing key.

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

Every key of `policy_context` is optional. `actor_type` is `agent`, `user`, `service` or `system`; `mfa_satisfied` is a `bool`; `session_age_seconds` is a non-negative `int`; `object_type` is `text`, `transaction`, `code`, `data`, `model` or `file`; `object_id` is a string of at most 256 bytes; and `classification` is `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `TOP_SECRET` or `TS_SCI`. The client raises `ValidationError` for an unknown key or any other value before sending, because a misspelt field must never be dropped: a rule on it would read its zero value. `actor_type`, `mfa_satisfied` and `session_age_seconds` describe the attested actor, so they need an `attested_context` that names the actor, such as its `actor_id`; the client and the server refuse them without one. `object_type`, `object_id` and `classification` work without it. The provider helpers attest an AI assistant, so they can send all six.

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

`list_account_runs` and `export_account_runs` cover every key in the account. The account's view covers the runs its keys made through Verdifax, not runs made elsewhere. `export_account_runs` returns an `AccountRunsExport`: the fields of `export_runs` with `account_id`, `account_policy_documents` and `account_policy_history`. `export_account_runs_csv` returns the same rows as raw CSV text, and checks the count headers as `export_runs_csv` does.

`create_account_key(name, expires_at=None)` returns the new key with its `secret`, shown this once. The key takes the account's tier, and a key on a trial account needs a request key before it can run, as every trial key does. `revoke_account_key(key_id)` revokes a member key. For a key outside the account, or an owner key, the server answers 404 and the client raises `APIError`. `clear_account_request_key()` works as `clear_request_key()`: the client then drops its signing key, and the account's policy cannot be changed until the owner registers another request key.

An administrator can put a new customer key in an existing account with `admin_create_key(name, account_id=7)`, where `7` is the number in `account-7`. Without `account_id`, the key gets an account of its own. A key never changes account.

## Optional execute fields

`attest`, `execute`, `execute_batch` and `verify_determinism` accept `attested_context`, `reproducibility_context`, `request_substance`, `authorization_chain`, `regulatory_scaffolding` and `causal_graph`. Each is recorded as supplied and Verdifax does not check it. The client derives `attested` and `declared` from the fields you provide. `AttestedContext`, `ReproducibilityContext` and `ExecuteRequest` raise `ValidationError` for a field they do not have, and so does an `attested_context` given as a mapping, because the server would drop a misspelt field with no error. A misspelt keyword argument to `attest`, `execute` or `verify_determinism` raises Python's own `TypeError`. Leave out `request_substance["origin"]["source_ip_hash"]` and `["user_agent_hash"]`: the server computes them. `attest`, `execute` and `verify_determinism` refuse them before sending, and a batch row that sets them fails in `results`.

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
