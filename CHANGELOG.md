# Changelog

## 1.7.0

A published stopped run is served as its sealed receipt.

- `publish_run` and `unpublish_run` return `public_receipt_url`, the address of a stopped run's receipt while it is public, `/public/runs/{token}/receipt.json`; a stopped run has no bundle address, so `public_bundle_url` is absent for it. `verdifax-verify` checks the receipt address as it checks a saved receipt.
- `get_public_receipt_by_token(token)`, sync and async, reads a published stopped run's sealed receipt from `GET /public/runs/{token}/receipt.json`, as the exact text the server sent, with no key.

## 1.6.1

The same code as 1.6.0, which was tagged but never published: its release job stopped at the formatting check on two test files. This release formats them and publishes.

## 1.6.0

The account owner publishes the account's records.

Added, on `VerdifaxClient` and as coroutines on `AsyncVerdifaxClient`:

- `publish_run(run_id)`: `POST /account/runs/{id}/publish` makes a record made by any key of the account public on its random link, the same link a later publish restores. Needs the owner key. The decision is sealed as a run publication (`verdifax.run-publication.v1`) naming the run, its record hash, its job and step and the time, with its place in the account's signal feed, and the feed carries it as a `run.published` event. Idempotent: a record already public is answered as it is, with `publication` `None`. The service's admin key cannot publish another key's record.
- `unpublish_run(run_id)`: `POST /account/runs/{id}/unpublish` withdraws the record and keeps its link; a `run.unpublished` event.
- Signal kinds `run.published` and `run.unpublished` in `SIGNAL_KINDS`; `verdifax-verify --signals` reads them since v0.24.0.

## 1.5.0

The signal feed. The feed lists every control signal Verdifax recorded for the account, in order, each with its sealed entry: a run refused, halted or failed, a policy changed, a sign-off recorded, an approver key registered or revoked, and a key created or revoked. The feed cannot show a signal Verdifax never recorded.

Added, on `VerdifaxClient` and as coroutines on `AsyncVerdifaxClient`:

- `get_signals(after=0, limit=None, wait=0, as_owner=False)`: one page of the feed from `GET /signals` for a feed key, or `GET /account/signals` for the owner key with `as_owner=True`. `after` is the last sequence read, `limit` is 1 to 500 and `wait` is 0 to 25 seconds; anything else raises `ValidationError` before sending. The HTTP timeout of this call is at least `wait` plus 30 seconds, whatever the client's own timeout.
- `follow_signals(after=0, wait=25, as_owner=False)`: follows the feed page after page from `next_after`, so it never skips or repeats an event, and waits on the server when there is nothing new. It is a generator on `VerdifaxClient` and an async generator on `AsyncVerdifaxClient`. A failed page is retried with the client's normal retry policy, and an error it raises carries `last_sequence`, the last sequence read, so the caller can go on from the same place.
- `create_feed_key(name, expires_at=None)` and `revoke_feed_key(id)`: `POST /account/feed-keys` and `DELETE /account/feed-keys/{id}`, for the owner key. Feed keys read the feed and nothing else.
- `create_webhook(url, types=None)`, `list_webhooks()`, `delete_webhook(id)` and `list_webhook_deliveries(id, limit=None)`: the account's webhooks and their delivery logs, for the owner key. The url must start `https://` and each type must be one of the nine signal kinds, at most once; with no types a webhook takes every kind. The server checks the address too. A webhook delivery is a copy of one event: the pull feed and the public log are the record.
- `get_failure_receipt(run_id)`: `GET /runs/{id}/failure-receipt`, the sealed failure receipt of a run that failed with a server error.
- `verify_webhook(headers, body, secret, tolerance_seconds=300, now=None)`, which checks a webhook delivery under the Standard Webhooks scheme and returns its CloudEvent, and `signal_event_hash(kind, entry_hash, account, sequence, previous_signal_hash)`, which recomputes an event's hash. Neither makes a request. `verify_webhook` compares signatures in constant time, refuses a timestamp more than the tolerance from now in either direction, and raises `WebhookVerificationError` naming the check that failed. It never logs the secret.
- `SIGNAL_KINDS`, the nine signal kinds, and `WebhookVerificationError`.

Save a page of the feed with `json.dump`; `verdifax-verify --signals` checks a saved feed.

## 1.4.0

Customer sign-off on results. An approver signs a decision, approve or reject, on one exact result with an approver key the account's owner registered, and Verdifax logs it on the public log.

Added, on `VerdifaxClient` and as coroutines on `AsyncVerdifaxClient`:

- `register_approver(name, approver_key)`: `POST /account/approvers`, for the owner key. The proof is computed on this machine from the approver's private key, or taken from `approver_key_proof`, which the approver can run on their own machine; a ready-made proof is verified on this machine and refused before sending if it does not verify. Only the public key, the name and the proof are sent.
- `list_approvers()` and `revoke_approver(approver_id)`: `GET /account/approvers` and `DELETE /account/approvers/{id}`.
- `sign_off(target, decision, approver_key, note=None, as_owner=False)`: reads `GET /signoffs/newest`, hashes the note, signs on this machine and submits with `POST /signoffs`. With `as_owner=True` it uses `GET /account/signoffs/newest` and `POST /account/signoffs`. It raises `ValidationError` for a bad target, decision, note, approver key or `as_owner` before sending anything, and for an approver key that is the client's own `signing_key`. The note's text is never sent, only its SHA-256. An empty note is refused; with no note, the body carries no `note_hash`.
- `get_signoffs(run_id, as_owner=False)`: `GET /runs/{id}/signoffs`, or `GET /account/runs/{id}/signoffs` for the owner key.
- `get_newest_signoff(as_owner=False)`: `GET /signoffs/newest`, or `GET /account/signoffs/newest`.
- `get_signoff_history()`: `GET /account/signoffs/history`.
- `signoff_preimage(...)` and `approver_key_proof(private_key)`, which make no request, and the `SignOffTarget` model.

Changed:

- `RunsExport` and `AccountRunsExport` carry `signoffs`, the account's sign-offs, which an owner key's `export_account_runs` now receives.

An approver key is registered by the account's owner, and it is never a request key in the same account. A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show that the review was careful, that the result is right, or who the person is: a key is not an identity. A sign-off gates nothing on its own. A later sign-off on the same result supersedes the earlier one, and nothing is deleted. Verdifax did not review the result.

## 1.3.0

Accounts. An account is a company, and every API key belongs to one account for life. The account's owner key manages the account and cannot run anything.

Added, on `VerdifaxClient` and as coroutines on `AsyncVerdifaxClient`:

- `get_account()`: `GET /account`.
- `create_account_key(name, expires_at=None)`, `list_account_keys()` and `revoke_account_key(key_id)`: the account's member keys.
- `register_account_request_key()` and `clear_account_request_key()`: the owner key's own request key, which signs every change to the account's policy.
- `list_account_runs(limit, offset)`, `export_account_runs(from_, to, job_id)` and `export_account_runs_csv(from_, to, job_id)`: the runs of every key in the account. The JSON export is the new `AccountRunsExport` model, which adds `account_id`, `account_policy_documents` and `account_policy_history`.
- `upload_account_policy`, `list_account_policies`, `get_account_policy`, `test_account_policy`, `get_account_policy_history` and `activate_account_policy`: the account's policy, with the same arguments and answers as the key's policy methods.
- `admin_create_account(name, tier=None, expires_at=None)` and `admin_list_accounts()`.

Changed:

- `admin_create_key` takes an optional `account_id`, which puts a new customer key in an existing account.
- `ExportRow` and `RunSummary` carry `api_key_id`, the key that requested the run, so an account's export can be grouped by key.
- `RunsExport`, the answer of `export_runs`, now keeps `policy_documents` and `policy_history`, which the server already sends and earlier releases dropped, and the key's `account_id`, `account_policy_documents` and `account_policy_history`.
- `activate_account_policy` signs each change with the client's `signing_key` over the account's chain, such as `account-7`, with the same bytes as `activate_policy`. It raises `ValidationError` on a client with no `signing_key`, before sending anything, because the server refuses an unsigned change to an account's policy.

The account number is a label Verdifax assigned, not a verified company identity. An account policy is the customer's own, and Verdifax did not write, review or approve it. Every key in the account must pass the account policy on top of its own, and a run is admitted only when both allow it.
- `DeterminismResultRow.receipt` and `DeterminismDiff.reason`: the server now compares two refused or halted replays by the manifest hashes they sealed, returns each sealed receipt, and says why there is no verdict when neither replay sealed a record.
