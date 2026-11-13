# Changelog

## 1.15.0

Request-key changes sealed in the feed, and the feed's head statement.

- The server now seals each registration, rotation and clear of a customer key's request key in the account's feed as an `account.changed` event, decided by the account's side (`owner`), in one transaction with the change. The two new actions are `request_key.registered`, whose `value` is the new public key, and `request_key.rotated`, whose `value` is the new public key and whose `request_key_approval` is the replaced key's approval (`public_key`, `signature`, `signed_at`, `nonce`), signed over the same request-key change bytes `rotate_request_key` already signs. A `request_key.cleared` its holder made carries the approval over the empty key; one Verdifax made is decided by `verdifax_admin` and carries none, as before. `verdifax-verify --signals` follows each key's chain from its registration. `register_request_key`, `rotate_request_key`, `clear_request_key`, `register_account_request_key` and `clear_account_request_key` send the same bodies as before. The feed's events are read as the server sends them, every field kept, and `pending_signoffs` and `follow_signals` take the new changes in stride; tests hold the approvals to the bytes the server checks.
- `rotate_account_request_key(new_signing_key)` (owner key) replaces the owner key's request key with `POST /account/request-key`, as `rotate_request_key` does on the API key's route and with the same code: the new key's proof, the current key's approval of the change, the switch to the new key only after a 2xx, and the current key kept after a refusal. The rotation is sealed in the feed as `request_key.rotated`, completing the owner key's request-key chain.
- When another change to the request key came first, those six calls now get a 409 from the server, "the request key changed since this change was signed". The client raises `APIError` with the server's message and status 409, sends the request once, and keeps its signing key.
- `get_signals` returns `head` on a page that reaches the feed's end: the feed's head statement, `verdifax.feed-head.v1`, with the account, the feed's highest event (`sequence`) and that event's hash (`head_hash`), `stated_at`, `head_statement_hash` and its public-log `anchor`. `verdifax-verify --signals` checks a saved feed against it. The page is returned as the server sent it; a head with a missing or malformed field raises `VerdifaxError`. `verdifax.FEED_HEAD_FORM` names the format, and `verdifax.FeedHead` types it.
- `follow_signals(after=0, wait=25, as_owner=False, on_head=None, after_event_hash=None)` now returns a `SignalFollower`, and an `AsyncSignalFollower` on `AsyncVerdifaxClient`: iterate it as before, with `for` or `async for`, and stop by leaving the loop or with `close()` or `aclose()`. A head is never yielded as an event. The follower keeps a head only once every event on its page has been handled (the loop asked for the item after the page's last event), only when its `sequence` is that page's `next_after` and its `head_hash` is the `event_hash` of the last event handled, and only when it is another statement than the one kept, at the same event or a later one: a head repeated on idle reads is not kept again, and a fresh statement for the same event, made after the server's five-minute reuse, replaces it. Before an event is handled, the last event handled is event `after`: pass `after_event_hash`, the `event_hash` of that event as you saved it, and a follower resuming at the feed's end keeps the head it is served; without it, no head is kept until an event is handled. A non-empty `after_event_hash` that is not 64 lowercase hex characters raises `ValidationError` before anything is sent. The kept head is in the follower's `head`, also after the loop stops; each newly kept head is passed to `on_head`; and an error raised while following carries it as `head`, beside `last_sequence` and `after_event_hash`, the `event_hash` of the last event finished (or the one given, when none was; `None` when neither), so a caller resumes with both values. The rule is shared by the four SDKs, and a test runs every case of the shared vector `tests/sdk-feed-head-vector.json` on both followers.
- A run-deletion tombstone is typed as `verdifax.RunDeletion`, `log_entries` a list of strings (the deleted record's public-log entries, as decimal text so no number is rounded). On a job step deleted since this server release it carries `job_links`, typed as `verdifax.DeletedJobLinks`, present even when empty: the step's `previous_record_hashes` (at most 64) and `external_previous` (at most 16), each sorted distinct 64 lowercase hex hashes, and `final`, each left out when empty or false. Older tombstones carry none. `delete_run` and `admin_delete_run` check the tombstone in their answer, and `get_signals` and `follow_signals` check the tombstone in an event's `data.deleted`: one that is not an object, whose `run_id` is not a whole number, whose `log_entries` is not a list of strings, or whose `job_links` breaks that shape or appears without a `job_id` raises `VerdifaxError`. Every value is kept as the server sent it, so a saved page or answer keeps every field.
- `pending_signoffs(events)` leaves a run out once its `run.deleted` event appears, at any place, as before; a deleted run's `run.sealed` event keeps its own entry. A `run.sealed` or `run.deleted` event that names no run raises `VerdifaxError`, as before, and so now does one whose `run_id` is 0 or less. The shared vector `tests/sdk-pending-signoffs-vector.json` fixes these answers for all four SDKs, and a test runs every case through `get_signals` and `follow_signals`, sync and async. A refused, halted or failed run's receipt event whose record was deleted, served with `entry` `None` and the tombstone in `data["deleted"]`, is not read for runs.
- The user agent is `verdifax-python/1.15.0`.

## 1.14.0

Owner settings, record deletion, owner-key replacement, and run bodies read strictly.

- `ExecutionManifest` keeps every field the server sends: the fields it types as attributes, and every other sealed field (policy gate, AI review, budget, ledger, account and job fields among them) in `model_extra`, where earlier releases dropped them when a response was read.
- `set_account_setting(setting, value, account_id=None)` (owner key) sets one of the owner's two blocks on Verdifax with `PUT /account/settings/{setting}`. `setting` is `owner-replacement` or `verdifax-deletion`, and `value` is `allowed` or `blocked`; anything else raises `ValidationError` before anything is sent. While `owner-replacement` is blocked, Verdifax cannot replace or revoke the owner key. While `verdifax-deletion` is blocked, Verdifax cannot delete one of the account's records. The answer's `account_change` is `None` when the value was already set.
- `delete_run(run_id, record_hash, account_id=None)` (owner key) deletes one of the account's records with `POST /account/runs/{id}/delete`. `record_hash` is the record's hash: a completed run's `record_hash`, or a stopped run's receipt hash. The record's tombstone stays in the account's feed.
- Both are signed on this machine by the owner key's request key, the client's `signing_key`, over `verdifax.owner-change-signature.v1`, the account's label (read from `GET /account` unless `account_id` is given), the change (`setting.owner_replacement`, `setting.verdifax_deletion` or `run.deleted`), its subject (the value, or `RUN_ID:RECORD_HASH`), the time and a fresh nonce. The record seals the signature. Verdifax never holds the owner's request key, so it cannot make a signature with it, and `verdifax-verify --signals --owner-request-key` confirms every owner change in the feed was signed with the owner's key. A client with no `signing_key` raises `ValidationError` before anything is sent. The client checks the sealed record in the answer carries what was sent, `decided_by` `owner` and the owner's signature with this client's public key, and raises `VerdifaxError` otherwise, as `sign_off` does. `verdifax.owner_change_preimage(account, change, subject, signed_at, nonce)` returns the signed bytes and makes no request. A test holds its signature to the vector every SDK checks, computed with the server's Go code.
- `admin_delete_run(run_id)` and `admin_replace_owner_key(account_id)` (admin key) delete a record as Verdifax, and start the replacement of a lost owner key, on the owner's written request, by emailing a one-time link. `account_id` is the account's number. The answer never holds the link or a key. The server refuses both while the owner blocks them.
- `get_account()` returns `owner_replacement` and `verdifax_deletion`, each `allowed` or `blocked`.
- The signal feed carries two new kinds, `account.changed` and `run.deleted`, and `verdifax.SIGNAL_KINDS` lists them. Each records who decided. A key change may now be `verdifax.key-change.v2`, which carries `decided_by`. Webhook verification is unchanged.
- The server now refuses a field it does not define in a body of `POST /execute`, `/execute/batch` or `/execute/verify-determinism` with `APIError` (400) naming it, unless the request asks `lenient=1`. Every body the SDK builds, the signed text of a version 2 request included, holds only fields the server defines.
- `pending_signoffs(events)` leaves out a run whose deletion is in the events given: a `run.deleted` event for its `run_id`, at any place, removes it from the list. A `run.deleted` entry that names no run raises `VerdifaxError`, as a `run.sealed` one does.
- The user agent is `verdifax-python/1.14.0`.

## 1.13.0

Sign-off read as the verifier reads it, and the sign-off history's head statement.

- `pending_signoffs(events)` reads the decision in force as `verdifax-verify` does: the latest job sign-off on a run governs when there is one, and otherwise the latest record sign-off. A run approved by a sign-off on its whole job is no longer listed, and one whose job was rejected is, even when the step carries its own approval.
- `get_public_signoff` and `get_public_signoff_by_token`: `decision_in_force` names the kind of sign-off in force (`signed_as`), its place (`sequence`) and time (`signed_at`) and, when the job's decision governs, the result's own latest decision (`own_decision`). It is `None` for a step whose job's sign-offs could not be read.
- `get_signoff_history()` ends with the chain's head statement, `verdifax.signoff-head.v1`, anchored on the public log. `verdifax-verify --signoff-history` reports the history complete as of that entry's time, and requires the head when a rule requires a person's sign-off, since v0.31.0.
- The server now refuses a request that gives a query value more than once with `APIError` (400). The SDK gives each value once.
- The user agent is `verdifax-python/1.13.0`.

## 1.12.0

Data-quality declarations, pending sign-offs, public sign-offs, and requests read strictly.

- `policy_context` takes `data_quality`: where the data came from (`source`), the time it describes (`as_of`, read as strictly as the server reads it) and the checks you ran on it (`checks`, each a `name` and a `result` of `pass`, `fail` or `warn`). It is sealed with the other policy values, and a policy's `data_quality` condition can require and test it. Verdifax judges none of it. The SDK checks it before sending, with the shared data-quality vector every SDK and the server test.
- `pending_signoffs(events)` lists, in feed order, the runs whose allowing rule requires a person's sign-off and on which no approval is in force. It makes no request.
- `get_public_signoff(run_id)` and `get_public_signoff_by_token(token)` read the sign-off a published run's audit report prints, and for a step of a job, the job's decision in force. No API key needed.
- `download_audit_pdf` and `download_public_audit_pdf` take `fallback`. The server now refuses a report format it does not know with `APIError` (400); `fallback="comprehensive"` asks for the comprehensive report instead.
- `list_runs`, `search_runs`, `list_account_runs` and `list_attestations` take `lenient`. The server now refuses a value it cannot read, such as a date in `search_runs`, with `APIError` (400); `lenient=True` asks it to ignore or replace the value instead.
- The user agent is `verdifax-python/1.12.0`.

## 1.11.0

Interrupted sign-offs and policy changes, exact records, and time limits.

- The signal feed carries a new kind, `chain.interrupted`: a sign-off or policy change whose public-log entry was never confirmed has its place closed by a sealed, anchored record naming the entry it would have made. `verdifax-verify --signals`, `--signoff-history` and `--policy-history` accept a skipped place through one since v0.29.0, and the sign-off and policy histories may hold interrupted records in place.
- Tests prove that a number above 2^53 in a sign-off, a policy change or a feed event comes back with every digit, from the sync and async clients.
- Every CI job has its own time limit.

## 1.10.0

Successful runs in the feed, restore gaps, a required AI review, reports that print the AI's answer, and the account's time zone.

- The signal feed carries two new kinds: `run.sealed`, a successful run's record naming the run and the exact record it sealed, and `chain.gap`, a restore gap that names the places a chain skips after a restore from backup. `verdifax-verify --signals` reads both since v0.28.0, and the sign-off and policy histories may hold restore gaps in place.
- `test_policy` and `test_account_policy` take `ai_output_declared=True` to test a policy whose `ai_review` sets `"required": true`: the server refuses, with reason `ai_review_required`, a step under the requirement that declares no AI output.
- `download_audit_pdf(run_id, format, ai_output_text=...)` sends the AI's exact answer, and the report prints it on its first page, marked as supplied, only when its SHA-256 is the hash the record seals; other text raises `APIError` (422). `download_public_audit_pdf(token, format, ai_output_text=None)` reads a published record's audit PDF with no key. Both exist on the async client.
- `set_account_time_zone(time_zone)` (owner key) sets the second time zone the account's audit PDFs show beside UTC: an IANA zone, `"none"` for UTC alone, or `""` for the server region's zone.

## 1.9.0

The AI review says what it found, and the trace that proves it comes back to you.

- When an account's AI review runs on a step's AI output, the record seals what it found: the review setup (prompt and model), the SHA-256 of the trace it checked, the checker, what the account policy chose a contradiction finding does (`halt` or `record`), the outcome (`clean`, `halted` or `recorded`) and the finding (two trace nodes and the opposing terms). Verdifax returns the trace once and does not store it; keep it to re-run the check with `verdifax-verify --aivp-trace` (or `--aivp-traces` for a job), since v0.27.0.
- `AttestationReceipt.aivp_trace_text` and each batch row's `aivp_trace_text` hold the trace of a released run; `APIError.aivp_trace_text` holds it for a run the review halted. `manifest.aivp_review` (`AivpReview`, `AivpFinding`) is the sealed review.

## 1.8.0

A publication says who decided.

- A run publication is now `verdifax.run-publication.v2` and seals who decided: `owner`, the account's owner key, or `verdifax_admin`, a Verdifax admin key, which can withdraw any public record and publish only records it made itself. Every change to a record's public state, Verdifax's included, is now sealed in the feed of the record's account. The publication dict carries it as `decided_by`. Publications sealed before v2 are v1, carry no `decided_by`, and were the owner's. `verdifax-verify --signals` reads v2 since v0.26.0.

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
