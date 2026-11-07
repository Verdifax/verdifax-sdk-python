# Changelog

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
