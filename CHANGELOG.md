# Changelog

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
