"""verdifax command-line interface.

Currently one subcommand, built for design-partner pilots:

    verdifax shadow denials.csv --hash ssn,income,dti --key vfx_...

Shadow mode replays a lender's ALREADY-MADE decisions (an ordinary
CSV export) through the Verdifax pipeline and seals each row into an
independently verifiable audit record. Everything privacy-critical
happens on the caller's machine:

  - The named --hash columns are replaced by SHA-256 fingerprints
    BEFORE anything is sent; raw values never leave this process.
  - With --salt, hashing is keyed (sha256(salt + ":" + value)), which
    defends low-cardinality fields (incomes, ZIP codes) against
    guess-and-hash. Keep the salt; re-verification recomputes with it.
  - The payload sent per row is the canonical JSON of the transformed
    row. Verdifax stores only the hash of that payload.

Outputs <input>.verdifax-results.csv mapping every row to its run id
and sealed manifest hash, then prints how to independently verify.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .client import VerdifaxClient
from .exceptions import VerdifaxError

# Deterministic defaults for pilots that have no program registry yet.
# program_id is a fixed domain hash; registry_record_hash is derived
# from the CSV header, so the sealed runs are bound to the exact
# export schema they attested (a different column set produces a
# different registry hash, visibly).
_SHADOW_PROGRAM_ID = hashlib.sha256(b"verdifax.shadow.program.v1").hexdigest()

# Default trial cap, mirrors the orchestrator's default. The CLI warns
# (not blocks) because the server enforces authoritatively.
_TRIAL_CAP_DEFAULT = 5000


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verdifax",
        description="Verdifax CLI (SDK %s)" % __version__,
    )
    sub = parser.add_subparsers(dest="command")

    shadow = sub.add_parser(
        "shadow",
        help="seal a CSV of past decisions in shadow mode (pilot workflow)",
    )
    shadow.add_argument("csv_path", help="CSV export of past decisions (header row required)")
    shadow.add_argument(
        "--hash",
        default="",
        metavar="COL1,COL2",
        help="comma-separated column names to replace with SHA-256 fingerprints before sending",
    )
    shadow.add_argument(
        "--salt",
        default="",
        help="optional secret salt for keyed hashing (recommended; keep it, re-verification needs it)",
    )
    shadow.add_argument("--key", default="", help="Verdifax API key (or env VERDIFAX_API_KEY)")
    # The LIBRARY defaults to localhost (developer ergonomics for
    # people running the orchestrator locally). The CLI is a
    # customer-facing pilot tool, so it defaults to production;
    # VERDIFAX_API_URL or --base-url still override.
    shadow.add_argument(
        "--base-url",
        default="",
        help="API base URL (default: $VERDIFAX_API_URL or https://api.verdifax.com)",
    )
    shadow.add_argument(
        "--route",
        default="shadow-" + _dt.date.today().isoformat(),
        help="route id recorded on every run (default shadow-<today>)",
    )
    shadow.add_argument(
        "--ai-output-column",
        default="",
        metavar="COL",
        help="optionally govern this column's text via the live AI stage per row (slower, ~1 cent/row)",
    )
    shadow.add_argument(
        "--limit", type=int, default=0, help="only process the first N rows (0 = all)"
    )
    shadow.add_argument(
        "--yes",
        action="store_true",
        help="proceed without prompting (required when rows exceed the trial cap)",
    )

    args = parser.parse_args(argv)
    if args.command != "shadow":
        parser.print_help()
        return 2
    return _run_shadow(args)


def _hash_value(value: str, salt: str) -> str:
    material = (salt + ":" + value) if salt else value
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _run_shadow(args: argparse.Namespace) -> int:
    src = Path(args.csv_path)
    if not src.exists():
        print(f"error: {src} not found", file=sys.stderr)
        return 2

    with src.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("error: CSV has no header row", file=sys.stderr)
            return 2
        header = list(reader.fieldnames)
        rows = list(reader)

    if args.limit > 0:
        rows = rows[: args.limit]

    hash_cols = [c.strip() for c in args.hash.split(",") if c.strip()]
    missing = [c for c in hash_cols if c not in header]
    if missing:
        print(f"error: --hash columns not in CSV header: {', '.join(missing)}", file=sys.stderr)
        print(f"       header is: {', '.join(header)}", file=sys.stderr)
        return 2
    if args.ai_output_column and args.ai_output_column not in header:
        print(
            f"error: --ai-output-column {args.ai_output_column!r} not in CSV header",
            file=sys.stderr,
        )
        return 2

    if not hash_cols:
        print("note: no --hash columns given; ALL values will be sent as-is.")
        print("      For applicant-identifying or financial fields, use --hash.")
    if hash_cols and not args.salt:
        print("note: hashing without --salt; low-cardinality values (incomes,")
        print("      ZIP codes) can be guessed-and-hashed. --salt is recommended.")

    if len(rows) > _TRIAL_CAP_DEFAULT and not args.yes:
        print(
            f"error: {len(rows)} rows exceeds the trial cap of {_TRIAL_CAP_DEFAULT} "
            f"sealed runs per 30 days.\n"
            f"       Process a subset with --limit, or pass --yes if this key is "
            f"on production terms.",
            file=sys.stderr,
        )
        return 2

    registry_hash = hashlib.sha256(
        ("verdifax.shadow.schema.v1:" + ",".join(header)).encode("utf-8")
    ).hexdigest()

    base_url = args.base_url or os.environ.get("VERDIFAX_API_URL") or "https://api.verdifax.com"
    # api_key=None lets the client fall back to $VERDIFAX_API_KEY.
    api_key = args.key or None

    out_path = src.with_suffix(src.suffix + ".verdifax-results.csv")
    sealed = 0
    failed = 0

    print(f"shadow mode: {len(rows)} rows from {src.name}")
    print(f"  hashed columns:  {', '.join(hash_cols) if hash_cols else '(none)'}")
    print(f"  route:           {args.route}")
    print(f"  schema binding:  {registry_hash[:16]}… (sha256 of the header)")
    print()

    with (
        VerdifaxClient(base_url=base_url, api_key=api_key) as client,
        out_path.open("w", newline="", encoding="utf-8") as out_f,
    ):
        writer = csv.writer(out_f)
        writer.writerow(["row_index", "status", "run_id", "manifest_hash", "error"])
        for i, row in enumerate(rows):
            transformed = dict(row)
            for col in hash_cols:
                transformed[col] = _hash_value(row.get(col) or "", args.salt)
            payload = json.dumps(transformed, sort_keys=True, separators=(",", ":"))
            ai_text = (row.get(args.ai_output_column) or "") if args.ai_output_column else None
            try:
                receipt = client.attest(
                    payload=payload,
                    program_id=_SHADOW_PROGRAM_ID,
                    route_id=args.route,
                    registry_record_hash=registry_hash,
                    ai_output_text=ai_text or None,
                )
                writer.writerow([i, "sealed", receipt.run_id or "", receipt.manifest_hash, ""])
                sealed += 1
            except VerdifaxError as exc:
                writer.writerow([i, "failed", "", "", str(exc)])
                failed += 1
                # A quota refusal will repeat for every remaining row;
                # stop early with an honest explanation instead of
                # hammering the API with N-i doomed requests.
                if "trial_quota_exceeded" in str(exc):
                    print(
                        f"\nrow {i}: trial quota reached; stopping. "
                        f"({sealed} rows sealed so far are unaffected.)"
                    )
                    break
            if (i + 1) % 50 == 0:
                print(f"  {i + 1}/{len(rows)} rows sealed…")

    print()
    print(f"done: {sealed} sealed, {failed} failed")
    print(f"results: {out_path}")
    print()
    print("Verify independently (no Verdifax trust required):")
    print("  1. Pick any run_id from the results file.")
    print("  2. Fetch its bundle:  GET /runs/<id>/artifacts  (with your key)")
    print("  3. Check it offline:  verdifax-verify --show-evidence-summary bundle.json")
    print("     (open-source: github.com/Verdifax/verdifax-verify)")
    if hash_cols:
        print()
        print("Keep your CSV" + (" and salt" if args.salt else "") + ": re-hashing any")
        print("original row must reproduce the sealed fingerprints exactly. That")
        print("comparison is your tamper-evidence.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
