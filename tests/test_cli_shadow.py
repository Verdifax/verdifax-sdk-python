"""Tests for the `verdifax shadow` CLI subcommand."""

from __future__ import annotations

import csv
import hashlib
import json
from unittest import mock

import httpx

from tests.conftest import make_execute_response
from verdifax import cli


def _write_csv(tmp_path, rows, header):
    p = tmp_path / "denials.csv"
    with p.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return p


HEADER = ["applicant_id", "income", "dti", "reason_codes"]
ROWS = [
    {"applicant_id": "A-1", "income": "41000", "dti": "0.52", "reason_codes": "R04,R11"},
    {"applicant_id": "A-2", "income": "88000", "dti": "0.31", "reason_codes": "R02"},
]


def _patched_client(captured):
    """Return a VerdifaxClient factory whose HTTP layer records bodies."""

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200, json=make_execute_response())

    from verdifax.client import VerdifaxClient

    real_init = VerdifaxClient.__init__

    def init(self, *a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        kw.setdefault("base_url", "http://test.invalid")
        kw.setdefault("api_key", "vfx_test")
        real_init(self, *a, **kw)

    return mock.patch.object(VerdifaxClient, "__init__", init)


def test_shadow_hashes_named_columns_and_writes_results(tmp_path, capsys):
    src = _write_csv(tmp_path, ROWS, HEADER)
    captured: list[dict] = []
    with _patched_client(captured):
        rc = cli.main(["shadow", str(src), "--hash", "applicant_id,income", "--salt", "s3cret"])
    assert rc == 0
    assert len(captured) == 2

    # The sent payload must carry fingerprints, never raw values.
    body0 = captured[0]
    payload0 = json.loads(body0["payload_text"])
    assert payload0["applicant_id"] == hashlib.sha256(b"s3cret:A-1").hexdigest()
    assert payload0["income"] == hashlib.sha256(b"s3cret:41000").hexdigest()
    # Unhashed columns pass through for the audit record.
    assert payload0["reason_codes"] == "R04,R11"
    assert "A-1" not in body0["payload_text"]
    assert "41000" not in body0["payload_text"]

    # registry hash binds the schema (sha256 of the header list).
    expected_registry = hashlib.sha256(
        ("verdifax.shadow.schema.v1:" + ",".join(HEADER)).encode()
    ).hexdigest()
    assert body0["registry_record_hash"] == expected_registry

    # Results CSV exists with one line per row.
    out = src.with_suffix(src.suffix + ".verdifax-results.csv")
    lines = out.read_text().strip().splitlines()
    assert lines[0].startswith("row_index,status,run_id,manifest_hash")
    assert len(lines) == 3
    assert ",sealed," in lines[1]


def test_shadow_missing_hash_column_errors(tmp_path, capsys):
    src = _write_csv(tmp_path, ROWS, HEADER)
    rc = cli.main(["shadow", str(src), "--hash", "nope"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not in CSV header" in err


def test_shadow_row_limit(tmp_path):
    src = _write_csv(tmp_path, ROWS, HEADER)
    captured: list[dict] = []
    with _patched_client(captured):
        rc = cli.main(["shadow", str(src), "--limit", "1"])
    assert rc == 0
    assert len(captured) == 1


def test_shadow_over_cap_requires_yes(tmp_path, capsys):
    src = _write_csv(tmp_path, ROWS, HEADER)
    with mock.patch.object(cli, "_TRIAL_CAP_DEFAULT", 1):
        rc = cli.main(["shadow", str(src)])
    assert rc == 2
    assert "exceeds the trial cap" in capsys.readouterr().err
