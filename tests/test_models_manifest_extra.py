"""Round 60: the manifest model keeps every field the server sends."""

from typing import Any

from verdifax.models import ExecutionManifest


def test_the_manifest_keeps_fields_it_does_not_type(manifest_dict: dict[str, Any]) -> None:
    sealed = dict(manifest_dict, PepgPolicyHash="b" * 64, AccountID="account-7")
    m = ExecutionManifest.model_validate(sealed)
    assert m.model_extra is not None
    assert m.model_extra["PepgPolicyHash"] == "b" * 64
    assert m.model_extra["AccountID"] == "account-7"
    assert m.manifest_hash == manifest_dict["ManifestHash"]
