"""The default request timeout outlasts a slow sealed run."""

from verdifax import VerdifaxClient
from verdifax.client import DEFAULT_TIMEOUT


def test_default_timeout_is_at_least_90_seconds():
    # 30 seconds made the client report an error for a run the server
    # went on to seal (readiness run 259, October 26, 2026).
    assert DEFAULT_TIMEOUT >= 90.0
    client = VerdifaxClient(api_key="vfx_test")
    try:
        assert client.timeout == DEFAULT_TIMEOUT
    finally:
        client.close()
