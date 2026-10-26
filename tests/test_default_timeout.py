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


def test_docstrings_state_the_actual_default():
    # 0.6.1 raised the default to 90 seconds but both constructors' docs
    # still said 30 (round 38). The docs must name the real default.
    import inspect
    import re
    from verdifax import AsyncVerdifaxClient

    for cls in (VerdifaxClient, AsyncVerdifaxClient):
        doc = inspect.getsource(cls)
        stated = re.findall(r"Defaults to (\d+)", doc)
        assert stated, f"{cls.__name__} docstring states no default timeout"
        assert all(int(s) == int(DEFAULT_TIMEOUT) for s in stated), (cls.__name__, stated)
