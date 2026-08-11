from app.api.v1.targets import _is_allowed


def test_lab_host_is_allowed() -> None:
    assert _is_allowed("http://dvwa") is True
    assert _is_allowed("http://dvwa/vulnerabilities/exec/") is True


def test_localhost_is_allowed() -> None:
    assert _is_allowed("http://localhost:8081") is True


def test_unknown_host_is_denied() -> None:
    assert _is_allowed("http://example.com") is False


def test_missing_url_is_denied() -> None:
    assert _is_allowed(None) is False
    assert _is_allowed("") is False
