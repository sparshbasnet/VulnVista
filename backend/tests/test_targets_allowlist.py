from app.api.v1.targets import _is_blocked_host, _is_trusted_host


def test_lab_host_is_trusted() -> None:
    assert _is_trusted_host("http://dvwa") is True
    assert _is_trusted_host("http://dvwa/vulnerabilities/exec/") is True


def test_localhost_is_trusted() -> None:
    assert _is_trusted_host("http://localhost:8080") is True


def test_unknown_host_is_not_trusted() -> None:
    assert _is_trusted_host("http://example.com") is False


def test_missing_url_is_not_trusted() -> None:
    assert _is_trusted_host(None) is False
    assert _is_trusted_host("") is False


def test_metadata_host_is_blocked() -> None:
    assert _is_blocked_host("http://169.254.169.254/latest/meta-data/") is True


def test_ordinary_host_is_not_blocked() -> None:
    assert _is_blocked_host("http://example.com") is False
    assert _is_blocked_host(None) is False
