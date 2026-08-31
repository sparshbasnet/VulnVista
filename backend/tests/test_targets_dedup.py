from app.api.v1.targets import _endpoint_identity, _same_scan_config

# --- endpoint normalisation --------------------------------------------------


def test_trailing_slash_is_the_same_endpoint() -> None:
    assert _endpoint_identity("http://dvwa", None) == _endpoint_identity("http://dvwa/", None)


def test_host_case_is_ignored() -> None:
    assert _endpoint_identity("http://DVWA", None) == _endpoint_identity("http://dvwa", None)


def test_default_port_is_implied() -> None:
    assert _endpoint_identity("http://dvwa:80", None) == _endpoint_identity("http://dvwa", None)
    assert _endpoint_identity("https://tls-test:443", None) == _endpoint_identity(
        "https://tls-test", None
    )


def test_surrounding_whitespace_is_ignored() -> None:
    assert _endpoint_identity("  http://dvwa  ", None) == _endpoint_identity("http://dvwa", None)


def test_non_default_port_is_a_different_endpoint() -> None:
    assert _endpoint_identity("http://juice-shop:3000", None) != _endpoint_identity(
        "http://juice-shop", None
    )


def test_scheme_is_part_of_the_endpoint() -> None:
    assert _endpoint_identity("https://dvwa", None) != _endpoint_identity("http://dvwa", None)


def test_different_path_is_a_different_scan_surface() -> None:
    assert _endpoint_identity("http://dvwa/vulnerabilities/exec/", None) != _endpoint_identity(
        "http://dvwa", None
    )


def test_ip_only_target_falls_back_to_the_address() -> None:
    assert _endpoint_identity(None, "10.0.0.5") == "10.0.0.5"
    assert _endpoint_identity("", " 10.0.0.5 ") == "10.0.0.5"


def test_target_with_no_endpoint_has_no_identity() -> None:
    # An empty identity must never match another empty one, or every endpointless
    # target would collapse into a single record.
    assert _endpoint_identity(None, None) == ""
    assert _endpoint_identity("", "") == ""


# --- scan_config equivalence -------------------------------------------------


def test_absent_config_spellings_are_equivalent() -> None:
    # SQLAlchemy's JSON column stores None as JSON null, so rows carry both.
    assert _same_scan_config(None, None)
    assert _same_scan_config({}, None)
    assert _same_scan_config(None, {})


def test_identical_overrides_are_equivalent() -> None:
    assert _same_scan_config({"use_zap": True}, {"use_zap": True})


def test_differing_overrides_are_a_distinct_context() -> None:
    assert not _same_scan_config({"use_zap": True}, None)
    assert not _same_scan_config({"username": "a"}, {"username": "b"})
    assert not _same_scan_config({"username": "a"}, {"username": "a", "password": "b"})
