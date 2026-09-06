import uuid

from app.models.scan import Scan
from app.models.target import Target
from app.scanners import get_detectors_for_profile
from app.services.scan_runner import MAX_SCOPED_PATHS, _build_runs


def _target() -> Target:
    t = Target(
        id=uuid.uuid4(),
        name="dvwa",
        target_type="lab",
        base_url="http://dvwa",
        environment="lab",
        is_allowed=True,
    )
    t.scan_config = {"login_path": "/login.php", "username": "admin", "password": "password"}
    return t


def _scan(in_scope=None) -> Scan:
    s = Scan(id=uuid.uuid4(), target_id=uuid.uuid4(), scan_profile="full")
    s.in_scope_paths = in_scope
    return s


def test_unscoped_scan_runs_each_detector_once() -> None:
    detectors = get_detectors_for_profile("full")
    runs = _build_runs(detectors, _target(), _scan(None))
    assert len(runs) == len(detectors)
    for _, context in runs:
        assert context.base_url == "http://dvwa"
        assert "discovery_path" not in context.extra


def test_scoped_scan_runs_path_detectors_per_path_and_host_once() -> None:
    detectors = get_detectors_for_profile("full")
    paths = ["/vulnerabilities/exec/", "/vulnerabilities/sqli/"]
    runs = _build_runs(detectors, _target(), _scan(paths))

    host_detectors = [d for d in detectors if d.scan_scope == "host"]
    path_detectors = [d for d in detectors if d.scan_scope == "path"]

    host_runs = [(d, c) for d, c in runs if d.scan_scope == "host"]
    path_runs = [(d, c) for d, c in runs if d.scan_scope == "path"]

    # host detectors run once each, against the bare target
    assert len(host_runs) == len(host_detectors)
    assert all(c.base_url == "http://dvwa" for _, c in host_runs)

    # path detectors run once per in-scope path, each pointed at that path
    assert len(path_runs) == len(path_detectors) * len(paths)
    exec_runs = [(d, c) for d, c in path_runs if c.extra.get("discovery_path") == paths[0]]
    assert len(exec_runs) == len(path_detectors)
    assert all(c.base_url == "http://dvwa/vulnerabilities/exec/" for _, c in exec_runs)


def test_scoped_scan_preserves_scan_config_and_normalizes_paths() -> None:
    detectors = get_detectors_for_profile("full")
    runs = _build_runs(detectors, _target(), _scan(["vulnerabilities/exec/"]))
    path_runs = [c for d, c in runs if d.scan_scope == "path"]
    assert path_runs, "expected at least one path-scoped run"
    for context in path_runs:
        assert context.extra["login_path"] == "/login.php"  # carried through
        assert context.extra["discovery_path"] == "/vulnerabilities/exec/"  # leading slash added
        assert context.base_url == "http://dvwa/vulnerabilities/exec/"


def test_scoped_scan_caps_number_of_paths() -> None:
    detectors = get_detectors_for_profile("full")
    many = [f"/p{i}" for i in range(MAX_SCOPED_PATHS + 10)]
    runs = _build_runs(detectors, _target(), _scan(many))
    path_detectors = [d for d in detectors if d.scan_scope == "path"]
    path_runs = [r for r in runs if r[0].scan_scope == "path"]
    assert len(path_runs) == len(path_detectors) * MAX_SCOPED_PATHS


def test_scoped_scan_attacks_each_duplicate_path_once() -> None:
    """The crawler keys entries by URL, so the same path arrives repeatedly
    (DVWA links /instructions.php from six pages). Each distinct path must be
    attacked exactly once, however many times it was discovered."""
    detectors = get_detectors_for_profile("command_injection")
    paths = ["/", "/instructions.php", "/instructions.php", "/", "/instructions.php"]
    runs = _build_runs(detectors, _target(), _scan(paths))

    attacked = [c.extra["discovery_path"] for _, c in runs]
    assert attacked == ["/", "/instructions.php"]


def test_scoped_scan_dedupes_before_applying_the_cap() -> None:
    """Duplicates must not consume the MAX_SCOPED_PATHS budget, or real paths
    the operator selected get silently dropped in favour of repeats."""
    detectors = get_detectors_for_profile("command_injection")
    paths = ["/dup"] * MAX_SCOPED_PATHS + ["/kept"]
    runs = _build_runs(detectors, _target(), _scan(paths))

    attacked = [c.extra["discovery_path"] for _, c in runs]
    assert attacked == ["/dup", "/kept"]


def test_scoped_scan_dedupes_across_slash_normalization() -> None:
    """'foo' and '/foo' are the same path once normalized, so they must collapse."""
    detectors = get_detectors_for_profile("command_injection")
    runs = _build_runs(detectors, _target(), _scan(["exec", "/exec"]))

    attacked = [c.extra["discovery_path"] for _, c in runs]
    assert attacked == ["/exec"]
