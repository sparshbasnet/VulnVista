import re

import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.file_upload import (
    FileUploadDetector,
    build_probes,
    classify,
    extract_upload_response_snippet,
)


def test_build_probes_never_contains_executable_code() -> None:
    probes = build_probes("UPLOAD-deadbeef")
    assert {probe.key for probe in probes} == {
        "plain_text_control",
        "script_extension_plain_text",
        "script_mime_text_extension",
    }
    assert any(probe.filename.endswith(".php") for probe in probes)
    assert any(probe.content_type == "application/x-httpd-php" for probe in probes)
    assert all(b"<?" not in probe.content for probe in probes)
    assert all(b"exec" not in probe.content.lower() for probe in probes)


def test_classify_public_script_extension_is_confirmed_critical() -> None:
    decision = classify(
        [
            {
                "script_extension": True,
                "mime_mismatch": True,
                "upload_accepted": True,
                "publicly_accessible": True,
            }
        ]
    )
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.severity == "CRITICAL"


def test_classify_accepted_but_not_retrievable_is_suspected() -> None:
    decision = classify(
        [
            {
                "script_extension": True,
                "mime_mismatch": True,
                "upload_accepted": True,
                "publicly_accessible": False,
            }
        ]
    )
    assert decision.detected is True
    assert decision.validation_status == "SUSPECTED"
    assert decision.confidence == "MEDIUM"


def test_classify_rejected_unsafe_upload_is_not_detected() -> None:
    decision = classify(
        [
            {
                "script_extension": True,
                "mime_mismatch": True,
                "upload_accepted": False,
                "publicly_accessible": False,
            }
        ]
    )
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"


def test_profile_resolves_to_file_upload_detector() -> None:
    detectors = get_detectors_for_profile("file_upload")
    assert [detector.detector_id for detector in detectors] == ["file_upload"]


def test_upload_response_snippet_centres_on_controlled_filename() -> None:
    body = "A" * 600 + "vulnvista-upload-canary.php succesfully uploaded" + "B" * 600
    snippet = extract_upload_response_snippet(body, "vulnvista-upload-canary.php", radius=40)
    assert snippet.startswith("A" * 40)
    assert "vulnvista-upload-canary.php succesfully uploaded" in snippet
    assert len(snippet) < len(body)


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


LOGIN_HTML = """
<form action="/login.php" method="POST">
  <input type="hidden" name="user_token" value="token-1">
  <input name="username">
  <input type="password" name="password">
  <input type="submit" name="Login" value="Login">
</form>
"""

UPLOAD_HTML = """
<form action="#" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="MAX_FILE_SIZE" value="100000">
  <input type="file" name="uploaded">
  <input type="submit" name="Upload" value="Upload">
</form>
"""


async def test_dvwa_preset_confirms_public_plain_text_php_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uploaded: dict[str, str] = {}
    upload_bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login.php" and request.method == "GET":
            return httpx.Response(200, text=LOGIN_HTML)
        if request.url.path == "/login.php" and request.method == "POST":
            return httpx.Response(302, headers={"Location": "/index.php"})
        if request.url.path == "/index.php":
            return httpx.Response(200, text="Welcome")
        if request.url.path == "/vulnerabilities/upload/" and request.method == "GET":
            return httpx.Response(200, text=UPLOAD_HTML)
        if request.url.path == "/vulnerabilities/upload/" and request.method == "POST":
            body = request.read()
            upload_bodies.append(body)
            filename = re.search(rb'filename="([^"]+)"', body)
            marker = re.search(rb"UPLOAD-[0-9a-f]+", body)
            assert filename is not None and marker is not None
            uploaded[filename.group(1).decode()] = marker.group(0).decode()
            return httpx.Response(200, text="succesfully uploaded!")
        if request.url.path.startswith("/hackable/uploads/"):
            filename = request.url.path.rsplit("/", 1)[-1]
            marker = uploaded.get(filename)
            return httpx.Response(200, text=marker) if marker else httpx.Response(404)
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await FileUploadDetector().check(ScanContext(target_id="t1", base_url="http://dvwa"))

    assert result.validation_status == "CONFIRMED"
    assert result.severity == "CRITICAL"
    assert result.cwe == "CWE-434"
    assert result.parameter == "uploaded"
    assert result.evidence["contains_executable_code"] is False
    assert any(
        probe["filename"].endswith(".php") and probe["publicly_accessible"]
        for probe in result.evidence["probes"]
    )
    assert all(b"<?" not in body for body in upload_bodies)


async def test_secure_form_rejects_script_and_mime_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/upload":
            return httpx.Response(
                200,
                text=(
                    '<form action="/upload" method="POST" enctype="multipart/form-data">'
                    '<input type="file" name="document"><button>Upload</button></form>'
                ),
            )
        if request.method == "POST" and request.url.path == "/upload":
            body = request.read()
            if b".php" in body or b"application/x-httpd-php" in body:
                return httpx.Response(415, text="Unsupported file type")
            return httpx.Response(200, text="plain text accepted")
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await FileUploadDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/upload",
            extra={"public_base_path": "/files/"},
        )
    )

    assert result.validation_status == "NOT_DETECTED"
    assert result.detected is False
    script_probe = next(probe for probe in result.evidence["probes"] if probe["script_extension"])
    assert script_probe["upload_accepted"] is False
    assert script_probe["publicly_accessible"] is False


async def test_missing_upload_form_returns_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>No upload form</html>")

    _mock_client(monkeypatch, handler)
    result = await FileUploadDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test")
    )

    assert result.validation_status == "ERROR"
    assert "No multipart file-upload form" in result.evidence_summary
