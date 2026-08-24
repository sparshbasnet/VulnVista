import httpx

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.file_upload import FileUploadDetector


class FakeAsyncClient:
    def __init__(self, responses: list[httpx.Response | Exception], **kwargs):
        self.responses = iter(responses)
        self.cookies = httpx.Cookies()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str):
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response

    async def post(self, url: str, data: dict[str, str]):
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def test_profile_resolves_to_file_upload_detector() -> None:
    detectors = get_detectors_for_profile("file_upload")

    assert [detector.detector_id for detector in detectors] == ["file_upload"]


async def test_file_upload_flags_file_input_without_accept_allowlist(monkeypatch):
    response = httpx.Response(
        200,
        text='<form><input type="file" name="upload"></form>',
        request=httpx.Request("GET", "http://test.local/vulnerabilities/upload/"),
    )
    monkeypatch.setattr(
        "app.scanners.file_upload.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([response], **kwargs),
    )

    result = await FileUploadDetector().check(
        ScanContext(target_id="test-target", base_url="http://test.local")
    )

    assert result.detected is True
    assert result.validation_status == "SUSPECTED"
    assert result.cwe == "CWE-434"
    assert result.evidence["probe"] == "authenticated form inspection only; no file was uploaded"


async def test_file_upload_accepts_restricted_file_input(monkeypatch):
    response = httpx.Response(
        200,
        text='<form><input name="upload" accept="image/png" type="file"></form>',
        request=httpx.Request("GET", "http://test.local/vulnerabilities/upload/"),
    )
    monkeypatch.setattr(
        "app.scanners.file_upload.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([response], **kwargs),
    )

    result = await FileUploadDetector().check(
        ScanContext(target_id="test-target", base_url="http://test.local")
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["accept_attribute_present"] is True


async def test_file_upload_reports_http_errors(monkeypatch):
    request = httpx.Request("GET", "http://test.local/vulnerabilities/upload/")
    monkeypatch.setattr(
        "app.scanners.file_upload.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(
            [httpx.ConnectError("connection failed", request=request)]
        ),
    )

    result = await FileUploadDetector().check(
        ScanContext(target_id="test-target", base_url="http://test.local")
    )

    assert result.detected is False
    assert result.validation_status == "ERROR"
    assert result.evidence == {"error": "connection failed"}
