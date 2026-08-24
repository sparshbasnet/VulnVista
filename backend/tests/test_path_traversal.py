import httpx

from app.scanners.base import ScanContext
from app.scanners.path_traversal import PathTraversalDetector


class FakeAsyncClient:
    def __init__(self, responses: list[httpx.Response], **kwargs):
        self.responses = iter(responses)
        self.requests: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str):
        self.requests.append(("GET", url))
        return next(self.responses)

    async def post(self, url: str, data: dict[str, str]):
        self.requests.append(("POST", url))
        return next(self.responses)


async def test_path_traversal_detects_passwd_disclosure(monkeypatch):
    base_url = "http://test.local"
    login_response = httpx.Response(200, text="<input name='user_token' value='token-123'>")
    login_post_response = httpx.Response(200)
    traversal_response = httpx.Response(
        200,
        text="root:x:0:0:root:/root:/bin/bash",
        request=httpx.Request("GET", f"{base_url}/vulnerabilities/fi/?page=../../etc/passwd"),
    )

    monkeypatch.setattr(
        "app.scanners.path_traversal.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(
            [login_response, login_post_response, traversal_response], **kwargs
        ),
    )

    result = await PathTraversalDetector().check(
        ScanContext(target_id="test-target", base_url=base_url)
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.severity == "HIGH"
    assert result.confidence == "HIGH"
    assert result.cwe == "CWE-22"
    assert result.endpoint == str(traversal_response.url)


async def test_path_traversal_does_not_flag_normal_response(monkeypatch):
    login_response = httpx.Response(200, text="<input name='user_token' value='token-123'>")
    login_post_response = httpx.Response(200)
    traversal_response = httpx.Response(200, text="File not found")

    monkeypatch.setattr(
        "app.scanners.path_traversal.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(
            [login_response, login_post_response, traversal_response], **kwargs
        ),
    )

    result = await PathTraversalDetector().check(
        ScanContext(target_id="test-target", base_url="http://test.local")
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence == {"reason": "Path traversal was not detected."}


async def test_path_traversal_returns_error_when_login_token_is_missing(monkeypatch):
    login_response = httpx.Response(200, text="<form></form>")

    monkeypatch.setattr(
        "app.scanners.path_traversal.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([login_response], **kwargs),
    )

    result = await PathTraversalDetector().check(
        ScanContext(target_id="test-target", base_url="http://test.local")
    )

    assert result.detected is False
    assert result.validation_status == "ERROR"
    assert result.evidence == {"reason": "Unable to extract DVWA login token."}


async def test_path_traversal_detects_juice_shop_package_metadata(monkeypatch):
    base_url = "http://vulnvista_juice_shop:3000"
    response = httpx.Response(
        200,
        text='{"name":"juice-shop","version":"1.0.0"}',
        request=httpx.Request("GET", f"{base_url}/ftp/%2e%2e%2fpackage.json"),
    )

    monkeypatch.setattr(
        "app.scanners.path_traversal.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([response], **kwargs),
    )

    result = await PathTraversalDetector().check(
        ScanContext(target_id="test-target", base_url=base_url)
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.endpoint == str(response.url)


async def test_path_traversal_reports_protected_juice_shop_file_endpoint(monkeypatch):
    response = httpx.Response(403, text="Forbidden")

    monkeypatch.setattr(
        "app.scanners.path_traversal.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([response], **kwargs),
    )

    result = await PathTraversalDetector().check(
        ScanContext(target_id="test-target", base_url="http://vulnvista_juice_shop:3000")
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["status_code"] == 403
