import httpx

from app.scanners.base import ScanContext
from app.scanners.csrf import CSRFDetector


class FakeAsyncClient:
    def __init__(self, response: httpx.Response, **kwargs):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url):
        return self.response


async def test_csrf_detects_post_form_without_token(monkeypatch):
    html = """
    <html>
        <body>
            <form method="POST" action="/change-email">
                <input type="email" name="email">
                <button type="submit">Change Email</button>
            </form>
        </body>
    </html>
    """

    response = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text=html,
    )

    monkeypatch.setattr(
        "app.scanners.csrf.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(response, **kwargs),
    )

    detector = CSRFDetector()

    result = await detector.check(
        ScanContext(
            target_id="test-target",
            base_url="http://test.local",
        )
    )

    assert result.detected is True
    assert result.validation_status == "SUSPECTED"
    assert result.severity == "MEDIUM"
    assert result.confidence == "MEDIUM"
    assert result.cwe == "CWE-352"
    assert result.endpoint == "http://test.local/change-email"


async def test_csrf_does_not_flag_form_with_token(monkeypatch):
    html = """
    <html>
        <body>
            <form method="POST" action="/change-email">
                <input type="hidden" name="csrf_token" value="random-token">
                <input type="email" name="email">
                <button type="submit">Change Email</button>
            </form>
        </body>
    </html>
    """

    response = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text=html,
    )

    monkeypatch.setattr(
        "app.scanners.csrf.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(response, **kwargs),
    )

    detector = CSRFDetector()

    result = await detector.check(
        ScanContext(
            target_id="test-target",
            base_url="http://test.local",
        )
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"