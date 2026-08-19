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


class CrawlerFakeAsyncClient:
    def __init__(self, responses: dict[str, httpx.Response], **kwargs):
        self.responses = responses
        self.visited: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url):
        self.visited.append(url)
        return self.responses[url]


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


async def test_csrf_crawls_same_origin_pages_and_skips_sensitive_links(monkeypatch):
    base_url = "http://test.local"
    responses = {
        base_url: httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="""
                <a href="/profile">Profile</a>
                <a href="/logout">Log out</a>
                <a href="https://other.test/form">External</a>
            """,
        ),
        f"{base_url}/profile": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="""
                <form method="POST" action="/change-email">
                    <input name="email">
                </form>
            """,
        ),
    }
    fake_client = CrawlerFakeAsyncClient(responses)
    monkeypatch.setattr(
        "app.scanners.csrf.httpx.AsyncClient",
        lambda **kwargs: fake_client,
    )

    results = await CSRFDetector().check_all(
        ScanContext(
            target_id="test-target",
            base_url=base_url,
            extra={"crawl_max_pages": 10, "crawl_max_depth": 2, "crawl_delay_seconds": 0},
        )
    )

    assert len(results) == 1
    assert results[0].detected is True
    assert results[0].endpoint == f"{base_url}/change-email"
    assert fake_client.visited == [base_url, f"{base_url}/profile"]
