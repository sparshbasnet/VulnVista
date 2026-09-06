import httpx
import pytest

from app.services.crawler import (
    CrawlError,
    _entry,
    crawl,
    extract_links,
    is_crawlable,
    parse_robots,
    parse_sitemap,
    same_host,
)


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def test_extract_links_absolutizes_and_strips_fragments() -> None:
    html = (
        '<a href="/vulnerabilities/exec/">exec</a>'
        '<a href="sqli/">sqli</a>'
        '<a href="#top">top</a>'
        '<a href="mailto:x@y.z">mail</a>'
        '<a href="http://other/x">other</a>'
    )
    links = extract_links(html, "http://dvwa/vulnerabilities/")
    assert "http://dvwa/vulnerabilities/exec/" in links
    assert "http://dvwa/vulnerabilities/sqli/" in links
    assert "http://other/x" in links  # host filtering happens in crawl(), not here
    # fragment-only and non-http schemes are dropped
    assert not any("#" in link for link in links)
    assert not any(link.startswith("mailto:") for link in links)


def test_same_host_matches_only_same_hostname() -> None:
    assert same_host("http://dvwa/a", "dvwa") is True
    assert same_host("https://dvwa/a", "dvwa") is True
    assert same_host("http://other/a", "dvwa") is False
    assert same_host("ftp://dvwa/a", "dvwa") is False


def test_is_crawlable_skips_static_assets() -> None:
    assert is_crawlable("http://dvwa/index.php") is True
    assert is_crawlable("http://dvwa/style.css") is False
    assert is_crawlable("http://dvwa/app.js") is False
    assert is_crawlable("http://dvwa/logo.png") is False


def test_entry_records_forms_methods_and_params() -> None:
    html = (
        '<form action="/exec/" method="POST">'
        '<input name="ip"><input name="Submit" type="submit"></form>'
    )
    entry = _entry("http://dvwa/exec/?debug=1", html, 2)
    assert entry["path"] == "/exec/"
    assert entry["has_form"] is True
    assert set(entry["methods"]) == {"GET", "POST"}
    assert "ip" in entry["params"] and "debug" in entry["params"]
    assert entry["depth"] == 2


async def test_crawl_stays_on_host_and_respects_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {
        "/": '<a href="/a">a</a><a href="/b">b</a><a href="http://evil/x">x</a>',
        "/a": '<a href="/a/deep">deep</a>',
        "/b": "<p>leaf</p>",
        "/a/deep": '<a href="/a/deeper">deeper</a>',
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = pages.get(request.url.path)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    _mock_client(monkeypatch, handler)
    results = await crawl("http://dvwa", {"max_depth": 1})
    paths = {r["path"] for r in results}
    # depth 0 (/) + depth 1 (/a, /b); /a/deep is depth 2, excluded by max_depth=1
    assert paths == {"/", "/a", "/b"}
    # off-host link never fetched
    assert not any(r["url"].startswith("http://evil") for r in results)


async def test_crawl_authenticates_then_discovers_protected_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logged_in = {"value": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login.php" and request.method == "GET":
            return httpx.Response(
                200,
                text='<form action="/login.php" method="POST"><input name="username">'
                '<input type="password" name="password"></form>',
                headers={"content-type": "text/html"},
            )
        if path == "/login.php" and request.method == "POST":
            logged_in["value"] = True
            return httpx.Response(302, headers={"Location": "/index.php"})
        if not logged_in["value"]:
            return httpx.Response(302, headers={"Location": "/login.php"})
        if path in ("/", "/index.php"):
            return httpx.Response(
                200,
                text='<a href="/secret">secret</a>',
                headers={"content-type": "text/html"},
            )
        if path == "/secret":
            return httpx.Response(
                200, text="<p>protected</p>", headers={"content-type": "text/html"}
            )
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    results = await crawl(
        "http://dvwa",
        {"login_path": "/login.php", "username": "admin", "password": "password"},
    )
    assert logged_in["value"] is True
    assert "/secret" in {r["path"] for r in results}


def test_parse_robots_extracts_paths_and_sitemaps() -> None:
    text = (
        "# comment\n"
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Allow: /public\n"
        "Disallow: /tmp/*.log\n"  # wildcard trimmed to concrete prefix
        "Disallow:\n"  # empty value ignored
        "Sitemap: http://app/sitemap.xml\n"
    )
    paths, sitemaps = parse_robots(text, "http://app")
    assert "http://app/admin/" in paths
    assert "http://app/public" in paths
    assert "http://app/tmp/" in paths
    assert sitemaps == ["http://app/sitemap.xml"]


def test_parse_sitemap_extracts_locs() -> None:
    xml = (
        "<urlset><url><loc>http://app/reports</loc></url>"
        "<url><loc> http://app/billing </loc></url></urlset>"
    )
    assert parse_sitemap(xml) == ["http://app/reports", "http://app/billing"]


async def test_crawl_seeds_from_robots_and_sitemap(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/robots.txt":
            return httpx.Response(
                200,
                text="Disallow: /admin\nSitemap: http://app/sitemap.xml\n",
                headers={"content-type": "text/plain"},
            )
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                text="<urlset><url><loc>http://app/reports</loc></url></urlset>",
                headers={"content-type": "application/xml"},
            )
        if path in ("/", "/admin", "/reports"):
            # no links anywhere — these are only reachable via robots/sitemap
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"})
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    results = await crawl("http://app", {})
    paths = {r["path"] for r in results}
    assert {"/admin", "/reports"} <= paths


async def test_crawl_honors_max_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # every page links to two more, unbounded without the cap
        n = request.url.path.strip("/") or "0"
        return httpx.Response(
            200,
            text=f'<a href="/{n}0">x</a><a href="/{n}1">y</a>',
            headers={"content-type": "text/html"},
        )

    _mock_client(monkeypatch, handler)
    results = await crawl("http://dvwa", {"max_pages": 5, "max_depth": 10})
    assert len(results) <= 5


async def test_unreachable_target_is_an_error_not_empty_success(monkeypatch) -> None:
    def handler(request):
        raise httpx.ConnectError("unreachable", request=request)

    _mock_client(monkeypatch, handler)
    with pytest.raises(CrawlError, match="ConnectError"):
        await crawl("http://unreachable")


async def test_http_failure_is_reported(monkeypatch) -> None:
    _mock_client(monkeypatch, lambda request: httpx.Response(503))
    with pytest.raises(CrawlError, match="HTTP 503"):
        await crawl("http://app")


async def test_crawler_follows_form_actions_but_never_logs_out(monkeypatch) -> None:
    visited = []

    def handler(request):
        visited.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(
                200,
                text=(
                    '<a href="/logout.php">Logout</a>'
                    '<form action="/search" method="POST"><input name="q"></form>'
                ),
                headers={"content-type": "text/html"},
            )
        return httpx.Response(200 if request.url.path == "/search" else 404)

    _mock_client(monkeypatch, handler)
    results = await crawl("http://app")
    assert {entry["path"] for entry in results} == {"/", "/search"}
    assert "/logout.php" not in visited


async def test_dvwa_setup_redirect_is_actionable(monkeypatch) -> None:
    def handler(request):
        if request.url.path == "/setup.php":
            return httpx.Response(200)
        if request.method == "POST":
            return httpx.Response(302, headers={"Location": "/setup.php"})
        return httpx.Response(200, text='<form method="POST"></form>')

    _mock_client(monkeypatch, handler)
    with pytest.raises(CrawlError, match="database is not initialized"):
        await crawl("http://dvwa")


async def test_failed_login_is_not_a_successful_login_page_discovery(monkeypatch) -> None:
    _mock_client(
        monkeypatch,
        lambda request: httpx.Response(
            200, text='<form method="POST"><input type="password" name="password"></form>'
        ),
    )
    with pytest.raises(CrawlError, match="login failed"):
        await crawl("http://dvwa")


@pytest.mark.parametrize("host,verify", [("tls-test", False), ("example.test", True)])
async def test_self_signed_exception_is_limited_to_tls_fixture(monkeypatch, host, verify) -> None:
    real_init = httpx.AsyncClient.__init__
    seen = []

    def patched_init(self, *args, **kwargs):
        seen.append(kwargs.get("verify", True))
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(200))
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
    assert (await crawl(f"https://{host}"))[0]["path"] == "/"
    assert seen == [verify]
