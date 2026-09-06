"""Same-host web crawler that maps a target's reachable paths.

Feeds the scope-selection tree on the Scan page: given a base URL (and optional
login config so pages behind auth are reached), it walks links and forms
breadth-first, staying on the target host, and returns a flat list of
discovered paths with lightweight metadata. The frontend nests these into a
tree; the operator then picks which paths are in-scope before scanning.

Detection/attack logic lives in the detectors. This module only enumerates
surface area and submits a configured login form; it never submits exercise
forms or generates attack payloads.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

from app.scanners.command_injection import LAB_PRESETS, parse_forms
from app.scanners.presets.discovery import LAB_PRESETS as DISCOVERY_LAB_PRESETS

logger = logging.getLogger(__name__)

# Crawl bounds — lab targets are small, and an unbounded crawl of an arbitrary
# host would be both slow and rude. Callers can override via cfg.
DEFAULT_MAX_PAGES = 80
DEFAULT_MAX_DEPTH = 3
DEFAULT_TIMEOUT = 15.0

# Only follow links that look like navigable pages. Skip assets and non-HTTP
# schemes (mailto:, javascript:, tel:, #fragments).
_SKIP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:", "#")
_ASSET_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".gz",
    ".mp4",
    ".webp",
    ".map",
)


class CrawlError(RuntimeError):
    """A discovery could not reach any usable page."""


class _LinkParser(HTMLParser):
    """Collects href targets from <a> tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value:
                self.hrefs.append(value)


def extract_links(html: str, page_url: str) -> list[str]:
    """Return absolute, fragment-stripped URLs for every <a href> on the page."""
    parser = _LinkParser()
    parser.feed(html)
    links: list[str] = []
    for href in parser.hrefs:
        href = href.strip()
        if not href or href.lower().startswith(_SKIP_SCHEMES):
            continue
        absolute, _ = urldefrag(urljoin(page_url, href))
        links.append(absolute)
    return links


def same_host(url: str, base_host: str) -> bool:
    """True when ``url`` is HTTP(S) and on the same host as the crawl root."""
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and (parsed.hostname or "") == base_host


def is_crawlable(url: str) -> bool:
    """Skip obvious static assets so the tree shows pages, not resources."""
    path = urlparse(url).path.lower()
    # Following logout links destroys the session before protected pages are visited.
    return not path.endswith(_ASSET_SUFFIXES) and not re.search(
        r"/(?:logout|signout|sign-out)(?:\.[a-z]+)?/?$", path
    )


_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_robots(text: str, base: str) -> tuple[list[str], list[str]]:
    """Parse a robots.txt into (candidate page URLs, advertised sitemap URLs).

    ``Disallow``/``Allow`` paths are surfaced as crawl seeds precisely because a
    site often lists there the very areas that aren't linked anywhere else
    (``/admin``, ``/backup``). Wildcards are trimmed to their concrete prefix so
    the seed is a real, fetchable path."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        if key in ("disallow", "allow"):
            prefix = value.split("*", 1)[0].split("$", 1)[0]
            if prefix.startswith("/"):
                paths.append(urljoin(base + "/", prefix.lstrip("/")))
        elif key == "sitemap":
            sitemaps.append(value)
    return paths, sitemaps


def parse_sitemap(xml: str) -> list[str]:
    """Return every ``<loc>`` URL from a sitemap or sitemap-index document."""
    return [m.strip() for m in _LOC_RE.findall(xml)]


async def _discover_seeds(client: httpx.AsyncClient, base: str, host: str) -> list[str]:
    """Collect extra crawl seeds from robots.txt and sitemap.xml.

    Best-effort and same-host only — failures are logged and skipped so a
    missing robots.txt never aborts discovery. Complements link-following by
    surfacing paths that no crawled page happens to link to."""
    seeds: list[str] = []
    sitemap_urls: list[str] = []

    try:
        resp = await client.get(urljoin(base + "/", "robots.txt"))
        ctype = resp.headers.get("content-type", "").lower()
        if resp.status_code < 400 and "html" not in ctype:
            found_paths, found_sitemaps = parse_robots(resp.text, base)
            seeds.extend(found_paths)
            sitemap_urls.extend(found_sitemaps)
    except httpx.HTTPError as exc:
        logger.debug("robots.txt fetch failed: %s", exc)

    # Fall back to the conventional location when none is advertised.
    if not sitemap_urls:
        sitemap_urls.append(urljoin(base + "/", "sitemap.xml"))

    for sitemap_url in sitemap_urls:
        if not same_host(sitemap_url, host):
            continue
        try:
            resp = await client.get(sitemap_url)
        except httpx.HTTPError as exc:
            logger.debug("sitemap fetch failed %s: %s", sitemap_url, exc)
            continue
        if resp.status_code < 400:
            seeds.extend(parse_sitemap(resp.text))

    return seeds


def _entry(url: str, html: str, depth: int) -> dict[str, Any]:
    """Build one discovered-path record from a fetched page."""
    parsed = urlparse(url)
    forms = parse_forms(html, url)
    methods = sorted({"GET", *(f.method for f in forms)})
    params = sorted(
        {f.name for form in forms for f in form.fields}
        | ({p.split("=", 1)[0] for p in parsed.query.split("&")} if parsed.query else set())
    )
    return {
        "url": url,
        "path": parsed.path or "/",
        "methods": methods,
        "has_form": bool(forms),
        "params": params,
        "depth": depth,
    }


async def _authenticate(
    client: httpx.AsyncClient, base: str, host: str, cfg: dict[str, Any]
) -> None:
    """Best-effort form login mirroring the detectors' approach: GET the login
    page, resubmit its hidden fields (carries any CSRF token) plus credentials.
    Transport errors allow an unauthenticated crawl. Explicit login failures
    and the DVWA setup redirect are surfaced instead of presenting the login
    screen as a successful discovery of the protected application."""
    login_url = urljoin(base + "/", cfg["login_path"])
    try:
        page = await client.get(login_url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        login_form = forms[0] if forms else None
        data: dict[str, str] = {}
        if login_form:
            data.update({f.name: f.value for f in login_form.fields if f.type == "hidden"})
        data[cfg.get("username_field", "username")] = cfg["username"]
        data[cfg.get("password_field", "password")] = cfg["password"]
        if cfg.get("login_submit_field"):
            data[cfg["login_submit_field"]] = cfg.get("login_submit_value", "")
        post_url = login_form.action if login_form else login_url
        response = await client.post(post_url, data=data)
        if urlparse(str(response.url)).path.endswith("/setup.php"):
            raise CrawlError(
                "DVWA's database is not initialized. Open its setup page and create the "
                "lab database before discovering paths."
            )
        if urlparse(str(response.url)).path == urlparse(login_url).path and any(
            field.type == "password"
            for form in parse_forms(response.text, str(response.url))
            for field in form.fields
        ):
            raise CrawlError(
                "Target login failed. Check the login credentials in Advanced settings."
            )
        for name, value in cfg.get("post_login_cookies", {}).items():
            client.cookies.set(name, value, domain=host, path="/")
    except httpx.HTTPError as exc:
        logger.warning("crawler login failed, continuing unauthenticated: %s", exc)


async def crawl(base_url: str, cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Breadth-first crawl of ``base_url`` on its own host, returning discovered
    path records sorted by path. ``cfg`` may carry login/cookie/header settings
    (same keys the detectors read from ``Target.scan_config``) plus crawl bounds
    (``max_pages``, ``max_depth``, ``request_timeout``)."""
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    base = f"{parsed.scheme}://{parsed.netloc}"
    start = parsed._replace(path=parsed.path or "/", fragment="").geturl()

    # Apply per-host lab presets (the same source the detectors use) so the
    # DVWA quick-start authenticates with zero config — it needs the login
    # form's submit button (Login=Login), which the UI can't supply. Layered
    # under the discovery-specific presets (extra_seeds for SPA targets like
    # Juice Shop that link-following can't reach) — caller cfg wins over both.
    cfg = {**LAB_PRESETS.get(host, {}), **DISCOVERY_LAB_PRESETS.get(host, {}), **(cfg or {})}

    max_pages = int(cfg.get("max_pages", DEFAULT_MAX_PAGES))
    max_depth = int(cfg.get("max_depth", DEFAULT_MAX_DEPTH))
    timeout = float(cfg.get("request_timeout", DEFAULT_TIMEOUT))

    entries: dict[str, dict[str, Any]] = {}
    seen: set[str] = {start}
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    failures: list[str] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        cookies=cfg.get("cookies", {}),
        headers=cfg.get("headers", {}),
        # Only the bundled TLS fixture has an intentionally self-signed certificate.
        # Certificate weaknesses are assessed separately by the TLS detector.
        verify=host not in {"tls-test", "vulnvista_tls_test"},
    ) as client:
        if cfg.get("login_path") and cfg.get("username") and cfg.get("password"):
            await _authenticate(client, base, host, cfg)

        # Seed the queue from robots.txt / sitemap.xml before link-following, so
        # unlinked-but-declared paths are crawled too. extra_seeds (lab presets
        # for SPA targets like Juice Shop) are tracked separately: they're known
        # real endpoints even when a plain GET probe 4xx/5xxes — e.g. a
        # POST-only login route — so they stay visible in the scope tree
        # instead of being silently dropped as crawl failures below.
        known_seeds = {
            urljoin(base + "/", path.lstrip("/")) for path in cfg.get("extra_seeds", [])
        }
        discovered_seeds = [*known_seeds, *(await _discover_seeds(client, base, host))]
        for seed in discovered_seeds:
            if seed not in seen and same_host(seed, host) and is_crawlable(seed):
                seen.add(seed)
                queue.append((seed, 0))

        while queue and len(entries) < max_pages:
            url, depth = queue.popleft()
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                logger.debug("crawl skip %s: %s", url, exc)
                if url in known_seeds:
                    entries[url] = _entry(url, "", depth)
                else:
                    failures.append(type(exc).__name__)
                continue
            if resp.status_code >= 400:
                if url in known_seeds:
                    entries[url] = _entry(url, "", depth)
                else:
                    failures.append(f"HTTP {resp.status_code}")
                continue

            final_url, _ = urldefrag(str(resp.url))
            if not same_host(final_url, host):
                failures.append("redirect outside target host")
                continue

            html = resp.text if "html" in resp.headers.get("content-type", "").lower() else ""
            entries[final_url] = _entry(final_url, html, depth)

            if html and depth < max_depth:
                form_actions = [form.action for form in parse_forms(html, final_url)]
                for link in [*extract_links(html, final_url), *form_actions]:
                    if link not in seen and same_host(link, host) and is_crawlable(link):
                        seen.add(link)
                        queue.append((link, depth + 1))

    if not entries:
        reason = ", ".join(dict.fromkeys(failures)) or "no reachable pages"
        raise CrawlError(
            f"Could not discover pages on {base} ({reason}). Check the target URL, port, "
            "and connectivity from the backend. Bundled lab containers must share "
            "the vulnvista_net network. For protected pages, check login settings."
        )
    return sorted(entries.values(), key=lambda e: (e["path"], e["url"]))
