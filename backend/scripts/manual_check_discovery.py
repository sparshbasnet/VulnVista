"""Check bundled lab discovery from the backend's network (no attack probes)."""

import asyncio
import json

import httpx

from app.services.crawler import crawl


async def main() -> None:
    for url in ("http://dvwa", "http://juice-shop:3000", "https://tls-test"):
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
            try:
                response = await client.get(url)
                print(url, response.status_code, str(response.url), flush=True)
            except httpx.HTTPError as exc:
                print(url, type(exc).__name__, str(exc), flush=True)
        try:
            paths = await crawl(url, {"max_pages": 30, "request_timeout": 5})
            print(json.dumps({"target": url, "count": len(paths), "paths": paths}), flush=True)
        except Exception as exc:
            print(url, type(exc).__name__, str(exc), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
