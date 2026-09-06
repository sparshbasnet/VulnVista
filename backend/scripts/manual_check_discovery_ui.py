"""Browser regression smoke checks with mocked API data; touches no user records."""

import json
import socket
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright


def main() -> None:
    # Vite permits IP hosts by default; the Docker service-name Host header is rejected.
    frontend_url = f"http://{socket.gethostbyname('frontend')}:5173"
    target = {
        "id": "target-fixture",
        "name": "Test DVWA",
        "base_url": "http://dvwa",
        "target_type": "webapp",
        "environment": "lab",
        "is_allowed": True,
        "authorization_confirmed": False,
        "created_at": "2026-09-06T00:00:00Z",
    }
    state = {"targets": [target], "empty": False, "deletes": 0}

    def api_route(route):
        path = urlparse(route.request.url).path.removeprefix("/api")
        if path == "/auth/me":
            body = {
                "id": "operator",
                "username": "operator",
                "role": "ANALYST",
                "is_active": True,
                "must_change_password": False,
            }
        elif path == "/targets":
            body = target if route.request.method == "POST" else state["targets"]
        elif path == "/targets/target-fixture" and route.request.method == "DELETE":
            state["targets"] = []
            state["deletes"] += 1
            route.fulfill(status=204)
            return
        elif path == "/discoveries":
            paths = (
                []
                if state["empty"]
                else [
                    {
                        "path": p,
                        "url": "http://dvwa" + p,
                        "methods": ["GET"],
                        "params": [],
                        "has_form": False,
                        "depth": 0,
                    }
                    for p in ("/", "/vulnerabilities/exec/")
                ]
            )
            body = {"id": "discovery", "status": "COMPLETED", "paths": paths}
        else:
            body = []
        route.fulfill(content_type="application/json", body=json.dumps(body))

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.add_init_script("sessionStorage.setItem('vulnvista_access_token', 'mock-session')")
        page.route("**/api/**", api_route)
        page.goto(frontend_url + "/scans")
        page.get_by_role("button", name="Discover paths", exact=True).click()
        expect(page.get_by_text("Discovered 2 path(s)", exact=True)).to_be_visible()
        expect(page.get_by_text("exec", exact=True)).to_be_visible()
        state["empty"] = True
        page.get_by_role("button", name="Re-discover paths", exact=True).click()
        expect(page.get_by_text("No reachable paths discovered", exact=True)).to_be_visible()
        expect(page.get_by_text("Select in-scope paths above, then start the scan")).to_have_count(
            0
        )
        page.locator("select").first.select_option("weak_tls")
        expect(page.get_by_text("Host-level scan", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Discover paths", exact=True)).to_have_count(0)
        page.goto(frontend_url + "/targets")
        page.once("dialog", lambda dialog: dialog.dismiss())
        page.get_by_role("button", name="Delete Test DVWA", exact=True).click()
        assert state["deletes"] == 0
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Delete Test DVWA", exact=True).click()
        expect(page.get_by_text("No targets match this search.")).to_be_visible()
        assert state["deletes"] == 1
        browser.close()
    print("PASS: discovery tree, empty discovery, TLS scope, delete cancel and confirm")


if __name__ == "__main__":
    main()
