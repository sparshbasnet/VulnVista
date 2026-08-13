"""
Scoped ZAP scan — SQL Injection rules only, targeted directly at Juice
Shop's login endpoint (POST /rest/user/login).

ZAP's active scanner can only attack URLs already present in its Sites
Tree/history. Since we skip spidering (Juice Shop is a JS SPA), we first
"seed" the login request into ZAP manually via core/action/sendRequest,
then run the scoped active scan against it.

Run with: docker compose exec backend python3 scripts/scan_sqli_juice_shop.py
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

ZAP_BASE = "http://zap:8080"
API_KEY = "vulnvista-dev-key"
TARGET = "http://juice-shop:3000"
LOGIN_PATH = "/rest/user/login"
LOGIN_URL = f"{TARGET}{LOGIN_PATH}"


def zap_call(endpoint: str, params: dict | None = None, retries: int = 3) -> dict:
    params = params or {}
    params["apikey"] = API_KEY
    url = f"{ZAP_BASE}{endpoint}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"X-ZAP-API-Key": API_KEY})
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"   HTTP {e.code} on attempt {attempt}/{retries}: {body}")
            last_error = e
            time.sleep(3)
        except Exception as e:
            last_error = e
            print(f"   Request failed (attempt {attempt}/{retries}): {e}")
            time.sleep(3)
    raise last_error


def wait_for(status_endpoint: str, scan_id: str, label: str, timeout: int = 300):
    start = time.time()
    while True:
        result = zap_call(status_endpoint, {"scanId": scan_id})
        progress = int(result["status"])
        print(f"   {label} progress: {progress}%")
        if progress >= 100:
            return
        if time.time() - start > timeout:
            raise TimeoutError(f"{label} did not complete within {timeout}s")
        time.sleep(3)


def get_sqli_rule_ids() -> list[str]:
    result = zap_call("/JSON/ascan/view/scanners/")
    scanners = result["scanners"]
    sqli_scanners = [s for s in scanners if "sql injection" in s["name"].lower()]
    print("Found SQLi scanners on this ZAP instance:")
    for s in sqli_scanners:
        print(f"  id={s['id']}  name={s['name']}")
    return [s["id"] for s in sqli_scanners]


def seed_login_request():
    """Sends the login POST through ZAP directly so it's recorded in the Sites Tree."""
    body = '{"email":"test@test.com","password":"test123"}'
    raw_request = (
        f"POST {LOGIN_PATH} HTTP/1.1\r\n"
        f"Host: juice-shop:3000\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )
    print("Seeding login request into ZAP's history...")
    zap_call("/JSON/core/action/sendRequest/", {
        "request": raw_request,
        "followRedirects": "true",
    })
    print("Login request seeded.\n")


def main():
    print(f"Accessing {TARGET} first to register the site...")
    zap_call("/JSON/core/action/accessUrl/", {"url": TARGET, "followRedirects": "true"})
    print("Site registered.\n")

    seed_login_request()

    print("Looking up SQL Injection scanner IDs...")
    sqli_ids = get_sqli_rule_ids()
    if not sqli_ids:
        print("No SQLi scanners found — aborting.")
        return
    print()

    print("Restricting active scan to SQL Injection rules only...")
    zap_call("/JSON/ascan/action/disableAllScanners/")
    zap_call("/JSON/ascan/action/enableScanners/", {"ids": ",".join(sqli_ids)})
    print("Scan policy scoped to SQLi rules.\n")

    print(f"Running SQLi-only active scan on {LOGIN_URL}...")
    ascan_result = zap_call("/JSON/ascan/action/scan/", {
        "url": LOGIN_URL,
        "recurse": "false",
        "inScopeOnly": "false",
        "method": "POST",
        "postData": '{"email":"test@test.com","password":"test123"}',
    })
    wait_for("/JSON/ascan/view/status/", ascan_result["scan"], "SQLi scan")
    print("Active scan complete.\n")

    print("Fetching alerts...")
    alerts_result = zap_call("/JSON/core/view/alerts/", {"baseurl": TARGET})
    alerts = alerts_result["alerts"]
    sqli_alerts = [a for a in alerts if "sql injection" in a["name"].lower()]

    print(f"\nTotal alerts: {len(alerts)}")
    print(f"SQL Injection alerts: {len(sqli_alerts)}\n")

    if sqli_alerts:
        print("=== SQL Injection Findings ===")
        for a in sqli_alerts:
            print(f"\n[{a['risk']}] {a['name']}")
            print(f"  URL: {a['url']}")
            print(f"  Param: {a.get('param', 'N/A')}")
            print(f"  Evidence: {a.get('evidence', 'N/A')}")
    else:
        print("No SQL Injection alerts found on the login endpoint.")

    print("\nRe-enabling all scanners...")
    zap_call("/JSON/ascan/action/enableAllScanners/")


if __name__ == "__main__":
    main()
# how it starts scanning
# docker compose exec backend python3 scripts/scan_sqli_juice_shop.py