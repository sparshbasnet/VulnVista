"""
Full ZAP scan — spiders and active-scans Juice Shop using EVERY rule ZAP
has (XSS, SQLi, path traversal, misconfig, etc.), then prints all alerts
found, grouped by risk level.

This is broader but much slower than the SQLi-scoped script — a full
active scan can take 10-20+ minutes depending on your machine, since it's
running 50+ rule types against every discovered URL/parameter.

Run with: docker compose exec backend python3 scripts/scan_juice_shop.py
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

ZAP_BASE = "http://zap:8080"
API_KEY = "vulnvista-dev-key"
TARGET = "http://juice-shop:3000"


def zap_call(endpoint: str, params: dict | None = None, retries: int = 3) -> dict:
    """Calls a ZAP API endpoint and returns parsed JSON, retrying on transient failures."""
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


def wait_for(status_endpoint: str, scan_id: str, label: str, timeout: int = 900):
    """Polls a ZAP scan status endpoint until it reports 100% complete."""
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


def main():
    print(f"Starting spider on {TARGET}...")
    spider_result = zap_call("/JSON/spider/action/scan/", {"url": TARGET})
    spider_id = spider_result["scan"]
    wait_for("/JSON/spider/view/status/", spider_id, "Spider")
    print("Spider complete.\n")

    print(f"Starting FULL active scan on {TARGET} (all rule types, no scoping)...")
    ascan_result = zap_call("/JSON/ascan/action/scan/", {"url": TARGET, "recurse": "true"})
    ascan_id = ascan_result["scan"]
    wait_for("/JSON/ascan/view/status/", ascan_id, "Active scan")
    print("Active scan complete.\n")

    print("Fetching alerts...")
    alerts_result = zap_call("/JSON/core/view/alerts/", {"baseurl": TARGET})
    alerts = alerts_result["alerts"]

    print(f"\nFound {len(alerts)} total alerts.\n")

    # Group alerts by risk level for a readable summary
    by_risk: dict[str, list[dict]] = {}
    for a in alerts:
        by_risk.setdefault(a["risk"], []).append(a)

    for risk in ["High", "Medium", "Low", "Informational"]:
        risk_alerts = by_risk.get(risk, [])
        if not risk_alerts:
            continue
        # Show unique alert *names* at this risk level, with a count each,
        # since the same rule often fires many times across different params/URLs
        names: dict[str, int] = {}
        for a in risk_alerts:
            names[a["name"]] = names.get(a["name"], 0) + 1

        print(f"--- {risk} ({len(risk_alerts)} total) ---")
        for name, count in sorted(names.items(), key=lambda x: -x[1]):
            print(f"  {name}  (x{count})")
        print()


if __name__ == "__main__":
    main()
#for the zap to start scarpping and scanning the juiceshop.
#docker compose exec backend python3 scripts/scan_juice_shop.py 