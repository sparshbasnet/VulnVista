"""Run every installed OWASP ZAP XSS rule against an authorized lab target.

The scan combines traditional crawling, browser-driven AJAX crawling, passive
analysis, and every installed active rule whose ZAP metadata identifies it as
XSS. Run with:

    docker compose exec backend python scripts/scan_xss_juice_shop.py

Configuration: XSS_TARGET, XSS_START_URL, XSS_ALLOWED_HOSTS, XSS_TIMEOUT,
ZAP_API_URL and ZAP_API_KEY. Only scan systems you have permission to test.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

ZAP_BASE = os.getenv("ZAP_API_URL", "http://zap:8080").rstrip("/")
API_KEY = os.getenv("ZAP_API_KEY", "vulnvista-dev-key")
TARGET = os.getenv("XSS_TARGET", "http://juice-shop:3000").rstrip("/")
START_URL = os.getenv("XSS_START_URL", f"{TARGET}/#/search?q=juice")
TIMEOUT = int(os.getenv("XSS_TIMEOUT", "600"))
SKIP_CRAWL = os.getenv("XSS_SKIP_CRAWL", "false").lower() in {"1", "true", "yes"}
ALLOWED_HOSTS = {
    host.strip().lower()
    for host in os.getenv(
        "XSS_ALLOWED_HOSTS", "juice-shop,localhost,127.0.0.1,::1"
    ).split(",")
    if host.strip()
}


def zap_call(endpoint: str, params: dict | None = None, retries: int = 3) -> dict:
    """Call a ZAP JSON endpoint, retrying transient failures."""
    query = {"apikey": API_KEY, **(params or {})}
    url = f"{ZAP_BASE}{endpoint}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url, headers={"X-ZAP-API-Key": API_KEY})
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            last_error = error
            print(f"HTTP {error.code} ({attempt}/{retries}): {error.read().decode(errors='replace')}")
        except (OSError, ValueError) as error:
            last_error = error
            print(f"ZAP request failed ({attempt}/{retries}): {error}")
        if attempt < retries:
            time.sleep(3)
    raise RuntimeError(f"ZAP API request failed: {endpoint}") from last_error


def validate_target() -> None:
    target = urllib.parse.urlsplit(TARGET)
    start = urllib.parse.urlsplit(START_URL)
    if target.scheme not in {"http", "https"} or not target.hostname:
        raise ValueError("XSS_TARGET must be a fully-qualified HTTP(S) URL")
    if target.hostname.lower() not in ALLOWED_HOSTS:
        raise ValueError(
            f"Refusing to scan {target.hostname!r}; add an authorized lab host "
            "to XSS_ALLOWED_HOSTS to scan it"
        )
    if (start.scheme, start.netloc) != (target.scheme, target.netloc):
        raise ValueError("XSS_START_URL must have the same origin as XSS_TARGET")


def wait_for_progress(endpoint: str, scan_id: str, label: str) -> None:
    started = time.monotonic()
    while True:
        progress = int(zap_call(endpoint, {"scanId": scan_id})["status"])
        print(f"{label}: {progress}%")
        if progress >= 100:
            return
        if time.monotonic() - started > TIMEOUT:
            raise TimeoutError(f"{label} exceeded {TIMEOUT} seconds")
        time.sleep(3)


def wait_for_ajax_spider() -> None:
    started = time.monotonic()
    while True:
        status = zap_call("/JSON/ajaxSpider/view/status/")["status"].lower()
        print(f"AJAX spider: {status}")
        if status == "stopped":
            return
        if time.monotonic() - started > TIMEOUT:
            zap_call("/JSON/ajaxSpider/action/stop/")
            raise TimeoutError(f"AJAX spider exceeded {TIMEOUT} seconds")
        time.sleep(3)


def wait_for_passive_scan() -> None:
    started = time.monotonic()
    last_change = started
    previous_remaining: int | None = None
    while True:
        remaining = int(zap_call("/JSON/pscan/view/recordsToScan/")["recordsToScan"])
        print(f"Passive records remaining: {remaining}")
        if remaining == 0:
            return
        if remaining != previous_remaining:
            previous_remaining = remaining
            last_change = time.monotonic()
        elif time.monotonic() - last_change > 60:
            print(
                "Passive queue did not change for 60 seconds; continuing because "
                "long-lived SPA traffic can keep records queued."
            )
            return
        if time.monotonic() - started > TIMEOUT:
            raise TimeoutError(f"Passive scan exceeded {TIMEOUT} seconds")
        time.sleep(2)


def is_xss_name(name: str) -> bool:
    normalized = name.casefold().replace("-", " ")
    return "cross site scripting" in normalized or "xss" in normalized


def get_xss_rules(scanners: list[dict]) -> list[dict]:
    rules = [rule for rule in scanners if is_xss_name(rule.get("name", ""))]
    if not rules:
        raise RuntimeError("No XSS active rules are installed in this ZAP instance")
    print("Installed XSS active rules:")
    for rule in rules:
        print(f"  {rule['id']}: {rule['name']}")
    return rules


def save_policy(scanners: list[dict]) -> dict[str, dict[str, str | bool]]:
    return {
        scanner["id"]: {
            "enabled": str(scanner.get("enabled", "false")).lower() == "true",
            "strength": scanner.get("attackStrength", "MEDIUM").upper(),
            "threshold": scanner.get("alertThreshold", "MEDIUM").upper(),
        }
        for scanner in scanners
    }


def configure_xss_policy(rules: list[dict]) -> None:
    zap_call("/JSON/ascan/action/disableAllScanners/")
    zap_call("/JSON/ascan/action/enableScanners/", {"ids": ",".join(r["id"] for r in rules)})
    for rule in rules:
        zap_call("/JSON/ascan/action/setScannerAttackStrength/", {
            "id": rule["id"], "attackStrength": "HIGH"
        })
        zap_call("/JSON/ascan/action/setScannerAlertThreshold/", {
            "id": rule["id"], "alertThreshold": "LOW"
        })


def restore_policy(policy: dict[str, dict[str, str | bool]]) -> None:
    """Restore ZAP's global scanner settings after success or failure."""
    zap_call("/JSON/ascan/action/disableAllScanners/")
    enabled = [rule_id for rule_id, state in policy.items() if state["enabled"]]
    if enabled:
        zap_call("/JSON/ascan/action/enableScanners/", {"ids": ",".join(enabled)})
    for rule_id, state in policy.items():
        zap_call("/JSON/ascan/action/setScannerAttackStrength/", {
            "id": rule_id, "attackStrength": state["strength"]
        })
        zap_call("/JSON/ascan/action/setScannerAlertThreshold/", {
            "id": rule_id, "alertThreshold": state["threshold"]
        })


def crawl() -> None:
    zap_call("/JSON/core/action/accessUrl/", {"url": START_URL, "followRedirects": "true"})
    print("Starting traditional spider...")
    spider_id = zap_call("/JSON/spider/action/scan/", {
        "url": TARGET, "recurse": "true", "subtreeOnly": "true"
    })["scan"]
    wait_for_progress("/JSON/spider/view/status/", spider_id, "Traditional spider")

    print("Starting browser-driven AJAX spider...")
    zap_call("/JSON/ajaxSpider/action/scan/", {
        "url": START_URL, "inScope": "false", "subtreeOnly": "true"
    })
    wait_for_ajax_spider()
    wait_for_passive_scan()


def active_scan() -> str:
    print("Running recursive active scan with all installed XSS rules...")
    scan_id = zap_call("/JSON/ascan/action/scan/", {
        "url": TARGET, "recurse": "true", "inScopeOnly": "false"
    })["scan"]
    wait_for_progress("/JSON/ascan/view/status/", scan_id, "XSS active scan")
    wait_for_passive_scan()
    return scan_id


def print_findings(scan_id: str, rule_ids: list[str]) -> None:
    alerts = zap_call("/JSON/core/view/alerts/", {"baseurl": TARGET}).get("alerts", [])
    findings = [alert for alert in alerts if is_xss_name(alert.get("name", ""))]
    print(f"\nXSS alerts: {len(findings)}")
    print(f"Active scan ID: {scan_id}")
    print(f"XSS rule IDs: {', '.join(rule_ids)}")
    for alert in findings:
        print(f"\n[{alert.get('risk', 'Unknown')}] {alert.get('name', 'XSS')}")
        for label, key in (
            ("Confidence", "confidence"), ("URL", "url"), ("Method", "method"),
            ("Parameter", "param"), ("Attack", "attack"),
            ("Evidence", "evidence"), ("CWE", "cweid"),
        ):
            print(f"  {label}: {alert.get(key, 'N/A')}")
    if not findings:
        print("No XSS was found in reachable routes/states; this is not proof of absence.")


def main() -> None:
    validate_target()
    scanners = zap_call("/JSON/ascan/view/scanners/").get("scanners", [])
    rules = get_xss_rules(scanners)
    previous_policy = save_policy(scanners)
    if SKIP_CRAWL:
        print("Reusing URLs already discovered in ZAP (XSS_SKIP_CRAWL=true).")
    else:
        crawl()
    scan_id: str | None = None
    try:
        configure_xss_policy(rules)
        scan_id = active_scan()
    finally:
        print("Restoring previous ZAP scanner settings...")
        restore_policy(previous_policy)
    if scan_id is not None:
        print_findings(scan_id, [rule["id"] for rule in rules])


if __name__ == "__main__":
    main()
