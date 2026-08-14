import time
from collections.abc import Iterable
from urllib.parse import urlsplit

from zapv2 import ZAPv2

from app.core.config import get_settings

from zapv2 import ZAPv2

from app.core.config import settings


class ZAPClient:
    def __init__(self):
        settings = get_settings()
        self.zap = ZAPv2(
            apikey=settings.zap_api_key,
            proxies={
                "http": settings.zap_api_url,
                "https": settings.zap_api_url,
            },
        )

    def is_ready(self) -> bool:
        """Health check — confirms ZAP daemon is reachable and responding."""
        try:
            version = self.zap.core.version
            return bool(version)
        except Exception:
            return False

    def new_context(self, context_name: str, target_url: str) -> str:
        """Creates (or reuses) a ZAP context scoped to a target URL."""
        context_id = self.zap.context.new_context(context_name)
        self.zap.context.include_in_context(context_name, f"{target_url}.*")
        return context_id

    def spider(self, target_url: str, context_name: str | None = None, timeout: int = 60):
        """Crawls the target first so the active scanner has URLs to test."""
        scan_id = self.zap.spider.scan(target_url, contextname=context_name)
        start = time.time()
        while int(self.zap.spider.status(scan_id)) < 100:
            if time.time() - start > timeout:
                raise TimeoutError("ZAP spider scan timed out")
            time.sleep(1)
        return scan_id

    def active_scan(self, target_url: str, context_id: str | None = None, timeout: int = 300):
        """Runs ZAP's active scan against the target, blocking until complete."""
        scan_id = self.zap.ascan.scan(target_url, contextid=context_id)
        start = time.time()
        while int(self.zap.ascan.status(scan_id)) < 100:
            if time.time() - start > timeout:
                raise TimeoutError("ZAP active scan timed out")
            time.sleep(2)
        return scan_id

    def access_url(self, target_url: str) -> None:
        """Register a target in ZAP's Sites Tree."""
        self.zap.core.access_url(target_url, followredirects=True)

    def seed_json_post_request(self, url: str, payload: str) -> None:
        """Add a JSON POST request to ZAP history so it can be actively scanned."""
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            raise ValueError("A fully-qualified URL is required to seed a ZAP request")

        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        raw_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {parts.netloc}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload.encode())}\r\n"
            "\r\n"
            f"{payload}"
        )
        self.zap.core.send_request(raw_request, followredirects=True)

    def get_sqli_rule_ids(self) -> list[str]:
        """Return the IDs of active-scanner rules whose name is SQL Injection."""
        return [
            scanner["id"]
            for scanner in self.zap.ascan.scanners()
            if "sql injection" in scanner.get("name", "").lower()
        ]

    def active_scan_with_rules(
        self,
        url: str,
        rule_ids: Iterable[str],
        *,
        method: str,
        post_data: str,
        timeout: int = 300,
    ) -> str:
        """Run an active scan with only ``rule_ids`` enabled, then restore ZAP's rules.

        ZAP scanner enablement is global to its daemon.  This method restores the
        prior configuration even if the scan fails, so a SQLi scan cannot leave
        later detectors with an unexpected policy.
        """
        rule_ids = list(rule_ids)
        if not rule_ids:
            raise ValueError("At least one active-scanner rule must be enabled")

        scanners = self.zap.ascan.scanners()
        previously_enabled = [
            scanner["id"]
            for scanner in scanners
            if str(scanner.get("enabled", "false")).lower() == "true"
        ]
        self.zap.ascan.disable_all_scanners()
        try:
            self.zap.ascan.enable_scanners(",".join(rule_ids))
            scan_id = self.zap.ascan.scan(
                url,
                recurse=False,
                inscopeonly=False,
                method=method,
                postdata=post_data,
            )
            start = time.monotonic()
            while int(self.zap.ascan.status(scan_id)) < 100:
                if time.monotonic() - start > timeout:
                    raise TimeoutError("ZAP SQL Injection active scan timed out")
                time.sleep(2)
            return scan_id
        finally:
            self.zap.ascan.disable_all_scanners()
            if previously_enabled:
                self.zap.ascan.enable_scanners(",".join(previously_enabled))

    def get_alerts(self, base_url: str, risk: str | None = None) -> list[dict]:
        """
        Retrieves ZAP alerts for a target, optionally filtered by risk level.
        Returns raw ZAP alert dicts — detectors parse these into DetectorResult.
        """
        alerts = self.zap.core.alerts(baseurl=base_url)
        if risk:
            alerts = [a for a in alerts if a.get("risk", "").lower() == risk.lower()]
        return alerts


# Singleton instance — import this in detectors, don't instantiate ZAPClient() repeatedly
zap_client = ZAPClient()
