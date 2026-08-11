from zapv2 import ZAPv2
from app.core.config import settings
import time


class ZAPClient:
    def __init__(self):
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