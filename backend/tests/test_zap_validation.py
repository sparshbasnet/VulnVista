from app.scanners.base import DetectorResult, ScanContext
from app.scanners.zap_validation import corroborate_with_zap


def _result(*, detected: bool = False) -> DetectorResult:
    return DetectorResult(
        detector="csrf",
        vulnerability="Cross-Site Request Forgery",
        detected=detected,
        validation_status="SUSPECTED" if detected else "NOT_DETECTED",
        severity="MEDIUM",
        confidence="MEDIUM",
        evidence_summary="A form lacks a token." if detected else None,
    )


async def test_zap_validation_is_skipped_when_disabled(monkeypatch) -> None:
    def unexpected_call() -> bool:
        raise AssertionError("ZAP should not be contacted")

    monkeypatch.setattr("app.scanners.zap_validation.zap_client.is_ready", unexpected_call)
    result = _result()

    validated = await corroborate_with_zap(
        "csrf", ScanContext(target_id="target", base_url="http://dvwa"), result
    )

    assert validated is result
    assert "zap_validation" not in validated.evidence


async def test_matching_zap_alert_confirms_primary_finding(monkeypatch) -> None:
    monkeypatch.setattr("app.scanners.zap_validation.zap_client.is_ready", lambda: True)
    monkeypatch.setattr(
        "app.scanners.zap_validation.zap_client.passive_scan",
        lambda _url: [
            {
                "alert": "Absence of Anti-CSRF Tokens",
                "risk": "Medium",
                "confidence": "Medium",
                "url": "http://dvwa/profile.php",
                "cweid": "352",
            }
        ],
    )

    validated = await corroborate_with_zap(
        "csrf",
        ScanContext(target_id="target", base_url="http://dvwa", extra={"use_zap": True}),
        _result(detected=True),
    )

    assert validated.validation_status == "CONFIRMED"
    assert validated.confidence == "HIGH"
    assert validated.evidence["zap_validation"]["matching_alerts"][0]["cweid"] == "352"


async def test_zap_only_alert_creates_suspected_finding(monkeypatch) -> None:
    monkeypatch.setattr("app.scanners.zap_validation.zap_client.is_ready", lambda: True)
    monkeypatch.setattr(
        "app.scanners.zap_validation.zap_client.passive_scan",
        lambda _url: [{"alert": "Cookie No HttpOnly Flag", "risk": "Low"}],
    )

    validated = await corroborate_with_zap(
        "jwt_session",
        ScanContext(target_id="target", base_url="http://dvwa", extra={"use_zap": True}),
        _result(),
    )

    assert validated.detected is True
    assert validated.validation_status == "SUSPECTED"
    assert validated.severity == "LOW"


async def test_unavailable_zap_preserves_primary_result(monkeypatch) -> None:
    monkeypatch.setattr("app.scanners.zap_validation.zap_client.is_ready", lambda: False)
    result = _result(detected=True)

    validated = await corroborate_with_zap(
        "csrf",
        ScanContext(target_id="target", base_url="http://dvwa", extra={"use_zap": True}),
        result,
    )

    assert validated.detected is True
    assert validated.validation_status == "SUSPECTED"
    assert validated.evidence["zap_validation"]["reachable"] is False
