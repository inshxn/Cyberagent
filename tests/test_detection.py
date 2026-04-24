from core.detection import AnomalyDetector, BehaviorDetector, SignatureDetector
from core.models import RequestContext, TrafficStats


def context(raw: str = "", route: str = "/api/search") -> RequestContext:
    return RequestContext(
        ip="10.0.0.5",
        method="GET",
        route=route,
        headers={},
        query={"q": raw},
        body=raw,
        raw_body=raw,
        traffic=TrafficStats(requests_last_second=1, requests_last_minute=1, payload_size=len(raw)),
    )


def test_signature_detector_finds_common_attacks() -> None:
    detector = SignatureDetector()
    attacks = detector.scan(context("' OR 1=1 --")) + detector.scan(context("<script>alert(1)</script>")) + detector.scan(context("; cat /etc/passwd"))
    types = {finding.attack_type for finding in attacks}
    assert {"sql_injection", "xss", "command_injection"}.issubset(types)


def test_behavior_detector_flags_rate_and_payload() -> None:
    detector = BehaviorDetector(requests_per_second=2, max_payload_bytes=10)
    ctx = context("x" * 20)
    ctx.traffic.requests_last_second = 4
    ctx.traffic.payload_size = 20
    findings = detector.scan(ctx)
    assert {finding.attack_type for finding in findings} == {"rate_limit", "large_payload"}


def test_anomaly_detector_uses_warm_baseline() -> None:
    detector = AnomalyDetector(warmup_samples=3, z_threshold=2.0)
    for _ in range(4):
        detector.scan(context("small"))
    findings = detector.scan(context("x" * 5000))
    assert any(finding.attack_type == "payload_anomaly" for finding in findings)

