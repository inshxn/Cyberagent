from __future__ import annotations

from core.models import DetectionFinding, RequestContext


class BehaviorDetector:
    def __init__(
        self,
        enabled: bool = True,
        requests_per_second: int = 8,
        requests_per_minute: int = 120,
        brute_force_failures: int = 5,
        max_payload_bytes: int = 32768,
    ) -> None:
        self.enabled = enabled
        self.requests_per_second = requests_per_second
        self.requests_per_minute = requests_per_minute
        self.brute_force_failures = brute_force_failures
        self.max_payload_bytes = max_payload_bytes

    def scan(self, context: RequestContext) -> list[DetectionFinding]:
        if not self.enabled:
            return []
        findings: list[DetectionFinding] = []
        traffic = context.traffic

        if traffic.requests_last_second > self.requests_per_second:
            findings.append(self._finding("rate_limit", 24, f"{traffic.requests_last_second} req/s"))
        if traffic.requests_last_minute > self.requests_per_minute:
            findings.append(self._finding("rate_limit", 28, f"{traffic.requests_last_minute} req/min"))
        if traffic.login_failures_last_5m >= self.brute_force_failures:
            findings.append(self._finding("brute_force", 36, f"{traffic.login_failures_last_5m} failed logins/5m"))
        if traffic.payload_size > self.max_payload_bytes:
            findings.append(self._finding("large_payload", 25, f"{traffic.payload_size} bytes"))
        return findings

    @staticmethod
    def _finding(attack_type: str, severity: int, evidence: str) -> DetectionFinding:
        return DetectionFinding(
            detector="behavior",
            attack_type=attack_type,
            severity=severity,
            confidence=0.82,
            evidence=evidence,
        )

