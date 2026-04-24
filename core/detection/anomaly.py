from __future__ import annotations

import math
from collections import defaultdict

from core.models import DetectionFinding, RequestContext


class RunningStat:
    def __init__(self) -> None:
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def stddev(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))


class AnomalyDetector:
    """Explainable baseline detector using running means and standard deviation."""

    def __init__(self, enabled: bool = True, warmup_samples: int = 15, z_threshold: float = 3.0) -> None:
        self.enabled = enabled
        self.warmup_samples = warmup_samples
        self.z_threshold = z_threshold
        self.payload_by_route: dict[str, RunningStat] = defaultdict(RunningStat)
        self.frequency_by_ip: dict[str, RunningStat] = defaultdict(RunningStat)

    def scan(self, context: RequestContext) -> list[DetectionFinding]:
        if not self.enabled:
            return []
        findings: list[DetectionFinding] = []
        payload_stat = self.payload_by_route[context.route]
        frequency_stat = self.frequency_by_ip[context.ip]

        payload_value = float(context.traffic.payload_size)
        frequency_value = float(context.traffic.requests_last_minute)
        if self._is_deviation(payload_stat, payload_value):
            findings.append(
                DetectionFinding(
                    detector="anomaly",
                    attack_type="payload_anomaly",
                    severity=22,
                    confidence=0.70,
                    evidence=f"payload={int(payload_value)} mean={payload_stat.mean:.1f} sd={payload_stat.stddev:.1f}",
                )
            )
        if self._is_deviation(frequency_stat, frequency_value):
            findings.append(
                DetectionFinding(
                    detector="anomaly",
                    attack_type="traffic_anomaly",
                    severity=20,
                    confidence=0.68,
                    evidence=f"rpm={int(frequency_value)} mean={frequency_stat.mean:.1f} sd={frequency_stat.stddev:.1f}",
                )
            )

        payload_stat.update(payload_value)
        frequency_stat.update(frequency_value)
        return findings

    def _is_deviation(self, stat: RunningStat, value: float) -> bool:
        if stat.count < self.warmup_samples:
            return False
        if stat.stddev == 0:
            return value > stat.mean * 2 and value - stat.mean > 256
        return value > stat.mean + self.z_threshold * stat.stddev
