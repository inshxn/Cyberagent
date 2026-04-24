from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Any


class Action(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    THROTTLE = "throttle"
    BLOCK = "block"


@dataclass
class TrafficStats:
    requests_last_second: int = 0
    requests_last_minute: int = 0
    login_failures_last_5m: int = 0
    payload_size: int = 0
    route_hits_last_minute: int = 0


@dataclass
class RequestContext:
    ip: str
    method: str
    route: str
    headers: dict[str, str]
    query: dict[str, Any]
    body: Any
    raw_body: str
    timestamp: float = field(default_factory=time)
    traffic: TrafficStats = field(default_factory=TrafficStats)

    @property
    def payload_snippet(self) -> str:
        merged = f"query={self.query} body={self.raw_body}"
        return merged[:512]


@dataclass
class DetectionFinding:
    detector: str
    attack_type: str
    severity: int
    confidence: float
    evidence: str


@dataclass
class Decision:
    risk_score: int
    action: Action
    findings: list[DetectionFinding]
    reasons: list[str]
    delay_ms: int = 0

    @property
    def attack_types(self) -> str:
        if not self.findings:
            return "none"
        return ",".join(sorted({finding.attack_type for finding in self.findings}))

