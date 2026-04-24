from __future__ import annotations

import re
from html import unescape
from urllib.parse import unquote_plus

from core.models import DetectionFinding, RequestContext


class SignatureDetector:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.patterns: list[tuple[str, int, re.Pattern[str]]] = [
            ("sql_injection", 38, re.compile(r"(\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|--|/\*|\bxp_cmdshell\b|\bdrop\s+table\b)", re.I)),
            ("xss", 34, re.compile(r"(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|<\s*img\b[^>]*src\s*=)", re.I)),
            ("command_injection", 42, re.compile(r"(\b(cat|curl|wget|bash|sh|nc|powershell)\b\s+|[;&|`]\s*(cat|curl|wget|bash|sh|nc|id|whoami)\b)", re.I)),
        ]

    def scan(self, context: RequestContext) -> list[DetectionFinding]:
        if not self.enabled:
            return []
        haystack = self._normalize(f"{context.route} {context.query} {context.raw_body}")
        findings: list[DetectionFinding] = []
        for attack_type, severity, pattern in self.patterns:
            match = pattern.search(haystack)
            if match:
                evidence = match.group(0)[:96]
                findings.append(
                    DetectionFinding(
                        detector="signature",
                        attack_type=attack_type,
                        severity=severity,
                        confidence=0.93,
                        evidence=evidence,
                    )
                )
        return findings

    @staticmethod
    def _normalize(value: str) -> str:
        decoded = value
        for _ in range(2):
            decoded = unquote_plus(unescape(decoded))
        decoded = decoded.replace("\x00", "")
        decoded = re.sub(r"/\*!?\d*", " ", decoded)
        decoded = re.sub(r"\s+", " ", decoded)
        return decoded.lower()

