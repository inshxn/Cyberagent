from __future__ import annotations

from core.models import Action, Decision, DetectionFinding
from core.traffic import SessionTracker


class DecisionEngine:
    def __init__(
        self,
        tracker: SessionTracker,
        signature_weight: float = 1.0,
        behavior_weight: float = 0.85,
        anomaly_weight: float = 0.65,
        throttle_delay_ms: int = 650,
    ) -> None:
        self.tracker = tracker
        self.weights = {
            "signature": signature_weight,
            "behavior": behavior_weight,
            "anomaly": anomaly_weight,
        }
        self.throttle_delay_ms = throttle_delay_ms

    def decide(self, ip: str, findings: list[DetectionFinding]) -> Decision:
        reasons: list[str] = []
        score = 0.0
        for finding in findings:
            weighted = finding.severity * finding.confidence * self.weights.get(finding.detector, 1.0)
            score += weighted
            reasons.append(f"{finding.detector}:{finding.attack_type} ({finding.evidence})")

        history = self.tracker.history_risk(ip)
        if history:
            score += history
            reasons.append(f"adaptive_history:+{history}")

        risk_score = min(100, max(0, round(score)))
        action = self._map_action(risk_score)
        delay_ms = self.throttle_delay_ms if action == Action.THROTTLE else 0
        return Decision(risk_score=risk_score, action=action, findings=findings, reasons=reasons, delay_ms=delay_ms)

    @staticmethod
    def _map_action(score: int) -> Action:
        if score <= 30:
            return Action.ALLOW
        if score <= 60:
            return Action.FLAG
        if score <= 80:
            return Action.THROTTLE
        return Action.BLOCK

